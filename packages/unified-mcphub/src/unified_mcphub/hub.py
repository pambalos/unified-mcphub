"""The foreground hub — spec §8, §10.

`unified-mcphub start` runs this. It binds transports, supervises external MCP
servers, serves as an MCP server aggregating external + built-in tools, and on
every call runs the hot path: resolve authz -> (prompt) -> two-phase audit ->
forward -> result. Hot-path pseudo is spec §5.2.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import signal
import sys
import time
from pathlib import Path

import yaml
from mcp import types
from ulid import ULID
from watchfiles import awatch

from . import audit as audit_mod
from . import discovery
from . import endpoints
from . import servers as servers_mod
from .approval import Approval
from .authz import AuthzResolver, Effect
from .config import (
    Config,
    Rule,
    audit_dir,
    bootstrap,
    canonical_truth_path,
    config_path,
    load_config,
    load_learned_rules,
    mcphub_home,
    workspace_local_path,
)
from .redaction import Redactor
from .secrets import SecretsStore
from .supervisor import SupervisedServer
from .tokens import TokenStore
from .tools import BuiltinRegistry
from .transports import TransportServer, build_app
from .util import now_iso, secure_write

logger = logging.getLogger(__name__)

BUILTIN_SERVER = "built-in"


def _config_hash(config: Config) -> str:
    blob = json.dumps(config.model_dump(), sort_keys=True, default=str).encode()
    return "sha256:" + hashlib.sha256(blob).hexdigest()[:16]


def _ok(req_id, result) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _err(req_id, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def _result_dict(value) -> dict:
    if isinstance(value, types.CallToolResult):
        return value.model_dump(by_alias=True, exclude_none=True, mode="json")
    text = value if isinstance(value, str) else json.dumps(value, default=str)
    return {"content": [{"type": "text", "text": text}], "isError": False}


class Hub:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.servers: dict[str, SupervisedServer] = {}
        self.builtins = BuiltinRegistry()
        self.authz = AuthzResolver(config.workspace, config.dangerous)
        self.redactor = Redactor(config.workspace.redact)
        self.approval = Approval(
            enabled=config.hub.approval.enabled,
            foreground=sys.stdin.isatty() and sys.stdout.isatty(),
        )
        self.audit = audit_mod.AuditLog(audit_dir())
        self.tokens = TokenStore()
        self.secrets = SecretsStore()
        self._transport = TransportServer(build_app(self), config.hub.listen)
        self._started_at = now_iso()
        self._reload_task: asyncio.Task | None = None
        self._refresh_task: asyncio.Task | None = None

    # --- lifecycle (spec §8) ---

    async def start(self) -> None:
        mcphub_home().mkdir(parents=True, exist_ok=True)
        self.audit.start()
        self.builtins.load_user_tools(mcphub_home() / "tools")

        for name, spec in self.config.workspace.servers.items():
            if not spec.enabled:
                logger.info("server '%s' disabled (enabled: false); skipping", name)
                continue
            await self._add_server(name, spec)
        await self._await_servers_ready()

        await self._transport.start()
        self._write_canonical_truth()
        self._publish_discovery()
        self._refresh_task = asyncio.create_task(self._refresh_loop())
        self._reload_task = asyncio.create_task(self._watch_reload())
        logger.info(
            "hub started: workspace=%s servers=%s",
            self.config.workspace_name,
            list(self.servers),
        )

    async def stop(self) -> None:
        tasks = [t for t in (self._reload_task, self._refresh_task) if t is not None]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        await self._transport.stop()
        for server in list(self.servers.values()):
            await server.stop()
        self.audit.stop()  # release the audit lock first — must always happen
        discovery.remove()  # best-effort; a leftover entry goes stale (ADR-0013)

    # --- MCP server surface (spec §10) ---

    async def handle_mcp(
        self, message: dict, caller_id: str, caller_token_id: str | None = None
    ) -> dict | None:
        method = message.get("method")
        req_id = message.get("id")
        if method == "initialize":
            return _ok(
                req_id,
                {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "unified-hub", "version": "0.0.1"},
                },
            )
        if method == "notifications/initialized":
            return None
        if method == "ping":
            return _ok(req_id, {})
        if method == "tools/list":
            return _ok(req_id, {"tools": self._aggregate_tools()})
        if method == "tools/call":
            return await self._handle_call(message, caller_id, caller_token_id)
        return _err(req_id, -32601, f"method not found: {method}")

    def _aggregate_tools(self) -> list[dict]:
        tools: list[dict] = []
        for server in self.servers.values():
            for tool in server.tools:
                tools.append(self._namespaced(server.name, tool))
        for tool in self.builtins.list_tools():
            tools.append(self._namespaced(BUILTIN_SERVER, tool))
        return tools

    @staticmethod
    def _namespaced(server: str, tool: types.Tool) -> dict:
        data = tool.model_dump(by_alias=True, exclude_none=True, mode="json")
        data["name"] = f"{server}__{tool.name}"
        return data

    async def _handle_call(
        self, message: dict, caller_id: str, caller_token_id: str | None = None
    ) -> dict:
        req_id = message.get("id")
        params = message.get("params") or {}
        full_name = params.get("name", "")
        args = params.get("arguments") or {}
        server_name, sep, tool = full_name.partition("__")
        if not sep:
            return _err(req_id, -32602, f"tool name must be '<server>__<tool>': {full_name!r}")

        tool_uri = f"mcp://{server_name}/{tool}"
        request_id = str(ULID())
        trace_id, span_id = audit_mod.new_trace_id(), audit_mod.new_span_id()
        decision = self.authz.resolve(tool_uri, args, caller_id)

        authz_decision = decision.effect.value
        prompt_ms: float | None = None
        if decision.effect is Effect.PROMPT:
            t0 = time.monotonic()
            outcome = await self.approval.resolve(
                tool_uri,
                caller_id,
                _summary(tool, args),
                args,
                floored=decision.source == "danger_floor",
            )
            prompt_ms = (time.monotonic() - t0) * 1000
            authz_decision = outcome.authz_decision
            if outcome.persistent:
                self._persist_exact_rule(
                    tool_uri, caller_id, allowed=outcome.allowed, args_filter=outcome.args_filter
                )
            denied_reason = outcome.reason
            allowed = outcome.allowed
        else:
            allowed = decision.effect is Effect.ALLOW
            denied_reason = None

        self.audit.write_received(
            request_id=request_id,
            trace_id=trace_id,
            span_id=span_id,
            caller_id=caller_id,
            caller_token_id=caller_token_id,
            mcp_server=server_name,
            tool=tool,
            args=args,
            authz_decision=authz_decision,
            authz_rule=decision.rule,
            audit_level=decision.audit_level,
            reason=denied_reason,
        )

        if not allowed:
            # deny / prompt_denied / no_approval_channel -> received only (spec §6.2)
            return _err(req_id, -32003, f"denied by policy ({authz_decision})")

        t0 = time.monotonic()
        try:
            value = await self._forward(server_name, tool, args)
            # Redact secrets before the result is audited or returned, so neither
            # the audit log nor the caller ever sees them (spec §10.2).
            result = self.redactor.result(_result_dict(value))
            status = "error" if result.get("isError") else "ok"
        except Exception as exc:  # noqa: BLE001
            duration = (time.monotonic() - t0) * 1000
            self.audit.write_completed(
                request_id=request_id,
                duration_ms=duration,
                result={"error": str(exc)},
                result_status="error",
                audit_level=decision.audit_level,
                prompt_response_ms=prompt_ms,
            )
            return _err(req_id, -32000, f"tool execution failed: {exc}")

        self.audit.write_completed(
            request_id=request_id,
            duration_ms=(time.monotonic() - t0) * 1000,
            result=result,
            result_status=status,
            audit_level=decision.audit_level,
            prompt_response_ms=prompt_ms,
        )
        return _ok(req_id, result)

    async def _forward(self, server_name: str, tool: str, args: dict):
        if server_name == BUILTIN_SERVER:
            if not self.builtins.has(tool):
                raise ValueError(f"unknown built-in tool: {tool}")
            return self.builtins.call(tool, args)
        server = self.servers.get(server_name)
        if server is None:
            raise ValueError(f"unknown server: {server_name}")
        return await server.call(tool, args)

    # --- server management ---

    def _pinning_ok(self, name: str, spec) -> bool:
        """Supply-chain floor: refuse to stand up an unpinned fetch-and-run upstream
        when `require_pinned_versions` is on (unless the server opts out). Fail closed
        — skip the server, keep the rest of the hub running."""
        if not self.config.hub.require_pinned_versions or spec.allow_unpinned:
            return True
        if servers_mod.is_pinned(spec):
            return True
        logger.error(
            "server '%s' refused: unpinned fetch-and-run upstream and "
            "require_pinned_versions is on. Pin a version, set `allow_unpinned: true` "
            "on the server, or disable the policy in config.yaml.",
            name,
        )
        return False

    async def _add_server(self, name: str, spec) -> None:
        if not self._pinning_ok(name, spec):
            return
        server = SupervisedServer(name, spec, token_store=self.secrets)
        self.servers[name] = server
        await server.start()

    async def _await_servers_ready(self) -> None:
        if not self.servers:
            return
        await asyncio.gather(
            *(s.wait_ready(timeout=30) for s in self.servers.values()),
            return_exceptions=True,
        )

    # --- approval persistence (spec §5.3, ADR-0006 tier-1 exact rule) ---

    def _persist_exact_rule(
        self, tool_uri: str, caller: str, *, allowed: bool, args_filter: dict | None = None
    ) -> None:
        rule = Rule(
            tool=tool_uri,
            callers=[caller],
            effect="allow" if allowed else "deny",
            args_filter=args_filter,
        )
        # Immediate effect: prepend in-memory so the next call sees it before reload.
        self.config.workspace.authz.rules.insert(0, rule)
        self.authz = AuthzResolver(self.config.workspace, self.config.dangerous)
        # Persist to the machine-managed `.local.yaml` (ADR-0024). The curated
        # workspace file is never rewritten by the hub, so a plain YAML dump of a
        # flat rule list is enough — no comments to preserve. The args_filter
        # (ADR-0025) is omitted when absent so tool-wide rules stay minimal.
        name = self.config.workspace_name
        learned = load_learned_rules(name)
        entry: dict = {"tool": tool_uri, "callers": [caller], "effect": rule.effect}
        if args_filter:
            entry["args_filter"] = args_filter
        learned.insert(0, entry)
        secure_write(workspace_local_path(name), yaml.safe_dump(learned, sort_keys=False).encode())

    # --- discovery + canonical truth (spec §11.1, §12) ---

    def _listen_dict(self) -> dict:
        listen: dict = {}
        if self._transport.uds_path:
            listen["unix_socket"] = self._transport.uds_path
        if self.config.hub.listen.tcp:
            listen["http"] = f"http://{self.config.hub.listen.tcp}"
        return listen

    def _publish_discovery(self) -> None:
        discovery.publish(
            listen=self._listen_dict(),
            servers=list(self.servers),
            config_hash=_config_hash(self.config),
            started_at=self._started_at,
        )

    def _write_canonical_truth(self) -> None:
        truth = endpoints.canonical_truth(self.config.workspace_name, self.config.hub)
        secure_write(canonical_truth_path(), json.dumps(truth, indent=2).encode())

    async def _refresh_loop(self) -> None:
        # Forever loop: a transient failure touching a multi-daemon file must not
        # kill liveness heartbeats, so this is the one place we keep a broad catch.
        while True:
            await asyncio.sleep(30)
            try:
                discovery.refresh()
            except Exception as exc:  # noqa: BLE001 - best-effort heartbeat
                logger.warning("discovery refresh failed: %s", exc)

    # --- file-watch reload (spec §8) ---

    def _watch_paths(self) -> list[str]:
        # Watch the hub config file and the whole workspaces directory. The active
        # workspace's curated <name>.yaml and machine-managed <name>.local.yaml both
        # live in that directory; watching the directory (rather than the two files)
        # also catches a .local.yaml created/removed mid-session, which awatch can't
        # do for a path that is absent when the watch starts. Reload is idempotent
        # and keyed to the active workspace, so events for other files are no-ops.
        return [
            p for p in (str(config_path()), str(mcphub_home() / "workspaces")) if Path(p).exists()
        ]

    async def _watch_reload(self) -> None:
        watched = self._watch_paths()
        if not watched:
            return
        # Cancellation on stop() propagates out of awatch and ends this task cleanly.
        async for _ in awatch(*watched):
            await self._reload()

    async def _reload(self) -> None:
        try:
            new = load_config(self.config.workspace_name)
        except Exception as exc:  # noqa: BLE001 - spec §8: any validation failure keeps prior config
            logger.error("config reload failed; keeping prior config: %s", exc)
            return
        self.config = new
        self.authz = AuthzResolver(new.workspace, new.dangerous)
        self.redactor = Redactor(new.workspace.redact)
        self.approval.enabled = new.hub.approval.enabled
        await self._apply_server_diff(new.workspace.servers)
        self._write_canonical_truth()
        self._publish_discovery()
        logger.info("config reloaded: servers=%s", list(self.servers))

    async def _apply_server_diff(self, desired: dict) -> None:
        # A disabled server is treated like an absent one: stop it if running,
        # never (re)start it. So flipping enabled: false on reload tears it down.
        active = {name: spec for name, spec in desired.items() if spec.enabled}
        for name in list(self.servers):
            if name not in active:
                await self.servers.pop(name).stop()
        for name, spec in active.items():
            current = self.servers.get(name)
            if current is None:
                await self._add_server(name, spec)
            elif current.spec != spec:
                await current.stop()
                self.servers.pop(name, None)
                await self._add_server(name, spec)

    # --- status (spec §15 /status) ---

    def status(self) -> dict:
        return {
            "name": "unified-hub",
            "workspace": self.config.workspace_name,
            "started_at": self._started_at,
            "servers": {
                name: {"healthy": s.healthy, "tools": len(s.tools), "last_error": s.last_error}
                for name, s in self.servers.items()
            },
        }


def _summary(tool: str, args: dict) -> str:
    rendered = json.dumps(args, default=str)
    return f"{tool}({rendered[:120]})"


async def run(workspace: str | None = None) -> None:
    """CLI entry: start the hub and run until SIGINT/SIGTERM (spec §8)."""
    created = bootstrap()  # first-run: seed a working default config
    if created:
        logger.info("seeded default config: %s", ", ".join(str(p) for p in created))
    hub = Hub(load_config(workspace))
    await hub.start()
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        # add_signal_handler is unavailable on Windows; the KeyboardInterrupt
        # fallback in cli.cmd_start covers ctrl-C there.
        if sys.platform != "win32":
            loop.add_signal_handler(sig, stop.set)
    try:
        await stop.wait()
    finally:
        await hub.stop()
