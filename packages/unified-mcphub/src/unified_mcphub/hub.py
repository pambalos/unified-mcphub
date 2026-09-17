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
import os
import signal
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import yaml
from mcp import types
from ulid import ULID
from watchfiles import awatch

from unified_enforce import Action, ActionContext, Principal, Telemetry
from unified_enforce.distribution import FLEET_WIDE as _FLEET_WIDE
from unified_paths import canonical

from . import audit as audit_mod
from . import discovery
from . import endpoints
from . import servers as servers_mod
from .approval import Approval, ApprovalChannel, TerminalChannel
from .control import ApprovalEventBroadcaster, ControlApiChannel, PendingRegistry
from .authz import AuthzResolver, Effect
from .fleet import FleetLink
from . import injection
from .config import (
    ApprovalConfig,
    Config,
    OtelConfig,
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
from .policy_diff import policy_broadening
from .redaction import Redactor
from .secrets import SecretsKeyError, SecretsStore
from .supervisor import SupervisedServer
from .tokens import TokenStore
from .tools import BuiltinRegistry
from .transports import TransportServer, build_app
from .util import now_iso, secure_write

logger = logging.getLogger(__name__)

BUILTIN_SERVER = "built-in"

#: The containment entry that means "everyone in the fleet". The engine's
#: sentinel, so `interdict("*")` and `gate()` cannot stop meaning the same
#: thing.
FLEET_WIDE = _FLEET_WIDE


#: How often one source's identity refusals are recorded (seconds), and how
#: many sources the hub tracks at once. Bounds on what an unauthenticated
#: caller can make the hub write.
REFUSAL_WINDOW = 60.0
REFUSAL_SOURCES = 1024


@dataclass
class Interdiction:
    """Why an in-flight forward was cancelled, and by whom."""

    by: str
    reason: str


@dataclass
class InFlight:
    """One forward between its `received` and its closing audit entry.

    The registry of these *is* the hub's in-flight state (build-04). It is
    derived from the two-phase bracket — an entry exists exactly while the
    forward task runs — rather than kept as a second source of truth that
    could disagree with the audit log.
    """

    request_id: str
    principal: str
    tool_uri: str
    task: asyncio.Task
    started: float
    interdiction: Interdiction | None = None


class PolicyDirWritableError(RuntimeError):
    """Raised at boot when `deployment.require_protected_config_dir` is set and
    the policy directory is writable by the account the servers run as."""


def _euid_label() -> str:
    """The effective uid as a string, or a portable placeholder off POSIX.

    `os.geteuid` does not exist on Windows; the permission check itself
    (`os.access`) is cross-platform, so only this diagnostic needs guarding.
    """
    getter = getattr(os, "geteuid", None)
    return f"uid {getter()}" if getter is not None else "this process's account"


def check_policy_dir_permissions(deployment, home) -> None:
    """Report — or, when asked, refuse — a locked deployment whose policy dir the
    account the servers run as can still write. Module-level so it is testable
    without standing up a hub. See `Hub._check_policy_dir_permissions`.
    """
    if not deployment.is_locked or not os.access(home, os.W_OK):
        return
    detail = (
        f"policy_protection=locked but {home} is writable by {_euid_label()}, the account "
        "the MCP servers also run as; the policy-layer protections are defence in depth and "
        "a symlink race or a shell redirection can still get through. Run the servers as a "
        "separate account or mount this directory read-only for them "
        "(docs/deployment-security.md)."
    )
    if deployment.require_protected_config_dir:
        # Opt-in: the operator declared the OS boundary a precondition, so a
        # writable dir is a misconfiguration to fix before serving, not a
        # warning to serve through.
        raise PolicyDirWritableError(detail)
    logger.warning(detail)


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


def _build_telemetry(cfg: OtelConfig) -> Telemetry:
    """Decision spans, off unless configured (UAI-86).

    A misconfigured collector must not stop the hub from serving tools —
    enforcement does not depend on being observed — so a failure here degrades
    to the no-op and logs. The usual cause is the `[otel]` extra not being
    installed, which is a deployment choice rather than an error.
    """
    if not cfg.enabled:
        return Telemetry.disabled()
    try:
        if cfg.langfuse_host and cfg.langfuse_public_key and cfg.langfuse_secret_key:
            return Telemetry.for_langfuse(
                cfg.langfuse_host,
                cfg.langfuse_public_key,
                cfg.langfuse_secret_key,
                service_name=cfg.service_name,
            )
        return Telemetry(
            service_name=cfg.service_name, endpoint=cfg.endpoint, headers=cfg.headers or None
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("otel disabled: %s", exc)
        return Telemetry.disabled()


class Hub:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.servers: dict[str, SupervisedServer] = {}
        self.builtins = BuiltinRegistry()
        self.telemetry = _build_telemetry(config.hub.otel)
        #: Joined to a fleet, or standalone (None). Built before the authorizer
        #: because the authorizer's Enforcer must hold the fleet's revocation
        #: state to gate on containment before policy.
        self.fleet: FleetLink | None = (
            FleetLink(config.hub.control_plane, on_containment=self._on_containment_change)
            if config.hub.control_plane.enabled
            else None
        )
        self.authz = self._build_authz(config)
        #: Forwards currently between `received` and their closing entry.
        self._inflight: dict[str, InFlight] = {}
        #: (source, method) → (window started at, refusals not recorded since).
        self._refusals: dict[tuple[str, str], tuple[float, int]] = {}
        self._loop: asyncio.AbstractEventLoop | None = None
        self.redactor = Redactor(config.workspace.redact)
        approval_cfg = config.hub.approval
        self.approval_events = ApprovalEventBroadcaster()
        self.pending = PendingRegistry(publish=self.approval_events.publish)
        self.approval = Approval(
            enabled=approval_cfg.enabled,
            channel=self._select_approval_channel(approval_cfg),
        )
        self.audit = audit_mod.AuditLog(audit_dir())
        self.tokens = TokenStore()
        self.secrets = SecretsStore.from_config(config.hub.secrets)
        self._transport = TransportServer(build_app(self), config.hub.listen)
        self._started_at = now_iso()
        self._reload_task: asyncio.Task | None = None
        self._refresh_task: asyncio.Task | None = None

    def _build_authz(self, config: Config) -> AuthzResolver:
        return AuthzResolver(
            config.workspace,
            config.dangerous,
            telemetry=self.telemetry,
            deployment=config.hub.deployment,
            distribution=self.fleet.distribution if self.fleet else None,
            evidence=self.fleet.evidence if self.fleet else None,
        )

    def _select_approval_channel(self, cfg: ApprovalConfig) -> ApprovalChannel | None:
        # Attached to a real terminal -> keypress reader (local dev / interactive).
        if sys.stdin.isatty() and sys.stdout.isatty():
            return TerminalChannel()
        # Headless + remote approvals enabled -> decisions arrive over the control
        # API (TUI / Discord bridge / web UI). Otherwise fail closed (None -> deny).
        if cfg.remote:
            return ControlApiChannel(self.pending, timeout_s=cfg.remote_timeout_s)
        return None

    # --- lifecycle (spec §8) ---

    def _required_secret_refs(self) -> list[str]:
        """Names this workspace's enabled servers will read from the secrets store."""
        refs: set[str] = set()
        for name, spec in self.config.workspace.servers.items():
            if not spec.enabled:
                continue
            if spec.oauth is not None:
                refs.add(f"{name}-oauth-refresh")
            elif spec.auth_secret_ref:
                refs.add(spec.auth_secret_ref)
        if self.fleet is not None:
            refs.add(self.fleet.credential_secret_ref)
        return sorted(refs)

    def _gate_secrets(self) -> None:
        """List the credentials the hub will read, then unlock the store once.

        Skipped entirely when nothing needs a secret or no store exists yet (a
        fresh install never touches the key backend). In `prompt` mode this waits
        for a single y/N and fails fast without a TTY; `auto` just proceeds. The
        one `unlock()` warms the per-process key cache so the per-server reads that
        follow never re-hit the backend (no repeated keychain prompts)."""
        refs = self._required_secret_refs()
        if not refs or not self.secrets.exists():
            return
        mode = self.config.hub.secrets.access_mode
        logger.info(
            "secrets: unlocking store (%s backend) to read: %s",
            self.secrets.backend,
            ", ".join(refs),
        )
        if mode == "prompt":
            if not (sys.stdin.isatty() and sys.stdout.isatty()):
                raise SystemExit(
                    "secrets: access_mode 'prompt' needs a TTY to confirm; set "
                    "`secrets.access_mode: auto` in config.yaml for headless runs"
                )
            if input("secrets: unlock now? [y/N] ").strip().lower() not in ("y", "yes"):
                raise SystemExit("secrets: unlock declined")
        try:
            self.secrets.unlock()
        except SecretsKeyError as exc:
            # A missing key is a configuration problem with a specific remedy,
            # not a crash. Failing here rather than at the first server that
            # needs a credential means the operator learns it at start-up.
            raise SystemExit(f"secrets: {exc}") from None

    async def start(self) -> None:
        mcphub_home().mkdir(parents=True, exist_ok=True)
        self._check_policy_dir_permissions()
        self.audit.start()
        self.builtins.load_user_tools(mcphub_home() / "tools")
        self._gate_secrets()
        self._loop = asyncio.get_running_loop()
        if self.fleet is not None:
            credential = (
                self.secrets.get(self.fleet.credential_secret_ref)
                if self.secrets.exists()
                else None
            )
            await self.fleet.start(credential)

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
        # Fail-closed: deny any in-flight remote prompts so their calls unblock.
        self.pending.shutdown()
        tasks = [t for t in (self._reload_task, self._refresh_task) if t is not None]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        await self._transport.stop()
        if self.fleet is not None:
            await self.fleet.stop()
        for server in list(self.servers.values()):
            await server.stop()
        self.audit.stop()  # release the audit lock first — must always happen
        self.telemetry.shutdown()  # flush batched spans before the process exits
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
        # Canonicalise path arguments BEFORE the Action is built, so the value
        # the policy is evaluated against, the value recorded in the audit
        # digest, and the value forwarded upstream are all the same string. The
        # engine used to canonicalise privately for the decision and then hand
        # the server the agent's original text, which left the server free to
        # resolve it differently and open a different file.
        args = self._canonical_path_args(server_name, args)
        request_id = str(ULID())
        trace_id, span_id = audit_mod.new_trace_id(), audit_mod.new_span_id()
        # Canonical Action (unified.action/v1): the enforcement engine's identity
        # for this call. strict=False — MCP args are free-form JSON (may hold floats).
        action = Action.build(
            principal=Principal(
                id=f"agent:{caller_id}",
                # Two genuinely different strengths, and conflating them is what
                # let "we enforce per agent" mean two things. A TCP caller is
                # resolved from a bearer token this hub issued, so the identity
                # is proven to the strength of that secret. A Unix-socket caller
                # is taken from a header and trusted because of filesystem
                # permissions -- which is a real control and is not the same
                # claim.
                attestation="derived" if caller_token_id else "assigned",
            ),
            tool=tool_uri,
            verb="call",
            resource="*",
            params=args,
            context=ActionContext(origin="mcp", trace_id=trace_id, span_id=span_id),
        )
        # The same canonical Action is decided on and audited (digest below).
        decision = self.authz.resolve(tool_uri, args, caller_id, action=action)

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
                action=action,  # same canonical Action the verdict was made on
            )
            prompt_ms = (time.monotonic() - t0) * 1000
            authz_decision = outcome.authz_decision
            if outcome.persistent:
                self._persist_exact_rule(
                    tool_uri, caller_id, allowed=outcome.allowed, args_filter=outcome.args_filter
                )
            denied_reason = outcome.reason
            allowed = outcome.allowed
            decided_by = outcome.decided_by
        else:
            allowed = decision.effect is Effect.ALLOW
            denied_reason = None
            decided_by = None

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
            decided_by=decided_by,
            action_digest=action.digest(strict=False),
        )

        if not allowed:
            # deny / prompt_denied / no_approval_channel -> received only (spec §6.2)
            return _err(req_id, -32003, f"denied by policy ({authz_decision})")

        t0 = time.monotonic()
        task = asyncio.create_task(
            self._forward(server_name, tool, args), name=f"forward:{request_id}"
        )
        flight = InFlight(
            request_id=request_id,
            principal=action.principal.id,
            tool_uri=tool_uri,
            task=task,
            started=t0,
        )
        self._inflight[request_id] = flight
        try:
            value = await task
            # Redact secrets before the result is audited or returned, so neither
            # the audit log nor the caller ever sees them (spec §10.2).
            result = self.redactor.result(_result_dict(value))
            status = "error" if result.get("isError") else "ok"
            hits = self._scan_result(request_id, tool_uri, action, result)
        except asyncio.CancelledError:
            if flight.interdiction is None:
                # Not ours: the caller's task was cancelled (shutdown, client
                # gone). Do not let the forward outlive the request either.
                task.cancel()
                raise
            # The plane stopped this call while it was in flight (build-04).
            # Whatever the upstream returns after this point is dropped: not
            # audited, not returned. The bracket closes as `interdicted`, which
            # a reader can tell from a crash.
            self.audit.write_interdicted(
                request_id=request_id,
                duration_ms=(time.monotonic() - t0) * 1000,
                interdicted_by=flight.interdiction.by,
                reason=flight.interdiction.reason,
                prompt_response_ms=prompt_ms,
            )
            return _err(req_id, -32004, f"interdicted: {flight.interdiction.reason}")
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
        finally:
            self._inflight.pop(request_id, None)

        self.audit.write_completed(
            request_id=request_id,
            duration_ms=(time.monotonic() - t0) * 1000,
            result=result,
            result_status=status,
            audit_level=decision.audit_level,
            prompt_response_ms=prompt_ms,
            injection=hits,
        )
        return _ok(req_id, result)

    def refuse_unidentified(self, *, source: str, method: str = "mcp") -> None:
        """A caller with no valid identity was turned away (build-14 S-1).

        Recorded twice, on purpose: in the hub's own audit as a received-only
        deny for the local operator, and through the authorizer as a
        structural decision on `agent:unknown` so a joined hub feeds the
        control plane's identity refusal stream like the gateway does.

        Recorded once per source per `REFUSAL_WINDOW`, with the refusals in
        between counted into the next record. The 401 is free; the record is
        a chained audit write and an evidence row, and a caller that can
        reach the port must not be able to grow the log or push real
        decisions out of the spool by being refused fast enough.
        """
        suppressed = self._refusal_budget(source or "unknown", method)
        if suppressed is None:
            return
        try:
            self.audit.write_received(
                request_id=str(ULID()),
                trace_id=audit_mod.new_trace_id(),
                span_id=audit_mod.new_span_id(),
                caller_id="unknown",
                caller_token_id=None,
                mcp_server="hub",
                tool=method,
                args={"source": source or "unknown", "suppressed": suppressed},
                authz_decision="deny",
                authz_rule=None,
                audit_level="standard",
                reason="no valid credential presented",
            )
            self.authz.record_unidentified(source=source, method=method)
        except Exception:  # noqa: BLE001 - a refusal must stay a refusal
            logger.exception("could not record an unidentified caller")

    def _refusal_budget(self, source: str, method: str) -> int | None:
        """None: this refusal is counted, not recorded. An int: record it,
        and this many were counted since the last record for this source."""
        now = time.monotonic()
        key = (source, method)
        started, counted = self._refusals.get(key, (None, 0))
        if started is not None and now - started < REFUSAL_WINDOW:
            self._refusals[key] = (started, counted + 1)
            return None
        if len(self._refusals) >= REFUSAL_SOURCES:
            # Many sources at once is its own finding; the table stays small
            # and the oldest windows go first.
            for stale in sorted(self._refusals, key=lambda k: self._refusals[k][0])[
                : len(self._refusals) - REFUSAL_SOURCES + 1
            ]:
                del self._refusals[stale]
        self._refusals[key] = (now, 0)
        return counted

    # --- in-flight interdiction (build-04) ---

    def in_flight(self) -> list[dict]:
        now = time.monotonic()
        return [
            {
                "request_id": f.request_id,
                "principal": f.principal,
                "tool": f.tool_uri,
                "elapsed_ms": round((now - f.started) * 1000, 3),
            }
            for f in self._inflight.values()
        ]

    def _scan_result(
        self, request_id: str, tool_uri: str, action: Action, result: dict
    ) -> list[str]:
        """D-12 (build-14): the deterministic injection pass over what is
        about to enter the agent. Ids only leave the hub; the result is
        returned unchanged — this is a finding, not a filter. So a failure
        *here* is logged and the result still goes back: the call succeeded,
        and a sensor that turns a success into `tool execution failed` has
        become a filter by accident."""
        try:
            hits = injection.scan(result)
            if hits:
                logger.warning(
                    "INJECTION SHAPES in result request=%s tool=%s: %s", request_id, tool_uri, hits
                )
                self.authz.record_ingress(action, hits)
            return hits
        except Exception:  # noqa: BLE001 - a finding must never change an outcome
            logger.exception("injection pass failed request=%s tool=%s", request_id, tool_uri)
            return []

    def interdict(self, principal: str, *, by: str, reason: str) -> list[str]:
        """Cancel every forward in flight for `principal` (`*` = all of them).

        Returns the request ids interrupted. This stops what is *in progress*;
        it does not contain the principal's next action — that is the
        revocation list's job, and the two arrive together when the control
        plane contains someone (`_on_containment_change`). An operator calling
        this directly on a standalone hub gets exactly what it says: the calls
        now in flight end, and the next one is decided by policy as usual.

        Upstream cancellation is best-effort. Cancelling the task drops the
        response and frees the hub; a stdio server that has already begun a
        side effect finishes it. Severing the effect is build-05 (egress-sever)
        and build-08 (sandbox), not this.
        """
        hit: list[str] = []
        for flight in list(self._inflight.values()):
            if principal != FLEET_WIDE and flight.principal != principal:
                continue
            if flight.interdiction is not None:
                continue  # already being stopped; do not overwrite the attribution
            if flight.task.done():
                continue  # finished; its result is on the way to the caller, not stopped
            flight.interdiction = Interdiction(by=by, reason=reason)
            flight.task.cancel()
            hit.append(flight.request_id)
        if hit:
            logger.warning(
                "interdicted %d in-flight call(s) for %s (%s): %s", len(hit), principal, by, reason
            )
        return hit

    def _on_containment_change(self, added: frozenset[str], removed: frozenset[str]) -> None:
        """`Distribution` announced a verified change to who is contained.

        Runs on the refreshing thread (the poller's worker, or the evidence
        shipper's on a receipt), so the cancellation is handed to the loop.
        Only additions matter here: a release does nothing to a call in
        flight, and the next action is simply decided by policy again.
        """
        if not added or self._loop is None:
            return
        snapshot = self.fleet.distribution.snapshot if self.fleet else None

        def _apply() -> None:
            for principal in sorted(added):
                # The snapshot may have been replaced by a later refresh (the
                # poller and the receipt path both run) before this runs on
                # the loop; a principal released in between is still stopped
                # here — the announcement stands — and must not abort the rest.
                entry = snapshot.containment.get(principal) if snapshot else None
                mode = entry.mode if entry is not None else "contained"
                self.interdict(
                    principal,
                    by="control-plane",
                    reason=f"{principal} is contained ({mode})",
                )

        self._loop.call_soon_threadsafe(_apply)

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
        self.authz = AuthzResolver(
            self.config.workspace,
            self.config.dangerous,
            telemetry=self.telemetry,
            deployment=self.config.hub.deployment,
        )
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
        if self.config.hub.listen.tcp_address:
            listen["http"] = f"http://{self.config.hub.listen.tcp_address}"
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
            # Deployment security profile (UAI-216): only `hot` reload auto-applies
            # a policy file change. Under `manual`/`approval` (the default in a
            # `locked` deployment) a detected change is NOT silently applied — the
            # enforcement plane must not be edited into an open door in production.
            # The pending change is logged; an operator applies it explicitly with
            # `unified-mcphub reload` (the POST /reload control endpoint), which is
            # the human-in-the-loop step `approval` names.
            mode = self.config.hub.deployment.effective_reload_mode()
            if mode == "hot":
                await self._reload()
            else:
                logger.warning(
                    "policy/config change detected but not applied "
                    "(deployment.reload_mode=%s, policy_protection=%s); "
                    "run `unified-mcphub reload` to apply it once you have reviewed it",
                    mode,
                    self.config.hub.deployment.policy_protection,
                )

    def _check_policy_dir_permissions(self) -> None:
        """In `locked`, report — or, when asked, refuse — a policy directory the
        account the servers run as can still write.

        The constitutional denies and reload-gating are checks on a path
        *string*, decided before the write and inspected again by the kernel
        after it. Between those two moments a symlink can be repointed, and no
        amount of matching closes that; a shell redirection carries no path
        argument to match in the first place. The boundary that actually holds
        is filesystem permissions: run the servers as an account that cannot
        write this directory, or mount it read-only into their namespace.

        Advisory by default: refusing to boot would strand a deployment that is
        locked and correct in every other respect, and a hub that will not start
        protects nothing. A deployment that wants the OS boundary treated as a
        hard precondition sets `deployment.require_protected_config_dir: true`,
        which turns the warning into a boot refusal. See
        docs/deployment-security.md.
        """
        check_policy_dir_permissions(self.config.hub.deployment, mcphub_home())

    def _canonical_path_args(self, server_name: str, args: dict) -> dict:
        """Rewrite a server's declared path arguments to their canonical form.

        Only the argument names the server itself declares (`path_args`): on
        another server `path` may be a URL path or an object key, and rewriting
        that would corrupt the call. Relative paths resolve against the
        server's declared `cwd`, falling back to the hub's own directory —
        which is what a stdio child inherits when no cwd is set, so the base is
        the one the process opening the file will actually use.

        A value that does not reduce to a single location is left untouched;
        the engine sees it as indeterminate and fails closed on it.
        """
        spec = self.config.workspace.servers.get(server_name)
        if spec is None or not spec.path_args:
            return args
        base = spec.upstream.cwd or os.getcwd()
        out = dict(args)
        for name in spec.path_args:
            value = out.get(name)
            if isinstance(value, str) and value:
                resolved = canonical(value, base=base)
                if resolved is not None:
                    out[name] = resolved
        return out

    async def reload_now(self) -> dict:
        """Apply the on-disk config now, on an operator's explicit command.

        This is the sanctioned way to apply a policy change in a `locked`
        deployment without a restart (UAI-216): file-watch reload is gated to
        never auto-apply under `manual`/`approval`, but an operator who has
        reviewed the change triggers it here — the human-in-the-loop step the
        `approval` mode names. The deployment profile is still pinned at boot;
        this re-reads everything else. Returns a small summary of the result.
        """
        before = _config_hash(self.config)
        old_rules = list(self.config.workspace.authz.rules)
        ok = await self._reload()
        after = _config_hash(self.config)
        broadening = policy_broadening(old_rules, self.config.workspace.authz.rules) if ok else []
        if broadening:
            # Surfaced, not buried: the reviewer sees exactly what this reload
            # granted that was not granted before (UAI-216).
            logger.warning(
                "reload broadens policy — %d new allow grant(s): %s",
                len(broadening),
                ", ".join(f"{b.tool} for {b.callers or 'any principal'}" for b in broadening),
            )
        return {
            "applied": ok,
            "changed": ok and before != after,
            "servers": list(self.servers),
            "reload_mode": self.config.hub.deployment.effective_reload_mode(),
            "broadening": [b.as_dict() for b in broadening],
        }

    async def _reload(self) -> bool:
        try:
            new = load_config(self.config.workspace_name)
        except Exception as exc:  # noqa: BLE001 - spec §8: any validation failure keeps prior config
            logger.error("config reload failed; keeping prior config: %s", exc)
            return False
        # The deployment security profile is fixed at boot and is NOT re-read
        # here (UAI-216). It describes how this process was deployed, not what
        # the config file currently says — otherwise the one control protecting
        # policy from tampering could be switched off by editing the very file
        # it protects. Changing `locked`/`open` takes a restart, in both
        # directions, exactly like any other deployment property.
        booted = self.config.hub.deployment
        if new.hub.deployment != booted:
            logger.warning(
                "deployment profile change ignored on reload "
                "(running policy_protection=%s, file says %s); a restart is required",
                booted.policy_protection,
                new.hub.deployment.policy_protection,
            )
        new.hub.deployment = booted
        # Likewise the fleet link: joining or leaving a fleet is a deployment
        # property, and an agent that could edit config to drop `control_plane`
        # would be editing itself out of containment.
        if new.hub.control_plane != self.config.hub.control_plane:
            logger.warning("control_plane change ignored on reload; a restart is required")
        new.hub.control_plane = self.config.hub.control_plane
        self.config = new
        self.authz = self._build_authz(new)
        self.redactor = Redactor(new.workspace.redact)
        self.approval.enabled = new.hub.approval.enabled
        await self._apply_server_diff(new.workspace.servers)
        self._write_canonical_truth()
        self._publish_discovery()
        logger.info("config reloaded: servers=%s", list(self.servers))
        return True

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
            "fleet": self.fleet.status() if self.fleet is not None else None,
            "in_flight": self.in_flight(),
        }


def _summary(tool: str, args: dict) -> str:
    rendered = json.dumps(args, default=str)
    return f"{tool}({rendered[:120]})"


async def run(
    workspace: str | None = None, *, port: int | None = None, no_tcp: bool = False
) -> None:
    """CLI entry: start the hub and run until SIGINT/SIGTERM (spec §8).

    `port` / `no_tcp` are the `start --port` / `--no-tcp` overrides, applied over
    the loaded config (precedence: CLI > config.yaml > defaults).
    """
    created = bootstrap()  # first-run: seed a working default config
    if created:
        logger.info("seeded default config: %s", ", ".join(str(p) for p in created))
    config = load_config(workspace)
    if no_tcp:
        config.hub.listen.tcp_enabled = False
    elif port is not None:
        config.hub.listen.tcp_enabled = True  # asking for a port means: serve on it
        config.hub.listen.port = port
    hub = Hub(config)
    try:
        await hub.start()
    except Exception:
        # A start failure (e.g. the TCP port is in use) happens after upstream
        # servers are spawned — tear them down so we don't leak subprocesses.
        await hub.stop()
        raise
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
