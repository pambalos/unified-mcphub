"""OpenClaw installer — spec §11 (UAI-108).

OpenClaw is the primary harness in front of the hub, so this is the reference
integration (the M1 adapters are third-party config-merge). Prefer
`openclaw mcp add ...` if the `openclaw` CLI is present; else merge into
~/.openclaw/openclaw.json under `mcp.servers` with a timestamped backup.

OpenClaw's MCP client speaks HTTP (no unix-socket transport — see
`config/types.mcp.ts`), so this connects over the hub's TCP streamable-http
endpoint with a per-caller bearer token + X-Caller-Id header. The single
connection fronts all upstreams, so no per-upstream secret lands in OpenClaw
config (the hub holds upstream OAuth; see UAI-112).
"""

from __future__ import annotations

from pathlib import Path

from unified_mcphub import endpoints
from unified_mcphub.tokens import TokenStore

from . import _common

CALLER = "openclaw"


def _config_path() -> Path:
    return Path.home() / ".openclaw" / "openclaw.json"


def install(
    *,
    dry_run: bool = False,
    append_instructions: str | None = None,
    scope: str = "local",
    with_redaction_hook: bool = False,
) -> None:
    # OpenClaw's MCP registry is global (no per-scope split) and has no
    # Claude-Code-style hooks; `scope` and `with_redaction_hook` are accepted for
    # the uniform dispatch signature and ignored.
    url = endpoints.http_url()
    if url is None:
        raise SystemExit("listen.tcp is disabled; enable it to wire an HTTP harness (spec §3.1)")
    token = "<bearer-token>" if dry_run else TokenStore().mint(CALLER)

    if _common.harness_cli_present("openclaw"):
        # `--no-probe`: the hub may not be running at install time; save the
        # definition without a live connection check (the operator can run
        # `openclaw mcp doctor unified-hub --probe` once the hub is up).
        _common.run_cli(
            [
                "openclaw",
                "mcp",
                "add",
                "unified-hub",
                "--url",
                url,
                "--transport",
                "streamable-http",
                "--header",
                f"X-Caller-Id: {CALLER}",
                "--header",
                f"Authorization: Bearer {token}",
                "--no-probe",
            ],
            dry_run=dry_run,
        )
    else:
        entry = {
            "url": url,
            "transport": "streamable-http",
            "enabled": True,
            "headers": {"X-Caller-Id": CALLER, "Authorization": f"Bearer {token}"},
        }
        _common.merge_json(
            _config_path(), ["mcp", "servers"], "unified-hub", entry, dry_run=dry_run
        )

    if append_instructions:
        _common.append_guidance(Path(append_instructions), dry_run=dry_run)


def uninstall(*, dry_run: bool = False, scope: str = "local") -> None:  # scope: see install()
    _common.remove_json(_config_path(), ["mcp", "servers"], "unified-hub", dry_run=dry_run)
    if not dry_run:
        TokenStore().revoke(CALLER)
