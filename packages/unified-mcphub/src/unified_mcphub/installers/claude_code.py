"""Claude Code installer — spec §11.

Prefer `claude mcp add ...` if the `claude` CLI is present; else merge into
~/.claude.json (mcpServers) with a timestamped backup. Connects over the hub's
TCP HTTP transport with a per-caller bearer token + X-Caller-Id header.
(Exact ~/.claude.json schema is doc-driven; verify against the live CLI.)
"""

from __future__ import annotations

from pathlib import Path

from unified_mcphub import endpoints
from unified_mcphub.tokens import TokenStore

from . import _common

CALLER = "claude-code"


def _config_path() -> Path:
    return Path.home() / ".claude.json"


def install(*, dry_run: bool = False, append_instructions: str | None = None) -> None:
    url = endpoints.http_url()
    if url is None:
        raise SystemExit("listen.tcp is disabled; enable it to wire an HTTP harness (spec §3.1)")
    token = "<bearer-token>" if dry_run else TokenStore().mint(CALLER)

    if _common.harness_cli_present("claude"):
        _common.run_cli(
            ["claude", "mcp", "add", "unified-hub", "--transport", "http", url,
             "--header", f"X-Caller-Id: {CALLER}", "--header", f"Authorization: Bearer {token}"],
            dry_run=dry_run,
        )
    else:
        entry = {
            "type": "http",
            "url": url,
            "headers": {"X-Caller-Id": CALLER, "Authorization": f"Bearer {token}"},
        }
        _common.merge_json(_config_path(), ["mcpServers"], "unified-hub", entry, dry_run=dry_run)

    if append_instructions:
        _common.append_guidance(Path(append_instructions), dry_run=dry_run)


def uninstall(*, dry_run: bool = False) -> None:
    _common.remove_json(_config_path(), ["mcpServers"], "unified-hub", dry_run=dry_run)
    if not dry_run:
        TokenStore().revoke(CALLER)
