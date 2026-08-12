"""Cursor installer — spec §11 (M1 adapter).

Cursor reads MCP servers from `mcp.json` (global `~/.cursor/mcp.json`, or
project `<cwd>/.cursor/mcp.json`). There is no `cursor mcp add` CLI, so this is
a JSON-merge install (with a timestamped backup), mirroring the OpenClaw
fallback path. Connects over the hub's TCP streamable-http endpoint with a
**dedicated `cursor` caller token** — on TCP the hub resolves identity from the
token, not the `X-Caller-Id` header, so a distinct token is what makes Cursor a
separately-governed, separately-audited caller (it inherits the caller-agnostic
read/list/get allows in the workspace policy; writes claude-code earned via
`*_always` are caller-scoped, so Cursor is prompted until it earns its own).

Redaction hook: Cursor's hook protocol (`~/.cursor/hooks.json`) is permission-
oriented (allow/deny/ask), not a Claude-Code-style command rewriter, so the
`redaction_hook` shell wrapper does not port as-is; `with_redaction_hook` is
accepted for the uniform dispatch signature and ignored. Cursor still benefits
from the hub-side result `redaction.Redactor` like every connected harness.
"""

from __future__ import annotations

from pathlib import Path

from unified_mcphub import endpoints
from unified_mcphub.tokens import TokenStore

from . import _common

CALLER = "cursor"


def _config_path(scope: str) -> Path:
    # Cursor has a global config and an optional per-project one; "project" maps
    # to the project file, every other scope to the global file.
    if scope == "project":
        return Path.cwd() / ".cursor" / "mcp.json"
    return Path.home() / ".cursor" / "mcp.json"


def install(
    *,
    dry_run: bool = False,
    append_instructions: str | None = None,
    scope: str = "local",
    with_redaction_hook: bool = False,
) -> None:
    # `with_redaction_hook` is accepted for the uniform dispatch signature and
    # ignored — see module docstring.
    url = endpoints.http_url()
    if url is None:
        raise SystemExit("listen.tcp is disabled; enable it to wire an HTTP harness (spec §3.1)")
    token = "<bearer-token>" if dry_run else TokenStore().mint(CALLER)

    entry = {
        "url": url,
        "headers": {"X-Caller-Id": CALLER, "Authorization": f"Bearer {token}"},
    }
    _common.merge_json(_config_path(scope), ["mcpServers"], "unified-hub", entry, dry_run=dry_run)

    if append_instructions:
        _common.append_guidance(Path(append_instructions), dry_run=dry_run)


def uninstall(*, dry_run: bool = False, scope: str = "local") -> None:
    _common.remove_json(_config_path(scope), ["mcpServers"], "unified-hub", dry_run=dry_run)
    if not dry_run:
        TokenStore().revoke(CALLER)
