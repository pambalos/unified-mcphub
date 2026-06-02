"""OpenCode installer — spec §11.

Prefer `opencode mcp add ...` if the `opencode` CLI is present; else merge into
~/.config/opencode/opencode.json (mcp) with a timestamped backup. Connects over
the hub's TCP HTTP transport with a per-caller bearer token + X-Caller-Id header.
(Exact opencode.json schema is doc-driven; verify against the live CLI.)
"""

from __future__ import annotations

from pathlib import Path

from unified_mcphub import endpoints
from unified_mcphub.tokens import TokenStore

from . import _common

CALLER = "opencode"


def _config_path() -> Path:
    return Path.home() / ".config" / "opencode" / "opencode.json"


def install(
    *,
    dry_run: bool = False,
    append_instructions: str | None = None,
    scope: str = "local",
    with_redaction_hook: bool = False,
) -> None:
    # OpenCode has no per-scope config or Claude-Code-style hooks; `scope` and
    # `with_redaction_hook` are accepted (uniform dispatch signature) and ignored.
    url = endpoints.http_url()
    if url is None:
        raise SystemExit("listen.tcp is disabled; enable it to wire an HTTP harness (spec §3.1)")
    token = "<bearer-token>" if dry_run else TokenStore().mint(CALLER)

    if _common.harness_cli_present("opencode"):
        _common.run_cli(["opencode", "mcp", "add", "unified-hub", url], dry_run=dry_run)
    else:
        entry = {
            "type": "remote",
            "url": url,
            "enabled": True,
            "headers": {"X-Caller-Id": CALLER, "Authorization": f"Bearer {token}"},
        }
        _common.merge_json(_config_path(), ["mcp"], "unified-hub", entry, dry_run=dry_run)

    if append_instructions:
        _common.append_guidance(Path(append_instructions), dry_run=dry_run)


def uninstall(*, dry_run: bool = False, scope: str = "local") -> None:  # scope: see install()
    _common.remove_json(_config_path(), ["mcp"], "unified-hub", dry_run=dry_run)
    if not dry_run:
        TokenStore().revoke(CALLER)
