"""Claude Code installer — spec §11.

Prefer `claude mcp add ...` if the `claude` CLI is present; else merge into the
harness config (with a timestamped backup). Connects over the hub's TCP HTTP
transport with a per-caller bearer token + X-Caller-Id header.
(Exact ~/.claude.json schema is doc-driven; verify against the live CLI.)

Scope mirrors Claude Code's own `--scope`:
  local   (default) private to the current project — ~/.claude.json under
                    projects[<cwd>].mcpServers
  user              global, all projects — ~/.claude.json top-level mcpServers
  project           shared via VCS — ./.mcp.json mcpServers
"""

from __future__ import annotations

from pathlib import Path

from unified_mcphub import endpoints
from unified_mcphub.tokens import TokenStore

from . import _common

CALLER = "claude-code"

# Opt-in defense-in-depth (spec §11.2): a PreToolUse hook that rewrites
# `claude mcp …` commands to pipe their output through a token redactor, so a
# bearer token echoed by the Claude CLI never lands in a transcript. Scoped via
# `if` to those commands only; degrades to a no-op (passthrough) if jq is absent
# or the command is already wrapped. The hub's own `run_cli` already redacts the
# install path — this covers direct `claude mcp` calls the harness makes.
_REDACT_MARKER = "#RDCT_HOOK"
_REDACT_HOOK_COMMAND = (
    "command -v jq >/dev/null 2>&1 || exit 0; "
    "i=$(cat); c=$(printf '%s' \"$i\" | jq -r '.tool_input.command // empty'); "
    '[ -z "$c" ] && exit 0; '
    'case "$c" in *RDCT_HOOK*) exit 0;; esac; '
    "n=\"{ $c ; } 2>&1 | sed -E 's/Bearer [0-9a-fA-F]{16,}/Bearer [REDACTED]/g' "
    + _REDACT_MARKER
    + '"; '
    'printf \'%s\' "$i" | jq -c --arg c "$n" '
    "'{hookSpecificOutput:{hookEventName:\"PreToolUse\",updatedInput:(.tool_input + {command:$c})}}'"
)


def _config_path() -> Path:
    return Path.home() / ".claude.json"


def _settings_path() -> Path:
    return Path.home() / ".claude" / "settings.json"


def _redaction_hook_group() -> dict:
    return {
        "matcher": "Bash",
        "hooks": [{"type": "command", "command": _REDACT_HOOK_COMMAND, "if": "Bash(claude mcp *)"}],
    }


def _scope_target(scope: str) -> tuple[Path, list[str]]:
    """Map a scope to the (config file, key path) its mcpServers entry lives at.

    Matches where `claude mcp add --scope <scope>` stores the entry, so the
    JSON-merge fallback and uninstall reverse the CLI path exactly.
    """
    if scope == "user":
        return _config_path(), ["mcpServers"]
    if scope == "project":
        return Path.cwd() / ".mcp.json", ["mcpServers"]
    # local (default): keyed by the current working directory.
    return _config_path(), ["projects", str(Path.cwd()), "mcpServers"]


def install(
    *,
    dry_run: bool = False,
    append_instructions: str | None = None,
    scope: str = "local",
    with_redaction_hook: bool = False,
) -> None:
    url = endpoints.http_url()
    if url is None:
        raise SystemExit("listen.tcp is disabled; enable it to wire an HTTP harness (spec §3.1)")
    token = "<bearer-token>" if dry_run else TokenStore().mint(CALLER)

    if _common.harness_cli_present("claude"):
        # `claude mcp add` refuses to overwrite an existing entry, so drop any
        # prior one first (tolerant: absent entry -> non-zero, ignored). Makes
        # re-install idempotent and rotates the bearer token in one step.
        _common.run_cli(
            ["claude", "mcp", "remove", "unified-hub", "-s", scope], dry_run=dry_run, check=False
        )
        _common.run_cli(
            [
                "claude",
                "mcp",
                "add",
                "unified-hub",
                "--scope",
                scope,
                "--transport",
                "http",
                url,
                "--header",
                f"X-Caller-Id: {CALLER}",
                "--header",
                f"Authorization: Bearer {token}",
            ],
            dry_run=dry_run,
        )
    else:
        entry = {
            "type": "http",
            "url": url,
            "headers": {"X-Caller-Id": CALLER, "Authorization": f"Bearer {token}"},
        }
        path, key_path = _scope_target(scope)
        _common.merge_json(path, key_path, "unified-hub", entry, dry_run=dry_run)

    if with_redaction_hook:
        # User-scope settings: a global safety hook, applies in every project.
        _common.merge_hook(
            _settings_path(),
            event="PreToolUse",
            group=_redaction_hook_group(),
            marker=_REDACT_MARKER,
            dry_run=dry_run,
        )

    if append_instructions:
        _common.append_guidance(Path(append_instructions), dry_run=dry_run)


def uninstall(*, dry_run: bool = False, scope: str = "local") -> None:
    path, key_path = _scope_target(scope)
    _common.remove_json(path, key_path, "unified-hub", dry_run=dry_run)
    # Always drop the redaction hook if present (harmless when it isn't).
    _common.remove_hook(
        _settings_path(), event="PreToolUse", marker=_REDACT_MARKER, dry_run=dry_run
    )
    if not dry_run:
        TokenStore().revoke(CALLER)
