"""Shared secret-redaction primitives — spec §11.2.

Single source of truth for masking bearer tokens, used by two layers:

* Python (`redact_text`): scrubs secrets from text the installer itself prints
  — e.g. `claude mcp add/get` output captured by `_common.run_cli`.
* Shell (`command_redaction_hook_group`): a Claude-Code-style PreToolUse hook
  that rewrites every Bash command so its combined output is piped through the
  same redactor. Catches a token surfaced by *any* command — the harness CLI, or
  a direct read of the MCP config via cat/grep/jq — that never transits the hub
  (so the hub-side `redaction.Redactor` can't see it). Reusable by any harness
  with PreToolUse Bash command-rewrite hooks (Claude Code, Cursor, ...).

Both layers derive their token charset from `TOKEN_CHARSET` so the Python regex
and the shell `sed` expression can never drift apart again.
"""

from __future__ import annotations

import re

# Marker that makes the hook idempotent: a command already carrying it is left
# untouched (the wrapper greps for it before re-wrapping), and the installer's
# merge/remove logic keys off it to find the hook group.
REDACT_MARKER = "#RDCT_HOOK"

# Bearer-token charset: a superset of hex that also covers base64url / JWT /
# mixed-case third-party tokens. The ordering is bracket-expression safe in both
# Python `re` and POSIX `sed -E` (the `-` is last, so it's a literal, not a
# range; `/` is literal because the sed expr below uses `|` as its delimiter).
TOKEN_CHARSET = "A-Za-z0-9._~+/=-"

BEARER_RE = re.compile(rf"(Bearer\s+)[{TOKEN_CHARSET}]{{16,}}")
# Bare 64-hex caller tokens (TokenStore.mint -> secrets.token_hex(32)) that may
# appear without a "Bearer " prefix.
HEX64_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")


def redact_text(text: str) -> str:
    """Mask bearer tokens / bare 64-hex caller tokens before text is shown."""
    text = BEARER_RE.sub(r"\1[REDACTED]", text)
    return HEX64_RE.sub("[REDACTED-TOKEN]", text)


def _sq(s: str) -> str:
    """POSIX single-quote `s` for safe literal embedding in a shell word."""
    return "'" + s.replace("'", "'\\''") + "'"


# The sed program, built from the shared charset. `|` delimiter so `/` needs no
# escaping inside the bracket expression.
_SED_EXPR = f"sed -E 's|Bearer [{TOKEN_CHARSET}]{{16,}}|Bearer [REDACTED]|g'"

# PreToolUse hook command. Reads the tool-call JSON on stdin, extracts the Bash
# command, and (unless already wrapped or jq is missing) rewrites it to:
#
#   set -o pipefail 2>/dev/null; {
#   <original command>
#   } 2>&1 | sed -E 's|Bearer ...|Bearer [REDACTED]|g' #RDCT_HOOK
#
# A newline-delimited brace group (not `{ c ; }`) keeps heredocs intact, and
# `pipefail` preserves the wrapped command's exit status through the sed pipe.
_HOOK_COMMAND = (
    "command -v jq >/dev/null 2>&1 || exit 0; "
    "i=$(cat); c=$(printf '%s' \"$i\" | jq -r '.tool_input.command // empty'); "
    '[ -z "$c" ] && exit 0; '
    'case "$c" in *RDCT_HOOK*) exit 0;; esac; '
    "n=$(printf '%s\\n%s\\n%s' 'set -o pipefail 2>/dev/null; {' \"$c\" "
    + _sq(f"}} 2>&1 | {_SED_EXPR} {REDACT_MARKER}")
    + "); "
    'printf \'%s\' "$i" | jq -c --arg c "$n" '
    "'{hookSpecificOutput:{hookEventName:\"PreToolUse\",updatedInput:(.tool_input + {command:$c})}}'"
)


def command_redaction_hook_group() -> dict:
    """A Claude-Code-style PreToolUse hook group that redacts bearer tokens from
    every Bash command's output. Un-gated (matcher ``Bash``, no ``if``) so it
    also covers direct reads of the MCP config, not just ``claude mcp`` calls."""
    return {
        "matcher": "Bash",
        "hooks": [{"type": "command", "command": _HOOK_COMMAND}],
    }
