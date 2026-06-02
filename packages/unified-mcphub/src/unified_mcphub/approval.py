"""In-process approval — spec §5, ADR-0018.

When a call resolves to `effect: prompt`, the decision is made here. The
keypress comes ONLY from the hub's own terminal (the same-user defense) — never
an HTTP endpoint.

Master switch (`approval.enabled`) and the background fail-safe are pure logic
and fully exercised. The interactive TUI keypress reader (SEC-MCP-4) is the only
piece left thin; it is never reached on the allow/deny or non-foreground paths.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from enum import Enum


class DecisionKind(str, Enum):
    ALLOW = "allow"
    ALLOW_SESSION = "allow_session"
    ALLOW_ALWAYS = "allow_always"
    DENY = "deny"
    DENY_ALWAYS = "deny_always"


@dataclass
class PromptOutcome:
    allowed: bool
    authz_decision: str           # prompt_allowed | prompt_denied | approval_disabled
    persistent: bool = False      # allow_always / deny_always -> write exact rule
    session: bool = False         # allow_session -> remember until restart
    reason: str | None = None     # e.g. no_approval_channel


_KEY_MAP = {
    "a": DecisionKind.ALLOW,
    "s": DecisionKind.ALLOW_SESSION,
    "A": DecisionKind.ALLOW_ALWAYS,
    "d": DecisionKind.DENY,
    "D": DecisionKind.DENY_ALWAYS,
}


class Approval:
    """Resolves a `prompt`-effect call to allow/deny per ADR-0018."""

    def __init__(self, enabled: bool, foreground: bool) -> None:
        self.enabled = enabled
        self.foreground = foreground
        self._session_allows: set[str] = set()

    async def resolve(self, tool_uri: str, caller: str, summary: str) -> PromptOutcome:
        # Master switch off -> no prompts at all, auto-allow (spec §5.1, ADR-0018).
        if not self.enabled:
            return PromptOutcome(allowed=True, authz_decision="approval_disabled")

        # Background hub (no TUI) -> fail safe: deny, never silently run.
        if not self.foreground:
            return PromptOutcome(
                allowed=False, authz_decision="prompt_denied", reason="no_approval_channel"
            )

        # Session allow remembered from a prior allow_session this run.
        if tool_uri in self._session_allows:
            return PromptOutcome(allowed=True, authz_decision="prompt_allowed", session=True)

        kind = await self._ask(tool_uri, caller, summary)
        if kind is DecisionKind.ALLOW_SESSION:
            self._session_allows.add(tool_uri)
        allowed = kind in (
            DecisionKind.ALLOW,
            DecisionKind.ALLOW_SESSION,
            DecisionKind.ALLOW_ALWAYS,
        )
        return PromptOutcome(
            allowed=allowed,
            authz_decision="prompt_allowed" if allowed else "prompt_denied",
            persistent=kind in (DecisionKind.ALLOW_ALWAYS, DecisionKind.DENY_ALWAYS),
            session=kind is DecisionKind.ALLOW_SESSION,
        )

    async def _ask(self, tool_uri: str, caller: str, summary: str) -> DecisionKind:
        """Read one keypress from the hub's terminal. Full TUI cards: SEC-MCP-4."""
        print(
            f"\n[approval] {caller} -> {tool_uri}\n  {summary}\n"
            f"  [a]llow  [s]ession  [A]lways  [d]eny  [D]eny-always: ",
            end="",
            flush=True,
        )
        line = sys.stdin.readline()
        key = line.strip()[:1] if line else "d"
        return _KEY_MAP.get(key, DecisionKind.DENY)
