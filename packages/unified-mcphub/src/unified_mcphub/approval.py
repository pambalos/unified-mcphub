"""In-process approval — spec §5, ADR-0018 (decisions), ADR-0025 (scoped allows).

When a call resolves to `effect: prompt`, the decision is made here. The
"ask a human" step is delegated to a pluggable `ApprovalChannel` (UAI-109):
`TerminalChannel` reads a keypress from the hub's own terminal (the same-user
defense) for an interactive hub; an out-of-process channel over the control API
(UAI-107) sources the decision for a headless hub.

Since UAI-133 the security-critical logic is **not** owned here. `Approval` is
an adapter over `unified_enforce.Approvals`, which owns the master switch, the
session cache, and every fail-closed path — the same move `AuthzResolver` made
onto `PolicyEngine`. The hub keeps its own vocabulary because `DecisionKind` is
the control API's wire format (transports.py parses these strings) and the
command/prefix distinction is meaningful in its UI; the engine's `ALLOW_ALWAYS`
carries that distinction in the scope filter instead.

What the hub gains: a channel that raises or never answers is now a deny rather
than an exception escaping into the call path — the "later phases" this module
used to promise.

Allow-always is argument-scoped (ADR-0025): rather than one tool-wide grant, the
operator allows *this command* (exact) or *this prefix*. Broad, whole-tool trust
is a curated-policy decision, not something accreted here. Deny-always stays
tool-wide.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from enum import Enum
from typing import Any, NamedTuple, Protocol

from unified_enforce import (
    Action,
    ApprovalKind,
    ApprovalRequest,
    Approvals,
    Principal,
)
from unified_enforce.policy import Decision as EngineDecision
from unified_enforce.policy import Verdict


class DecisionKind(str, Enum):
    ALLOW = "allow"
    ALLOW_SESSION = "allow_session"
    ALLOW_ALWAYS_COMMAND = "allow_always_command"  # scope to this exact arg value
    ALLOW_ALWAYS_PREFIX = "allow_always_prefix"  # scope to this arg prefix
    DENY = "deny"
    DENY_ALWAYS = "deny_always"


@dataclass
class PromptOutcome:
    allowed: bool
    authz_decision: str  # prompt_allowed | prompt_denied | approval_disabled
    persistent: bool = False  # *_always -> write a rule to <name>.local.yaml
    session: bool = False  # allow_session -> remember until restart
    reason: str | None = None  # e.g. no_approval_channel
    args_filter: dict | None = None  # set for the scoped allow-always variants
    decided_by: str | None = None  # responder identity for the audit trail


class ChannelDecision(NamedTuple):
    """What an ApprovalChannel returns: the decision, the optional persist filter
    for scoped allow-always, and who decided (audited as the responder)."""

    kind: DecisionKind
    args_filter: dict | None = None
    decided_by: str | None = None


# Argument names that count as the call's "primary" (command-like) argument, in
# priority order. Both scoped allow-always modes key off this single argument.
_PRIMARY_ARG_NAMES = ("command", "cmd", "url", "path", "query", "expression", "code")


def primary_arg(args: dict) -> str | None:
    """The argument a scoped rule should match on, or None if none is suitable.

    Prefers a known command-like name; otherwise the sole string argument.
    """
    for name in _PRIMARY_ARG_NAMES:
        value = args.get(name)
        if isinstance(value, str) and value:
            return name
    string_args = [k for k, v in args.items() if isinstance(v, str) and v]
    return string_args[0] if len(string_args) == 1 else None


def default_prefix(value: str) -> str:
    """First whitespace token of a command, keeping its trailing space — a sane
    editable default for prefix grants ('git status' -> 'git ', 'ls' -> 'ls')."""
    head, sep, _ = value.partition(" ")
    return head + sep


def build_arg_filter(arg: str, value: str, *, prefix: bool) -> dict:
    return {arg: {("starts_with" if prefix else "equals"): [value]}}


def _describe(args_filter: dict) -> str:
    arg, ops = next(iter(args_filter.items()))
    op, values = next(iter(ops.items()))
    return f"{arg} {op} {values[0]!r}"


_BASE_KEYS = {
    "a": DecisionKind.ALLOW,
    "s": DecisionKind.ALLOW_SESSION,
    "d": DecisionKind.DENY,
    "D": DecisionKind.DENY_ALWAYS,
}


class ApprovalChannel(Protocol):
    """A source of approval decisions for a `prompt`-effect call.

    Implementations return the operator's decision and, for the scoped
    allow-always variants, the `args_filter` to persist. They must NOT
    re-implement the master switch, session cache, or fail-safe — that stays in
    `Approval`. A channel that cannot reach an operator should raise; `Approval`
    treats the absence of a channel (and, in later phases, a channel failure) as
    fail-closed deny.
    """

    async def ask(
        self,
        tool_uri: str,
        caller: str,
        summary: str,
        args: dict,
        floored: bool,
    ) -> ChannelDecision: ...


class TerminalChannel:
    """Reads one keypress from the hub's own terminal (the same-user defense).

    The interactive-hub / local-dev source. Full TUI cards: SEC-MCP-4. This is
    the path that was previously inlined into `Approval`; it is selected when the
    hub runs attached to a TTY.
    """

    async def ask(
        self, tool_uri: str, caller: str, summary: str, args: dict, floored: bool
    ) -> ChannelDecision:
        """Read one keypress from the hub's terminal (+ a prefix line for `p`).

        Returns the decision and, for the scoped allow-always variants, the
        args_filter to persist. The responder is the local terminal operator.
        """
        primary = primary_arg(args)
        keys = dict(_BASE_KEYS)
        keys["c"] = DecisionKind.ALLOW_ALWAYS_COMMAND
        if primary is not None:
            keys["p"] = DecisionKind.ALLOW_ALWAYS_PREFIX
        menu = (
            "[a]llow  [s]ession  [c]ommand-always"
            + ("  [p]refix-always" if primary is not None else "")
            + "  [d]eny  [D]eny-always"
        )
        print(f"\n[approval] {caller} -> {tool_uri}\n  {summary}\n  {menu}: ", end="", flush=True)
        line = sys.stdin.readline()
        key = line.strip()[:1] if line else "d"
        kind = keys.get(key, DecisionKind.DENY)

        if kind is DecisionKind.ALLOW_ALWAYS_COMMAND:
            if primary is None:
                # No scopeable argument -> exact degenerates to tool scope (ADR-0025).
                print(
                    f"  -> allowing ALL calls to {tool_uri} (no arguments to scope on)", flush=True
                )
                return ChannelDecision(kind, None, "terminal")
            args_filter = build_arg_filter(primary, args[primary], prefix=False)
            self._echo_rule(tool_uri, args_filter, floored)
            return ChannelDecision(kind, args_filter, "terminal")

        if kind is DecisionKind.ALLOW_ALWAYS_PREFIX:
            default = default_prefix(args[primary])  # primary not None when `p` offered
            print(f"  prefix [{default}]: ", end="", flush=True)
            typed = sys.stdin.readline()
            prefix = typed.rstrip("\r\n") or default
            args_filter = build_arg_filter(primary, prefix, prefix=True)
            self._echo_rule(tool_uri, args_filter, floored, broad=True)
            return ChannelDecision(kind, args_filter, "terminal")

        return ChannelDecision(kind, None, "terminal")

    @staticmethod
    def _echo_rule(tool_uri: str, args_filter: dict, floored: bool, broad: bool = False) -> None:
        print(f"  -> will persist: allow {tool_uri} where {_describe(args_filter)}", flush=True)
        if floored:
            print(
                "  ! this was prompted by the danger floor — the floor will stop prompting it",
                flush=True,
            )
        if broad:
            print(
                "  ! prefix grants are broad — they can match commands you didn't intend",
                flush=True,
            )


#: Hub kinds -> engine kinds. The two allow-always variants differ only in how
#: their scope filter was built (`equals` vs `starts_with`), which the filter
#: itself records — so the engine needs one kind, not two.
_TO_ENGINE_KIND = {
    DecisionKind.ALLOW: ApprovalKind.ALLOW,
    DecisionKind.ALLOW_SESSION: ApprovalKind.ALLOW_SESSION,
    DecisionKind.ALLOW_ALWAYS_COMMAND: ApprovalKind.ALLOW_ALWAYS,
    DecisionKind.ALLOW_ALWAYS_PREFIX: ApprovalKind.ALLOW_ALWAYS,
    DecisionKind.DENY: ApprovalKind.DENY,
    DecisionKind.DENY_ALWAYS: ApprovalKind.DENY_ALWAYS,
}


class _EngineChannel:
    """Presents a hub `ApprovalChannel` through the engine's protocol.

    Only a shape translation: the hub's channels keep taking the arguments
    their UIs and wire format are built around, and nothing about how a
    decision is *interpreted* lives here.
    """

    def __init__(self, inner: ApprovalChannel) -> None:
        self.inner = inner

    async def ask(self, request: ApprovalRequest):
        from unified_enforce import ApprovalResponse

        decision = await self.inner.ask(
            request.action.tool,
            request.principal.removeprefix("agent:"),
            request.summary,
            dict(request.action.params),
            request.floored,
        )
        return ApprovalResponse(
            kind=_TO_ENGINE_KIND[decision.kind],
            decided_by=decision.decided_by,
            scope=decision.args_filter,
        )


class Approval:
    """Resolves a `prompt`-effect call to allow/deny per ADR-0018/0025.

    `channel` is the decision source (a `TerminalChannel` for an interactive hub,
    or an out-of-process channel for a headless one). `channel=None` means there
    is no way to reach an operator: the hub fails closed to deny
    (`no_approval_channel`), exactly as a detached hub did before.

    The logic itself is `unified_enforce.Approvals`; this class translates in
    and out of the hub's vocabulary.
    """

    def __init__(self, enabled: bool, channel: ApprovalChannel | None) -> None:
        self._approvals = Approvals(
            None,
            enabled=enabled,
            # ADR-0018: `approval.enabled: false` means "don't prompt, run it".
            # The engine defaults to deny and requires this to be spelled out,
            # which is the right default for every deployment except this one.
            when_disabled="allow",
        )
        self.channel = channel

    # `enabled` and `channel` are reassigned on config reload, so both stay
    # plain attributes from the caller's point of view.

    @property
    def enabled(self) -> bool:
        return self._approvals.enabled

    @enabled.setter
    def enabled(self, value: bool) -> None:
        self._approvals.enabled = value

    @property
    def channel(self) -> ApprovalChannel | None:
        wrapper = self._approvals.channel
        return wrapper.inner if wrapper is not None else None

    @channel.setter
    def channel(self, value: ApprovalChannel | None) -> None:
        self._approvals.channel = _EngineChannel(value) if value is not None else None

    async def resolve(
        self,
        tool_uri: str,
        caller: str,
        summary: str,
        args: dict | None = None,
        *,
        floored: bool = False,
        action: Action | None = None,
    ) -> PromptOutcome:
        """`action` is the canonical Action the hub already built for this call;
        it is reconstructed here only for callers that do not have one (tests,
        and any path that prompts outside `_handle_call`)."""
        args = args or {}
        if action is None:
            action = Action.build(
                principal=Principal(id=f"agent:{caller}"),
                tool=tool_uri,
                verb="call",
                resource="*",
                params=args,
            )
        outcome = await self._approvals.resolve(
            ApprovalRequest(
                action=action,
                decision=EngineDecision(verdict=Verdict.DEFER, rule_id=None, source="prompt"),
                summary=summary,
                floored=floored,
            )
        )
        return PromptOutcome(
            allowed=outcome.allowed,
            authz_decision=_authz_decision(outcome),
            persistent=outcome.persistent,
            session=outcome.session,
            reason=outcome.reason,
            args_filter=outcome.scope,
            decided_by=outcome.decided_by,
        )


def _authz_decision(outcome: Any) -> str:
    """The hub's audit vocabulary for an engine outcome (spec §6.2)."""
    if outcome.decision.source == "approval_disabled" and outcome.allowed:
        return "approval_disabled"
    return "prompt_allowed" if outcome.allowed else "prompt_denied"
