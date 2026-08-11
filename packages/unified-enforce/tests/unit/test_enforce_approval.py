"""UAI-133: the approval contract — the consumer that makes DEFER mean something.

Most of these test what happens when asking a human does NOT work, because
that is where a fail-open would hide.
"""

import asyncio
import json

import pytest

from unified_enforce import (
    Action,
    ApprovalKind,
    ApprovalRequest,
    ApprovalResponse,
    Approvals,
    AuditChain,
    Enforcer,
    PolicyEngine,
    Principal,
    Verdict,
)

POLICY = """
version: 1
rules:
  - id: reads-ok
    match: {tool: "mcp://files/read", verb: call}
    effect: allow
  - id: payouts-need-a-human
    match: {tool: "mcp://bank/payout", verb: call}
    effect: defer
    audit_level: full
"""


def action(tool="mcp://bank/payout", **params):
    return Action.build(
        principal=Principal(id="agent:crew-1"),
        tool=tool,
        verb="call",
        resource="*",
        params=params,
    )


class Channel:
    """A scripted operator."""

    def __init__(self, response=None, *, raises=None, delay=0.0):
        self.response = response or ApprovalResponse(ApprovalKind.ALLOW, decided_by="alice")
        self.raises = raises
        self.delay = delay
        self.seen: list[ApprovalRequest] = []

    async def ask(self, request):
        self.seen.append(request)
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.raises:
            raise self.raises
        return self.response


def request_for(act=None, decision=None):
    engine = PolicyEngine.from_yaml(POLICY)
    act = act or action()
    return ApprovalRequest(action=act, decision=decision or engine.decide(act))


# --- the happy path ---


async def test_a_human_allow_resolves_the_deferral():
    outcome = await Approvals(Channel()).resolve(request_for())
    assert outcome.allowed
    assert outcome.decision.verdict is Verdict.ALLOW
    assert outcome.decision.source == "approval"
    assert outcome.decided_by == "alice"


async def test_a_human_deny_resolves_to_deny():
    channel = Channel(ApprovalResponse(ApprovalKind.DENY, decided_by="bob"))
    outcome = await Approvals(channel).resolve(request_for())
    assert not outcome.allowed
    assert outcome.decision.source == "approval"


async def test_the_deferring_rule_survives_into_the_final_decision():
    """An auditor needs to see WHICH rule demanded review, not just that one did."""
    outcome = await Approvals(Channel()).resolve(request_for())
    assert outcome.decision.rule_id == "payouts-need-a-human"
    assert outcome.decision.audit_level == "full"


async def test_the_channel_receives_the_action_and_its_digest():
    channel = Channel()
    req = request_for()
    await Approvals(channel).resolve(req)
    seen = channel.seen[0]
    assert seen.principal == "agent:crew-1"
    assert len(seen.digest) == 64


# --- every other path fails closed ---


async def test_no_channel_denies():
    """A headless process with no bridge must not become an implicit approver."""
    outcome = await Approvals(None).resolve(request_for())
    assert not outcome.allowed
    assert outcome.decision.source == "approval_unavailable"
    assert outcome.reason == "no_approval_channel"


async def test_a_raising_channel_denies():
    outcome = await Approvals(Channel(raises=RuntimeError("bridge down"))).resolve(request_for())
    assert not outcome.allowed
    assert outcome.decision.source == "approval_error"
    assert outcome.reason == "approval_channel_error"
    assert "bridge down" in outcome.decision.reason


async def test_a_silent_channel_times_out_and_denies():
    """Silence is not consent."""
    approvals = Approvals(Channel(delay=10), timeout_s=0.05)
    outcome = await approvals.resolve(request_for())
    assert not outcome.allowed
    assert outcome.decision.source == "approval_timeout"


async def test_cancellation_propagates_rather_than_becoming_a_verdict():
    """Process shutdown is not a decision about the action."""
    approvals = Approvals(Channel(delay=10))
    task = asyncio.create_task(approvals.resolve(request_for()))
    await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


async def test_disabled_denies_by_default():
    outcome = await Approvals(Channel(), enabled=False).resolve(request_for())
    assert not outcome.allowed
    assert outcome.decision.source == "approval_disabled"


async def test_disabled_can_allow_only_when_asked_for_explicitly():
    """The hub's ADR-0018 master switch. Fail-open is expressible, never default."""
    approvals = Approvals(Channel(), enabled=False, when_disabled="allow")
    outcome = await approvals.resolve(request_for())
    assert outcome.allowed
    assert outcome.decision.source == "approval_disabled"


# --- session and persistence ---


async def test_allow_session_is_remembered_and_stops_asking():
    channel = Channel(ApprovalResponse(ApprovalKind.ALLOW_SESSION, decided_by="alice"))
    approvals = Approvals(channel)
    first = await approvals.resolve(request_for())
    second = await approvals.resolve(request_for())
    assert first.allowed and second.allowed
    assert len(channel.seen) == 1, "the second call must not re-prompt"
    assert second.decided_by == "session"
    assert second.decision.source == "approval_session"


async def test_a_session_allow_does_not_leak_to_other_tools():
    channel = Channel(ApprovalResponse(ApprovalKind.ALLOW_SESSION))
    approvals = Approvals(channel)
    await approvals.resolve(request_for())
    await approvals.resolve(request_for(action(tool="mcp://bank/wire")))
    assert len(channel.seen) == 2


async def test_clear_session_forces_a_re_prompt():
    channel = Channel(ApprovalResponse(ApprovalKind.ALLOW_SESSION))
    approvals = Approvals(channel)
    await approvals.resolve(request_for())
    approvals.clear_session()
    await approvals.resolve(request_for())
    assert len(channel.seen) == 2


@pytest.mark.parametrize(
    "kind,persistent",
    [
        (ApprovalKind.ALLOW, False),
        (ApprovalKind.ALLOW_SESSION, False),
        (ApprovalKind.ALLOW_ALWAYS, True),
        (ApprovalKind.DENY, False),
        (ApprovalKind.DENY_ALWAYS, True),
    ],
)
async def test_persistence_intent_is_surfaced_not_acted_on(kind, persistent):
    """The engine never writes policy — where rules live is a deployment
    property. It reports the intent and the scope; the caller persists."""
    scope = {"command": {"starts_with": ["git "]}}
    channel = Channel(ApprovalResponse(kind, decided_by="alice", scope=scope))
    outcome = await Approvals(channel).resolve(request_for())
    assert outcome.persistent is persistent
    assert outcome.scope == scope


# --- integration with the Enforcer ---


async def test_enforce_with_approval_resolves_a_deferral_end_to_end(tmp_path):
    chain = AuditChain(tmp_path / "audit")
    chain.start()
    try:
        enforcer = Enforcer(
            PolicyEngine.from_yaml(POLICY), chain=chain, approvals=Approvals(Channel())
        )
        outcome = await enforcer.enforce_with_approval(action(), summary="pay $9,000")
    finally:
        chain.stop()
    assert outcome.allowed

    entries = [
        json.loads(line)
        for line in next((tmp_path / "audit").glob("*.jsonl")).read_text().splitlines()
    ]
    kinds = [e["kind"] for e in entries]
    assert kinds == ["decision", "approval"], "both halves must be recorded"
    assert entries[0]["payload"]["verdict"] == "defer"
    assert entries[1]["payload"]["verdict"] == "allow"
    assert entries[1]["payload"]["decided_by"] == "alice"
    # The join an auditor performs: which decision did this approval settle?
    assert entries[1]["payload"]["action_digest"] == entries[0]["payload"]["action_digest"]


async def test_a_non_deferred_verdict_asks_nobody():
    channel = Channel()
    enforcer = Enforcer(PolicyEngine.from_yaml(POLICY), approvals=Approvals(channel))
    outcome = await enforcer.enforce_with_approval(action(tool="mcp://files/read"))
    assert outcome.allowed
    assert outcome.kind is None
    assert channel.seen == []


async def test_defer_stays_defer_without_approvals_configured():
    """Not a synthesized deny: the caller is told this needs review and nothing
    here can obtain it, rather than a missing configuration being hidden."""
    enforcer = Enforcer(PolicyEngine.from_yaml(POLICY))
    outcome = await enforcer.enforce_with_approval(action())
    assert outcome.decision.verdict is Verdict.DEFER
    assert not outcome.allowed


async def test_floored_is_derived_from_the_decision_source():
    floored_policy = """
version: 1
floors:
  - id: dangerous
    match: {tool: "mcp://bank/payout"}
"""
    channel = Channel()
    enforcer = Enforcer(PolicyEngine.from_yaml(floored_policy), approvals=Approvals(channel))
    await enforcer.enforce_with_approval(action())
    assert channel.seen[0].floored is True
