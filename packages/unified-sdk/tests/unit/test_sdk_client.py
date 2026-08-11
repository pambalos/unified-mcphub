"""E4: the SDK client — semantic actions, guards, and correlation."""

import json
from decimal import Decimal

import pytest

from unified_enforce import AuditChain, Enforcer, PolicyEngine
from unified_sdk import CORRELATION_HEADER, ApprovalRequired, Denied, UnifiedAI

POLICY = """
version: 1
rules:
  - id: small-refunds
    match: {principal: "agent:crew-*", tool: "stripe://refunds", verb: create}
    when: 'double(params.amount) <= 5000.0'
    effect: allow
  - id: lookups-ok
    match: {principal: "agent:crew-*", tool: "stripe://customers", verb: read}
    effect: allow
  - id: payouts-need-a-human
    match: {tool: "stripe://payouts", verb: create}
    effect: defer
"""


@pytest.fixture
def ua(tmp_path):
    client = UnifiedAI.local(
        PolicyEngine.from_yaml(POLICY),
        principal="agent:crew-1",
        audit_dir=tmp_path / "audit",
    )
    yield client
    client.close()


def entries(tmp_path):
    lines = next((tmp_path / "audit").glob("*.jsonl")).read_text().splitlines()
    return [json.loads(line)["payload"] for line in lines]


# --- deciding ---


def test_allowed_action_returns_a_verdict(ua):
    act = ua.check(
        "stripe://refunds", verb="create", resource="customer:42", params={"amount": 100}
    )
    assert act.allowed
    assert act.decision.rule_id == "small-refunds"


def test_the_value_inside_params_decides(ua):
    """The whole point of E4: same tool, same verb, different meaning."""
    assert ua.check("stripe://refunds", verb="create", params={"amount": 100}).allowed
    assert not ua.check("stripe://refunds", verb="create", params={"amount": 9000}).allowed


def test_check_does_not_raise_so_callers_can_branch(ua):
    act = ua.check("stripe://refunds", verb="create", params={"amount": 9000})
    assert not act.allowed  # no exception


def test_actions_are_tagged_as_sdk_origin(ua):
    act = ua.check("stripe://customers", verb="read")
    assert act.action.context.origin == "sdk"
    assert act.action.principal.id == "agent:crew-1"


# --- guards ---


def test_acting_runs_the_block_when_allowed(ua):
    ran = False
    with ua.acting("stripe://refunds", verb="create", params={"amount": 10}):
        ran = True
    assert ran


def test_acting_raises_before_the_block_runs(ua):
    ran = False
    with pytest.raises(Denied) as exc:
        with ua.acting("stripe://refunds", verb="create", params={"amount": 9000}):
            ran = True  # pragma: no cover
    assert not ran, "a denied operation must never start"
    assert exc.value.decision.rule_id is None or exc.value.digest


def test_defer_raises_a_distinct_error(ua):
    """DEFER is a decision not yet made — an agent that treats it as a
    permanent refusal abandons work a human would have approved."""
    with pytest.raises(ApprovalRequired):
        with ua.acting("stripe://payouts", verb="create"):
            pass  # pragma: no cover


def test_errors_carry_the_action_digest_for_audit_lookup(ua):
    with pytest.raises(Denied) as exc:
        ua.check("stripe://refunds", verb="create", params={"amount": 9000}).raise_for_verdict()
    assert len(exc.value.digest) == 64
    assert "stripe://refunds" in str(exc.value)


# --- the decorator ---


def test_decorator_enforces_and_templates_arguments(ua):
    @ua.action(
        "stripe://refunds", verb="create", resource="customer:{customer_id}", params=["amount"]
    )
    def issue_refund(customer_id, amount):
        return "refunded"

    assert issue_refund("42", 100) == "refunded"
    with pytest.raises(Denied):
        issue_refund("42", 9000)


def test_decorator_captures_only_named_params(ua, tmp_path):
    """Explicit capture keeps secrets out of the evidence chain by default."""

    @ua.action("stripe://refunds", verb="create", params=["amount"])
    def issue_refund(amount, api_key):
        return "ok"

    issue_refund(100, "sk_live_SUPERSECRET")
    recorded = entries(tmp_path)[-1]["action"]["params"]
    assert recorded == {"amount": 100}
    assert "api_key" not in recorded


def test_decorator_rejects_unknown_argument_names_at_decoration_time(ua):
    with pytest.raises(TypeError, match="nope"):

        @ua.action("stripe://refunds", verb="create", params=["nope"])
        def issue_refund(amount):  # pragma: no cover
            ...


def test_decorator_rejects_unknown_template_names_at_call_time(ua):
    @ua.action("stripe://refunds", verb="create", resource="customer:{missing}")
    def issue_refund(amount):  # pragma: no cover
        ...

    with pytest.raises(TypeError, match="missing"):
        issue_refund(100)


async def test_decorator_supports_async_functions(ua):
    """A sync wrapper would decide, then return a coroutine that runs the real
    work after the guard exited — authorized, but at a misleading moment."""
    calls = []

    @ua.action("stripe://refunds", verb="create", params=["amount"])
    async def issue_refund(amount):
        calls.append(amount)
        return "refunded"

    assert await issue_refund(100) == "refunded"
    with pytest.raises(Denied):
        await issue_refund(9000)
    assert calls == [100], "the denied call must never reach the function body"


# --- canonicalization ---


def test_floats_and_decimals_become_exact_strings(ua):
    """Strict canonicalization rejects floats (non-portable repr), so a signed
    action carrying an amount has to survive as text — and must match what the
    gateway's body parser produces for the same payload."""
    act = ua.check(
        "stripe://refunds", verb="create", params={"amount": Decimal("4999.99"), "fee": 1.5}
    )
    assert act.action.params == {"amount": "4999.99", "fee": "1.5"}
    assert len(act.action.digest()) == 64  # strict mode: would raise on a float


def test_nested_params_are_normalized_too(ua):
    act = ua.check(
        "stripe://customers", verb="read", params={"lines": [{"amount": 1.25}], "ok": True}
    )
    assert act.action.params == {"lines": [{"amount": "1.25"}], "ok": True}


# --- audit + correlation ---


def test_decisions_are_chained(ua, tmp_path):
    ua.check("stripe://customers", verb="read")
    with pytest.raises(Denied):
        ua.check("stripe://refunds", verb="create", params={"amount": 9000}).raise_for_verdict()
    recorded = entries(tmp_path)
    assert [e["verdict"] for e in recorded] == ["allow", "deny"]
    assert all(e["action"]["context"]["origin"] == "sdk" for e in recorded)


def test_correlation_headers_carry_the_action_digest(ua):
    act = ua.check("stripe://refunds", verb="create", params={"amount": 100})
    assert act.headers[CORRELATION_HEADER] == act.digest


def test_traceparent_is_omitted_without_an_ambient_span(ua):
    """No tracing configured must not mean a fabricated trace id that links
    nothing — the header is simply absent."""
    act = ua.check("stripe://customers", verb="read")
    assert "traceparent" not in act.headers


# --- lifecycle ---


def test_client_closes_its_chain(tmp_path):
    with UnifiedAI.local(
        PolicyEngine.from_yaml(POLICY), principal="agent:crew-1", audit_dir=tmp_path / "audit"
    ) as client:
        client.check("stripe://customers", verb="read")
    assert entries(tmp_path)[0]["verdict"] == "allow"


def test_wrapping_an_existing_enforcer_shares_one_chain(tmp_path):
    """A process already running the engine (a hub, a gateway) must be able to
    share its chain rather than open a second, competing writer."""
    chain = AuditChain(tmp_path / "audit")
    chain.start()
    try:
        client = UnifiedAI(
            Enforcer(PolicyEngine.from_yaml(POLICY), chain=chain), principal="agent:crew-1"
        )
        client.check("stripe://customers", verb="read")
    finally:
        chain.stop()
    assert len(entries(tmp_path)) == 1


# --- approvals (UAI-133) ---


class _Operator:
    """A scripted human."""

    def __init__(self, kind, decided_by="alice"):
        self.kind = kind
        self.decided_by = decided_by
        self.asked = []

    async def ask(self, request):
        from unified_enforce import ApprovalResponse

        self.asked.append(request)
        return ApprovalResponse(self.kind, decided_by=self.decided_by)


def with_approvals(operator, tmp_path=None):
    from unified_enforce import Approvals

    return UnifiedAI.local(
        PolicyEngine.from_yaml(POLICY),
        principal="agent:crew-1",
        audit_dir=(tmp_path / "audit") if tmp_path else None,
        approvals=Approvals(operator),
    )


async def test_a_human_can_release_a_deferred_action():
    """Without this the SDK's ApprovalRequired was a dead end — DEFER meant
    'deny with a nicer label' outside the hub."""
    from unified_enforce import ApprovalKind

    operator = _Operator(ApprovalKind.ALLOW)
    with with_approvals(operator) as ua:
        act = await ua.check_async("stripe://payouts", verb="create", summary="pay $9,000")
    assert act.allowed
    assert operator.asked[0].summary == "pay $9,000"


async def test_a_human_denial_is_a_denial():
    from unified_enforce import ApprovalKind

    with with_approvals(_Operator(ApprovalKind.DENY)) as ua:
        act = await ua.check_async("stripe://payouts", verb="create")
    assert not act.allowed


async def test_the_decorator_waits_for_approval_on_async_actions():
    from unified_enforce import ApprovalKind

    operator = _Operator(ApprovalKind.ALLOW)
    with with_approvals(operator) as ua:

        @ua.action("stripe://payouts", verb="create", summary="payout")
        async def issue_payout():
            return "paid"

        assert await issue_payout() == "paid"
    assert len(operator.asked) == 1


async def test_a_denied_approval_stops_the_decorated_body():
    from unified_enforce import ApprovalKind

    ran = []
    with with_approvals(_Operator(ApprovalKind.DENY)) as ua:

        @ua.action("stripe://payouts", verb="create")
        async def issue_payout():
            ran.append(1)  # pragma: no cover

        # A human's "no" is a settled denial, not a pending approval.
        with pytest.raises(Denied):
            await issue_payout()
    assert ran == []


async def test_without_approvals_a_defer_stays_a_defer(ua):
    """A missing approval channel stays visible rather than becoming a silent
    deny that looks like policy."""
    act = await ua.check_async("stripe://payouts", verb="create")
    assert not act.allowed
    with pytest.raises(ApprovalRequired):
        act.raise_for_verdict()


async def test_both_halves_of_an_approval_are_chained(tmp_path):
    from unified_enforce import ApprovalKind

    with with_approvals(_Operator(ApprovalKind.ALLOW), tmp_path) as ua:
        await ua.check_async("stripe://payouts", verb="create")
    recorded = [
        json.loads(line)
        for line in next((tmp_path / "audit").glob("*.jsonl")).read_text().splitlines()
    ]
    assert [e["kind"] for e in recorded] == ["decision", "approval"]
    assert recorded[1]["payload"]["decided_by"] == "alice"
