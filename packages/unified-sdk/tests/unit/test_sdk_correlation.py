"""E4 §4: joining the SDK's semantic action to the gateway's network action.

One logical operation produces two observations — "an $8,000 refund to customer
42" (SDK) and `POST https://api.stripe.com/v1/refunds` (sidecar). These tests
pin the contract between them, including what happens when the client lies.
"""

import json

import pytest

from unified_enforce import (
    CORRELATION_HEADER,
    AuditChain,
    CheckInput,
    Enforcer,
    ExtAuthzCore,
    PolicyEngine,
)
from unified_sdk import UnifiedAI

SDK_POLICY = """
version: 1
rules:
  - id: small-refunds
    match: {principal: "agent:crew-*", tool: "stripe://refunds", verb: create}
    when: 'double(params.amount) <= 5000.0'
    effect: allow
"""

GATEWAY_POLICY = """
version: 1
rules:
  - id: stripe-egress
    match: {principal: "agent:crew-*", tool: "https://api.stripe.com/**", verb: post}
    effect: allow
"""


def gateway(chain=None):
    return ExtAuthzCore(Enforcer(PolicyEngine.from_yaml(GATEWAY_POLICY), chain=chain))


def outbound(headers):
    return CheckInput(
        principal_id="agent:crew-1",
        method="POST",
        host="api.stripe.com",
        path="/v1/refunds",
        headers=headers,
    )


def test_the_gateway_records_the_sdk_digest_as_a_claim(tmp_path):
    with UnifiedAI.local(PolicyEngine.from_yaml(SDK_POLICY), principal="agent:crew-1") as ua:
        act = ua.check("stripe://refunds", verb="create", params={"amount": 100})

    # The application attaches act.headers to the call it is about to make; the
    # sidecar sees them on the way out.
    result = gateway().check(outbound(act.headers))

    assert result.allowed
    assert result.action.context.extra["sdk_action_claimed"] == act.digest


def test_both_observations_land_in_one_chain_and_can_be_joined(tmp_path):
    """The join an auditor actually performs: find the semantic action behind a
    network call. Both entries live in the same hash chain."""
    chain = AuditChain(tmp_path / "audit")
    chain.start()
    try:
        ua = UnifiedAI(
            Enforcer(PolicyEngine.from_yaml(SDK_POLICY), chain=chain), principal="agent:crew-1"
        )
        act = ua.check("stripe://refunds", verb="create", params={"amount": 100})
        gateway(chain).check(outbound(act.headers))
    finally:
        chain.stop()

    payloads = [
        json.loads(line)["payload"]
        for line in next((tmp_path / "audit").glob("*.jsonl")).read_text().splitlines()
    ]
    sdk_entry, gw_entry = payloads
    assert sdk_entry["action"]["context"]["origin"] == "sdk"
    assert gw_entry["action"]["context"]["origin"] == "gateway"
    assert (
        gw_entry["action"]["context"]["extra"]["sdk_action_claimed"] == sdk_entry["action_digest"]
    )


def test_a_missing_correlation_header_changes_nothing(tmp_path):
    """The link is a convenience. An agent that never calls the SDK is still
    enforced at the network layer, with the same verdict."""
    result = gateway().check(outbound({}))
    assert result.allowed
    assert "sdk_action_claimed" not in result.action.context.extra


def test_a_forged_correlation_header_cannot_change_the_verdict():
    """Anything inside the trust boundary can set this header. It must never
    grant anything — a hostile agent pointing it at an unrelated digest gets
    exactly the verdict the gateway would have issued anyway."""
    honest = gateway().check(outbound({}))
    forged = gateway().check(outbound({CORRELATION_HEADER: "f" * 64}))
    assert forged.decision.verdict is honest.decision.verdict
    assert forged.decision.rule_id == honest.decision.rule_id
    # Still recorded — as a claim, so an auditor sees the assertion was made.
    assert forged.action.context.extra["sdk_action_claimed"] == "f" * 64


def test_the_sdk_verdict_does_not_soften_the_gateway_verdict():
    """The invariant that makes an optional SDK safe: annotation can never buy
    more than the network layer would allow on its own."""
    with UnifiedAI.local(PolicyEngine.from_yaml(SDK_POLICY), principal="agent:crew-1") as ua:
        act = ua.check("stripe://refunds", verb="create", params={"amount": 100})
    assert act.allowed

    # ...but the gateway policy says nothing about paypal.
    blocked = gateway().check(
        CheckInput(
            principal_id="agent:crew-1",
            method="POST",
            host="api.paypal.com",
            path="/v1/refunds",
            headers=act.headers,
        )
    )
    assert not blocked.allowed, "an SDK allow must not unlock an egress the gateway denies"


@pytest.mark.parametrize("bogus", ["not-a-digest", "", "ABC", "f" * 63, "g" * 64])
def test_malformed_correlation_values_are_ignored(bogus):
    """Shape is validated before the value enters the evidence record, so the
    chain cannot be used as a scratchpad for arbitrary client-supplied text."""
    result = gateway().check(outbound({CORRELATION_HEADER: bogus}))
    assert "sdk_action_claimed" not in result.action.context.extra
