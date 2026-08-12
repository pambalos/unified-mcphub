"""The sidecar side of an approval: ask a control plane, and refuse to be lied to.

A resolved approval releases an action a policy floor deliberately held, so
**anything able to produce that JSON can unblock a blocked action**. That is the
whole reason this file exists, and it shapes what is tested: not "a valid
resolution is honoured" — which passes against a verifier that returns True
unconditionally, the exact implementation somebody reaches for when signature
checks start failing in staging — but that every tampered, expired, misdirected
or unsigned resolution is refused, and that refusing means the agent is denied.

The cases map to what an attacker who has reached the network can otherwise do:
serve their own JSON, sign it with their own key, replay a genuine allow onto a
different action, replay another tenant's, keep one and use it tomorrow, or
rewrite who approved it.

`test_an_allow_for_another_action_does_not_release_this_one` is the one to read
first. Everything else is a variation on refusing to trust the connection.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Any

import pytest

from unified_enforce import Action, Approvals, Principal
from unified_enforce.attest import (
    DEFAULT_SKEW_MS,
    Reason,
    VerificationKey,
    accept_resolution,
    b64u,
    canonical,
    key_id,
    resolution_payload,
)
from unified_enforce.approval import ApprovalRequest
from unified_enforce.policy import Decision, Verdict
from unified_enforce.remote_approvals import (
    ApprovalTransportError,
    RemoteApprovals,
    UnverifiedResolution,
)
from unified_enforce.signing import Signer

FLEET = "acme"
NOW_MS = 1_786_000_000_000
APPROVER = {
    "sub": "google:117000000000000000001",
    "email": "alice@acme.test",
    "sid": "sess-1",
    "auth_time_ms": 1_785_999_000_000,
}


def action(tool: str = "sdk://payments/refund") -> Action:
    return Action.build(
        principal=Principal(id="agent:payments-1"),
        tool=tool,
        verb="create",
        resource="customer:42",
        params={"amount": "12400.00"},
    )


def request_for(a: Action) -> ApprovalRequest:
    return ApprovalRequest(
        action=a,
        decision=Decision(verdict=Verdict.DEFER, rule_id="payouts", source="floor"),
        summary="refund $12,400",
        floored=True,
    )


def signer() -> Signer:
    return Signer.generate("decision")


def sign(s: Signer, payload: bytes) -> str:
    """Base64**url**, unpadded — what the control plane actually puts on the wire.

    `Signer.sign_bytes` returns standard base64 for the audit chain. The two
    happen to interoperate for most inputs, which is precisely why the test
    should not rely on it: a signature containing `+` or `/` would decode by
    luck rather than by contract.
    """
    import base64

    return b64u(base64.b64decode(s.sign_bytes(payload)))


def keys_for(s: Signer, *, role: str = "decision", expires_at_ms: int = 2**62) -> dict:
    public = b64u(s.public_bytes())
    kid = key_id(public)
    return {
        kid: VerificationKey(kid=kid, public_key=public, role=role, expires_at_ms=expires_at_ms)
    }


def resolution(
    s: Signer,
    digest: str,
    *,
    kind: str = "allow",
    approver: dict | None = None,
    scope: dict | None = None,
    fleet_id: str = FLEET,
    resolved_at_ms: int = NOW_MS,
    expires_at_ms: int = NOW_MS + 3_600_000,
    nonce: str = "Xczcmdh4Gjpfk7Q6OCXuWw",
) -> dict[str, Any]:
    """A genuine signed resolution, exactly as the control plane returns one."""
    approver = approver if approver is not None else APPROVER
    payload = resolution_payload(
        action_digest=digest,
        kind=kind,
        approver=approver,
        scope=scope,
        resolved_at_ms=resolved_at_ms,
        expires_at_ms=expires_at_ms,
        nonce=nonce,
        fleet_id=fleet_id,
    )
    public = b64u(s.public_bytes())
    return {
        "status": "resolved",
        "kind": kind,
        "approver": approver,
        "scope": scope,
        "action_digest": digest,
        "fleet_id": fleet_id,
        "resolved_at_ms": resolved_at_ms,
        "expires_at_ms": expires_at_ms,
        "nonce": nonce,
        "signature": sign(s, canonical(payload)),
        "key_id": key_id(public),
    }


def fresh(s: Signer, digest: str, **kwargs) -> dict[str, Any]:
    """A resolution anchored to the real clock.

    The verifier tests pin `now_ms` so they can reason about expiry exactly;
    the channel tests cannot, because the channel reads the clock itself. Using
    the fixed timestamp for those produced a week-old resolution and a denial
    that looked like a verification bug.
    """
    now = int(datetime.now(UTC).timestamp() * 1000)
    kwargs.setdefault("resolved_at_ms", now)
    kwargs.setdefault("expires_at_ms", now + 3_600_000)
    return resolution(s, digest, **kwargs)


def check(response: dict, keys: dict, *, digest: str, fleet: str = FLEET, now_ms: int = NOW_MS):
    return accept_resolution(response, keys, fleet_id=fleet, action_digest=digest, now_ms=now_ms)


# --- the verifier ---------------------------------------------------------------


def test_a_genuine_resolution_is_accepted():
    s = signer()
    digest = action().digest(strict=False)
    assert check(resolution(s, digest), keys_for(s), digest=digest)


def test_the_verifier_is_not_vacuous():
    """Guards every other test here.

    If `accept_resolution` returned ok unconditionally, every negative case
    below would pass while proving nothing.
    """
    s = signer()
    digest = action().digest(strict=False)
    forged = {**resolution(s, digest), "signature": b64u(b"not a signature" * 4)}
    assert not check(forged, keys_for(s), digest=digest)


def test_an_allow_for_another_action_does_not_release_this_one():
    """The binding that matters most.

    Without it, a genuine allow for something trivial — captured, or simply
    requested by an attacker who can queue their own approvals — releases a
    payout. The digest is supplied by the caller, from the action it actually
    asked about, and is never read out of the response.
    """
    s = signer()
    theirs = action("mcp://github/list_prs").digest(strict=False)
    ours = action().digest(strict=False)

    verdict = check(resolution(s, theirs), keys_for(s), digest=ours)

    assert not verdict
    assert verdict.reason is Reason.WRONG_ACTION


def test_another_tenants_decision_is_refused():
    """The digest is content-derived, so two fleets doing the identical thing
    produce identical digests. Only the fleet binding separates them."""
    s = signer()
    digest = action().digest(strict=False)

    verdict = check(resolution(s, digest, fleet_id="globex"), keys_for(s), digest=digest)

    assert verdict.reason is Reason.WRONG_FLEET


def test_an_expired_resolution_is_refused():
    """A decision is an answer to a question asked now.

    One that still verifies next week is a credential, and a captured allow
    would be reusable for as long as the action recurred.
    """
    s = signer()
    digest = action().digest(strict=False)
    stale = resolution(
        s, digest, resolved_at_ms=NOW_MS - 7_200_000, expires_at_ms=NOW_MS - 3_600_000
    )

    assert check(stale, keys_for(s), digest=digest).reason is Reason.EXPIRED


def test_extending_the_expiry_does_not_help():
    """The expiry is inside the signature, not beside it. Otherwise the attack
    is to keep a captured allow and rewrite the field that limits it."""
    s = signer()
    digest = action().digest(strict=False)
    genuine = resolution(s, digest, expires_at_ms=NOW_MS - 1)

    assert check(
        {**genuine, "expires_at_ms": NOW_MS + 10**9}, keys_for(s), digest=digest
    ).reason is (Reason.BAD_SIGNATURE)


@pytest.mark.parametrize(
    "field,value",
    [
        ("kind", "deny"),
        ("scope", {"amount_max": "1000000"}),
        ("nonce", "AAAAAAAAAAAAAAAAAAAAAA"),
        ("resolved_at_ms", NOW_MS + 5),
    ],
)
def test_changing_any_signed_field_invalidates_it(field, value):
    """`kind` is the obvious one — flipping deny to allow is the attack.

    `scope` matters for a subtler reason: it is what bounds an `allow_always`,
    so an unsigned scope would let a narrow approval be widened after the fact.
    """
    s = signer()
    digest = action().digest(strict=False)
    tampered = {**resolution(s, digest), field: value}

    assert not check(tampered, keys_for(s), digest=digest)


@pytest.mark.parametrize("field", ["sub", "email", "sid", "auth_time_ms"])
def test_rewriting_any_part_of_the_approver_invalidates_it(field):
    """Including the parts that look like metadata.

    "Approved eleven hours into a session that started before the incident" is
    a checkable statement only if the session and authentication time are inside
    the signature. Left outside, anyone with write access could rewrite the
    circumstances of an approval while keeping it verifiable.
    """
    s = signer()
    digest = action().digest(strict=False)
    genuine = resolution(s, digest)
    forged = {
        **genuine,
        "approver": {**APPROVER, field: "mallory@evil.test" if field != "auth_time_ms" else 1},
    }

    assert check(forged, keys_for(s), digest=digest).reason is Reason.BAD_SIGNATURE


def test_a_resolution_signed_by_another_key_is_refused():
    """Signed by *a* key is not signed by *the* key. An attacker who can serve
    the response can also serve a signature — from their own key."""
    s = signer()
    impostor = signer()
    digest = action().digest(strict=False)

    verdict = check(resolution(impostor, digest), keys_for(s), digest=digest)

    assert verdict.reason is Reason.UNKNOWN_KEY


def test_the_policy_key_cannot_release_a_held_action():
    """Role separation, enforced rather than documented.

    The key hierarchy exists so compromising the key that signs policy does not
    also confer the ability to answer approvals. If the role were not checked,
    the hierarchy would be decorative.
    """
    s = signer()
    digest = action().digest(strict=False)

    verdict = check(resolution(s, digest), keys_for(s, role="policy"), digest=digest)

    assert verdict.reason is Reason.WRONG_ROLE


def test_an_expired_key_is_refused():
    s = signer()
    digest = action().digest(strict=False)
    keys = keys_for(s, expires_at_ms=NOW_MS - DEFAULT_SKEW_MS - 1)

    assert check(resolution(s, digest), keys, digest=digest).reason is Reason.KEY_EXPIRED


def test_no_keys_at_all_means_refuse():
    """What a sidecar holds when its key set has expired or never verified.

    Not an edge case: `Distribution` drops its keys when a key set stops
    verifying, precisely so approvals stop being honoured on stale authority.
    """
    s = signer()
    digest = action().digest(strict=False)

    assert check(resolution(s, digest), {}, digest=digest).reason is Reason.UNKNOWN_KEY


@pytest.mark.parametrize(
    "mutate,reason",
    [
        (lambda r: {**r, "signature": None}, Reason.MALFORMED),
        (lambda r: {k: v for k, v in r.items() if k != "signature"}, Reason.MALFORMED),
        (lambda r: {**r, "approver": {"sub": "google:1"}}, Reason.MALFORMED),
        (lambda r: {**r, "approver": "alice@acme.test"}, Reason.MALFORMED),
        (lambda r: {**r, "resolved_at_ms": "2026-08-12T00:00:00Z"}, Reason.MALFORMED),
        (lambda r: {**r, "kind": "maybe"}, Reason.UNKNOWN_KIND),
        (lambda r: {**r, "status": "pending"}, Reason.NOT_RESOLVED),
    ],
    ids=[
        "null signature",
        "no signature at all",
        "half an approver",
        "an approver that is just a name",
        "a formatted timestamp",
        "a verdict we do not know",
        "not answered yet",
    ],
)
def test_malformed_resolutions_are_refused_not_raised(mutate, reason):
    """Returns a verdict rather than raising, on every hostile shape.

    A verifier that throws invites a caller to wrap it in try/except, and the
    except branch is where somebody eventually decides to let the action
    through. "No signature at all" is the case an attacker serving plain JSON
    produces, and it is refused for the same reason as a wrong one.
    """
    s = signer()
    digest = action().digest(strict=False)

    verdict = check(mutate(resolution(s, digest)), keys_for(s), digest=digest)

    assert not verdict
    assert verdict.reason is reason


def test_a_float_in_a_signed_field_is_refused():
    """A float has no portable representation, so the producer cannot have
    signed one. Its presence means the wire form is not what was signed."""
    s = signer()
    digest = action().digest(strict=False)
    genuine = resolution(s, digest, scope={"limit": 1000})

    assert check({**genuine, "scope": {"limit": 1000.5}}, keys_for(s), digest=digest).reason is (
        Reason.MALFORMED
    )


def test_the_canonical_form_is_order_independent():
    """Otherwise verification depends on JSON key ordering, which differs
    between the producer and any consumer that round-trips the payload."""
    assert canonical({"b": 1, "a": 2}) == canonical({"a": 2, "b": 1})


def test_a_json_round_trip_does_not_change_the_verdict():
    """The seam that broke signing the first time.

    The unit cases above verify a dict assembled in Python. A real response has
    been through `json.dumps`/`loads`, which is where signature schemes usually
    break — a datetime formatted differently, an int that became a float, a key
    reordered.
    """
    s = signer()
    digest = action().digest(strict=False)
    over_the_wire = json.loads(json.dumps(resolution(s, digest)))

    assert check(over_the_wire, keys_for(s), digest=digest)


# --- the channel ------------------------------------------------------------------


class FakeControlPlane:
    """Stands in for the HTTP calls, so the channel's own logic is under test.

    A real control plane is exercised in the integration test; this is for the
    paths that are awkward to provoke against a live service — a resolution for
    the wrong action, a signature from the wrong key, a server that never
    answers.
    """

    def __init__(self, responses: list[dict[str, Any]], *, approval_id: str = "01APPROVAL") -> None:
        self.responses = responses
        self.approval_id = approval_id
        self.queued: list[dict[str, Any]] = []
        self.polls = 0

    def queue(self, request: ApprovalRequest) -> Any:
        self.queued.append({"digest": request.digest})
        return type("Q", (), {"approval_id": self.approval_id, "already_resolved": False})()

    def poll(self, _approval_id: str) -> dict[str, Any]:
        self.polls += 1
        return self.responses[min(self.polls - 1, len(self.responses) - 1)]


def channel_over(fake: FakeControlPlane, s: Signer, **kwargs) -> RemoteApprovals:
    channel = RemoteApprovals(
        "http://cp.invalid",
        "uai_sc_test",
        fleet_id=FLEET,
        keys=lambda: keys_for(s),
        poll_seconds=0.001,
        **kwargs,
    )
    channel._queue = fake.queue  # noqa: SLF001 - substituting the transport, not the logic
    channel._poll_once = fake.poll  # noqa: SLF001
    return channel


async def test_a_verified_allow_reaches_the_agent():
    s = signer()
    a = action()
    fake = FakeControlPlane([{"status": "pending"}, fresh(s, a.digest(strict=False))])

    outcome = await Approvals(channel_over(fake, s)).resolve(request_for(a))

    assert outcome.allowed
    assert fake.polls == 2, "the channel must keep asking while a human thinks"
    # The approver survives to the caller, which is what the audit chain records.
    assert outcome.approver is not None
    assert outcome.approver.subject == APPROVER["sub"]
    assert outcome.decided_by == APPROVER["sub"], "the subject, not the address"
    assert outcome.attestation is not None
    assert outcome.attestation.signature


@pytest.mark.parametrize(
    "build,why",
    [
        (lambda s, d: fresh(s, "0" * 64), "an allow for a different action"),
        (lambda s, d: fresh(s, d, fleet_id="globex"), "another tenant's decision"),
        (lambda s, d: fresh(signer(), d), "signed by a key we do not trust"),
        (
            lambda s, d: {**fresh(s, d), "signature": b64u(b"x" * 64)},
            "a forged signature",
        ),
        (
            lambda s, d: {k: v for k, v in fresh(s, d).items() if k != "signature"},
            "plain JSON with no signature",
        ),
        (
            lambda s, d: fresh(s, d, resolved_at_ms=NOW_MS, expires_at_ms=NOW_MS + 1),
            "an allow that expired days ago",
        ),
    ],
    ids=[
        "wrong action",
        "wrong fleet",
        "wrong key",
        "forged signature",
        "unsigned",
        "expired",
    ],
)
async def test_an_unverifiable_allow_denies_the_agent(build, why):
    """The property the whole module exists for.

    Each of these is a resolution saying `allow`. None releases the action, and
    the agent is denied rather than the failure surfacing as an exception the
    caller has to remember to handle.
    """
    s = signer()
    a = action()
    fake = FakeControlPlane([build(s, a.digest(strict=False))])

    outcome = await Approvals(channel_over(fake, s)).resolve(request_for(a))

    assert not outcome.allowed, f"{why} released the action"
    assert outcome.decision.verdict is Verdict.DENY


async def test_an_unverifiable_resolution_stops_polling():
    """It is not a transient condition. The same bytes with the same signature
    would arrive again, so retrying only delays the denial."""
    s = signer()
    a = action()
    fake = FakeControlPlane([fresh(signer(), a.digest(strict=False))])

    with pytest.raises(UnverifiedResolution):
        await channel_over(fake, s).ask(request_for(a))

    assert fake.polls == 1


async def test_a_control_plane_that_never_answers_denies():
    """Silence is not consent. The sidecar owns the deadline and fails closed
    on it rather than holding an agent open indefinitely."""
    s = signer()
    a = action()
    fake = FakeControlPlane([{"status": "pending"}])

    outcome = await Approvals(channel_over(fake, s, deadline_seconds=0.05)).resolve(request_for(a))

    assert not outcome.allowed
    assert "approval_channel_error" in (outcome.reason or "")


async def test_an_unreachable_control_plane_denies():
    """No network at all. The address is unroutable, so this exercises the real
    urllib path rather than a stub of it."""
    channel = RemoteApprovals(
        "http://127.0.0.1:1",
        "uai_sc_test",
        fleet_id=FLEET,
        decision_key=b64u(signer().public_bytes()),
        http_timeout=0.5,
    )

    with pytest.raises(ApprovalTransportError):
        await channel.ask(request_for(action()))


async def test_the_deadline_does_not_block_the_event_loop():
    """A five-minute poll must not stall everything else in the process.

    Worth pinning rather than assuming: the obvious implementation of "poll
    every two seconds" is a blocking sleep, and the symptom of getting it wrong
    is every other agent in the process freezing behind one pending approval.
    """
    s = signer()
    a = action()
    fake = FakeControlPlane([{"status": "pending"}])
    channel = channel_over(fake, s, deadline_seconds=0.3)

    ticks = 0

    async def other_work():
        nonlocal ticks
        for _ in range(10):
            await asyncio.sleep(0.01)
            ticks += 1

    await asyncio.gather(channel.ask(request_for(a)), other_work(), return_exceptions=True)

    assert ticks == 10, "the event loop was blocked while waiting for a human"


def test_a_channel_with_no_key_source_is_refused_at_construction():
    """Rather than at the first deferred action.

    Constructed without a key, every resolution would fail to verify and every
    deferred action would deny — which looks like a broken control plane rather
    than a misconfigured sidecar.
    """
    with pytest.raises(ValueError, match="key source"):
        RemoteApprovals("http://cp.invalid", "uai_sc_test", fleet_id=FLEET)


# --- what lands in the chain --------------------------------------------------------


async def test_the_chain_records_the_approver_and_the_proof(tmp_path):
    """The outstanding half of UAI-153, and the reason it had to live here.

    The control plane's `approvals` table is a queue. This is the evidence: it
    is in the customer's environment, it is hash-chained, and it carries the
    signature — so "alice approved the $12,400 refund" can be re-verified years
    later, by somebody who does not trust whoever operates the control plane.
    A chain entry recording only a name would be our word for it.
    """
    from unified_enforce import AuditChain, RecordedApproval

    s = signer()
    a = action()
    fake = FakeControlPlane([fresh(s, a.digest(strict=False))])
    request = request_for(a)

    outcome = await Approvals(channel_over(fake, s)).resolve(request)

    chain = AuditChain(tmp_path)
    chain.start()
    chain.append_decision(a, request.decision)
    entry = chain.append_approval(RecordedApproval.build(request, outcome))
    chain.stop()

    payload = entry["payload"]
    assert payload["approver"]["subject"] == APPROVER["sub"]
    assert payload["approver"]["session_id"] == APPROVER["sid"]
    assert payload["approver"]["authenticated_at_ms"] == APPROVER["auth_time_ms"]
    assert payload["attestation"]["signature"]
    assert payload["attestation"]["key_id"]
    # The join back to the DEFER that demanded review. Two entries, not one
    # rewritten: that review was demanded and that a human resolved it are
    # separate events, and a log collapsing them cannot answer "who approved
    # this?" at all.
    assert payload["action_digest"] == a.digest(strict=False)
    assert AuditChain.verify(tmp_path).ok


async def test_a_denied_approval_records_no_approver(tmp_path):
    """Absence, not an empty object.

    When nobody authenticated — no channel, a timeout, an unverifiable
    resolution — the entry must not carry an approver structure with blank
    fields. That reads as "someone approved this and we lost their details",
    which is the opposite of what happened.
    """
    from unified_enforce import AuditChain, RecordedApproval

    request = request_for(action())
    outcome = await Approvals(channel=None).resolve(request)

    chain = AuditChain(tmp_path)
    chain.start()
    entry = chain.append_approval(RecordedApproval.build(request, outcome))
    chain.stop()

    assert entry["payload"]["approver"] is None
    assert entry["payload"]["attestation"] is None
    assert entry["payload"]["reason"] == "no_approval_channel"
