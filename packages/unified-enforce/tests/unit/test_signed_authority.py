"""Signed authority: under what standing a person released an action (attest v4).

entity-rbac §4 and §11: "who approved $4,200, and under what authority" has to
be answerable from the evidence, not from a row in somebody else's database.
So a control plane signs the answering person's standing into the resolution
-- membership, role, the authority limits evaluated and how each came out,
whether it overrode another person's claim, and the case -- and the chain
records it beside the approver, where `pack_verify` re-checks it offline.

The properties, each a way this could quietly fail:

- **Old resolutions keep verifying.** Without `authority` the payload is v2 or
  v3 byte for byte; a v4 is only signed for a reporter that asks for one.
- **The signature covers the authority.** Stripping it from a v4 response,
  adding one to a v2, or flipping a limit's `held` all fail verification.
- **The evidence pack proves it.** A chain entry carrying a v4 resolution
  verifies, says which limits held, and an edited limit fails the pack.
- **One wire format on both sides.** `vectors/resolutions.json` is the same
  file in the control plane's tests, checked against its vendored copy.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from test_remote_approvals import (
    APPROVER,
    FLEET,
    NOW_MS,
    FakeControlPlane,
    action,
    channel_over,
    check,
    fresh,
    keys_for,
    request_for,
    resolution,
    sign,
    signer,
)

from unified_enforce import Approvals
from unified_enforce.attest import (
    RESOLUTION_VERSION_AUTHORITY,
    Reason,
    VerificationKey,
    accept_resolution,
    b64u,
    canonical,
    key_id,
    resolution_payload,
)
from unified_enforce.signing import Signer

AUTHORITY = {
    "membership": "01JMEMBERSHIP0000000000000",
    "role": "csr",
    "entity": "01JENTITYACME0000000000000",
    "limits": [
        {
            "id": "csr-payout-cap",
            "when": 'tool != "mcp://insurance/approve_claim" || double(params.amount) <= 5000.0',
            "held": True,
        }
    ],
    "override": False,
    "case": "01JCASECLM2001000000000000",
}


def with_authority(s: Signer, digest: str, authority: dict | None = AUTHORITY, **kw) -> dict:
    """A genuine resolution whose signature covers `authority` (v4)."""
    response = (fresh if kw.pop("live", False) else resolution)(s, digest, **kw)
    payload = resolution_payload(
        action_digest=digest,
        kind=response["kind"],
        approver=response["approver"],
        scope=response["scope"],
        resolved_at_ms=response["resolved_at_ms"],
        expires_at_ms=response["expires_at_ms"],
        nonce=response["nonce"],
        fleet_id=response["fleet_id"],
        authority=authority,
    )
    response["signature"] = sign(s, canonical(payload))
    response["authority"] = authority
    return response


# --- the payload ----------------------------------------------------------------


def test_v4_adds_authority_and_v2_v3_are_unchanged():
    fields = dict(
        action_digest="ab",
        kind="allow",
        approver={"sub": "s"},
        scope=None,
        resolved_at_ms=1,
        expires_at_ms=2,
        nonce="n",
        fleet_id="f",
    )
    v2 = resolution_payload(**fields)
    assert canonical(v2) == canonical(resolution_payload(**fields, authority=None))
    assert v2["v"] == 2 and "authority" not in v2
    v3 = resolution_payload(**fields, attachments_digest="d" * 64)
    assert v3["v"] == 3 and "authority" not in v3
    v4 = resolution_payload(**fields, attachments_digest="d" * 64, authority=AUTHORITY)
    assert v4["v"] == RESOLUTION_VERSION_AUTHORITY == 4
    assert v4["authority"] == AUTHORITY and v4["attachments_digest"] == "d" * 64


def test_a_v4_resolution_verifies_and_old_ones_still_do():
    s = signer()
    digest = action().digest(strict=False)
    assert check(with_authority(s, digest), keys_for(s), digest=digest)
    assert check(resolution(s, digest), keys_for(s), digest=digest), "v2 must keep verifying"


@pytest.mark.parametrize(
    "tamper,why",
    [
        (lambda r: r.pop("authority"), "stripped: a v4 cannot pass as a v2"),
        (
            lambda r: r["authority"]["limits"][0].update(held=False) or None,
            "a limit's outcome rewritten",
        ),
        (lambda r: r["authority"].update(role="supervisor"), "the role upgraded"),
        (lambda r: r["authority"].update(override=True), "an override hidden or invented"),
        (
            lambda r: r["authority"].update(case="01JOTHERCASE00000000000000"),
            "moved to another case",
        ),
    ],
)
def test_the_signature_covers_the_authority(tamper, why):
    s = signer()
    digest = action().digest(strict=False)
    response = json.loads(json.dumps(with_authority(s, digest)))
    tamper(response)
    verdict = check(response, keys_for(s), digest=digest)
    assert not verdict, why
    assert verdict.reason is Reason.BAD_SIGNATURE, why


def test_authority_cannot_be_added_to_an_old_resolution():
    s = signer()
    digest = action().digest(strict=False)
    response = resolution(s, digest) | {"authority": AUTHORITY}
    assert check(response, keys_for(s), digest=digest).reason is Reason.BAD_SIGNATURE


@pytest.mark.parametrize(
    "authority",
    [
        "csr",
        {k: v for k, v in AUTHORITY.items() if k != "limits"},
        AUTHORITY | {"limits": [{"id": "x", "held": "yes"}]},
        AUTHORITY | {"override": "no"},
    ],
)
def test_a_malformed_authority_is_refused_not_canonicalised(authority):
    s = signer()
    digest = action().digest(strict=False)
    response = with_authority(s, digest) | {"authority": authority}
    assert check(response, keys_for(s), digest=digest).reason is Reason.MALFORMED


# --- the channel and the chain ----------------------------------------------------


async def test_the_channel_asks_for_it_and_the_chain_records_it(tmp_path):
    from unified_enforce import AuditChain, RecordedApproval

    s = signer()
    a = action()
    fake = FakeControlPlane([with_authority(s, a.digest(strict=False), live=True)])
    request = request_for(a)
    outcome = await Approvals(channel_over(fake, s)).resolve(request)
    assert outcome.allowed and outcome.authority == AUTHORITY

    chain = AuditChain(tmp_path)
    chain.start()
    entry = chain.append_approval(RecordedApproval.build(request, outcome))
    plain = chain.append_approval(
        RecordedApproval.build(
            request,
            await Approvals(
                channel_over(FakeControlPlane([fresh(s, a.digest(strict=False))]), s)
            ).resolve(request),
        )
    )
    chain.stop()
    assert entry["payload"]["authority"] == AUTHORITY
    # Absent, not null, when the resolution carried none: older entries stay
    # byte for byte what they were.
    assert "authority" not in plain["payload"]


def test_the_request_tells_the_control_plane_it_verifies_v4(monkeypatch):
    from unified_enforce.remote_approvals import RemoteApprovals

    sent: list[dict[str, Any]] = []
    channel = RemoteApprovals(
        "http://cp.invalid", "uai_sc_test", fleet_id=FLEET, keys=lambda: keys_for(signer())
    )
    monkeypatch.setattr(
        channel, "_post", lambda path, body: sent.append(body) or {"id": "01A", "status": "pending"}
    )
    channel._queue(request_for(action()))  # noqa: SLF001 - the body is the contract
    assert sent[0]["signed_authority"] is True


# --- the evidence pack ------------------------------------------------------------


def _chain_record(response: dict) -> dict[str, Any]:
    """A sidecar chain entry's payload for this resolution, as audit.py writes it."""
    return {
        "action_digest": response["action_digest"],
        "kind": response["kind"],
        "scope": response["scope"],
        "approver": {
            "subject": response["approver"]["sub"],
            "email": response["approver"]["email"],
            "session_id": response["approver"]["sid"],
            "authenticated_at_ms": response["approver"]["auth_time_ms"],
        },
        "attestation": {
            "signature": response["signature"],
            "key_id": response["key_id"],
            "nonce": response["nonce"],
            "resolved_at_ms": response["resolved_at_ms"],
            "expires_at_ms": response["expires_at_ms"],
            "fleet_id": response["fleet_id"],
        },
        **({"authority": response["authority"]} if "authority" in response else {}),
    }


def test_the_pack_proves_the_approver_was_within_authority():
    from unified_enforce.pack_verify import _check_one_approval

    s = signer()
    digest = action().digest(strict=False)
    ok, detail = _check_one_approval(_chain_record(with_authority(s, digest)), keys_for(s))
    assert ok, detail
    assert "as csr under membership 01JMEMBERSHIP" in detail
    assert "csr-payout-cap held" in detail

    edited = _chain_record(with_authority(s, digest))
    edited["authority"]["limits"][0]["held"] = False
    ok, detail = _check_one_approval(edited, keys_for(s))
    assert not ok and "does not verify" in detail

    # A v2 record, written before authority was signed, verifies as before.
    ok, detail = _check_one_approval(_chain_record(resolution(s, digest)), keys_for(s))
    assert ok, detail


def test_a_hub_entry_records_authority_under_resolution():
    from unified_enforce.pack_verify import Chain, _approvals_in, _check_one_approval

    s = signer()
    digest = action().digest(strict=False)
    record = _chain_record(with_authority(s, digest))
    hub_entry = {
        "phase": "received",
        "seq": 1,
        "action_digest": digest,
        "approver": record["approver"],
        "attestation": record["attestation"],
        "resolution": {"kind": "allow", "scope": None, "authority": record["authority"]},
    }
    found = _approvals_in(Chain(name="hub", meta={}, entries=[hub_entry]))
    ok, detail = _check_one_approval(found[0], keys_for(s))
    assert ok, detail


# --- shared vectors -----------------------------------------------------------------

VECTORS = Path(__file__).resolve().parents[1] / "vectors" / "resolutions.json"

#: A fixed, test-only seed, so the vectors are reproducible (Ed25519 signing
#: is deterministic). It signs nothing outside this file and its twin in the
#: control plane's tests; it is not, and must never become, a real key.
VECTOR_SEED = bytes(range(32))


def _vectors() -> dict[str, Any]:
    s = Signer.from_private_bytes(VECTOR_SEED, "vectors")
    public = b64u(s.public_bytes())
    digest = "c" * 64
    base = dict(
        kind="allow",
        approver=APPROVER,
        resolved_at_ms=NOW_MS,
        expires_at_ms=NOW_MS + 3_600_000,
        nonce="Xczcmdh4Gjpfk7Q6OCXuWw",
    )
    cases: list[tuple[str, dict[str, Any]]] = [
        ("v2", {}),
        ("v3-attachments", {"attachments_digest": "d" * 64}),
        ("v4-authority", {"authority": AUTHORITY}),
        ("v4-authority-and-attachments", {"attachments_digest": "d" * 64, "authority": AUTHORITY}),
    ]
    out = []
    for name, extra in cases:
        payload = resolution_payload(
            action_digest=digest, scope=None, fleet_id=FLEET, **base, **extra
        )
        response = {
            "status": "resolved",
            "action_digest": digest,
            "scope": None,
            "fleet_id": FLEET,
            **base,
            **extra,
            "signature": sign(s, canonical(payload)),
            "key_id": key_id(public),
        }
        out.append(
            {
                "name": name,
                "canonical": canonical(payload).decode(),
                "response": response,
                "attachments_digest": extra.get("attachments_digest"),
            }
        )
    return {"public_key": public, "fleet_id": FLEET, "now_ms": NOW_MS, "vectors": out}


def test_the_shared_vectors_are_current():
    """Regenerate with UNIFIED_UPDATE_VECTORS=1 after a deliberate format change,
    then copy the file into the control plane (tests/vectors/resolutions.json)."""
    expected = _vectors()
    if os.environ.get("UNIFIED_UPDATE_VECTORS"):
        VECTORS.parent.mkdir(exist_ok=True)
        VECTORS.write_text(json.dumps(expected, indent=2, sort_keys=True) + "\n")
    assert json.loads(VECTORS.read_text()) == expected


def test_the_shared_vectors_verify():
    data = json.loads(VECTORS.read_text())
    public = data["public_key"]
    keys = {
        key_id(public): VerificationKey(
            kid=key_id(public), public_key=public, role="decision", expires_at_ms=2**62
        )
    }
    for v in data["vectors"]:
        verdict = accept_resolution(
            v["response"],
            keys,
            fleet_id=data["fleet_id"],
            action_digest=v["response"]["action_digest"],
            now_ms=data["now_ms"],
            attachments_digest=v["attachments_digest"],
        )
        assert verdict, (v["name"], verdict)
