"""Policy bundle verification, attacked.

The canonical suite for the canonical verifier. The control plane vendors the
module and re-runs these against its copy, so a divergence fails there too.

An attacker who can push policy does not need to defeat the enforcement plane —
they push allow-all and walk through it, and the audit chain records that
nothing was violated. So the property under test is never "a good bundle
verifies". It is that every forged, rolled-back, expired, misdirected,
mis-keyed and tampered bundle is refused, **and refused for the right reason**,
because §5 requires different alarms for "cannot verify", "rolled back" and
"expired".

Each test names the attack it prevents. `test_the_verifier_is_not_vacuous`
guards the rest: if `accept_manifest` returned success unconditionally, every
negative case here would pass while proving nothing.
"""

from __future__ import annotations

import hashlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from unified_enforce import attest
from unified_enforce.attest import (
    KEYSET_SCHEMA,
    MANIFEST_SCHEMA,
    BundleState,
    Reason,
    accept_manifest,
    b64u,
    key_id,
    load_key_set,
    sign_bytes,
    unb64u,
    verify_files,
)

NOW = 1_786_000_000_000
HOUR = 3_600_000
DAY = 24 * HOUR


class Key:
    """A keypair plus the derived kid, which is all the tests ever need."""

    def __init__(self) -> None:
        self.private = Ed25519PrivateKey.generate()
        raw = self.private.public_key().public_bytes_raw()
        self.public = b64u(raw)
        self.kid = key_id(self.public)


@pytest.fixture
def root() -> Key:
    return Key()


@pytest.fixture
def policy_key() -> Key:
    return Key()


def make_key_set(root: Key, entries, *, expires_at_ms=NOW + DAY, schema=KEYSET_SCHEMA):
    payload = json.dumps(
        {
            "schema": schema,
            "issued_at_ms": NOW,
            "expires_at_ms": expires_at_ms,
            "keys": [
                {
                    "kid": k.kid,
                    "alg": "EdDSA",
                    "role": role,
                    "public_key": k.public,
                    "expires_at_ms": key_expiry,
                }
                for k, role, key_expiry in entries
            ],
        }
    ).encode()
    return sign_bytes(payload, root.private, root.kid)


def make_manifest(
    signer: Key,
    *,
    fleet_id="acme",
    version=47,
    expires_at_ms=NOW + DAY,
    files=(),
    schema=MANIFEST_SCHEMA,
    mode="enforce",
):
    payload = json.dumps(
        {
            "schema": schema,
            "fleet_id": fleet_id,
            "version": version,
            "issued_at_ms": NOW,
            "expires_at_ms": expires_at_ms,
            "mode": mode,
            "files": list(files),
        }
    ).encode()
    return sign_bytes(payload, signer.private, signer.kid)


@pytest.fixture
def keys(root, policy_key):
    verdict, loaded = load_key_set(
        make_key_set(root, [(policy_key, "policy", NOW + 90 * DAY)]),
        root_public_key=root.public,
        now_ms=NOW,
    )
    assert verdict, verdict
    return loaded


# --- the guard ----------------------------------------------------------------


def test_the_verifier_is_not_vacuous(keys, policy_key):
    """If this passes and the negative tests below also pass, they mean something."""
    good = accept_manifest(
        make_manifest(policy_key), keys, fleet_id="acme", current=None, now_ms=NOW
    )
    assert good, good

    forged = make_manifest(Key())
    assert not accept_manifest(forged, keys, fleet_id="acme", current=None, now_ms=NOW)


# --- signatures ---------------------------------------------------------------


def test_a_bundle_signed_by_an_unknown_key_is_refused(keys):
    """The bare attack: sign your own policy and serve it."""
    verdict = accept_manifest(make_manifest(Key()), keys, fleet_id="acme", current=None, now_ms=NOW)
    assert verdict.reason is Reason.UNKNOWN_KEY


def test_a_tampered_payload_is_refused(keys, policy_key):
    """Rewrite the policy after signing and keep the signature."""
    envelope = make_manifest(policy_key)
    payload = json.loads(unb64u(envelope["payload"]))
    payload["files"] = [{"path": "evil.yaml", "sha256": "0" * 64}]
    envelope["payload"] = b64u(json.dumps(payload).encode())

    verdict = accept_manifest(envelope, keys, fleet_id="acme", current=None, now_ms=NOW)
    assert verdict.reason is Reason.BAD_SIGNATURE


def test_alg_none_is_refused(keys, policy_key):
    """The classic JWS attack: declare no algorithm and supply no signature.

    Rejected on the header, before any key lookup — so it cannot depend on a
    key happening to be absent.
    """
    envelope = make_manifest(policy_key)
    header = json.loads(unb64u(envelope["signatures"][0]["protected"]))
    header["alg"] = "none"
    envelope["signatures"][0]["protected"] = b64u(json.dumps(header).encode())

    verdict = accept_manifest(envelope, keys, fleet_id="acme", current=None, now_ms=NOW)
    assert verdict.reason is Reason.BAD_ALGORITHM


def test_a_decision_key_cannot_sign_policy(root, policy_key):
    """Role separation.

    A key issued for signing approval decisions must not also authorise policy.
    Otherwise compromising the busier, more exposed online key silently confers
    the ability to rewrite the rules.
    """
    decision_key = Key()
    _, keys = load_key_set(
        make_key_set(
            root,
            [(policy_key, "policy", NOW + 90 * DAY), (decision_key, "decision", NOW + 90 * DAY)],
        ),
        root_public_key=root.public,
        now_ms=NOW,
    )

    verdict = accept_manifest(
        make_manifest(decision_key), keys, fleet_id="acme", current=None, now_ms=NOW
    )
    assert verdict.reason is Reason.WRONG_ROLE


def test_an_expired_signing_key_is_refused(root, policy_key):
    _, keys = load_key_set(
        make_key_set(root, [(policy_key, "policy", NOW - 1)]),
        root_public_key=root.public,
        now_ms=NOW,
    )
    verdict = accept_manifest(
        make_manifest(policy_key), keys, fleet_id="acme", current=None, now_ms=NOW
    )
    assert verdict.reason is Reason.KEY_EXPIRED


# --- the key set --------------------------------------------------------------


def test_a_key_set_not_signed_by_root_is_refused(root):
    """Otherwise an attacker nominates their own signing keys and everything else follows."""
    impostor = Key()
    verdict, keys = load_key_set(
        make_key_set(impostor, [(Key(), "policy", NOW + DAY)]),
        root_public_key=root.public,
        now_ms=NOW,
    )
    assert not verdict
    assert verdict.reason is Reason.UNKNOWN_KEY
    assert keys == {}


def test_an_expired_key_set_is_refused(root, policy_key):
    verdict, _ = load_key_set(
        make_key_set(root, [(policy_key, "policy", NOW + DAY)], expires_at_ms=NOW - DAY),
        root_public_key=root.public,
        now_ms=NOW,
    )
    assert verdict.reason is Reason.KEYSET_EXPIRED


def test_a_kid_must_match_its_key_material(root):
    """A name that does not match its key lets one entry borrow another's role."""
    a, b = Key(), Key()
    envelope = make_key_set(root, [(a, "policy", NOW + DAY)])
    payload = json.loads(unb64u(envelope["payload"]))
    payload["keys"][0]["public_key"] = b.public  # kid still names `a`
    envelope = sign_bytes(json.dumps(payload).encode(), root.private, root.kid)

    verdict, _ = load_key_set(envelope, root_public_key=root.public, now_ms=NOW)
    assert verdict.reason is Reason.MALFORMED


def test_rotation_accepts_either_key_with_no_restart(root, policy_key):
    """Overlapping validity.

    Rotation that requires every sidecar to restart at the same moment does not
    happen, so both keys must verify while the old one is being retired.
    """
    incoming = Key()
    _, keys = load_key_set(
        make_key_set(
            root,
            [(policy_key, "policy", NOW + DAY), (incoming, "policy", NOW + 90 * DAY)],
        ),
        root_public_key=root.public,
        now_ms=NOW,
    )

    for signer in (policy_key, incoming):
        verdict = accept_manifest(
            make_manifest(signer), keys, fleet_id="acme", current=None, now_ms=NOW
        )
        assert verdict, f"{signer.kid} rejected mid-rotation: {verdict}"


# --- freshness ----------------------------------------------------------------


def test_an_older_version_is_refused(keys, policy_key):
    """Rollback. Last month's policy, before the floor was added, is signed forever."""
    verdict = accept_manifest(
        make_manifest(policy_key, version=41),
        keys,
        fleet_id="acme",
        current=BundleState(version=47, expires_at_ms=NOW + DAY),
        now_ms=NOW,
    )
    assert verdict.reason is Reason.ROLLBACK


def test_a_fresh_sidecar_refuses_an_expired_old_bundle(keys, policy_key):
    """The hole a version number alone leaves open.

    A sidecar that has just started has no previous version, so it has no floor
    and a genuine old bundle would be accepted. Only expiry catches this — and
    the moment it matters is a deploy, an autoscale event, or an incident.
    """
    stale = make_manifest(policy_key, version=41, expires_at_ms=NOW - DAY)
    verdict = accept_manifest(stale, keys, fleet_id="acme", current=None, now_ms=NOW)
    assert verdict.reason is Reason.EXPIRED


def test_a_freeze_becomes_visible(keys, policy_key):
    """An attacker who stops serving updates forges nothing.

    Without expiry the sidecar enforces v41 indefinitely and the console stays
    green. With it, the same silence becomes a refusal an operator can alarm on.
    """
    bundle = make_manifest(policy_key, version=47, expires_at_ms=NOW + DAY)
    assert accept_manifest(bundle, keys, fleet_id="acme", current=None, now_ms=NOW)

    a_week_later = NOW + 7 * DAY
    verdict = accept_manifest(bundle, keys, fleet_id="acme", current=None, now_ms=a_week_later)
    assert verdict.reason is Reason.EXPIRED


def test_the_same_version_refreshes_freshness(keys, policy_key):
    """Time passing must not burn a version number.

    The control plane re-signs unchanged policy with a later expiry, so this is
    the ordinary path, not an exception.
    """
    current = BundleState(version=47, expires_at_ms=NOW + HOUR)
    verdict = accept_manifest(
        make_manifest(policy_key, version=47, expires_at_ms=NOW + DAY),
        keys,
        fleet_id="acme",
        current=current,
        now_ms=NOW,
    )
    assert verdict, verdict


def test_replaying_a_refresh_is_refused(keys, policy_key):
    """Same version, no later expiry — a replayed refresh buys an attacker time."""
    current = BundleState(version=47, expires_at_ms=NOW + DAY)
    verdict = accept_manifest(
        make_manifest(policy_key, version=47, expires_at_ms=NOW + HOUR),
        keys,
        fleet_id="acme",
        current=current,
        now_ms=NOW,
    )
    assert verdict.reason is Reason.STALE_REFRESH


@pytest.mark.parametrize(
    "offset,expected",
    [(-30_000, True), (-120_000, False)],
    ids=["inside-skew", "outside-skew"],
)
def test_clock_skew_is_bounded_not_ignored(keys, policy_key, offset, expected):
    """Expiry makes correctness depend on time, so some tolerance is required.

    Unbounded tolerance would make the expiry decorative, and none at all would
    make a slightly fast clock look like an attack.
    """
    bundle = make_manifest(policy_key, expires_at_ms=NOW + offset)
    assert (
        bool(accept_manifest(bundle, keys, fleet_id="acme", current=None, now_ms=NOW)) is expected
    )


# --- binding ------------------------------------------------------------------


def test_a_staging_bundle_is_refused_in_production(keys, policy_key):
    """Staging is always the weakest environment.

    Without fleet binding its policy becomes everyone's, and the easiest way in
    is to compromise the environment nobody watches.
    """
    verdict = accept_manifest(
        make_manifest(policy_key, fleet_id="staging"),
        keys,
        fleet_id="production",
        current=None,
        now_ms=NOW,
    )
    assert verdict.reason is Reason.WRONG_FLEET


def test_an_unrecognised_schema_is_refused(keys, policy_key):
    verdict = accept_manifest(
        make_manifest(policy_key, schema="unified.policy-bundle/v99"),
        keys,
        fleet_id="acme",
        current=None,
        now_ms=NOW,
    )
    assert verdict.reason is Reason.WRONG_SCHEMA


def test_a_key_set_document_cannot_pose_as_a_manifest(root, policy_key, keys):
    """Type confusion between two documents signed by related keys."""
    verdict = accept_manifest(
        make_key_set(root, [(policy_key, "policy", NOW + DAY)]),
        keys,
        fleet_id="acme",
        current=None,
        now_ms=NOW,
    )
    assert not verdict


# --- files --------------------------------------------------------------------


def _files(**contents: bytes):
    manifest = {
        "files": [
            {"path": p, "sha256": hashlib.sha256(c).hexdigest(), "size": len(c)}
            for p, c in contents.items()
        ]
    }
    return manifest, dict(contents)


def test_files_matching_their_hashes_are_accepted():
    manifest, files = _files(**{"a.yaml": b"deny: everything"})
    assert verify_files(manifest, files)


def test_a_tampered_file_rejects_the_whole_bundle():
    """All or nothing.

    A partially applied bundle is a policy nobody wrote and nobody reviewed —
    worse than keeping the previous one, which at least someone approved.
    """
    manifest, files = _files(**{"a.yaml": b"deny: everything", "b.yaml": b"allow: reads"})
    files["b.yaml"] = b"allow: everything"

    verdict = verify_files(manifest, files)
    assert verdict.reason is Reason.FILE_TAMPERED
    assert verdict.detail == "b.yaml"


def test_a_missing_file_is_refused():
    manifest, files = _files(**{"a.yaml": b"x", "b.yaml": b"y"})
    del files["b.yaml"]
    assert verify_files(manifest, files).reason is Reason.FILE_MISSING


def test_an_unlisted_file_is_refused_not_ignored():
    """Smuggling a file the signature never covered.

    Ignoring it would mean whatever loads policy from disk can still read a file
    the manifest never described, and "the signature covered everything" quietly
    stops being true.
    """
    manifest, files = _files(**{"a.yaml": b"x"})
    files["extra.yaml"] = b"allow: everything"
    assert verify_files(manifest, files).reason is Reason.FILE_UNEXPECTED


# --- malformed input ----------------------------------------------------------


@pytest.mark.parametrize(
    "envelope",
    [
        None,
        {},
        "a string",
        {"payload": "not-base64-json", "signatures": [{"protected": "x", "signature": "y"}]},
        {"payload": b64u(b"[]"), "signatures": [{"protected": "x", "signature": "y"}]},
        {"payload": b64u(b"{}"), "signatures": []},
        {"payload": b64u(b"{}"), "signatures": [{}]},
        {"payload": b64u(b"{}"), "signatures": "not-a-list"},
    ],
    ids=[
        "none",
        "empty",
        "string",
        "bad-payload",
        "array-payload",
        "no-sigs",
        "empty-sig",
        "sigs-not-list",
    ],
)
def test_malformed_envelopes_are_refused_not_raised(keys, envelope):
    """Returns a verdict for every input.

    A verifier that throws on hostile input invites a `try/except` around it,
    and the except branch is where somebody eventually lets the bundle through.
    """
    verdict = accept_manifest(envelope, keys, fleet_id="acme", current=None, now_ms=NOW)
    assert not verdict
    assert verdict.reason is not None


# --- evidence attestation --------------------------------------------------------
#
# What is signed here is the *summary*, not the chain entry, and the difference
# is the whole point. The chain signs an entry hash covering action content that
# deliberately never leaves the customer's environment — so a receiver holding a
# metadata summary could verify that signature, learn an entry exists, and still
# have no reason to believe the summary beside it describes that entry. Signing
# the summary makes the receiver's stored copy checkable by anyone holding the
# reporter's key, including against the receiver itself.


def _record(**overrides):
    record = {
        "action_digest": "a" * 64,
        "principal_id": "agent:payments-1",
        "tool": "sdk://payments/refund",
        "verb": "create",
        "verdict": "allow",
        "rule_id": "payouts",
        "source": "rule",
        "chain_seq": 41,
        "chain_hash": "b" * 64,
        "decided_at": "2026-08-12T00:00:00+00:00",
    }
    record.update(overrides)
    return record


def _reporter():
    from unified_enforce.signing import Signer

    signer = Signer.generate("chain")
    return signer, attest.b64u(signer.public_bytes())


def test_a_signed_record_verifies():
    signer, public = _reporter()
    assert attest.accept_evidence(attest.sign_evidence(_record(), signer), public)


def test_the_evidence_verifier_is_not_vacuous():
    """Guards every negative case below."""
    signer, public = _reporter()
    signed = attest.sign_evidence(_record(), signer)
    assert not attest.accept_evidence({**signed, "sig": attest.b64u(b"x" * 64)}, public)


@pytest.mark.parametrize(
    "field,value",
    [
        ("verdict", "deny"),
        ("action_digest", "c" * 64),
        ("principal_id", "agent:someone-else"),
        ("tool", "mcp://aws/delete_bucket"),
        ("rule_id", "some-other-rule"),
        ("chain_seq", 99),
        ("chain_hash", "d" * 64),
    ],
)
def test_rewriting_any_signed_field_is_caught(field, value):
    """Including the chain position and hash.

    Those are what a receiver uses to notice a missing range, so leaving them
    outside the signature would let anyone able to write the record erase the
    evidence of their own gap.
    """
    signer, public = _reporter()
    signed = attest.sign_evidence(_record(), signer)

    assert not attest.accept_evidence({**signed, field: value}, public)


def test_the_timestamp_is_deliberately_not_signed():
    """Stated as a test so it is a decision rather than an oversight.

    Every signed field is a string, an integer or null — nothing whose textual
    form two implementations can disagree about. This project has twice shipped
    a signature over a formatted timestamp and watched it verify on the machine
    that produced it and fail everywhere else. The digest and the chain hash
    identify the entry; a timestamp adds nothing an attacker cannot already see.
    """
    signer, public = _reporter()
    signed = attest.sign_evidence(_record(), signer)

    assert attest.accept_evidence({**signed, "decided_at": "2099-01-01T00:00:00+00:00"}, public)


def test_an_unsigned_record_is_refused_as_unsigned():
    """A distinct reason from a bad signature, because the responses differ: one
    is a reporter that does not attest, the other is one whose attestation
    failed."""
    _, public = _reporter()
    verdict = attest.accept_evidence(_record(), public)

    assert not verdict
    assert verdict.reason is attest.Reason.MALFORMED


def test_another_reporters_key_does_not_verify():
    signer, _ = _reporter()
    _, someone_else = _reporter()

    assert not attest.accept_evidence(attest.sign_evidence(_record(), signer), someone_else)


def test_a_json_round_trip_does_not_change_the_verdict():
    """The seam that has broken signing here before."""
    signer, public = _reporter()
    signed = json.loads(json.dumps(attest.sign_evidence(_record(), signer)))

    assert attest.accept_evidence(signed, public)


def test_a_null_field_is_signed_as_null():
    """`rule_id` is routinely absent. Treating missing and null differently
    would make a signature depend on how the sender omitted something."""
    signer, public = _reporter()
    signed = attest.sign_evidence(_record(rule_id=None), signer)

    assert attest.accept_evidence(signed, public)
    assert not attest.accept_evidence({**signed, "rule_id": ""}, public)


def test_the_shipper_signs_what_it_ships():
    """End to end through the real summariser, since that is what builds the
    record a receiver actually sees."""
    from unified_enforce import Action, Principal
    from unified_enforce.evidence import summarise
    from unified_enforce.policy import Decision, Verdict

    signer, public = _reporter()
    action = Action.build(
        principal=Principal(id="agent:payments-1"),
        tool="sdk://payments/refund",
        verb="create",
        resource="*",
        params={"amount": "12400.00"},
    )
    decision = Decision(verdict=Verdict.ALLOW, rule_id="payouts", source="rule")

    record = summarise(action, decision, entry={"seq": 7, "hash": "e" * 64}, signer=signer)

    assert attest.accept_evidence(record, public)
    assert "12400.00" not in json.dumps(record), "signing must not have started shipping content"
