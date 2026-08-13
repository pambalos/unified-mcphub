"""Merkle checkpoints and where they go. UAI-134.

The test to read first is
`test_a_rewritten_chain_verifies_perfectly_and_still_fails_the_anchor`. It is
the whole argument for this module: it performs the attack the audit chain
explicitly cannot detect — rewrite the history, recompute every hash, re-sign
every entry — confirms `verify()` reports the result pristine, and then catches
it against a root that was published beforehand.

The second is `test_an_internal_node_cannot_be_passed_off_as_a_leaf`. Naive
Merkle implementations have a real second-preimage attack, and RFC 6962's
domain separation is the fix rather than decoration.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

import pytest

from unified_enforce.anchors import Anchoring, AnchorError, DirectoryAnchor
from unified_enforce.audit import AuditChain
from unified_enforce.checkpoint import (
    build,
    conflicts,
    inclusion_proof,
    leaf_hash,
    merkle_root,
    verify_inclusion,
    verify_signature,
)
from unified_enforce.signing import Signer

NOW = datetime(2026, 8, 13, 12, 0, tzinfo=UTC)


def hashes(n: int, *, salt: str = "") -> list[str]:
    return [hashlib.sha256(f"{salt}{i}".encode()).hexdigest() for i in range(n)]


def entries(n: int, *, start: int = 1, salt: str = "") -> list[dict]:
    return [{"seq": start + i, "hash": h} for i, h in enumerate(hashes(n, salt=salt))]


# --- the point ------------------------------------------------------------------------


def test_a_rewritten_chain_verifies_perfectly_and_still_fails_the_anchor(tmp_path):
    """The attack the chain cannot see, caught by a root published beforehand.

    An attacker who owns the machine rewrites the log and re-signs every entry
    with the key it holds. `AuditChain.verify()` is perfectly happy — that is
    the honest limit of a hash chain and there is a test for it in
    `test_audit.py`. What they cannot reach is the checkpoint already sitting in
    the anchor.
    """
    signer = Signer.generate("sidecar-1")
    anchor = DirectoryAnchor(tmp_path / "anchor")

    real = entries(8, salt="real")
    published = build(real, fleet_id="acme", reporter_id="rep-1", signer=signer, now=NOW)
    anchor.submit(published)

    # The rewrite. Different history, internally flawless, signed by the same
    # key, covering exactly the same range.
    forged = entries(8, salt="forged")
    reissued = build(forged, fleet_id="acme", reporter_id="rep-1", signer=signer, now=NOW)

    assert verify_signature(reissued, signer.public_bytes()), (
        "the forged checkpoint is correctly signed — that is the point"
    )
    assert reissued.checkpoint.root != published.checkpoint.root

    found = conflicts(published.checkpoint, reissued.checkpoint)
    assert found is not None
    assert "rewritten" in found


def test_the_anchor_refuses_to_overwrite_a_published_checkpoint(tmp_path):
    """Silently replacing it would destroy the evidence at the moment it was
    created — the same inversion the control plane's chain handling documents."""
    signer = Signer.generate("sidecar-1")
    anchor = DirectoryAnchor(tmp_path)

    anchor.submit(build(entries(4, salt="real"), fleet_id="acme", reporter_id="r", signer=signer))

    with pytest.raises(AnchorError, match="already exists"):
        anchor.submit(
            build(entries(4, salt="forged"), fleet_id="acme", reporter_id="r", signer=signer)
        )


def test_disjoint_ranges_are_not_a_conflict():
    signer = Signer.generate("s")
    first = build(entries(4), fleet_id="acme", reporter_id="r", signer=signer).checkpoint
    second = build(
        entries(4, start=5, salt="b"), fleet_id="acme", reporter_id="r", signer=signer
    ).checkpoint

    assert conflicts(first, second) is None


def test_two_reporters_at_one_position_are_not_a_conflict():
    """Ten sidecars legitimately have an entry at position four."""
    signer = Signer.generate("s")
    a = build(entries(4, salt="a"), fleet_id="acme", reporter_id="rep-1", signer=signer).checkpoint
    b = build(entries(4, salt="b"), fleet_id="acme", reporter_id="rep-2", signer=signer).checkpoint

    assert conflicts(a, b) is None


# --- the tree -------------------------------------------------------------------------


def test_an_internal_node_cannot_be_passed_off_as_a_leaf():
    """The second-preimage attack on naive Merkle trees.

    Without domain separation, `H(left || right)` for an internal node is
    indistinguishable from a leaf whose data happens to be those 64 bytes — so
    an attacker can present an interior node as a member of the tree. The
    0x00/0x01 prefixes are what stop it.
    """
    entry = "ab" * 32
    naive = hashlib.sha256(bytes.fromhex(entry)).digest()

    assert leaf_hash(entry) != naive
    assert leaf_hash(entry) == hashlib.sha256(b"\x00" + bytes.fromhex(entry)).digest()


def test_odd_levels_promote_rather_than_duplicate():
    """Duplicating the last node to pad a level is CVE-2012-2459: two different
    trees producing one root. Promotion cannot collide, because nothing is
    duplicated.

    Checked behaviourally — a three-leaf tree and a four-leaf tree whose fourth
    leaf repeats the third must not share a root.
    """
    three = hashes(3)
    four = [*three, three[-1]]

    assert merkle_root(three) != merkle_root(four)


@pytest.mark.parametrize("size", [1, 2, 3, 5, 8, 17, 64, 1000])
def test_every_entry_can_prove_its_own_inclusion(size):
    """Including the awkward sizes, which is where a tree implementation is
    wrong if it is wrong at all."""
    hs = hashes(size)
    root = merkle_root(hs)

    for index in range(size):
        proof = inclusion_proof(hs, index)
        assert verify_inclusion(hs[index], proof, root), f"{index} of {size}"


def test_a_proof_is_logarithmic():
    """The reason this is a tree and not the chain head: an investigator
    discloses one entry and about twenty hashes rather than the whole log."""
    hs = hashes(1000)

    assert len(inclusion_proof(hs, 500)) <= 12


def test_a_proof_does_not_verify_against_a_different_tree():
    real, forged = hashes(64), hashes(64, salt="forged")

    assert not verify_inclusion(real[7], inclusion_proof(real, 7), merkle_root(forged))


def test_a_proof_for_the_wrong_entry_fails():
    hs = hashes(16)

    assert not verify_inclusion(hs[4], inclusion_proof(hs, 5), merkle_root(hs))


def test_a_malformed_proof_is_a_failed_proof():
    hs = hashes(8)
    root = merkle_root(hs)

    for bad in ([{"side": "sideways", "hash": "aa" * 32}], [{"hash": "zz"}], [{}]):
        assert verify_inclusion(hs[0], bad, root) is False


def test_an_empty_range_is_refused():
    with pytest.raises(ValueError, match="attest to nothing"):
        merkle_root([])


# --- building -------------------------------------------------------------------------


def test_a_non_contiguous_range_is_refused():
    """A checkpoint over a filtered view would verify perfectly and attest to a
    log that never existed."""
    signer = Signer.generate("s")
    gapped = [*entries(3), {"seq": 9, "hash": hashes(1, salt="x")[0]}]

    with pytest.raises(ValueError, match="not contiguous"):
        build(gapped, fleet_id="acme", reporter_id="r", signer=signer)


def test_a_checkpoint_is_signed_over_its_payload():
    signer = Signer.generate("s")
    signed = build(entries(5), fleet_id="acme", reporter_id="r", signer=signer)

    assert verify_signature(signed, signer.public_bytes())
    assert not verify_signature(signed, Signer.generate("other").public_bytes())


def test_tampering_with_any_field_breaks_the_signature():
    """Including the range, which is what an attacker would edit to make one
    checkpoint appear to cover a different part of the log."""
    import dataclasses

    signer = Signer.generate("s")
    signed = build(entries(5), fleet_id="acme", reporter_id="r", signer=signer)

    for field, value in [
        ("root", "00" * 32),
        ("from_seq", 99),
        ("to_seq", 99),
        ("reporter_id", "somebody-else"),
        ("fleet_id", "another-tenant"),
        ("head", "11" * 32),
    ]:
        signed.checkpoint = dataclasses.replace(signed.checkpoint, **{field: value})
        assert not verify_signature(signed, signer.public_bytes()), f"{field} was not covered"
        signed = build(entries(5), fleet_id="acme", reporter_id="r", signer=signer)


def test_a_checkpoint_round_trips_through_json():
    """It travels as JSON to an anchor and has to come back byte-identical, or
    the signature stops verifying for a reason nobody can see."""
    from unified_enforce.checkpoint import SignedCheckpoint

    signer = Signer.generate("s")
    signed = build(entries(5), fleet_id="acme", reporter_id="r", signer=signer)

    restored = SignedCheckpoint.from_dict(json.loads(json.dumps(signed.as_dict())))

    assert verify_signature(restored, signer.public_bytes())
    assert restored.checkpoint == signed.checkpoint


# --- anchoring a real chain -----------------------------------------------------------


def test_anchoring_covers_a_real_chain_and_then_only_what_is_new(tmp_path):
    """The ordinary loop: checkpoint, wait, checkpoint the tail.

    The second checkpoint must not re-cover the first's range — an overlap is
    reported as a possible rewrite, so a sidecar that re-checkpointed on every
    run would generate its own false alarms forever.
    """
    chain = AuditChain(tmp_path / "audit")
    chain.start()
    for i in range(5):
        chain.append("test", {"i": i})

    signer = Signer.generate("sidecar-1")
    anchoring = Anchoring(
        chain,
        DirectoryAnchor(tmp_path / "anchor"),
        fleet_id="acme",
        reporter_id="rep-1",
        signer=signer,
    )

    first = anchoring.checkpoint()
    assert first is not None
    assert (first.checkpoint.from_seq, first.checkpoint.to_seq) == (1, 5)

    assert anchoring.checkpoint() is None, "nothing new should produce no checkpoint"

    for i in range(3):
        chain.append("test", {"i": 100 + i})

    second = anchoring.checkpoint()
    assert second is not None
    assert (second.checkpoint.from_seq, second.checkpoint.to_seq) == (6, 8)
    assert second.checkpoint.prev_root == first.checkpoint.root
    chain.stop()


def test_an_unreachable_anchor_does_not_take_the_sidecar_with_it(tmp_path):
    """Anchoring is after-the-fact by construction. An anchor being down is a
    gap in coverage, never a reason to stop enforcing or stop recording."""

    class Broken:
        def submit(self, signed):
            raise AnchorError("the anchor is down")

        def latest(self, *, fleet_id, reporter_id):
            return None

    chain = AuditChain(tmp_path / "audit")
    chain.start()
    chain.append("test", {"i": 1})

    anchoring = Anchoring(
        chain, Broken(), fleet_id="acme", reporter_id="rep-1", signer=Signer.generate("s")
    )

    with pytest.raises(AnchorError):
        anchoring.checkpoint()

    # The chain is untouched and still usable, which is the property that
    # matters: evidence keeps being written while the anchor is down.
    chain.append("test", {"i": 2})
    assert AuditChain.verify(tmp_path / "audit").ok
    chain.stop()


def test_a_checkpoint_proves_one_real_entry_was_in_the_log(tmp_path):
    """End to end: a specific decision, proven to be in a checkpointed range,
    without handing over the rest of the log."""
    chain = AuditChain(tmp_path / "audit")
    chain.start()
    written = [chain.append("decision", {"i": i}) for i in range(20)]
    chain.stop()

    signer = Signer.generate("s")
    signed = build(written, fleet_id="acme", reporter_id="rep-1", signer=signer)

    interesting = written[13]
    proof = inclusion_proof([e["hash"] for e in written], 13)

    assert verify_inclusion(interesting["hash"], proof, signed.checkpoint.root)
    assert verify_signature(signed, signer.public_bytes())


def test_anchoring_advances_even_when_the_anchor_keys_by_something_else(tmp_path):
    """The bug a live run found and the unit tests above could not.

    `DirectoryAnchor` keys on the reporter name it is handed, so the sidecar's
    idea of its own name and the anchor's agreed by construction. The control
    plane does not: it keys on the authenticated credential id, deliberately,
    because a body-supplied reporter would let one sidecar file checkpoints
    against another.

    So `latest()` returned nothing, `checkpoint()` started from zero, and every
    run re-covered a range that was already anchored — which is reported as a
    possible rewrite. A sidecar raising a fresh tampering alarm about itself on
    every run, forever.
    """

    class KeyedByCredential:
        """An anchor that ignores the reporter name, like the real one."""

        def __init__(self):
            self.stored: list = []

        def submit(self, signed):
            self.stored.append(signed)
            return {}

        def latest(self, *, fleet_id, reporter_id):
            if not self.stored:
                return None
            return self.stored[-1].as_dict()

    chain = AuditChain(tmp_path / "audit")
    chain.start()
    for i in range(5):
        chain.append("test", {"i": i})

    anchor = KeyedByCredential()
    anchoring = Anchoring(
        chain,
        anchor,
        fleet_id="acme",
        # Deliberately not what the anchor keys on.
        reporter_id="a-name-the-anchor-does-not-use",
        signer=Signer.generate("s"),
    )

    first = anchoring.checkpoint()
    chain.append("test", {"i": 99})
    second = anchoring.checkpoint()
    chain.stop()

    assert (first.checkpoint.from_seq, first.checkpoint.to_seq) == (1, 5)
    assert (second.checkpoint.from_seq, second.checkpoint.to_seq) == (6, 6), (
        "the second checkpoint re-covered an anchored range, which the control "
        "plane reports as a possible rewrite"
    )
    assert conflicts(first.checkpoint, second.checkpoint) is None
