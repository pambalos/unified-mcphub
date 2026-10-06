import json

import pytest

from unified_enforce import (
    Action,
    AuditChain,
    CanonicalizationError,
    GENESIS_HASH,
    PolicyEngine,
    Principal,
)


@pytest.fixture
def chain(tmp_path):
    c = AuditChain(tmp_path / "audit")
    c.start()
    yield c
    c.stop()


def test_chain_links_and_verifies(chain, tmp_path):
    e1 = chain.append("decision", {"n": 1})
    e2 = chain.append("decision", {"n": 2})
    assert e1["prev_hash"] == GENESIS_HASH
    assert e2["prev_hash"] == e1["hash"]
    result = AuditChain.verify(tmp_path / "audit")
    assert result.ok and result.entries == 2


def test_tampering_is_detected(chain, tmp_path):
    chain.append("decision", {"n": 1})
    chain.append("decision", {"n": 2})
    chain.stop()
    path = next((tmp_path / "audit").glob("*.jsonl"))
    lines = path.read_text().splitlines()
    entry = json.loads(lines[0])
    entry["payload"]["n"] = 999  # rewrite history
    lines[0] = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n")
    result = AuditChain.verify(tmp_path / "audit")
    assert not result.ok
    assert "hash mismatch" in result.error


def test_deleting_an_entry_breaks_the_chain(chain, tmp_path):
    chain.append("decision", {"n": 1})
    chain.append("decision", {"n": 2})
    chain.append("decision", {"n": 3})
    chain.stop()
    path = next((tmp_path / "audit").glob("*.jsonl"))
    lines = path.read_text().splitlines()
    path.write_text("\n".join([lines[0], lines[2]]) + "\n")
    result = AuditChain.verify(tmp_path / "audit")
    assert not result.ok
    assert "chain break" in result.error


def test_restart_resumes_the_chain(tmp_path):
    d = tmp_path / "audit"
    c1 = AuditChain(d)
    c1.start()
    e1 = c1.append("decision", {"n": 1})
    c1.stop()

    c2 = AuditChain(d)
    c2.start()
    e2 = c2.append("decision", {"n": 2})
    c2.stop()

    assert e2["prev_hash"] == e1["hash"]
    assert e2["seq"] == 2
    assert AuditChain.verify(d).ok


def test_pre_chain_legacy_logs_are_quarantined_not_fatal(tmp_path):
    # Logs written before the unified-enforce migration are flat JSONL with no
    # hash/prev_hash. Starting on top of them must not crash, must not delete
    # them, and must leave a directory that verify() passes.
    d = tmp_path / "audit"
    d.mkdir()
    legacy_line = json.dumps({"phase": "received", "seq": 41, "tool": "x"})
    (d / "2026-08-14.jsonl").write_text(legacy_line + "\n")
    (d / "2026-08-15.jsonl").write_text(legacy_line + "\n")

    c = AuditChain(d)
    c.start()
    e = c.append("decision", {"n": 1})
    c.stop()

    assert e["prev_hash"] == GENESIS_HASH
    moved = sorted(p.name for p in (d / "legacy").glob("*.jsonl"))
    assert moved == ["2026-08-14.jsonl", "2026-08-15.jsonl"]
    assert (d / "legacy" / "2026-08-15.jsonl").read_text() == legacy_line + "\n"
    assert AuditChain.verify(d).ok


def test_single_writer_lock(tmp_path, chain):
    other = AuditChain(chain._dir)
    with pytest.raises(RuntimeError, match="locked by another writer"):
        other.start()


def test_float_payloads_are_rejected(chain):
    with pytest.raises(CanonicalizationError):
        chain.append("decision", {"amount": 1.5})


def test_append_decision_end_to_end(chain, tmp_path):
    engine = PolicyEngine.from_yaml("""
version: 1
rules:
  - {id: ok, match: {tool: "mcp://a/b"}, effect: allow}
""")
    action = Action.build(
        principal=Principal(id="agent:x"), tool="mcp://a/b", verb="call", resource="*"
    )
    decision = engine.decide(action)
    entry = chain.append_decision(action, decision)
    assert entry["payload"]["verdict"] == "allow"
    assert entry["payload"]["rule_id"] == "ok"
    assert entry["payload"]["action_digest"] == action.digest()
    assert isinstance(entry["payload"]["elapsed_us"], int)
    assert AuditChain.verify(tmp_path / "audit").ok


# --- signed chains (UAI-145) ---


def test_a_signed_chain_verifies_with_the_public_key(tmp_path):
    from unified_enforce import Signer

    signer = Signer.generate("test-key-1")
    chain = AuditChain(tmp_path / "audit", signer=signer)
    chain.start()
    try:
        chain.append("decision", {"verdict": "allow"})
        chain.append("decision", {"verdict": "deny"})
    finally:
        chain.stop()

    assert AuditChain.verify(tmp_path / "audit", public_key=signer.public_bytes()).ok


def test_a_rewritten_history_survives_the_hash_check_but_not_the_signature(tmp_path):
    """The property signing actually buys.

    An attacker with write access can rewrite an unsigned chain end to end —
    recomputing every hash — and `verify()` reports it as pristine. That is the
    honest limit of a hash chain, and it is what a signature closes: forging
    the rewrite now needs the key as well as the file.
    """
    from unified_enforce import Signer

    signer = Signer.generate("test-key-1")
    audit_dir = tmp_path / "audit"
    chain = AuditChain(audit_dir, signer=signer)
    chain.start()
    try:
        chain.append("decision", {"verdict": "deny"})
    finally:
        chain.stop()

    # Rewrite the entry as an ALLOW, recomputing the hash exactly as the writer
    # would. This is the attack, done properly rather than by corrupting bytes.
    path = next(audit_dir.glob("*.jsonl"))
    entry = json.loads(path.read_text().splitlines()[0])
    entry.pop("hash"), entry.pop("sig"), entry.pop("key_id")
    entry["payload"]["verdict"] = "allow"
    from unified_enforce import canonical_bytes, sha256_hex

    rehashed = sha256_hex(canonical_bytes(entry, strict=False))
    path.write_text(json.dumps({**entry, "hash": rehashed}, sort_keys=True) + "\n")

    # Hash chain alone: no complaint. This is not a bug, it is the model.
    assert AuditChain.verify(audit_dir).ok

    # With the key, the forgery is caught — here as a missing signature, since
    # the attacker cannot produce one.
    signed = AuditChain.verify(audit_dir, public_key=signer.public_bytes())
    assert not signed.ok
    assert "unsigned" in signed.error


def test_a_signature_from_the_wrong_key_is_rejected(tmp_path):
    from unified_enforce import Signer

    signer, other = Signer.generate("real"), Signer.generate("attacker")
    chain = AuditChain(tmp_path / "audit", signer=signer)
    chain.start()
    try:
        chain.append("decision", {"verdict": "allow"})
    finally:
        chain.stop()

    result = AuditChain.verify(tmp_path / "audit", public_key=other.public_bytes())
    assert not result.ok
    assert "bad signature" in result.error


def test_signing_is_optional_and_off_by_default(tmp_path):
    """Existing deployments must keep verifying unchanged."""
    chain = AuditChain(tmp_path / "audit")
    chain.start()
    try:
        written = chain.append("decision", {"verdict": "allow"})
    finally:
        chain.stop()
    assert "sig" not in written
    assert AuditChain.verify(tmp_path / "audit").ok


# --- a chain that gains a key mid-life (signed_from_seq) ---


def _write(audit_dir, entries, signer=None, *, sign_from: int | None = None):
    """Append flat `{seq: n}` entries, attaching `signer` at `sign_from`.

    The shape of a hub that ran unsigned and was later given a key: the writer
    is started without one and the signer set partway through.
    """
    from unified_enforce.audit import HashChainWriter

    writer = HashChainWriter(audit_dir, strict=False)
    writer.start()
    try:
        for seq in entries:
            if signer is not None and sign_from is not None and seq == sign_from:
                writer.signer = signer
            writer.append({"seq": seq, "phase": "received"})
    finally:
        writer.stop()


def _lines(audit_dir):
    path = next(audit_dir.glob("*.jsonl"))
    return path, [json.loads(line) for line in path.read_text().splitlines()]


def test_an_unsigned_prefix_verifies_when_signing_began_later(tmp_path):
    from unified_enforce import Signer
    from unified_enforce.audit import HashChainWriter

    signer = Signer.generate("hub")
    audit_dir = tmp_path / "audit"
    _write(audit_dir, [1, 2, 3, 4, 5], signer, sign_from=4)

    _, entries = _lines(audit_dir)
    assert [("sig" in e) for e in entries] == [False, False, False, True, True]

    # Without a start point the old rule stands: every entry must be signed.
    assert not HashChainWriter.verify(audit_dir, public_key=signer.public_bytes()).ok
    result = HashChainWriter.verify(audit_dir, public_key=signer.public_bytes(), signed_from_seq=4)
    assert result.ok and result.entries == 5


def test_a_stripped_signature_after_the_start_point_fails(tmp_path):
    """The downgrade: remove the signature from an entry that had one. Its
    hash still verifies (sig and key_id sit outside it), so only the start
    point can say this entry was owed a signature."""
    from unified_enforce import Signer
    from unified_enforce.audit import HashChainWriter

    signer = Signer.generate("hub")
    audit_dir = tmp_path / "audit"
    _write(audit_dir, [1, 2, 3, 4, 5], signer, sign_from=3)

    path, entries = _lines(audit_dir)
    entries[3].pop("sig"), entries[3].pop("key_id")
    path.write_text("".join(json.dumps(e, sort_keys=True) + "\n" for e in entries))

    assert HashChainWriter.verify(audit_dir).ok, "the hash chain alone cannot see it"
    result = HashChainWriter.verify(audit_dir, public_key=signer.public_bytes(), signed_from_seq=3)
    assert not result.ok
    assert "unsigned" in result.error and ":4:" in result.error


def test_rewriting_the_unsigned_prefix_is_caught_by_the_first_signature(tmp_path):
    """The prefix carries no signatures of its own and is still protected:
    the first signed entry's hash covers its prev_hash, and so the prefix."""
    from unified_enforce import Signer, canonical_bytes, sha256_hex
    from unified_enforce.audit import HashChainWriter

    signer = Signer.generate("hub")
    audit_dir = tmp_path / "audit"
    _write(audit_dir, [1, 2, 3], signer, sign_from=3)

    path, entries = _lines(audit_dir)
    # Rewrite entry 1 properly, then re-link the chain forward as far as the
    # attacker can: entry 2 rehashes freely, entry 3's signature does not.
    prev = entries[0]["prev_hash"]
    for e in entries:
        e.pop("hash")
        sig = e.pop("sig", None), e.pop("key_id", None)
        if e["seq"] == 1:
            e["phase"] = "forged"
        e["prev_hash"] = prev
        e["hash"] = prev = sha256_hex(canonical_bytes(e, strict=False))
        if sig[0] is not None:
            e["sig"], e["key_id"] = sig
    path.write_text("".join(json.dumps(e, sort_keys=True) + "\n" for e in entries))

    assert HashChainWriter.verify(audit_dir).ok, "a consistent rewrite passes the hash check"
    result = HashChainWriter.verify(audit_dir, public_key=signer.public_bytes(), signed_from_seq=3)
    assert not result.ok and "bad signature" in result.error


def test_renumbering_a_signed_entry_below_the_start_point_does_not_shed_its_signature(tmp_path):
    from unified_enforce import Signer, canonical_bytes, sha256_hex
    from unified_enforce.audit import HashChainWriter

    signer = Signer.generate("hub")
    audit_dir = tmp_path / "audit"
    _write(audit_dir, [1, 2, 3, 4], signer, sign_from=2)

    path, entries = _lines(audit_dir)
    last = entries[-1]
    last.pop("hash"), last.pop("sig"), last.pop("key_id")
    last["seq"] = 1  # "this one predates signing"
    last["hash"] = sha256_hex(canonical_bytes(last, strict=False))
    path.write_text("".join(json.dumps(e, sort_keys=True) + "\n" for e in entries))

    result = HashChainWriter.verify(audit_dir, public_key=signer.public_bytes(), signed_from_seq=2)
    assert not result.ok and "unsigned" in result.error


def test_a_missing_signed_tail_is_reported(tmp_path):
    """Signing was recorded from seq 4; the chain now ends at 3. That is the
    one shape in which the unsigned prefix would be rewritable undetected."""
    from unified_enforce import Signer
    from unified_enforce.audit import HashChainWriter

    signer = Signer.generate("hub")
    audit_dir = tmp_path / "audit"
    _write(audit_dir, [1, 2, 3])

    result = HashChainWriter.verify(audit_dir, public_key=signer.public_bytes(), signed_from_seq=4)
    assert not result.ok and "no entry at or after" in result.error


def test_signed_from_seq_without_a_key_is_a_usage_error(tmp_path):
    from unified_enforce.audit import HashChainWriter

    with pytest.raises(ValueError):
        HashChainWriter.verify(tmp_path, signed_from_seq=1)
