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
