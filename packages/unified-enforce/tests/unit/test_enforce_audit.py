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
