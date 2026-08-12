"""E2: capture levels, SQLite read index, offline replay."""

import pytest

from unified_enforce import (
    Action,
    AuditChain,
    AuditIndex,
    PolicyEngine,
    Principal,
    replay,
)
from unified_enforce.redaction import capture_action, scrub

POLICY = """
version: 1
rules:
  - {id: reads-ok, match: {tool: "mcp://github/*", verb: read}, effect: allow}
  - id: secret-tool
    match: {tool: "mcp://vault/read_secret"}
    effect: allow
    audit_level: minimal
  - id: refunds-capped
    match: {tool: "sdk://payments/refund"}
    when: 'int(params.amount_cents) <= 5000'
    effect: allow
  - {id: refunds-defer, match: {tool: "sdk://payments/refund"}, effect: defer}
"""


def act(tool="mcp://github/list_prs", verb="read", params=None):
    return Action.build(
        principal=Principal(id="agent:x"),
        tool=tool,
        verb=verb,
        resource="*",
        params=params or {},
    )


@pytest.fixture
def engine():
    return PolicyEngine.from_yaml(POLICY)


@pytest.fixture
def audit_dir(tmp_path, engine):
    """A populated chain: 2 allows, 1 minimal-capture, 1 defer, 1 default-deny."""
    d = tmp_path / "audit"
    chain = AuditChain(d)
    chain.start()
    for action in [
        act(),
        act(params={"token": "ghp_" + "a" * 24}),
        act(tool="mcp://vault/read_secret", verb="call", params={"path": "prod/db"}),
        act(tool="sdk://payments/refund", verb="call", params={"amount_cents": "990000"}),
        act(tool="mcp://slack/post", verb="call"),
    ]:
        chain.append_decision(action, engine.decide(action))
    chain.stop()
    return d


# --- redaction / capture levels ---


def test_scrub_hits_known_secret_shapes():
    scrubbed = scrub({"gh": "ghp_" + "a" * 24, "aws": "AKIA" + "A" * 16, "plain": "hello"})
    assert scrubbed["gh"] == "«redacted»"
    assert scrubbed["aws"] == "«redacted»"
    assert scrubbed["plain"] == "hello"


def test_minimal_capture_drops_params():
    dump = act(params={"path": "prod/db"}).model_dump(mode="json")
    stored, redacted = capture_action(dump, "minimal")
    assert redacted
    assert stored["params"] is None
    assert stored["context"]["extra"] is None
    assert stored["tool"] == dump["tool"]  # skeleton survives


def test_standard_capture_untouched_when_no_secrets():
    dump = act(params={"q": "hello"}).model_dump(mode="json")
    stored, redacted = capture_action(dump, "standard")
    assert not redacted
    assert stored == dump


def test_chain_stores_redacted_copy_but_full_digest(audit_dir):
    import json

    entries = [
        json.loads(line)
        for p in sorted(audit_dir.glob("*.jsonl"))
        for line in p.read_text().splitlines()
    ]
    secret_entry = next(
        e
        for e in entries
        if e["payload"]["action"]["tool"] == "mcp://github/list_prs" and e["payload"]["redacted"]
    )
    assert secret_entry["payload"]["action"]["params"]["token"] == "«redacted»"
    minimal_entry = next(e for e in entries if e["payload"]["audit_level"] == "minimal")
    assert minimal_entry["payload"]["action"]["params"] is None
    assert len(minimal_entry["payload"]["action_digest"]) == 64  # full digest kept
    assert AuditChain.verify(audit_dir).ok  # chain covers the stored (redacted) copy


# --- SQLite index ---


def test_index_refresh_and_query(audit_dir, tmp_path):
    with AuditIndex(tmp_path / "index.db") as idx:
        assert idx.refresh(audit_dir) == 5
        denies = idx.query(verdict="deny")
        assert len(denies) == 1 and denies[0]["tool"] == "mcp://slack/post"
        assert len(idx.query(principal="agent:x")) == 5
        assert idx.query(rule_id="refunds-defer")[0]["verdict"] == "defer"
        assert idx.locate(1) is not None


def test_index_refresh_is_incremental(audit_dir, tmp_path, engine):
    with AuditIndex(tmp_path / "index.db") as idx:
        assert idx.refresh(audit_dir) == 5
        assert idx.refresh(audit_dir) == 0  # nothing new
        chain = AuditChain(audit_dir)
        chain.start()
        a = act()
        chain.append_decision(a, engine.decide(a))
        chain.stop()
        assert idx.refresh(audit_dir) == 1


def test_index_rejects_unknown_filter(tmp_path):
    with AuditIndex(tmp_path / "index.db") as idx:
        with pytest.raises(ValueError, match="unknown filter"):
            idx.query(hash="abc")  # not queryable — chain is the source of truth


# --- replay ---


def test_replay_same_policy_is_clean_except_minimal(audit_dir, engine):
    report = replay(audit_dir, engine)
    assert report.total == 5
    assert report.skipped == 1  # the minimal-capture vault entry
    assert report.replayed == 4
    assert report.clean


def test_replay_candidate_policy_reports_divergences(audit_dir):
    tightened = PolicyEngine.from_yaml("""
version: 1
rules:
  - {id: reads-ok, match: {tool: "mcp://github/*", verb: read}, effect: allow}
""")
    report = replay(audit_dir, tightened)
    assert not report.clean
    diverged = {d.tool for d in report.divergences}
    assert "sdk://payments/refund" in diverged  # defer → default deny
    refund = next(d for d in report.divergences if d.tool == "sdk://payments/refund")
    assert refund.recorded_verdict == "defer"
    assert refund.replayed_verdict == "deny"
    assert refund.replayed_rule is None
