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


def _entries(audit_dir):
    import json

    return [
        json.loads(line)
        for p in sorted(audit_dir.glob("*.jsonl"))
        for line in p.read_text().splitlines()
    ]


def test_chain_stores_the_raw_action_whatever_the_audit_level(audit_dir):
    """audit_level no longer shapes what is written: it is the default view.
    The record holds exactly what the agent asked for, and the hash commits to
    it through a salted digest so an export can still withhold it."""
    entries = _entries(audit_dir)
    secret_entry = next(
        e for e in entries if e["payload"]["action"]["params"].get("token", "").startswith("ghp_")
    )
    assert secret_entry["payload"]["action"]["params"]["token"] == "ghp_" + "a" * 24
    assert secret_entry["payload"]["redacted"] is False
    assert secret_entry["payload"]["audit_level"] == "standard"  # the view, recorded
    minimal_entry = next(e for e in entries if e["payload"]["audit_level"] == "minimal")
    assert minimal_entry["payload"]["action"]["params"] == {"path": "prod/db"}
    assert set(minimal_entry["detached"]) == {
        "payload.action.params",
        "payload.action.context.extra",
    }
    assert len(minimal_entry["payload"]["action_digest"]) == 64  # full digest kept
    result = AuditChain.verify(audit_dir)
    assert result.ok and result.payloads_verified == 10 and result.payloads_withheld == 0


def test_capture_levels_still_shape_the_view(audit_dir):
    """What a reader is shown by default still follows the rule's level."""
    minimal_entry = next(e for e in _entries(audit_dir) if e["payload"]["audit_level"] == "minimal")
    shown, hidden = capture_action(minimal_entry["payload"]["action"], "minimal")
    assert hidden and shown["params"] is None


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


def test_replay_same_policy_is_clean_including_minimal(audit_dir, engine):
    """Recorded raw, a `minimal` rule's decision replays like any other — it
    used to be skipped because its params were never kept."""
    report = replay(audit_dir, engine)
    assert report.total == 5
    assert report.skipped == 0
    assert report.replayed == 5
    assert report.clean


def test_replay_reads_the_params_it_recorded(audit_dir):
    """A condition on params is re-evaluated against the recorded value: the
    990000-cent refund is over the cap whatever policy replays it."""
    raised = PolicyEngine.from_yaml(POLICY.replace("<= 5000", "<= 1000000"))
    report = replay(audit_dir, raised)
    refund = next(d for d in report.divergences if d.tool == "sdk://payments/refund")
    assert refund.recorded_rule == "refunds-defer"
    assert refund.replayed_rule == "refunds-capped"


def test_replay_skips_withheld_params_rather_than_reading_them_as_empty(audit_dir, engine):
    """A digests-only excerpt has no params. Replaying it as `params: {}` would
    turn "we don't know" into a confident verdict — so it is counted instead."""
    import json

    from unified_enforce import detach

    for path in audit_dir.glob("*.jsonl"):
        lines = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
        path.write_text("".join(json.dumps(detach.redact(e)) + "\n" for e in lines))
    assert AuditChain.verify(audit_dir).ok, "redaction must not break the chain"
    report = replay(audit_dir, engine)
    assert report.total == 5
    assert report.skipped == report.withheld == 5
    assert report.replayed == 0


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
