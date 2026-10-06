import pytest

from unified_enforce import Action, PolicyEngine, PolicyError, Principal, Verdict

POLICY = """
version: 1
rules:
  - id: freeze-prod-db
    match:
      tool: "mcp://postgres/query"
      resource: "db:prod/**"
    effect: deny
    reason: "prod is frozen"

  - id: small-refunds-ok
    match:
      tool: "sdk://payments/refund"
    when: 'int(params.amount_cents) <= 5000'
    effect: allow

  - id: big-refunds-need-human
    match:
      tool: "sdk://payments/refund"
    effect: defer

  - id: github-read-all
    match:
      principal: "agent:*"
      tool: "mcp://github/*"
      verb: "read"
    effect: allow
    audit_level: minimal
"""


def act(
    tool="mcp://github/list_prs",
    verb="read",
    resource="*",
    params=None,
    principal="agent:claude-code",
):
    return Action.build(
        principal=Principal(id=principal),
        tool=tool,
        verb=verb,
        resource=resource,
        params=params or {},
    )


@pytest.fixture(scope="module")
def engine():
    return PolicyEngine.from_yaml(POLICY)


def test_default_deny_when_nothing_matches(engine):
    d = engine.decide(act(tool="mcp://slack/post_message", verb="call"))
    assert d.verdict is Verdict.DENY
    assert d.rule_id is None
    assert d.source == "default"


def test_wildcard_allow(engine):
    d = engine.decide(act())
    assert d.verdict is Verdict.ALLOW
    assert d.rule_id == "github-read-all"
    assert d.source == "wildcard"
    assert d.audit_level == "minimal"


def test_wildcard_does_not_cross_verbs(engine):
    d = engine.decide(act(verb="write"))
    assert d.verdict is Verdict.DENY
    assert d.source == "default"


def test_exact_rule_beats_wildcard_order():
    # An exact rule later in the file still outranks an earlier wildcard allow.
    engine = PolicyEngine.from_yaml("""
version: 1
rules:
  - id: everything-goes
    match: {tool: "mcp://github/*"}
    effect: allow
  - id: except-deletes
    match: {tool: "mcp://github/delete_repo"}
    effect: deny
""")
    d = engine.decide(act(tool="mcp://github/delete_repo", verb="call"))
    assert d.verdict is Verdict.DENY
    assert d.source == "exact"


def test_cel_condition_true_allows(engine):
    d = engine.decide(
        act(tool="sdk://payments/refund", verb="call", params={"amount_cents": "4999"})
    )
    assert d.verdict is Verdict.ALLOW
    assert d.rule_id == "small-refunds-ok"


def test_cel_condition_false_falls_through_to_defer(engine):
    d = engine.decide(
        act(tool="sdk://payments/refund", verb="call", params={"amount_cents": "250000"})
    )
    assert d.verdict is Verdict.DEFER
    assert d.rule_id == "big-refunds-need-human"


def test_cel_error_fails_closed_to_deny(engine):
    # amount_cents missing → int(params.amount_cents) raises → DENY, not fall-through.
    d = engine.decide(act(tool="sdk://payments/refund", verb="call", params={}))
    assert d.verdict is Verdict.DENY
    assert d.source == "condition_error"
    assert d.rule_id == "small-refunds-ok"


def test_double_star_crosses_segments(engine):
    d = engine.decide(
        act(tool="mcp://postgres/query", verb="call", resource="db:prod/billing/invoices")
    )
    assert d.verdict is Verdict.DENY
    assert d.rule_id == "freeze-prod-db"


def test_single_star_does_not_cross_segments():
    engine = PolicyEngine.from_yaml("""
version: 1
rules:
  - id: one-level
    match: {tool: "mcp://github/*", resource: "db:prod/*"}
    effect: allow
""")
    assert engine.decide(act(resource="db:prod/billing/invoices", verb="call")).source == "default"


def test_bad_cel_is_a_load_error():
    with pytest.raises(PolicyError, match="bad CEL"):
        PolicyEngine.from_yaml("""
version: 1
rules:
  - id: broken
    match: {tool: "mcp://x/y"}
    when: 'params.amount <== 5'
    effect: allow
""")


def test_duplicate_rule_ids_rejected():
    with pytest.raises(PolicyError, match="duplicate rule id"):
        PolicyEngine.from_yaml("""
version: 1
rules:
  - {id: r1, match: {tool: "mcp://a/b"}, effect: allow}
  - {id: r1, match: {tool: "mcp://c/d"}, effect: deny}
""")


def test_unknown_effect_rejected():
    with pytest.raises(PolicyError):
        PolicyEngine.from_yaml("""
version: 1
rules:
  - {id: r1, match: {tool: "mcp://a/b"}, effect: maybe}
""")


def test_decision_is_fast(engine):
    import time

    a = act(tool="sdk://payments/refund", verb="call", params={"amount_cents": "100"})
    engine.decide(a)  # warm
    start = time.perf_counter()
    for _ in range(100):
        engine.decide(a)
    per_call_ms = (time.perf_counter() - start) * 1000 / 100
    assert per_call_ms < 10, f"decision took {per_call_ms:.2f} ms (budget 10 ms)"


# --- policy_digest: which policy decided ---

DIGEST_POLICY = """
version: 1
rules:
  - id: reads
    match: {tool: "mcp://files/read"}
    effect: allow
"""


def test_every_policy_verdict_carries_the_digest_of_its_policy():
    engine = PolicyEngine.from_yaml(DIGEST_POLICY)
    allowed = engine.decide(_digest_action("mcp://files/read"))
    defaulted = engine.decide(_digest_action("mcp://files/write"))
    assert len(engine.policy_digest) == 64
    assert allowed.policy_digest == engine.policy_digest
    assert defaulted.policy_digest == engine.policy_digest, (
        "default-deny is still this policy's verdict"
    )


def test_the_digest_ignores_formatting_but_not_rules():
    """An auditor hashes the policy under review and compares: reformatting the
    YAML must not change the answer, and changing what a rule does must."""
    reformatted = PolicyEngine.from_yaml(
        "# same policy, different file\nrules:\n- effect: allow\n  id: reads\n"
        "  match: {tool: 'mcp://files/read'}\nversion: 1\n"
    )
    changed = PolicyEngine.from_yaml(DIGEST_POLICY.replace("effect: allow", "effect: deny"))
    original = PolicyEngine.from_yaml(DIGEST_POLICY)
    assert reformatted.policy_digest == original.policy_digest
    assert changed.policy_digest != original.policy_digest


def _digest_action(tool: str) -> Action:
    return Action.build(principal=Principal(id="agent:a"), tool=tool, verb="call", resource="*")
