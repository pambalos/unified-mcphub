"""Policy v0.2 (specs/enforce/policy.v2.md): principal lists, args matchers, floors."""

import pytest

from unified_enforce import Action, PolicyEngine, PolicyError, Principal, Verdict

POLICY = """
version: 1
floors:
  - id: floor-shell-rm
    match:
      tool: "mcp://shell/execute_command"
      args: {command: {starts_with: ["rm ", "sudo "]}}
    reason: "destructive shell commands need a human"
  - id: floor-secrets
    match: {tool: "mcp://*/read_secret"}
rules:
  - id: shell-rm-tmp-ok
    match:
      tool: "mcp://shell/execute_command"
      args: {command: {starts_with: ["rm /tmp/"]}}
    effect: allow
  - id: crew-only-fs
    match:
      principal: ["agent:crew-1", "agent:crew-2"]
      tool: "mcp://fs/*"
    effect: allow
  - id: env-guard
    match:
      tool: "mcp://deploy/*"
      args: {env: {equals: ["staging", "dev"]}, dry_run: {equals: ["true"]}}
    effect: allow
  - id: path-regex
    match:
      tool: "mcp://fs2/read"
      args: {path: {matches: ["(?i)^/data/", "reports?/"]}}
    effect: allow
  - id: shell-anything
    match: {tool: "mcp://shell/*"}
    effect: allow
"""


def act(tool, verb="call", params=None, principal="agent:crew-1"):
    return Action.build(
        principal=Principal(id=principal),
        tool=tool,
        verb=verb,
        resource="*",
        params=params or {},
    )


@pytest.fixture(scope="module")
def engine():
    return PolicyEngine.from_yaml(POLICY)


# --- floors tier ---


def test_floor_forces_defer_over_wildcard_allow(engine):
    # shell-anything (wildcard allow) matches, but the floor outranks it.
    d = engine.decide(act("mcp://shell/execute_command", params={"command": "rm -rf /data"}))
    assert d.verdict is Verdict.DEFER
    assert d.rule_id == "floor-shell-rm"
    assert d.source == "floor"
    assert d.reason == "destructive shell commands need a human"


def test_exact_rule_overrides_floor(engine):
    d = engine.decide(act("mcp://shell/execute_command", params={"command": "rm /tmp/x"}))
    assert d.verdict is Verdict.ALLOW
    assert d.rule_id == "shell-rm-tmp-ok"
    assert d.source == "exact"


def test_floor_arg_prefix_scopes_the_floor(engine):
    # Non-destructive command: floor doesn't match; wildcard allow applies.
    d = engine.decide(act("mcp://shell/execute_command", params={"command": "ls -la"}))
    assert d.verdict is Verdict.ALLOW
    assert d.rule_id == "shell-anything"
    assert d.source == "wildcard"


def test_floor_without_args_matches_by_tool(engine):
    d = engine.decide(act("mcp://vault/read_secret", params={"path": "prod"}))
    assert d.verdict is Verdict.DEFER
    assert d.rule_id == "floor-secrets"


# --- principal lists ---


def test_principal_list_is_or(engine):
    assert engine.decide(act("mcp://fs/read", principal="agent:crew-2")).verdict is Verdict.ALLOW
    assert engine.decide(act("mcp://fs/read", principal="agent:other")).source == "default"


# --- args operators (ADR-0006 semantics) ---


def test_equals_is_case_insensitive_and_bool_friendly(engine):
    # Python str(True) == "True"; equals is case-insensitive so "true" matches.
    d = engine.decide(act("mcp://deploy/push", params={"env": "STAGING", "dry_run": True}))
    assert d.verdict is Verdict.ALLOW and d.rule_id == "env-guard"


def test_args_and_across_arg_names(engine):
    # env matches but dry_run is False -> str "False" != "true" -> no match -> default deny.
    d = engine.decide(act("mcp://deploy/push", params={"env": "staging", "dry_run": False}))
    assert d.source == "default"


def test_missing_arg_compares_as_empty_string(engine):
    d = engine.decide(act("mcp://deploy/push", params={"env": "staging"}))
    assert d.source == "default"  # dry_run missing -> "" != "true"


def test_matches_is_search_not_fullmatch(engine):
    # "reports?/" matches anywhere in the string (re.search semantics).
    d = engine.decide(act("mcp://fs2/read", params={"path": "/srv/reports/q3.csv"}))
    assert d.verdict is Verdict.ALLOW and d.rule_id == "path-regex"
    d = engine.decide(act("mcp://fs2/read", params={"path": "/DATA/x"}))
    assert d.verdict is Verdict.ALLOW  # (?i) case-insensitive


def test_starts_with_is_case_sensitive(engine):
    d = engine.decide(act("mcp://shell/execute_command", params={"command": "RM -rf /"}))
    # "RM" doesn't hit the floor prefix (case-sensitive), falls to wildcard allow.
    assert d.rule_id == "shell-anything"


# --- load-time strictness ---


def test_unknown_operator_is_a_load_error():
    with pytest.raises(PolicyError, match="unknown args operator"):
        PolicyEngine.from_yaml("""
version: 1
rules:
  - id: r1
    match: {tool: "mcp://a/b", args: {x: {globby: ["*"]}}}
    effect: allow
""")


def test_bad_regex_is_a_load_error():
    with pytest.raises(PolicyError, match="bad regex"):
        PolicyEngine.from_yaml("""
version: 1
rules:
  - id: r1
    match: {tool: "mcp://a/b", args: {x: {matches: ["([unclosed"]}}}
    effect: allow
""")


def test_floor_ids_share_the_rule_id_namespace():
    with pytest.raises(PolicyError, match="duplicate rule id"):
        PolicyEngine.from_yaml("""
version: 1
floors:
  - {id: r1, match: {tool: "mcp://a/b"}}
rules:
  - {id: r1, match: {tool: "mcp://c/d"}, effect: allow}
""")


def test_empty_principal_list_rejected():
    with pytest.raises(PolicyError, match="empty principal list"):
        PolicyEngine.from_yaml("""
version: 1
rules:
  - {id: r1, match: {principal: [], tool: "mcp://a/b"}, effect: allow}
""")
