"""Unit tests for the authz resolver — spec §4, ADR-0006 (covers SEC-MCP-1 logic)."""

from __future__ import annotations

from unified_mcphub.authz import AuthzResolver, Effect
from unified_mcphub.config import Authz, DangerousCommands, Rule, Workspace


def mk(rules=None, danger=None) -> AuthzResolver:
    ws = Workspace(authz=Authz(rules=rules or []))
    return AuthzResolver(ws, DangerousCommands(require_approval=danger or []))


def test_default_deny_with_no_rules():
    d = mk().resolve("mcp://github/create_issue", {}, "claude-code")
    assert d.effect is Effect.DENY
    assert d.source == "default"
    assert d.rule is None


def test_wildcard_allow_and_miss():
    r = mk([Rule(tool="mcp://*/list_*", effect="allow")])
    assert r.resolve("mcp://fs/list_files", {}, "x").effect is Effect.ALLOW
    assert r.resolve("mcp://fs/read_file", {}, "x").effect is Effect.DENY  # unmatched -> deny


def test_exact_rule_beats_danger_floor():
    # explicit per-op allow overrides the safety floor for that one op (precedence 1).
    r = mk([Rule(tool="mcp://shell/exec", effect="allow")], danger=["mcp://shell/exec"])
    d = r.resolve("mcp://shell/exec", {"command": "ls"}, "x")
    assert d.effect is Effect.ALLOW
    assert d.source == "exact"


def test_danger_floor_forces_prompt_over_wildcard_allow():
    r = mk([Rule(tool="mcp://*/*", effect="allow")], danger=["mcp://*/delete_*"])
    dangerous = r.resolve("mcp://db/delete_table", {}, "x")
    assert dangerous.effect is Effect.PROMPT
    assert dangerous.source == "danger_floor"
    # a non-dangerous op falls through to the catch-all allow
    assert r.resolve("mcp://db/list_rows", {}, "x").effect is Effect.ALLOW


def test_danger_floor_arg_prefix():
    r = mk([Rule(tool="mcp://*/*", effect="allow")], danger=["mcp://shell/exec:rm -rf*"])
    assert r.resolve("mcp://shell/exec", {"command": "rm -rf /"}, "x").effect is Effect.PROMPT
    assert r.resolve("mcp://shell/exec", {"command": "ls -la"}, "x").effect is Effect.ALLOW


def test_caller_scoping():
    r = mk([Rule(tool="mcp://gh/create", callers=["claude-code"], effect="allow")])
    assert r.resolve("mcp://gh/create", {}, "claude-code").effect is Effect.ALLOW
    assert r.resolve("mcp://gh/create", {}, "opencode").effect is Effect.DENY  # caller miss


def test_args_filter_starts_with_ors_values():
    r = mk(
        [
            Rule(
                tool="mcp://shell/exec",
                args_filter={"command": {"starts_with": ["git ", "pytest "]}},
                effect="allow",
            )
        ]
    )
    # value list ORs: either prefix matches
    assert r.resolve("mcp://shell/exec", {"command": "git status"}, "x").effect is Effect.ALLOW
    assert r.resolve("mcp://shell/exec", {"command": "pytest -q"}, "x").effect is Effect.ALLOW
    assert r.resolve("mcp://shell/exec", {"command": "rm x"}, "x").effect is Effect.DENY


def test_first_wildcard_match_wins():
    r = mk([Rule(tool="mcp://*/secret", effect="deny"), Rule(tool="mcp://*/*", effect="allow")])
    assert r.resolve("mcp://s/secret", {}, "u").effect is Effect.DENY
    assert r.resolve("mcp://s/other", {}, "u").effect is Effect.ALLOW


def test_deny_rule_is_explicit():
    r = mk([Rule(tool="mcp://*/*", effect="deny")])
    d = r.resolve("mcp://x/y", {}, "u")
    assert d.effect is Effect.DENY
    assert d.source == "wildcard"  # explicit deny, not the implicit default


def test_audit_level_propagates():
    r = mk([Rule(tool="mcp://*/x", effect="allow", audit_level="detailed")])
    assert r.resolve("mcp://s/x", {}, "u").audit_level == "detailed"


def test_args_filter_matches_regex():
    r = mk(
        [
            Rule(
                tool="mcp://shell/exec",
                args_filter={"command": {"matches": [r"^git (status|log)$"]}},
                effect="allow",
            )
        ]
    )
    assert r.resolve("mcp://shell/exec", {"command": "git status"}, "x").effect is Effect.ALLOW
    assert r.resolve("mcp://shell/exec", {"command": "git push"}, "x").effect is Effect.DENY


def test_args_filter_matches_arbitrary_arg():
    # The new matcher can gate on ANY arg name, not just command/path/repo.
    r = mk(
        [
            Rule(
                tool="mcp://fetch/get",
                args_filter={"url": {"matches": [r"\.internal\.corp"]}},
                effect="allow",
            )
        ]
    )
    assert (
        r.resolve("mcp://fetch/get", {"url": "https://x.internal.corp/y"}, "u").effect
        is Effect.ALLOW
    )
    assert r.resolve("mcp://fetch/get", {"url": "https://evil.com"}, "u").effect is Effect.DENY


def test_args_filter_equals_is_case_insensitive_and_bool_friendly():
    # equals matches whether the harness sends JSON true (Python bool) or "true"/"True".
    r = mk(
        [
            Rule(
                tool="mcp://fetch/get",
                args_filter={"allow_blocked": {"equals": ["true"]}},
                effect="prompt",
            )
        ]
    )
    assert r.resolve("mcp://fetch/get", {"allow_blocked": True}, "u").effect is Effect.PROMPT
    assert r.resolve("mcp://fetch/get", {"allow_blocked": "true"}, "u").effect is Effect.PROMPT
    # absent / false -> rule doesn't apply -> default-deny
    assert r.resolve("mcp://fetch/get", {}, "u").effect is Effect.DENY
    assert r.resolve("mcp://fetch/get", {"allow_blocked": False}, "u").effect is Effect.DENY


def test_args_filter_arg_names_and_together():
    r = mk(
        [
            Rule(
                tool="mcp://shell/exec",
                args_filter={
                    "command": {"starts_with": ["git "]},
                    "path": {"matches": ["^/repo/"]},
                },
                effect="allow",
            )
        ]
    )
    assert (
        r.resolve("mcp://shell/exec", {"command": "git x", "path": "/repo/a"}, "u").effect
        is Effect.ALLOW
    )
    # one condition fails -> whole filter fails (AND)
    assert (
        r.resolve("mcp://shell/exec", {"command": "git x", "path": "/tmp/a"}, "u").effect
        is Effect.DENY
    )


def test_args_filter_operators_on_one_arg_and_together():
    r = mk(
        [
            Rule(
                tool="mcp://fetch/get",
                args_filter={"url": {"starts_with": ["https://"], "matches": [r"\.corp"]}},
                effect="allow",
            )
        ]
    )
    assert r.resolve("mcp://fetch/get", {"url": "https://x.corp"}, "u").effect is Effect.ALLOW
    assert (
        r.resolve("mcp://fetch/get", {"url": "http://x.corp"}, "u").effect is Effect.DENY
    )  # scheme fails


def test_args_filter_unknown_operator_fails_closed():
    r = mk([Rule(tool="mcp://x/y", args_filter={"arg": {"bogus": ["v"]}}, effect="allow")])
    assert r.resolve("mcp://x/y", {"arg": "v"}, "x").effect is Effect.DENY


def test_danger_floor_non_scheme_pattern_is_glob():
    # A floor pattern without "://" is treated as a plain whole-URI glob (defensive path).
    r = mk([Rule(tool="mcp://*/*", effect="allow")], danger=["no-scheme-pattern"])
    assert r.resolve("mcp://x/y", {}, "u").effect is Effect.ALLOW  # doesn't match -> not floored
