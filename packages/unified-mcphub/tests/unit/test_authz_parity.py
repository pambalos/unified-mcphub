"""Differential parity: engine-backed AuthzResolver vs the frozen legacy resolver.

policy.v2.md's verification contract: the legacy implementation below is the
pre-migration authz.py, frozen verbatim as the reference semantics. The adapter
must produce bit-identical (effect, rule, audit_level, source) across the
hub's rule space — structured corpus plus seeded-random configs × calls.

Excluded by design (intentional divergences, policy.v2.md): unknown args
operators and invalid regexes (engine rejects at load; the adapter drops the
former as dead rules), and bare `*` tool patterns (dead in the hub, dropped).
Dead-rule dropping itself IS covered: dead rules appear in the corpus and both
sides must agree they never fire.
"""

from __future__ import annotations

import itertools
import random
import re
from dataclasses import dataclass
from typing import Any

from unified_mcphub.authz import AuthzResolver, Decision, Effect
from unified_mcphub.config import Authz, DangerousCommands, Rule, Workspace

# --- frozen legacy resolver (pre-migration authz.py, verbatim) -----------------


def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    out = []
    for ch in pattern:
        out.append("[^/]*" if ch == "*" else re.escape(ch))
    return re.compile("^" + "".join(out) + "$")


def _uri_matches(pattern: str, uri: str) -> bool:
    return _glob_to_regex(pattern).fullmatch(uri) is not None


def _has_wildcard(pattern: str) -> bool:
    return "*" in pattern


def _operator_matches(op: str, values: list[str], actual: str) -> bool:
    if op == "equals":
        return actual.lower() in {v.lower() for v in values}
    if op == "starts_with":
        return any(actual.startswith(v) for v in values)
    if op == "matches":
        return any(re.search(v, actual) for v in values)
    return False


def _args_filter_matches(
    args_filter: dict[str, dict[str, list[str]]], args: dict[str, Any]
) -> bool:
    for arg_name, operators in args_filter.items():
        actual = str(args.get(arg_name, ""))
        for op, values in operators.items():
            if not _operator_matches(op, values, actual):
                return False
    return True


def _rule_matches(rule: Rule, uri: str, args: dict[str, Any], caller: str) -> bool:
    if not _uri_matches(rule.tool, uri):
        return False
    if rule.callers is not None and caller not in rule.callers:
        return False
    if rule.args_filter and not _args_filter_matches(rule.args_filter, args):
        return False
    return True


def _danger_matches(pattern: str, uri: str, args: dict[str, Any]) -> bool:
    scheme, sep_scheme, rest = pattern.partition("://")
    if not sep_scheme:
        return _uri_matches(pattern, uri)
    uri_tail, sep_arg, arg_part = rest.partition(":")
    uri_pattern = f"{scheme}://{uri_tail}"
    if not _uri_matches(uri_pattern, uri):
        return False
    if not sep_arg:
        return True
    return str(args.get("command", "")).startswith(arg_part.rstrip("*"))


@dataclass
class LegacyDecision:
    effect: Effect
    rule: str | None
    audit_level: str = "standard"
    source: str = "default"


class LegacyResolver:
    def __init__(self, workspace: Workspace, dangerous: DangerousCommands) -> None:
        self._rules = workspace.authz.rules
        self._danger = dangerous.require_approval

    def resolve(self, tool_uri: str, args: dict[str, Any], caller: str) -> LegacyDecision:
        for rule in self._rules:
            if not _has_wildcard(rule.tool) and _rule_matches(rule, tool_uri, args, caller):
                return LegacyDecision(Effect(rule.effect), rule.tool, rule.audit_level, "exact")
        for pattern in self._danger:
            if _danger_matches(pattern, tool_uri, args):
                return LegacyDecision(Effect.PROMPT, pattern, "standard", "danger_floor")
        for rule in self._rules:
            if _has_wildcard(rule.tool) and _rule_matches(rule, tool_uri, args, caller):
                return LegacyDecision(Effect(rule.effect), rule.tool, rule.audit_level, "wildcard")
        return LegacyDecision(Effect.DENY, None, "standard", "default")


# --- corpus --------------------------------------------------------------------

TOOL_PATTERNS = [
    "mcp://shell/execute_command",
    "mcp://fs/read_file",
    "mcp://fs/*",
    "mcp://*/read_file",
    "mcp://*/*",
    "mcp://fs/li*",
    "mcp://built-in/ping",
    "mcp://**/read_file",  # `**` ≡ `*` under hub globs — collapse must preserve this
    "*",  # dead in the hub; adapter drops it — both sides must agree it never fires
    "sdk://payments/refund",
]
CALLERS = ["claude-code", "opencode", "cursor"]
DANGER_PATTERNS = [
    "mcp://shell/execute_command:rm *",
    "mcp://shell/execute_command:sudo *",
    "mcp://shell/execute_command:",  # empty prefix -> matches any command value
    "mcp://*/delete_file",
    "mcp://fs/write_file",
    "*",  # dead in the hub; adapter drops
]
ARG_VALUES: dict[str, list[Any]] = {
    "command": ["rm -rf /", "rm /tmp/x", "sudo reboot", "ls -la", "RM -RF /", ""],
    "path": ["/tmp/x", "/DATA/reports/q3.csv", "reports/z", "/etc/passwd"],
    "recursive": [True, False, "true", "True"],
    "count": [0, 1, 42],
}
ARGS_FILTERS: list[dict[str, dict[str, list[str]]] | None] = [
    None,
    {"command": {"starts_with": ["rm ", "sudo "]}},
    {"command": {"equals": ["ls -la", "RM -RF /"]}},
    {"path": {"matches": ["(?i)^/data/", "reports?/"]}},
    {"recursive": {"equals": ["true"]}},
    {"count": {"equals": ["42"]}},
    {"command": {"starts_with": ["rm"]}, "path": {"matches": ["^/tmp/"]}},
    {"path": {"starts_with": ["/tmp"], "matches": ["x$"]}},  # two ops on one arg AND
]
URIS = [
    "mcp://shell/execute_command",
    "mcp://fs/read_file",
    "mcp://fs/write_file",
    "mcp://fs/list_files",
    "mcp://fs/delete_file",
    "mcp://github/read_file",
    "mcp://built-in/ping",
    "sdk://payments/refund",
    "mcp://a/b/c",  # 3-segment: exercises the `/`-crossing edge
]


def _random_rule(rng: random.Random) -> Rule:
    callers: list[str] | None = None
    if rng.random() < 0.4:
        callers = rng.sample(CALLERS, rng.randint(0, len(CALLERS)))  # may be [] (dead)
    return Rule(
        tool=rng.choice(TOOL_PATTERNS),
        callers=callers,
        args_filter=rng.choice(ARGS_FILTERS),
        effect=rng.choice(["allow", "deny", "prompt"]),
        audit_level=rng.choice(["minimal", "standard", "detailed", "full"]),
    )


def _random_call(rng: random.Random) -> tuple[str, dict[str, Any], str]:
    args = {
        name: rng.choice(values)
        for name, values in ARG_VALUES.items()
        if rng.random() < 0.6  # missing-arg paths matter as much as present ones
    }
    return rng.choice(URIS), args, rng.choice(CALLERS)


def _assert_parity(rules: list[Rule], danger: list[str], calls) -> None:
    ws = Workspace(authz=Authz(rules=rules))
    dc = DangerousCommands(require_approval=danger)
    legacy = LegacyResolver(ws, dc)
    engine = AuthzResolver(ws, dc)
    for uri, args, caller in calls:
        expected = legacy.resolve(uri, args, caller)
        actual: Decision = engine.resolve(uri, args, caller)
        got = (actual.effect, actual.rule, actual.audit_level, actual.source)
        want = (expected.effect, expected.rule, expected.audit_level, expected.source)
        assert got == want, (
            f"parity break: uri={uri!r} args={args!r} caller={caller!r}\n"
            f"  rules={[r.model_dump(exclude_none=True) for r in rules]}\n"
            f"  danger={danger}\n  legacy={want}\n  engine={got}"
        )


def test_parity_structured_corpus():
    """Every pattern × every URI × every caller, no randomness: one rule at a
    time so each construct is exercised in isolation, plus the full floor set."""
    calls = list(itertools.product(URIS, [{}, {"command": "rm -rf /", "path": "/tmp/x"}], CALLERS))
    for tool in TOOL_PATTERNS:
        for args_filter in ARGS_FILTERS:
            rules = [Rule(tool=tool, args_filter=args_filter, effect="allow")]
            _assert_parity(rules, DANGER_PATTERNS, calls)


def test_parity_randomized_configs():
    rng = random.Random(0xE1E2)
    for _ in range(150):
        rules = [_random_rule(rng) for _ in range(rng.randint(0, 6))]
        danger = rng.sample(DANGER_PATTERNS, rng.randint(0, len(DANGER_PATTERNS)))
        calls = [_random_call(rng) for _ in range(25)]
        _assert_parity(rules, danger, calls)


def test_parity_precedence_stack():
    """All four tiers live at once: exact allow overriding a floor, floor over
    wildcard allow, wildcard prompt, default deny."""
    rules = [
        Rule(
            tool="mcp://shell/execute_command",
            effect="allow",
            args_filter={"command": {"starts_with": ["rm /tmp/"]}},
        ),
        Rule(tool="mcp://shell/*", effect="allow"),
        Rule(tool="mcp://fs/*", effect="prompt", callers=["claude-code"]),
    ]
    danger = ["mcp://shell/execute_command:rm *"]
    calls = [
        ("mcp://shell/execute_command", {"command": "rm /tmp/x"}, "claude-code"),  # exact
        ("mcp://shell/execute_command", {"command": "rm -rf /"}, "claude-code"),  # floor
        ("mcp://shell/execute_command", {"command": "ls"}, "claude-code"),  # wildcard
        ("mcp://fs/read_file", {}, "claude-code"),  # caller-scoped prompt
        ("mcp://fs/read_file", {}, "cursor"),  # caller miss -> default deny
    ]
    _assert_parity(rules, danger, calls)
