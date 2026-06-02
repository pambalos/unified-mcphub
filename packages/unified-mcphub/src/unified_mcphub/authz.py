"""Authorization policy resolver — spec §4, ADR-0006.

Three states per tool: allow / deny / prompt.

Precedence (highest to lowest):
  1. explicit exact-tool rule in the active workspace (no wildcard, matches URI)
  2. dangerous-commands.yaml floor match  -> prompt
  3. workspace wildcard rules (first-match-wins)
  4. implicit default-deny (NOT configurable)

Tool URIs: mcp://<server>/<tool>, mcp://built-in/<tool>, sdk://..., agent://...
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any

from .config import DangerousCommands, Rule, Workspace


class Effect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    PROMPT = "prompt"


@dataclass
class Decision:
    effect: Effect
    rule: str | None          # the matching rule's `tool` pattern (audit `authz_rule`)
    audit_level: str = "standard"
    source: str = "default"   # exact | danger_floor | wildcard | default


def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    """`*` matches any run of chars except `/` (URIs are server/tool, 2-segment)."""
    out = []
    for ch in pattern:
        out.append("[^/]*" if ch == "*" else re.escape(ch))
    return re.compile("^" + "".join(out) + "$")


def _uri_matches(pattern: str, uri: str) -> bool:
    return _glob_to_regex(pattern).fullmatch(uri) is not None


def _has_wildcard(pattern: str) -> bool:
    return "*" in pattern


def _operator_matches(op: str, values: list[str], actual: str) -> bool:
    """One operator clause against a stringified arg value (ADR-0006).

    Value list is OR'd. Unknown operator → False (fail closed, never an accidental allow).
    """
    if op == "equals":  # case-insensitive (JSON true / "true" both match)
        return actual.lower() in {v.lower() for v in values}
    if op == "starts_with":  # case-sensitive prefix
        return any(actual.startswith(v) for v in values)
    if op == "matches":  # regex search ((?i) for case-insensitivity)
        return any(re.search(v, actual) for v in values)
    return False


def _args_filter_matches(args_filter: dict[str, dict[str, list[str]]], args: dict[str, Any]) -> bool:
    """Per-argument operator map (ADR-0006). Arg names AND'd; operators per arg AND'd.

    A missing argument compares as "" (so it won't match a non-empty target).
    """
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
    """Floor patterns are `mcp://srv/tool` or `mcp://srv/tool:<command-prefix>*`.

    Split on the `:` that follows the scheme's `://`, never the scheme colon.
    """
    scheme, sep_scheme, rest = pattern.partition("://")
    if not sep_scheme:
        return _uri_matches(pattern, uri)  # not a scheme URI; treat whole pattern as a glob
    uri_tail, sep_arg, arg_part = rest.partition(":")
    uri_pattern = f"{scheme}://{uri_tail}"
    if not _uri_matches(uri_pattern, uri):
        return False
    if not sep_arg:
        return True
    return str(args.get("command", "")).startswith(arg_part.rstrip("*"))


class AuthzResolver:
    def __init__(self, workspace: Workspace, dangerous: DangerousCommands) -> None:
        self._rules = workspace.authz.rules
        self._danger = dangerous.require_approval

    def resolve(self, tool_uri: str, args: dict[str, Any], caller: str) -> Decision:
        # 1. explicit exact-tool rule (no wildcard) — wins, overrides the floor.
        for rule in self._rules:
            if not _has_wildcard(rule.tool) and _rule_matches(rule, tool_uri, args, caller):
                return Decision(Effect(rule.effect), rule.tool, rule.audit_level, "exact")

        # 2. dangerous-commands floor -> prompt.
        for pattern in self._danger:
            if _danger_matches(pattern, tool_uri, args):
                return Decision(Effect.PROMPT, pattern, "standard", "danger_floor")

        # 3. workspace wildcard rules (first match wins).
        for rule in self._rules:
            if _has_wildcard(rule.tool) and _rule_matches(rule, tool_uri, args, caller):
                return Decision(Effect(rule.effect), rule.tool, rule.audit_level, "wildcard")

        # 4. implicit default-deny.
        return Decision(Effect.DENY, None, "standard", "default")
