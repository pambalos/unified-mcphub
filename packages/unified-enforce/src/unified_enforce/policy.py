"""Policy engine v0.2 — YAML rules + structured matchers + CEL conditions.

Spec: specs/enforce/e1.v1.md §4 (v0.1 core) and specs/enforce/policy.v2.md
(v0.2: the hub's ADR-0006 authz constructs absorbed as first-class policy).

- match on all four Action axes; `principal` accepts a glob or a list of globs
- `match.args` — per-argument operator maps (equals / starts_with / matches),
  ported verbatim from the hub: str()-coerced values, missing arg compares as
  "" (rule quietly doesn't match). Structured matchers are for shape.
- optional `when:` CEL condition for value-level constraints — compiled once at
  policy load, evaluated in-process. CEL is for value logic.
- `floors:` — a tier that forces DEFER, overridable only by an exact rule
- verdicts: ALLOW / DENY / DEFER (defer = hand to the approval contract)

Precedence (highest to lowest):
  1. exact rules (no wildcard in the tool pattern), in file order
  2. floors (generalized dangerous-commands: wildcard allows can't waive them)
  3. wildcard rules, first match wins
  4. implicit default-deny — NOT configurable

Fail closed, always:
- malformed rule, duplicate id, unknown args operator, invalid regex, bad CEL
  → load error, engine refuses to start
- CEL evaluation error or non-boolean result → DENY (source "condition_error"),
  never "skip the rule and fall through" (a skipped deny is an accidental allow)
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Literal

import celpy
import yaml
from pydantic import BaseModel, ConfigDict, Field

from .action import Action


class Verdict(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    DEFER = "defer"


@dataclass
class Decision:
    verdict: Verdict
    rule_id: str | None  # matching rule's id (audit field), None for default-deny
    source: str  # exact | floor | wildcard | default | condition_error
    audit_level: str = "standard"
    reason: str | None = None
    elapsed_ms: float = 0.0


class PolicyError(ValueError):
    """Policy file is malformed or a rule does not compile."""


# --- policy document models ---

ArgsMap = dict[str, dict[str, list[str]]]


class Match(BaseModel):
    model_config = ConfigDict(extra="forbid")

    principal: str | list[str] = "*"  # glob, or OR-list of globs
    tool: str = "*"
    verb: str = "*"
    resource: str = "*"
    # {arg: {equals|starts_with|matches: [values]}} — ADR-0006 semantics verbatim
    args: ArgsMap | None = None


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    match: Match = Field(default_factory=Match)
    when: str | None = None  # CEL; names: action, principal, tool, verb, resource, params, context
    effect: Literal["allow", "deny", "defer"]
    audit_level: Literal["minimal", "standard", "detailed", "full"] = "standard"
    reason: str | None = None


class Floor(BaseModel):
    """Forces DEFER between the exact and wildcard tiers (policy.v2.md §3)."""

    model_config = ConfigDict(extra="forbid")

    id: str
    match: Match = Field(default_factory=Match)
    when: str | None = None
    audit_level: Literal["minimal", "standard", "detailed", "full"] = "standard"
    reason: str | None = None


class PolicyDoc(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal[1]
    rules: list[Rule] = Field(default_factory=list)
    floors: list[Floor] = Field(default_factory=list)


# --- glob compilation ---
# `*`  = any run of chars except `/` (URIs stay segment-aware)
# `**` = any run of chars including `/`
# a pattern that is exactly "*" means match-all (axis left unconstrained)


def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    if pattern == "*":
        return re.compile(r"^.*$", re.DOTALL)
    out: list[str] = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("^" + "".join(out) + "$")


# --- args operator matching (ported verbatim from the hub's authz.py, ADR-0006) ---

_ARGS_OPERATORS = ("equals", "starts_with", "matches")


def _compile_args(args_map: ArgsMap, owner_id: str) -> dict[str, list[tuple[str, list[Any]]]]:
    """Validate operators and precompile `matches` regexes. Unknown operators and
    bad regexes are load errors (policy.v2.md: stricter than the hub, which left
    them to fail at evaluation)."""
    compiled: dict[str, list[tuple[str, list[Any]]]] = {}
    for arg, operators in args_map.items():
        ops: list[tuple[str, list[Any]]] = []
        for op, values in operators.items():
            if op not in _ARGS_OPERATORS:
                raise PolicyError(
                    f"rule {owner_id!r}: unknown args operator {op!r} "
                    f"(allowed: {', '.join(_ARGS_OPERATORS)})"
                )
            if op == "matches":
                try:
                    ops.append((op, [re.compile(v) for v in values]))
                except re.error as exc:
                    raise PolicyError(f"rule {owner_id!r}: bad regex in matches: {exc}") from exc
            else:
                ops.append((op, list(values)))
        compiled[arg] = ops
    return compiled


def _args_match(compiled: dict[str, list[tuple[str, list[Any]]]], params: dict[str, Any]) -> bool:
    """Arg names AND'd; operators per arg AND'd; value lists OR'd.
    A missing argument compares as "" (so it won't match a non-empty target)."""
    for arg, ops in compiled.items():
        actual = str(params.get(arg, ""))
        for op, values in ops:
            if op == "equals":  # case-insensitive (JSON true / "true" both match)
                if actual.lower() not in {v.lower() for v in values}:
                    return False
            elif op == "starts_with":  # case-sensitive prefix
                if not any(actual.startswith(v) for v in values):
                    return False
            else:  # matches — regex search ((?i) for case-insensitivity)
                if not any(p.search(actual) for p in values):
                    return False
    return True


@dataclass
class _Compiled:
    id: str
    effect: Verdict
    audit_level: str
    reason: str | None
    principals: list[re.Pattern[str]]
    tool: re.Pattern[str]
    verb: re.Pattern[str]
    resource: re.Pattern[str]
    args: dict[str, list[tuple[str, list[Any]]]] | None
    condition: celpy.Runner | None
    is_exact: bool  # no wildcard in the tool pattern


class PolicyEngine:
    def __init__(self, doc: PolicyDoc) -> None:
        self._doc = doc
        env = celpy.Environment()
        seen_ids: set[str] = set()

        def compile_one(
            id_: str,
            match: Match,
            when: str | None,
            effect: Verdict,
            audit_level: str,
            reason: str | None,
        ) -> _Compiled:
            if id_ in seen_ids:
                raise PolicyError(f"duplicate rule id: {id_!r}")
            seen_ids.add(id_)
            condition = None
            if when is not None:
                try:
                    condition = env.program(env.compile(when))
                except Exception as exc:  # celpy raises lark/CEL parse errors
                    raise PolicyError(f"rule {id_!r}: bad CEL condition: {exc}") from exc
            principals = match.principal if isinstance(match.principal, list) else [match.principal]
            if not principals:
                raise PolicyError(f"rule {id_!r}: empty principal list")
            return _Compiled(
                id=id_,
                effect=effect,
                audit_level=audit_level,
                reason=reason,
                principals=[_glob_to_regex(p) for p in principals],
                tool=_glob_to_regex(match.tool),
                verb=_glob_to_regex(match.verb),
                resource=_glob_to_regex(match.resource),
                args=_compile_args(match.args, id_) if match.args else None,
                condition=condition,
                is_exact="*" not in match.tool,
            )

        rules = [
            compile_one(r.id, r.match, r.when, Verdict(r.effect), r.audit_level, r.reason)
            for r in doc.rules
        ]
        # Precedence tier 1 vs 3 is decided by the tool pattern; floors are tier 2.
        self._exact = [c for c in rules if c.is_exact]
        self._floors = [
            compile_one(f.id, f.match, f.when, Verdict.DEFER, f.audit_level, f.reason)
            for f in doc.floors
        ]
        self._wildcard = [c for c in rules if not c.is_exact]

    # --- loaders ---

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PolicyEngine":
        try:
            return cls(PolicyDoc.model_validate(data))
        except PolicyError:
            raise
        except Exception as exc:
            raise PolicyError(f"invalid policy document: {exc}") from exc

    @classmethod
    def from_yaml(cls, text: str) -> "PolicyEngine":
        data = yaml.safe_load(text)
        if not isinstance(data, dict):
            raise PolicyError("policy document must be a YAML mapping")
        return cls.from_dict(data)

    @classmethod
    def from_file(cls, path: str | Path) -> "PolicyEngine":
        return cls.from_yaml(Path(path).read_text(encoding="utf-8"))

    # --- evaluation ---

    def decide(self, action: Action) -> Decision:
        start = time.perf_counter()

        def done(d: Decision) -> Decision:
            d.elapsed_ms = round((time.perf_counter() - start) * 1000, 3)
            return d

        activation: dict[str, Any] | None = None  # built lazily, only if a rule has CEL

        for tier, source in (
            (self._exact, "exact"),
            (self._floors, "floor"),
            (self._wildcard, "wildcard"),
        ):
            for c in tier:
                if not (
                    any(p.fullmatch(action.principal.id) for p in c.principals)
                    and c.tool.fullmatch(action.tool)
                    and c.verb.fullmatch(action.verb)
                    and c.resource.fullmatch(action.resource)
                ):
                    continue
                if c.args is not None and not _args_match(c.args, action.params):
                    continue
                if c.condition is not None:
                    if activation is None:
                        activation = _activation(action)
                    try:
                        result = c.condition.evaluate(activation)
                    except Exception as exc:
                        return done(
                            Decision(
                                Verdict.DENY,
                                c.id,
                                "condition_error",
                                c.audit_level,
                                f"condition raised: {exc}",
                            )
                        )
                    if not isinstance(result, celpy.celtypes.BoolType):
                        return done(
                            Decision(
                                Verdict.DENY,
                                c.id,
                                "condition_error",
                                c.audit_level,
                                f"condition returned {type(result).__name__}, not bool",
                            )
                        )
                    if not result:
                        continue  # condition false → rule does not match
                return done(Decision(c.effect, c.id, source, c.audit_level, c.reason))

        return done(Decision(Verdict.DENY, None, "default", "standard", "no rule matched"))


def _activation(action: Action) -> dict[str, Any]:
    dumped = action.model_dump(mode="json")
    return {
        "action": celpy.json_to_cel(dumped),
        "principal": celpy.json_to_cel(dumped["principal"]),
        "tool": celpy.json_to_cel(action.tool),
        "verb": celpy.json_to_cel(action.verb),
        "resource": celpy.json_to_cel(action.resource),
        "params": celpy.json_to_cel(dumped["params"]),
        "context": celpy.json_to_cel(dumped["context"]),
    }
