"""Policy engine v0.1 — YAML rules + CEL conditions. Spec §4 (specs/enforce/e1.v1.md).

Evolves the hub's three-state default-deny resolver (authz.py, ADR-0006) into the
engine's generalized form:

- match on all four Action axes (principal, tool, verb, resource) with globs
- optional `when:` CEL condition for value-level constraints (spend limits,
  data boundaries) — compiled once at policy load, evaluated in-process
- verdicts: ALLOW / DENY / DEFER (defer = hand to the approval contract)

Precedence (highest to lowest), matching the hub:
  1. exact rules (no wildcard in the tool pattern), in file order
  2. wildcard rules, first match wins
  3. implicit default-deny — NOT configurable

Fail closed, always:
- unknown effect / malformed rule → load error, engine refuses to start
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
    source: str  # exact | wildcard | default | condition_error
    audit_level: str = "standard"
    reason: str | None = None
    elapsed_ms: float = 0.0


class PolicyError(ValueError):
    """Policy file is malformed or a CEL condition does not compile."""


# --- policy document models ---


class Match(BaseModel):
    model_config = ConfigDict(extra="forbid")

    principal: str = "*"
    tool: str = "*"
    verb: str = "*"
    resource: str = "*"


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    match: Match = Field(default_factory=Match)
    when: str | None = None  # CEL; names: action, principal, tool, verb, resource, params, context
    effect: Literal["allow", "deny", "defer"]
    audit_level: Literal["minimal", "standard", "detailed", "full"] = "standard"
    reason: str | None = None


class PolicyDoc(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal[1]
    rules: list[Rule] = Field(default_factory=list)


# --- glob compilation (hub semantics, extended) ---
# `*`  = any run of chars except `/` (URIs stay segment-aware)
# `**` = any run of chars including `/`
# a pattern that is exactly "*" means match-all (field left unconstrained)


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


@dataclass
class _CompiledRule:
    rule: Rule
    principal: re.Pattern[str]
    tool: re.Pattern[str]
    verb: re.Pattern[str]
    resource: re.Pattern[str]
    condition: celpy.Runner | None
    is_exact: bool  # no wildcard in the tool pattern


class PolicyEngine:
    def __init__(self, doc: PolicyDoc) -> None:
        self._doc = doc
        env = celpy.Environment()
        compiled: list[_CompiledRule] = []
        seen_ids: set[str] = set()
        for rule in doc.rules:
            if rule.id in seen_ids:
                raise PolicyError(f"duplicate rule id: {rule.id!r}")
            seen_ids.add(rule.id)
            condition = None
            if rule.when is not None:
                try:
                    condition = env.program(env.compile(rule.when))
                except Exception as exc:  # celpy raises lark/CEL parse errors
                    raise PolicyError(f"rule {rule.id!r}: bad CEL condition: {exc}") from exc
            compiled.append(
                _CompiledRule(
                    rule=rule,
                    principal=_glob_to_regex(rule.match.principal),
                    tool=_glob_to_regex(rule.match.tool),
                    verb=_glob_to_regex(rule.match.verb),
                    resource=_glob_to_regex(rule.match.resource),
                    condition=condition,
                    is_exact="*" not in rule.match.tool,
                )
            )
        # Precedence tier 1 vs 2 is decided by the tool pattern, as in the hub.
        self._exact = [c for c in compiled if c.is_exact]
        self._wildcard = [c for c in compiled if not c.is_exact]

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

        for tier, source in ((self._exact, "exact"), (self._wildcard, "wildcard")):
            for c in tier:
                if not (
                    c.principal.fullmatch(action.principal.id)
                    and c.tool.fullmatch(action.tool)
                    and c.verb.fullmatch(action.verb)
                    and c.resource.fullmatch(action.resource)
                ):
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
                                c.rule.id,
                                "condition_error",
                                c.rule.audit_level,
                                f"condition raised: {exc}",
                            )
                        )
                    if not isinstance(result, celpy.celtypes.BoolType):
                        return done(
                            Decision(
                                Verdict.DENY,
                                c.rule.id,
                                "condition_error",
                                c.rule.audit_level,
                                f"condition returned {type(result).__name__}, not bool",
                            )
                        )
                    if not result:
                        continue  # condition false → rule does not match
                return done(
                    Decision(
                        Verdict(c.rule.effect),
                        c.rule.id,
                        source,
                        c.rule.audit_level,
                        c.rule.reason,
                    )
                )

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
