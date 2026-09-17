"""Policy engine v0.2 — YAML rules + structured matchers + CEL conditions.

Spec: specs/enforce/e1.v1.md §4 (v0.1 core) and specs/enforce/policy.v2.md
(v0.2: the hub's ADR-0006 authz constructs absorbed as first-class policy).

- match on all four Action axes; `principal` accepts a glob or a list of globs
- `match.args` — per-argument operator maps (equals / starts_with / matches /
  path_under), ported verbatim from the hub: str()-coerced values, missing arg
  compares as "" (rule quietly doesn't match). Structured matchers are for
  shape. `path_under` is the exception to "verbatim": it canonicalises both
  sides and tests real directory containment, because a lexical prefix is not
  a safe way to protect a directory (see `_is_under`).
- optional `when:` CEL condition for value-level constraints — compiled once at
  policy load, evaluated in-process. CEL is for value logic.
- `floors:` — a tier that forces DEFER, overridable only by an exact rule
- verdicts: ALLOW / DENY / DEFER (defer = hand to the approval contract)

Precedence (highest to lowest):
  0. constitutional rules — outrank everything, un-waivable (UAI-216); empty by
     default, so absent them precedence is unchanged
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

import logging
import re
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from collections.abc import Mapping
from typing import Any, Literal

import celpy
import yaml
from pydantic import BaseModel, ConfigDict, Field

from unified_paths import canonical, is_under

from .action import Action, Attestation, grade_at_least

log = logging.getLogger("unified_enforce.policy")


class Verdict(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    DEFER = "defer"


@dataclass
class Decision:
    verdict: Verdict
    rule_id: str | None  # matching rule's id (audit field), None for default-deny
    source: str  # exact | floor | wildcard | default | condition_error | attestation_floor
    audit_level: str = "standard"
    reason: str | None = None
    elapsed_ms: float = 0.0
    #: Structured detail the `why` needs but a reason string cannot carry —
    #: today the offending hop of a chain that failed an attestation floor
    #: (build-01 §5). Optional and defaulted so every existing construction
    #: site keeps working unchanged.
    context: dict[str, Any] | None = None


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


class AttestationFloor(BaseModel):
    """A minimum chain grade for a matched verb class — build-01 §5.

    Today the strength of every rule is silently the weakest identity path in
    the deployment: a rule naming `agent:refunder` is exactly as strong as
    whatever established that name, and nothing says which. This makes that
    strength a value policy states and the engine enforces, rather than a
    topology property nobody can see.

    `effect` is deliberately limited to deny|defer. A floor is a precondition
    on *who is asking*, so the most it can ever do is refuse — an identity
    requirement that could grant would be an authorization rule wearing the
    wrong name.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    match: Match = Field(default_factory=Match)
    #: `assigned` < `derived` < `attested`. Compared against
    #: `Principal.chain_grade()`, never the leaf's own grade — that is the
    #: minimum-grade rule, and reading the leaf here would reintroduce exactly
    #: the laundering build-01 §4 exists to stop.
    minimum: Attestation
    effect: Literal["deny", "defer"] = "deny"
    audit_level: Literal["minimal", "standard", "detailed", "full"] = "standard"
    reason: str | None = None


class Counter(BaseModel):
    """What to accumulate, so a rule can ask a cumulative question (UAI-147).

    Declared separately from the rule that reads it, because the two are not
    one-to-one: a spend total is written by the refund rule and read by the
    budget floor, and a deny count is written by every rule and read by none of
    them (the control plane reads it, as the rogue signal of UAI-167).

    `value` is CEL over the same names a rule condition sees, so the amount
    counted is the amount in the action rather than a field name this module
    has to know about. Absent, each matching action counts as one — which is
    what a rate limit is.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    match: Match = Field(default_factory=Match)
    value: str | None = None
    #: Which decisions add to it. `allow` by default: a refund that was denied
    #: did not spend anything, and counting it would let a blocked agent
    #: exhaust its own budget and then point at the total as evidence it was
    #: throttled unfairly. `deny` is the rogue signal; `any` is attempt rate.
    #:
    #: Named `on_verdict` and not `on`, which was the first choice and lasted
    #: one test run: YAML 1.1 reads a bare `on` as the boolean true, so the key
    #: never reached this model. A policy language whose fields silently become
    #: booleans is a policy language that eventually loads a rule nobody wrote.
    on_verdict: Literal["allow", "deny", "any"] = "allow"


class PolicyDoc(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal[1]
    #: Highest-precedence tier (UAI-216). Evaluated before every other tier, so
    #: a constitutional rule cannot be waived by any workspace rule or floor.
    #: This is where a `locked` deployment installs the protections a compromised
    #: agent must not be able to edit away (e.g. deny writes to the policy dir).
    #: Empty by default: with no constitutional rules the engine behaves exactly
    #: as before, which is what keeps the legacy-parity guarantee intact.
    constitutional: list[Rule] = Field(default_factory=list)
    #: Identity preconditions, evaluated after `constitutional` and before every
    #: other tier (build-01 §5). After, because a constitutional rule is the one
    #: thing a deployment has said cannot be waived by any floor — the existing
    #: `floors` tier is already subordinate to it, and a second kind of floor
    #: that outranked it would make "constitutional" mean two different things.
    #: Before the rest, because a rule evaluated on behalf of an identity that
    #: was never established to the required grade is a rule whose strength is
    #: fiction.
    attestation_floors: list[AttestationFloor] = Field(default_factory=list)
    rules: list[Rule] = Field(default_factory=list)
    floors: list[Floor] = Field(default_factory=list)
    counters: list[Counter] = Field(default_factory=list)


# --- glob compilation ---
# `*`  = any run of chars except `/` (URIs stay segment-aware)
# `**` = any run of chars including `/`
# a pattern that is exactly "*" means match-all (axis left unconstrained)


def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    # Brace expansion is NOT supported, and silently treating `{a,b}` as
    # literal characters is the worst available behaviour: the pattern compiles,
    # the policy loads, and the rule matches nothing forever. A dead *allow*
    # is merely annoying; a dead *deny* is a security control that was never
    # there. Anyone writing braces means alternation, so fail at load and say
    # what to do instead — same reasoning as unknown args operators being a
    # load error rather than a silent non-match.
    if "{" in pattern or "}" in pattern:
        raise PolicyError(
            f"glob pattern {pattern!r} contains braces, which are not expanded. "
            "Write one rule per alternative (a deny that matches nothing looks "
            "identical to a deny that is working)."
        )
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

_ARGS_OPERATORS = ("equals", "starts_with", "matches", "path_under")


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
            if op == "path_under":
                # Canonicalise the rule side once at load, so evaluation is a
                # comparison of two already-normalised absolute paths. A rule
                # that names a relative directory cannot be resolved against
                # anything meaningful, so it is a load error rather than a rule
                # that silently never matches.
                resolved = []
                for v in values:
                    c = canonical(v)
                    if c is None:
                        raise PolicyError(
                            f"rule {owner_id!r}: path_under needs an absolute directory, got {v!r}"
                        )
                    resolved.append(c)
                ops.append((op, resolved))
            elif op == "matches":
                try:
                    ops.append((op, [re.compile(v) for v in values]))
                except re.error as exc:
                    raise PolicyError(f"rule {owner_id!r}: bad regex in matches: {exc}") from exc
            else:
                ops.append((op, list(values)))
        compiled[arg] = ops
    return compiled


def _args_match(
    compiled: dict[str, list[tuple[str, list[Any]]]],
    params: dict[str, Any],
    effect: Verdict = Verdict.DENY,
) -> bool:
    """Arg names AND'd; operators per arg AND'd; value lists OR'd.
    A missing argument compares as "" (so it won't match a non-empty target).

    `effect` is the verdict of the rule being tested, and it decides only one
    thing: what an *indeterminate* comparison means. `path_under` can fail to
    reduce an argument to a single location — a relative path with no known
    base, a value the filesystem refuses to parse. Guessing there is how a
    protection gets walked around, so the answer resolves in whichever
    direction is safe for this rule: a deny rule treats it as a match (the
    write is refused), an allow rule as a miss (the grant is withheld). Either
    way the uncertain case fails closed instead of silently choosing one.
    """
    for arg, ops in compiled.items():
        actual = str(params.get(arg, ""))
        for op, values in ops:
            if op == "equals":  # case-insensitive (JSON true / "true" both match)
                if actual.lower() not in {v.lower() for v in values}:
                    return False
            elif op == "starts_with":  # case-sensitive prefix
                if not any(actual.startswith(v) for v in values):
                    return False
            elif op == "path_under":  # real containment, not a string prefix
                resolved = canonical(actual) if actual else None
                if resolved is None:
                    # Indeterminate. Fail closed in this rule's direction.
                    if effect is Verdict.DENY:
                        continue
                    return False
                if not any(is_under(resolved, v) for v in values):
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
        # Constitutional tier (UAI-216): compiled like any rule but evaluated
        # ahead of everything, so it cannot be overridden. Empty ⇒ no-op.
        self._constitutional = [
            compile_one(r.id, r.match, r.when, Verdict(r.effect), r.audit_level, r.reason)
            for r in doc.constitutional
        ]
        # Precedence tier 1 vs 3 is decided by the tool pattern; floors are tier 2.
        self._exact = [c for c in rules if c.is_exact]
        self._floors = [
            compile_one(f.id, f.match, f.when, Verdict.DEFER, f.audit_level, f.reason)
            for f in doc.floors
        ]
        self._wildcard = [c for c in rules if not c.is_exact]
        # Attestation floors compile through the same path as everything else --
        # same globs, same duplicate-id check -- and carry their minimum grade
        # alongside, the way counters carry `on_verdict`. `when` is deliberately
        # not offered: a floor that could be conditioned off is not a floor.
        self._attestation: list[tuple[_Compiled, Attestation]] = [
            (
                compile_one(f.id, f.match, None, Verdict(f.effect), f.audit_level, f.reason),
                f.minimum,
            )
            for f in doc.attestation_floors
        ]

        # Counters compile through the same path as rules -- same globs, same
        # CEL environment, same duplicate-id check -- so a counter whose match
        # is subtly different from the rule it is meant to shadow fails loudly
        # at load rather than by quietly totalling nothing.
        self._counters = [
            (
                compile_one(c.id, c.match, c.value, Verdict.ALLOW, "standard", None),
                c.on_verdict,
            )
            for c in doc.counters
        ]
        #: Every declared id, so a snapshot can resolve all of them to a number.
        #: A counter that resolved to nothing would make the rule reading it
        #: raise, which becomes a deny -- safe, and awful to debug.
        self.counter_ids = [c.id for c in doc.counters]

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

    def decide(
        self, action: Action, counters: Mapping[str, Mapping[str, float]] | None = None
    ) -> Decision:
        """Still a pure function; `counters` is an argument, not a lookup.

        That is the whole of ADR-0026. The engine could not count because
        counting means state and state on this path means a lookup that can
        hang -- but a pure function can be *handed* a number, and the layer
        that already does I/O is the one that should compute it.
        """
        start = time.perf_counter()

        def done(d: Decision) -> Decision:
            d.elapsed_ms = round((time.perf_counter() - start) * 1000, 3)
            return d

        activation: dict[str, Any] | None = None  # built lazily, only if a rule has CEL

        def matches(c: _Compiled) -> bool:
            return bool(
                any(p.fullmatch(action.principal.id) for p in c.principals)
                and c.tool.fullmatch(action.tool)
                and c.verb.fullmatch(action.verb)
                and c.resource.fullmatch(action.resource)
            )

        def scan(tier: list[_Compiled], source: str) -> Decision | None:
            nonlocal activation
            for c in tier:
                if not matches(c):
                    continue
                if c.args is not None and not _args_match(c.args, action.params, c.effect):
                    continue
                if c.condition is not None:
                    if activation is None:
                        activation = _activation(action, counters)
                    try:
                        result = c.condition.evaluate(activation)
                    except Exception as exc:
                        return Decision(
                            Verdict.DENY,
                            c.id,
                            "condition_error",
                            c.audit_level,
                            f"condition raised: {exc}",
                        )
                    if not isinstance(result, celpy.celtypes.BoolType):
                        return Decision(
                            Verdict.DENY,
                            c.id,
                            "condition_error",
                            c.audit_level,
                            f"condition returned {type(result).__name__}, not bool",
                        )
                    if not result:
                        continue  # condition false → rule does not match
                return Decision(c.effect, c.id, source, c.audit_level, c.reason)
            return None

        # Constitutional first: the one tier no floor may waive (UAI-216).
        hit = scan(self._constitutional, "constitutional")
        if hit is not None:
            return done(hit)

        # Then identity: a rule evaluated on behalf of an identity never
        # established to the required grade is a rule whose strength is fiction
        # (build-01 §5). Checked against the *chain* grade, so a well-attested
        # leaf behind a weak hop does not pass.
        hit = self._attestation_check(action)
        if hit is not None:
            return done(hit)

        for tier, source in (
            (self._exact, "exact"),
            (self._floors, "floor"),
            (self._wildcard, "wildcard"),
        ):
            hit = scan(tier, source)
            if hit is not None:
                return done(hit)

        return done(Decision(Verdict.DENY, None, "default", "standard", "no rule matched"))

    def _attestation_check(self, action: Action) -> Decision | None:
        """First matching attestation floor the chain fails — build-01 §5.

        The `why` names the offending hop rather than reporting only that the
        chain was too weak, because a denial an operator cannot trace to a link
        sends them to read the whole topology to find out which one it was.
        """
        principal = action.principal
        grade = principal.chain_grade()
        for c, minimum in self._attestation:
            if not (
                any(p.fullmatch(principal.id) for p in c.principals)
                and c.tool.fullmatch(action.tool)
                and c.verb.fullmatch(action.verb)
                and c.resource.fullmatch(action.resource)
            ):
                continue
            if grade_at_least(grade, minimum):
                continue
            weak = principal.weakest_link()
            where = f"hop {weak.id!r}" if weak is not None else f"principal {principal.id!r}"
            return Decision(
                c.effect,
                c.id,
                "attestation_floor",
                c.audit_level,
                c.reason or f"chain grade {grade!r} below floor {minimum!r} at {where}",
                context={
                    "attestation_below_floor": {
                        "required": minimum,
                        "chain_grade": grade,
                        "offending_hop": weak.model_dump(mode="json") if weak else None,
                        "chain": [h.id for h in principal.chain()],
                        "human_rooted": principal.human_rooted(),
                    }
                },
            )
        return None

    def deltas(self, action: Action, decision: Decision) -> dict[str, float]:
        """What this action adds to each counter. Pure, like everything else here.

        Computed after the verdict because `on:` depends on it, and returned
        rather than applied because applying is state and state does not live
        in this class. The `Enforcer` applies it and writes it into the audit
        entry, which is what makes the totals recoverable after a restart.
        """
        if not self._counters:
            return {}

        activation: dict[str, Any] | None = None
        out: dict[str, float] = {}
        for compiled, on in self._counters:
            if on != "any" and decision.verdict.value != on:
                continue
            if not (
                any(p.fullmatch(action.principal.id) for p in compiled.principals)
                and compiled.tool.fullmatch(action.tool)
                and compiled.verb.fullmatch(action.verb)
                and compiled.resource.fullmatch(action.resource)
            ):
                continue
            if compiled.args is not None and not _args_match(
                compiled.args, action.params, compiled.effect
            ):
                continue

            if compiled.condition is None:
                out[compiled.id] = out.get(compiled.id, 0.0) + 1.0
                continue

            if activation is None:
                activation = _activation(action)
            try:
                computed = compiled.condition.evaluate(activation)
                if isinstance(computed, celpy.celtypes.BoolType) or not isinstance(
                    computed,
                    celpy.celtypes.DoubleType | celpy.celtypes.IntType | celpy.celtypes.UintType,
                ):
                    # A counter that evaluates to a string or a bool is a policy
                    # that means something other than what it says. `true` would
                    # otherwise quietly become 1.0 and total the number of times
                    # a condition held, which is a plausible thing to want and
                    # not what was written.
                    raise TypeError(f"value must be numeric, got {type(computed).__name__}")
                value = float(computed)
            except Exception as exc:  # noqa: BLE001 -- one counter must not break a decision
                # Deliberately not a deny. The verdict is already made and
                # returning it is correct; a counter that cannot compute its
                # own value is a policy bug, and turning it into a denial would
                # mean a typo in an accounting expression takes an agent
                # offline. Logged loudly, and the total is visibly wrong rather
                # than silently wrong.
                log.error("counter %r could not compute a value: %s", compiled.id, exc)
                continue
            out[compiled.id] = out.get(compiled.id, 0.0) + value
        return out


def _activation(
    action: Action, counters: Mapping[str, Mapping[str, float]] | None = None
) -> dict[str, Any]:
    dumped = action.model_dump(mode="json")
    return {
        # `count.<id>.day` and friends. Always present, even with no counters
        # declared, so a policy referencing one that does not exist fails on the
        # missing id rather than on a missing name -- a much better error.
        "count": celpy.json_to_cel({k: dict(v) for k, v in (counters or {}).items()}),
        "action": celpy.json_to_cel(dumped),
        "principal": celpy.json_to_cel(dumped["principal"]),
        "tool": celpy.json_to_cel(action.tool),
        "verb": celpy.json_to_cel(action.verb),
        "resource": celpy.json_to_cel(action.resource),
        "params": celpy.json_to_cel(dumped["params"]),
        "context": celpy.json_to_cel(dumped["context"]),
    }
