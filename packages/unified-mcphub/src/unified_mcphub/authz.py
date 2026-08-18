"""Authorization policy resolver — spec §4, ADR-0006; engine-backed per policy.v2.md.

Since the unified-enforce migration this module no longer owns the decision
logic: it mechanically translates the hub's workspace rules and
dangerous-commands floor into an engine `PolicyDoc` (policy v0.2 absorbed the
hub's constructs verbatim — args operator maps, caller lists, the floor tier)
and delegates to `PolicyEngine.decide()`. Semantics are unchanged and pinned by
tests/unit/test_authz_parity.py against a frozen copy of the legacy resolver.

Three states per tool: allow / deny / prompt (engine DEFER ⇄ hub PROMPT).

Precedence (highest to lowest):
  1. explicit exact-tool rule in the active workspace (no wildcard, matches URI)
  2. dangerous-commands.yaml floor match  -> prompt   (engine `floors` tier)
  3. workspace wildcard rules (first-match-wins)
  4. implicit default-deny (NOT configurable)

Translation notes (policy.v2.md):
- `callers` -> principal list `agent:<caller>`; rules with `callers: []` never
  matched in the hub (dead) and are dropped.
- rules with unknown args operators never matched in the hub (fail-closed
  operator) and are dropped; the engine would reject them at load.
- `**` runs collapse to `*` (hub globs never cross `/`); a bare `*` tool
  pattern never matched a URI in the hub (dead) and is dropped, because the
  engine reads bare `*` as match-all.

Tool URIs: mcp://<server>/<tool>, mcp://built-in/<tool>, sdk://..., agent://...
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any

from unified_enforce import Action, Enforcer, Principal, Telemetry
from unified_enforce.policy import Floor as EngineFloor
from unified_enforce.policy import Match as EngineMatch
from unified_enforce.policy import PolicyDoc, PolicyEngine, Verdict
from unified_enforce.policy import Rule as EngineRule

from .config import DangerousCommands, DeploymentConfig, Rule, Workspace, mcphub_home

# Filesystem write tools that could edit/replace/remove a policy file. Reads are
# intentionally left out — a locked deployment protects policy *integrity*, and
# denying reads would surprise legitimate tooling without adding protection.
_FS_WRITE_TOOLS = ("create_file", "edit_file", "delete_file")


def _constitutional_rules(deployment: DeploymentConfig | None) -> list[EngineRule]:
    """Rules a `locked` deployment installs at the highest precedence tier so a
    compromised agent cannot edit them away (UAI-216).

    Front-line defense-in-depth: deny agent-driven filesystem writes into the
    hub config/policy dir. The robust backstop is reload-gating in hub.py — even
    a write that slips past this (e.g. via a shell redirection, which carries no
    structured path arg to match; tracked as a follow-up) does not take effect
    in a locked deployment, because non-`hot` reload never auto-applies.
    """
    if deployment is None or not deployment.is_locked:
        return []
    protected = str(mcphub_home())
    rules: list[EngineRule] = []
    for tool in _FS_WRITE_TOOLS:
        rules.append(
            EngineRule(
                id=f"const-fs-{tool}",
                match=EngineMatch(
                    principal="*",
                    tool=f"mcp://filesystem/{tool}",
                    args={"path": {"starts_with": [protected]}},
                ),
                effect="deny",
                reason="locked deployment: the policy/config dir is not agent-writable",
            )
        )
    return rules


class Effect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    PROMPT = "prompt"


@dataclass
class Decision:
    effect: Effect
    rule: str | None  # the matching rule's `tool` pattern (audit `authz_rule`)
    audit_level: str = "standard"
    source: str = "default"  # exact | danger_floor | wildcard | default


_VERDICT_TO_EFFECT = {
    Verdict.ALLOW: Effect.ALLOW,
    Verdict.DENY: Effect.DENY,
    Verdict.DEFER: Effect.PROMPT,
}
_KNOWN_OPERATORS = {"equals", "starts_with", "matches"}


def _collapse_stars(pattern: str) -> str:
    """Hub globs never cross `/`; engine `**` does. `**` ≡ `*` under hub rules."""
    return re.sub(r"\*{2,}", "*", pattern)


def _rule_is_dead(rule: Rule) -> bool:
    """Rules that could never match in the hub (see module docstring)."""
    if rule.tool == "*":
        return True  # bare `*` never matches a URI (URIs contain `/`)
    if rule.callers is not None and not rule.callers:
        return True  # empty caller list: membership test always False
    if rule.args_filter:
        for operators in rule.args_filter.values():
            if any(op not in _KNOWN_OPERATORS for op in operators):
                return True  # unknown operator evaluated False in the hub
    return False


def _floor_from_pattern(pattern: str, index: int) -> EngineFloor | None:
    """Danger patterns: `mcp://srv/tool` or `mcp://srv/tool:<command-prefix>*`,
    or a scheme-less whole-URI glob. Mirrors the legacy _danger_matches split
    (partition on the `:` after `://`, never the scheme colon)."""
    scheme, sep_scheme, rest = pattern.partition("://")
    if not sep_scheme:
        if pattern == "*":
            return None  # dead in the hub; would be match-all in the engine
        return EngineFloor(id=f"floor-{index}", match=EngineMatch(tool=_collapse_stars(pattern)))
    uri_tail, sep_arg, arg_part = rest.partition(":")
    match_kwargs: dict[str, Any] = {"tool": _collapse_stars(f"{scheme}://{uri_tail}")}
    if sep_arg:
        match_kwargs["args"] = {"command": {"starts_with": [arg_part.rstrip("*")]}}
    return EngineFloor(id=f"floor-{index}", match=EngineMatch(**match_kwargs))


class AuthzResolver:
    def __init__(
        self,
        workspace: Workspace,
        dangerous: DangerousCommands,
        telemetry: Telemetry | None = None,
        deployment: DeploymentConfig | None = None,
    ) -> None:
        rules: list[EngineRule] = []
        names: dict[str, str] = {}  # engine rule id -> hub tool pattern (audit `authz_rule`)
        for i, rule in enumerate(workspace.authz.rules):
            if _rule_is_dead(rule):
                continue
            rid = f"rule-{i}"
            names[rid] = rule.tool
            principal: str | list[str] = "*"
            if rule.callers is not None:
                principal = [f"agent:{c}" for c in rule.callers]
            rules.append(
                EngineRule(
                    id=rid,
                    match=EngineMatch(
                        principal=principal,
                        tool=_collapse_stars(rule.tool),
                        args=rule.args_filter or None,
                    ),
                    effect="defer" if rule.effect == "prompt" else rule.effect,
                    audit_level=rule.audit_level,
                )
            )
        floors: list[EngineFloor] = []
        for i, pattern in enumerate(dangerous.require_approval):
            floor = _floor_from_pattern(pattern, i)
            if floor is not None:
                names[floor.id] = pattern
                floors.append(floor)
        constitutional = _constitutional_rules(deployment)
        for r in constitutional:
            names[r.id] = r.reason or r.id
        self._engine = PolicyEngine(
            PolicyDoc(version=1, constitutional=constitutional, rules=rules, floors=floors)
        )
        self._names = names
        # Route through the Enforcer rather than the raw engine so every hub
        # decision emits a span (UAI-86). No audit chain here: the hub keeps its
        # own two-phase AuditLog, which is already chained and records the
        # completion half that the engine's single-entry form cannot express.
        self._enforcer = Enforcer(self._engine, telemetry=telemetry)

    def resolve(
        self, tool_uri: str, args: dict[str, Any], caller: str, action: Action | None = None
    ) -> Decision:
        if action is None:
            action = Action.build(
                principal=Principal(id=f"agent:{caller}"),
                tool=tool_uri,
                verb="call",
                resource="*",
                params=args,
            )
        d = self._enforcer.enforce(action)
        return Decision(
            effect=_VERDICT_TO_EFFECT[d.verdict],
            rule=self._names.get(d.rule_id) if d.rule_id else None,
            audit_level=d.audit_level,
            source="danger_floor" if d.source == "floor" else d.source,
        )
