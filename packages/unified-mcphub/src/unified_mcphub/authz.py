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

from unified_enforce import Action, ActionContext, Enforcer, Principal, Telemetry
from unified_enforce.policy import Decision as EngineDecision
from unified_enforce.policy import Floor as EngineFloor
from unified_enforce.policy import Match as EngineMatch
from unified_enforce.policy import PolicyDoc, PolicyEngine, Verdict
from unified_enforce.policy import Rule as EngineRule

from .config import DangerousCommands, DeploymentConfig, Rule, Workspace, mcphub_home

# Filesystem write tools that could edit/replace/remove a policy file, each paired
# with the argument that carries their write target. Reads are intentionally left
# out — a locked deployment protects policy *integrity*, and denying reads would
# surprise legitimate tooling without adding protection.
#
# The target arg is named per tool rather than guarded across a blanket path-arg
# set, and that is load-bearing given how `path_under` fails closed: an *absent*
# path argument on a DENY rule is treated as a match (deny), because a write
# whose destination cannot be determined must not be allowed. That is correct
# for the arg a tool actually writes through, and wrong for any other — a deny
# rule on `directory` would match every `edit_file` (which never sends one),
# blocking all edits. So each tool is guarded on exactly the arg it writes to.
_FS_WRITE_TARGETS = {
    "create_file": "path",
    "edit_file": "path",
    "delete_file": "path",
}


def _constitutional_rules(deployment: DeploymentConfig | None) -> list[EngineRule]:
    """Rules a `locked` deployment installs at the highest precedence tier so a
    compromised agent cannot edit them away (UAI-216).

    Front-line defense-in-depth: deny agent-driven filesystem writes into the
    hub config/policy dir. The robust backstop is reload-gating in hub.py — even
    a write that slips past this (e.g. via a shell redirection, which carries no
    structured path arg to match; tracked as a follow-up) does not take effect
    in a locked deployment, because non-`hot` reload never auto-applies.

    Matched with `path_under`, not a string prefix: the argument is canonicalised
    before comparison, so `<home>/../mcphub/config.yaml` and a symlink pointing
    into the directory are caught, and a sibling like `<home>-backup` is not
    swept up by an accidental prefix match.
    """
    if deployment is None or not deployment.is_locked:
        return []
    protected = str(mcphub_home())
    rules: list[EngineRule] = []
    for tool, target_arg in _FS_WRITE_TARGETS.items():
        rules.append(
            EngineRule(
                id=f"const-fs-{tool}",
                match=EngineMatch(
                    principal="*",
                    tool=f"mcp://filesystem/{tool}",
                    args={target_arg: {"path_under": [protected]}},
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
    #: sha256 of the compiled policy that decided (audit `policy_digest`): the
    #: workspace rules, the dangerous-commands floors and any constitutional
    #: rules together, as one document. None when no policy decided.
    policy_digest: str | None = None
    #: The engine's own decision, unmapped. What leaves the hub — the DEFER an
    #: approver is asked about, the evidence row the control plane stores —
    #: is the engine's vocabulary, and it carries the rule id (now the
    #: readable pattern, see `_RuleIds`) and the policy digest together.
    engine: EngineDecision | None = None


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


class _RuleIds:
    """Engine rule ids that a reader can recognise: the hub's own pattern.

    The hub's rules have no ids — a rule *is* its `tool` pattern — so the
    engine's were once synthesized from list position (`rule-22`, `floor-3`).
    Those never surfaced in the hub's own audit (the `names` map turns an id
    back into the pattern for `authz_rule`), but they did surface everywhere
    the engine's decision travels unmapped: the evidence the control plane
    stores, the approval it queues, the console an approver reads. `rule-22`
    there means nothing without the workspace file it indexed — and it means
    something *different* after a learned rule is prepended, because every
    position shifts. The pattern means the same thing in both places.

    Ids must be unique across rules, floors and constitutional rules (one
    namespace in `PolicyEngine`), and the same pattern can legitimately appear
    twice — once per caller list, say. Repeats take `#2`, `#3`… in list order,
    so the first occurrence, the one first-match-wins usually picks, keeps the
    bare pattern. Floors are prefixed `floor:` so a workspace rule and a floor
    over the same tool stay distinguishable — they are different decisions.
    """

    def __init__(self, reserved: list[str]) -> None:
        self._seen: set[str] = set(reserved)

    def take(self, base: str) -> str:
        candidate, n = base, 1
        while candidate in self._seen:
            n += 1
            candidate = f"{base}#{n}"
        self._seen.add(candidate)
        return candidate


def _floor_from_pattern(pattern: str, floor_id: str) -> EngineFloor | None:
    """Danger patterns: `mcp://srv/tool` or `mcp://srv/tool:<command-prefix>*`,
    or a scheme-less whole-URI glob. Mirrors the legacy _danger_matches split
    (partition on the `:` after `://`, never the scheme colon)."""
    scheme, sep_scheme, rest = pattern.partition("://")
    if not sep_scheme:
        if pattern == "*":
            return None  # dead in the hub; would be match-all in the engine
        return EngineFloor(id=floor_id, match=EngineMatch(tool=_collapse_stars(pattern)))
    uri_tail, sep_arg, arg_part = rest.partition(":")
    match_kwargs: dict[str, Any] = {"tool": _collapse_stars(f"{scheme}://{uri_tail}")}
    if sep_arg:
        match_kwargs["args"] = {"command": {"starts_with": [arg_part.rstrip("*")]}}
    return EngineFloor(id=floor_id, match=EngineMatch(**match_kwargs))


class AuthzResolver:
    def __init__(
        self,
        workspace: Workspace,
        dangerous: DangerousCommands,
        telemetry: Telemetry | None = None,
        deployment: DeploymentConfig | None = None,
        distribution: Any = None,
        evidence: Any = None,
    ) -> None:
        rules: list[EngineRule] = []
        names: dict[str, str] = {}  # engine rule id -> hub tool pattern (audit `authz_rule`)
        constitutional = _constitutional_rules(deployment)
        ids = _RuleIds([r.id for r in constitutional])
        for rule in workspace.authz.rules:
            if _rule_is_dead(rule):
                continue
            rid = ids.take(rule.tool)
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
        for pattern in dangerous.require_approval:
            if pattern == "*":
                continue  # dead (see _floor_from_pattern); spend no id on it
            floor = _floor_from_pattern(pattern, ids.take(f"floor:{pattern}"))
            if floor is not None:
                names[floor.id] = pattern
                floors.append(floor)
        for r in constitutional:
            # `names` maps engine rule id -> hub tool pattern for the audit
            # `authz_rule` field. The pattern, not the reason: a reader of the
            # audit log expects the same shape here as for every other rule.
            names[r.id] = r.match.tool
        self._engine = PolicyEngine(
            PolicyDoc(version=1, constitutional=constitutional, rules=rules, floors=floors)
        )
        self._names = names
        # Route through the Enforcer rather than the raw engine so every hub
        # decision emits a span (UAI-86). No audit chain here: the hub keeps its
        # own two-phase AuditLog, which is already chained and records the
        # completion half that the engine's single-entry form cannot express.
        # `distribution` is the fleet's verified policy + revocation state
        # (build-04): when the hub is joined to a control plane, containment is
        # consulted before any workspace rule, in the Enforcer, in the same
        # order the Envoy sidecar uses. Standalone hubs pass None and nothing
        # changes.
        #
        # `evidence` is deliberately *not* handed to the Enforcer. The Enforcer
        # ships at decision time with the chain entry it wrote — and the hub's
        # Enforcer writes none, so every row reached the control plane with
        # `chain_seq`/`chain_hash` empty and could be joined to the hub's
        # signed local entry only by digest. The hub's entry is its own
        # `received` line, written after the decision (and, for a prompt,
        # after the human), so the hub ships through `ship()` once that entry
        # exists and points the row at it. The Enforcer's own rule — ship only
        # what the chain holds — is kept, with the hub's chain as the chain: a
        # failed audit write ships nothing.
        self._enforcer = Enforcer(self._engine, telemetry=telemetry, distribution=distribution)
        self._evidence = evidence
        # The receipt wiring the Enforcer would have done had it held the
        # shipper (see Enforcer.__init__): a receipt that says the revocation
        # list moved must still refresh containment at once.
        if (
            distribution is not None
            and evidence is not None
            and getattr(evidence, "on_receipt", None) is None
        ):
            evidence.on_receipt = distribution.on_receipt

    def ship(self, action: Action, decision: EngineDecision, entry: dict[str, Any] | None) -> None:
        """Report one decision to the fleet, pointing at the hub entry that holds it.

        `decision` is what that entry records: the engine's verdict for a call
        decided by policy, and for a `prompt` the *resolved* verdict (source
        `approval`, `approval_timeout`, … with the deferring rule's id and
        policy digest kept). Not the DEFER, because the entry the row points
        at says `prompt_allowed`/`prompt_denied` and a row must describe the
        line it cites; and not both, because the control plane keeps one row
        per action digest and drops the second. That review was demanded
        stays visible — the source says a human settled it, and in console
        mode the approval itself is a signed row of its own at the control
        plane, joined on the same digest.

        No-op for a standalone hub. Cannot raise (`EvidenceShipper.record`).
        """
        if self._evidence is not None:
            self._evidence.record(action, decision, entry=entry)

    def ship_payload(self, entry: dict[str, Any], path: str, *, action_digest: str | None) -> None:
        """Offer a detached value from a hub entry to the fleet (payload-evidence.v1).

        `args` from a `received` entry, `result` from a `completed` one. The
        shipper decides whether anything leaves: the control plane must have
        accepted payloads, the hub must sign, and the entry must actually hold
        the value (not `record_payloads: false`). No-op for a standalone hub
        and for `control_plane.payloads: off`. Cannot raise.
        """
        # Looked up, as in `Enforcer.record`: an evidence sink that only
        # implements `record` is still valid, and must not start failing calls.
        ship = getattr(self._evidence, "record_payload", None)
        if ship is not None:
            ship(entry, path, action_digest=action_digest)

    # --- structural records (build-14): refusals and findings the policy
    # --- engine never saw, landed in the chain and the evidence like verdicts

    def record_unidentified(
        self, *, source: str, method: str, entry: dict[str, Any] | None = None
    ) -> None:
        """A caller that presented no valid identity was refused (S-1).

        The hub already returns 401. This makes the refusal a *decision* on
        the unknown principal, so it reaches the control plane's identity
        refusal stream like the gateway's do. The same shape the gateway
        records: source "identity_invalid", verdict deny.
        """
        action = Action.build(
            principal=Principal(id="agent:unknown", attestation="assigned"),
            tool=f"mcp://hub/{method}",
            verb="call",
            resource="*",
            params={},
            context=ActionContext(origin="mcp", extra={"source": source or "unknown"}),
        )
        decision = self._enforcer.record(
            action,
            EngineDecision(
                verdict=Verdict.DENY,
                rule_id=None,
                source="identity_invalid",
                reason=f"no valid credential presented from {source or 'unknown'}",
            ),
            count=False,  # a refusal at the door is not the fleet's spend
        )
        self.ship(action, decision, entry)

    def record_ingress(
        self, action: Action, hits: list[str], entry: dict[str, Any] | None = None
    ) -> None:
        """A tool result carried instruction shapes (D-12). Recorded as a
        structural decision on the same principal and tool, verb `ingest`,
        with the pattern ids as the resource — never the text. Verdict
        `allow`, because the call already happened; the finding is the
        `source`."""
        finding = Action.build(
            principal=action.principal,
            tool=action.tool,
            verb="ingest",
            resource=",".join(hits),
            params={},
            context=ActionContext(origin="mcp", extra={"injection": hits}),
        )
        decision = self._enforcer.record(
            finding,
            EngineDecision(
                verdict=Verdict.ALLOW,
                rule_id=None,
                source="injection_suspected",
                reason=f"tool result carried instruction shapes: {', '.join(hits)}",
            ),
            count=False,  # the call was counted when it was decided
        )
        self.ship(finding, decision, entry)

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
            policy_digest=d.policy_digest,
            engine=d,
        )
