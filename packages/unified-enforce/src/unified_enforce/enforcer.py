"""Enforcer — the engine's front door: decide, then record everywhere.

Composes the three E1 primitives plus telemetry into the canonical loop:
decide (pure, <10 ms) → audit chain (court-grade record) → OTel span (optional).
Recording failures must never change a verdict that was already decided — but an
audit failure cannot be swallowed either (an unrecorded ALLOW is a hole in the
evidence), so audit errors raise *after* telemetry still gets the decision out.

`enforce()` is synchronous and stays that way: the decision path is pure CPU
work and nothing on it may await. Resolving a DEFER means waiting on a human,
which is a different kind of operation entirely — hence the separate
`enforce_with_approval()`.
"""

from __future__ import annotations

from .action import Action
from .approval import ApprovalOutcome, ApprovalRequest, Approvals, RecordedApproval
from .audit import AuditChain
from .counters import Counters
from .distribution import Distribution
from .evidence import EvidenceShipper
from .shadow import ShadowEvaluator
from .policy import Decision, PolicyEngine, Verdict
from .telemetry import Telemetry


class Enforcer:
    def __init__(
        self,
        engine: PolicyEngine,
        chain: AuditChain | None = None,
        telemetry: Telemetry | None = None,
        approvals: Approvals | None = None,
        distribution: Distribution | None = None,
        evidence: EvidenceShipper | None = None,
        shadow: ShadowEvaluator | None = None,
        counters: Counters | None = None,
    ) -> None:
        self._engine = engine
        self._chain = chain
        self._telemetry = telemetry or Telemetry.disabled()
        self.approvals = approvals
        self._distribution = distribution
        self._evidence = evidence
        self._shadow = shadow
        # Wired here rather than left as a component someone remembers to
        # connect, for the reason `enforce()` gives about the kill switch: a
        # sidecar that ships evidence and polls containment but never learns
        # from the receipt that the list moved is a containment that arrives a
        # poll interval late, while everything looks correctly configured.
        if (
            distribution is not None
            and evidence is not None
            and getattr(evidence, "on_receipt", None) is None
        ):
            evidence.on_receipt = distribution.on_receipt
        #: Cumulative totals (UAI-147). Lives here rather than in the engine
        #: because it is state, and the engine's purity is what the latency
        #: budget and the fail-closed story rest on. Created unconditionally:
        #: a policy that declares no counters costs an empty dict lookup, and
        #: making it optional would mean a deployment can load a policy with a
        #: budget in it and silently not enforce the budget.
        self.counters = counters or Counters()

    def recover_counters(self) -> int:
        """Rebuild cumulative totals from the audit chain. Call once, at start-up.

        Without this a budget is reset by restarting the sidecar, which an
        agent that can crash its own process does for free — and a daily limit
        an attacker can re-arm on demand is not a limit. The chain is the right
        source because it is signed, append-only, and already records every
        decision along with what that decision added to each total.

        Returns how many deltas were applied, so a deployment can log it. A
        recovery that silently applies zero after a restart is indistinguishable
        from one that worked, and it is the failure worth noticing.
        """
        if self._chain is None or not self._engine.counter_ids:
            return 0
        return self.counters.replay(self._chain.entries())

    def enforce(self, action: Action) -> Decision:
        """Distribution state first, then policy.

        Wired here rather than left as a component someone remembers to call.
        This project has already shipped one security feature that was correct
        and unreachable (signing, UAI-145), and an unwired kill switch is worse
        than none: it is a button an operator believes they pressed.

        The order matters and is not negotiable. A contained principal is
        contained whatever the rules say, and a sidecar that cannot verify its
        policy must not consult it — otherwise the two failures that most need
        to override policy are the two that policy would overrule.
        """
        if self._distribution is not None:
            forced = self._distribution.gate(action)
            if forced is not None:
                return self.record(action, forced)

        totals = (
            self.counters.snapshot(action.principal.id, self._engine.counter_ids)
            if self._engine.counter_ids
            else None
        )
        return self.record(action, self._engine.decide(action, totals))

    def record(self, action: Action, decision: Decision, *, count: bool = True) -> Decision:
        """Chain and trace a decision that did NOT come from the policy engine.

        Some verdicts are structural rather than rule-driven — the gateway
        denying a request whose body it could not read, for instance. Those
        must land in the audit chain and the trace exactly like policy verdicts,
        or the evidence would show only the decisions the engine happened to
        make. `Decision.source` is what distinguishes them to a reader.

        `count=False` for a *finding*: a record beside a verdict (an
        unenrolled peer's protocol, an injection shape in a result, an
        identity refusal) that describes an action already decided and
        counted. Charging it to the policy's counters would spend a budget
        twice for one request, and a floor that reads the counter would trip
        at half its stated rate for exactly that traffic.
        """
        # Before the chain write, and unconditionally. If the write then fails
        # the caller aborts the action and this counted something that never
        # happened -- over-counting, which restricts, and which ages out of the
        # window on its own. The alternative ordering under-counts a spend that
        # did happen, and that is a fail-open bought for nothing.
        deltas = self._engine.deltas(action, decision) if count else {}
        for counter_id, value in deltas.items():
            self.counters.add(action.principal.id, counter_id, value)

        audit_error: Exception | None = None
        entry: dict | None = None
        if self._chain is not None:
            try:
                entry = self._chain.append_decision(action, decision, counters=deltas)
            except Exception as exc:
                audit_error = exc
        self._telemetry.record_decision(action, decision)

        # Only ship what the chain actually holds. Reporting a decision whose
        # chain write failed would put a row in someone's dashboard that cannot
        # be corroborated against the evidence it claims to summarise -- and
        # the dashboard is the copy, not the record.
        if self._evidence is not None and audit_error is None:
            self._evidence.record(action, decision, entry=entry)

        # Last, and after the decision is final. A candidate policy exists to
        # be measured, not consulted: evaluating it before this point would put
        # an unreviewed proposal in the decision path, which is the one thing
        # shadow mode must never do.
        if self._shadow is not None:
            self._shadow.compare(action, decision)

        if audit_error is not None:
            raise audit_error
        return decision

    async def enforce_with_approval(
        self, action: Action, *, summary: str = "", floored: bool | None = None
    ) -> ApprovalOutcome:
        """Decide, and if the verdict is DEFER, take it to a human.

        Returns an `ApprovalOutcome` in every case, so callers have one shape to
        handle whether or not a human was involved. For a non-DEFER verdict the
        outcome simply wraps it, with `kind` left None — nobody was asked.

        With no `approvals` configured a DEFER stays a DEFER: the caller is told
        the truth (this needs review and nothing here can obtain it) rather than
        being handed a synthesized deny that hides a missing configuration.
        Surfaces that cannot wait — the gateway — must still treat it as a
        refusal, which is exactly what they do today.
        """
        decision = self.enforce(action)
        if decision.verdict is not Verdict.DEFER or self.approvals is None:
            return ApprovalOutcome(decision=decision)

        request = ApprovalRequest(
            action=action,
            decision=decision,
            summary=summary,
            floored=decision.source == "floor" if floored is None else floored,
        )
        outcome = await self.approvals.resolve(request)
        self.record_approval(request, outcome)
        return outcome

    def record_approval(self, request: ApprovalRequest, outcome: ApprovalOutcome) -> None:
        """Chain and trace how a deferral was resolved.

        The resolution gets its own audit entry (joined to the decision by
        action digest) and its own span, so a DEFER that a human turned into an
        ALLOW shows both halves — the demand for review and the person who
        answered it.
        """
        audit_error: Exception | None = None
        if self._chain is not None:
            try:
                self._chain.append_approval(RecordedApproval.build(request, outcome))
            except Exception as exc:
                audit_error = exc
        self._telemetry.record_decision(request.action, outcome.decision)
        if audit_error is not None:
            raise audit_error
