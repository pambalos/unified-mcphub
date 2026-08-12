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
from .distribution import Distribution
from .evidence import EvidenceShipper
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
    ) -> None:
        self._engine = engine
        self._chain = chain
        self._telemetry = telemetry or Telemetry.disabled()
        self.approvals = approvals
        self._distribution = distribution
        self._evidence = evidence

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
        return self.record(action, self._engine.decide(action))

    def record(self, action: Action, decision: Decision) -> Decision:
        """Chain and trace a decision that did NOT come from the policy engine.

        Some verdicts are structural rather than rule-driven — the gateway
        denying a request whose body it could not read, for instance. Those
        must land in the audit chain and the trace exactly like policy verdicts,
        or the evidence would show only the decisions the engine happened to
        make. `Decision.source` is what distinguishes them to a reader.
        """
        audit_error: Exception | None = None
        entry: dict | None = None
        if self._chain is not None:
            try:
                entry = self._chain.append_decision(action, decision)
            except Exception as exc:
                audit_error = exc
        self._telemetry.record_decision(action, decision)

        # Only ship what the chain actually holds. Reporting a decision whose
        # chain write failed would put a row in someone's dashboard that cannot
        # be corroborated against the evidence it claims to summarise -- and
        # the dashboard is the copy, not the record.
        if self._evidence is not None and audit_error is None:
            self._evidence.record(action, decision, entry=entry)

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
