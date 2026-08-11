"""Enforcer — the engine's front door: decide, then record everywhere.

Composes the three E1 primitives plus telemetry into the canonical loop:
decide (pure, <10 ms) → audit chain (court-grade record) → OTel span (optional).
Recording failures must never change a verdict that was already decided — but an
audit failure cannot be swallowed either (an unrecorded ALLOW is a hole in the
evidence), so audit errors raise *after* telemetry still gets the decision out.
"""

from __future__ import annotations

from .action import Action
from .audit import AuditChain
from .policy import Decision, PolicyEngine
from .telemetry import Telemetry


class Enforcer:
    def __init__(
        self,
        engine: PolicyEngine,
        chain: AuditChain | None = None,
        telemetry: Telemetry | None = None,
    ) -> None:
        self._engine = engine
        self._chain = chain
        self._telemetry = telemetry or Telemetry.disabled()

    def enforce(self, action: Action) -> Decision:
        decision = self._engine.decide(action)
        audit_error: Exception | None = None
        if self._chain is not None:
            try:
                self._chain.append_decision(action, decision)
            except Exception as exc:
                audit_error = exc
        self._telemetry.record_decision(action, decision)
        if audit_error is not None:
            raise audit_error
        return decision
