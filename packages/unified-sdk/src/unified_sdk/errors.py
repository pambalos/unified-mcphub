"""What the SDK raises when a verdict is not ALLOW.

Both carry the `Decision` and the `Action`, so an application can log the rule
that stopped it, and an operator can find the same action in the audit chain by
digest without correlating on timestamps.
"""

from __future__ import annotations

from unified_enforce import Action, Decision


class EnforcementError(Exception):
    """Base class — catch this to handle any non-allow verdict uniformly."""

    def __init__(self, action: Action, decision: Decision) -> None:
        self.action = action
        self.decision = decision
        self.digest = action.digest()
        rule = decision.rule_id or decision.source
        super().__init__(
            f"{decision.verdict.value}: {action.verb} {action.tool} "
            f"(rule={rule}, action={self.digest[:12]})"
            + (f" — {decision.reason}" if decision.reason else "")
        )


class Denied(EnforcementError):
    """Policy said no. Retrying without changing the action will say no again."""


class ApprovalRequired(EnforcementError):
    """Policy deferred to a human, and no approval channel is wired up yet.

    Distinct from Denied because the two call for different handling: a DEFER
    is a decision that has not been made, so an agent that treats it as a
    permanent refusal will abandon work a human would have approved. Once the
    approval contract lands in the engine, this is the exception that grows a
    resolution path rather than a new type.
    """
