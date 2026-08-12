"""unified-sdk — annotate agent actions with business semantics.

*The proxy is the lock; the SDK is the label.* The gateway sees
`POST /v1/refunds`; this sees "a $8,000 refund to customer 42, touching PII".

    from unified_sdk import UnifiedAI

    ua = UnifiedAI.local("policy.yaml", principal="agent:crew-1",
                         audit_dir="~/.unified/audit")

    @ua.action("stripe://refunds", verb="create",
               resource="customer:{customer_id}", params=["amount"])
    def issue_refund(customer_id: str, amount: Decimal) -> None:
        ...

    issue_refund("42", Decimal("8000.00"))   # raises Denied if policy says no

Optional by design: an application that never calls this is still enforced at
the network layer (E3). The SDK raises the resolution of policy — it is not
what makes enforcement happen.
"""

from .adapters import ToolGuard
from .client import CORRELATION_HEADER, Acting, UnifiedAI
from .errors import ApprovalRequired, Denied, EnforcementError

__all__ = [
    "CORRELATION_HEADER",
    "Acting",
    "ApprovalRequired",
    "Denied",
    "EnforcementError",
    "ToolGuard",
    "UnifiedAI",
]
