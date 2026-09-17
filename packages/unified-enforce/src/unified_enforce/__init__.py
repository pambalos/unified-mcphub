"""unified-enforce — the enforcement plane engine.

Canonicalize → decide → record:

    engine = PolicyEngine.from_file("policy.yaml")
    action = Action.build(principal=Principal(id="agent:x"), tool="mcp://s/t",
                          verb="call", resource="*")
    decision = engine.decide(action)
    chain.append_decision(action, decision)
"""

from .action import (
    Action,
    ActionContext,
    Attestation,
    Hop,
    Principal,
    SCHEMA_VERSION,
    grade_at_least,
)
from .approval import (
    ApprovalChannel,
    ApprovalKind,
    ApprovalOutcome,
    ApprovalRequest,
    ApprovalResponse,
    Approvals,
    Approver,
    RecordedApproval,
    SignedResolution,
)
from .audit import AuditChain, HashChainWriter, VerifyResult
from .canonical import CanonicalizationError, GENESIS_HASH, canonical_bytes, digest, sha256_hex
from .enforcer import Enforcer
from .extauthz import (
    CORRELATION_HEADER,
    PRINCIPAL_HEADER,
    BodyInspection,
    CheckInput,
    CheckResult,
    ConnInput,
    ExtAuthzCore,
    create_http_service,
)
from .identity import OIDCValidator, VerifiedIdentity
from .index import AuditIndex
from .policy import (
    AttestationFloor,
    Decision,
    Floor,
    Match,
    PolicyDoc,
    PolicyEngine,
    PolicyError,
    Rule,
    Verdict,
)
from .replay import Divergence, ReplayReport, replay
from .signing import SignedAction, Signer, verify_bytes
from .telemetry import Telemetry

__all__ = [
    "CORRELATION_HEADER",
    "PRINCIPAL_HEADER",
    "SCHEMA_VERSION",
    "GENESIS_HASH",
    "Action",
    "ActionContext",
    "ApprovalChannel",
    "ApprovalKind",
    "ApprovalOutcome",
    "ApprovalRequest",
    "ApprovalResponse",
    "Approvals",
    "Approver",
    "SignedResolution",
    "AuditChain",
    "AuditIndex",
    "BodyInspection",
    "RecordedApproval",
    "CanonicalizationError",
    "CheckInput",
    "ConnInput",
    "OIDCValidator",
    "VerifiedIdentity",
    "CheckResult",
    "Decision",
    "Divergence",
    "ExtAuthzCore",
    "Enforcer",
    "Floor",
    "HashChainWriter",
    "ReplayReport",
    "Telemetry",
    "replay",
    "Match",
    "PolicyDoc",
    "PolicyEngine",
    "PolicyError",
    "Attestation",
    "AttestationFloor",
    "Hop",
    "Principal",
    "grade_at_least",
    "Rule",
    "SignedAction",
    "Signer",
    "verify_bytes",
    "Verdict",
    "VerifyResult",
    "canonical_bytes",
    "create_http_service",
    "digest",
    "sha256_hex",
]
