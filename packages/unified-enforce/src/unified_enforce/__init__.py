"""unified-enforce — the enforcement plane engine.

Canonicalize → decide → record:

    engine = PolicyEngine.from_file("policy.yaml")
    action = Action.build(principal=Principal(id="agent:x"), tool="mcp://s/t",
                          verb="call", resource="*")
    decision = engine.decide(action)
    chain.append_decision(action, decision)
"""

from .action import Action, ActionContext, Principal, SCHEMA_VERSION
from .audit import AuditChain, HashChainWriter, VerifyResult
from .canonical import CanonicalizationError, GENESIS_HASH, canonical_bytes, digest, sha256_hex
from .enforcer import Enforcer
from .extauthz import (
    BodyInspection,
    CheckInput,
    CheckResult,
    ExtAuthzCore,
    create_http_service,
)
from .index import AuditIndex
from .policy import Decision, Floor, Match, PolicyDoc, PolicyEngine, PolicyError, Rule, Verdict
from .replay import Divergence, ReplayReport, replay
from .signing import SignedAction, Signer
from .telemetry import Telemetry

__all__ = [
    "SCHEMA_VERSION",
    "GENESIS_HASH",
    "Action",
    "ActionContext",
    "AuditChain",
    "AuditIndex",
    "BodyInspection",
    "CanonicalizationError",
    "CheckInput",
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
    "Principal",
    "Rule",
    "SignedAction",
    "Signer",
    "Verdict",
    "VerifyResult",
    "canonical_bytes",
    "create_http_service",
    "digest",
    "sha256_hex",
]
