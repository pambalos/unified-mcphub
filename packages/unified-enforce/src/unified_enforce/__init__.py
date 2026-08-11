"""unified-enforce — the enforcement plane engine.

Canonicalize → decide → record:

    engine = PolicyEngine.from_file("policy.yaml")
    action = Action.build(principal=Principal(id="agent:x"), tool="mcp://s/t",
                          verb="call", resource="*")
    decision = engine.decide(action)
    chain.append_decision(action, decision)
"""

from .action import Action, ActionContext, Principal, SCHEMA_VERSION
from .audit import AuditChain, VerifyResult
from .canonical import CanonicalizationError, GENESIS_HASH, canonical_bytes, digest, sha256_hex
from .policy import Decision, Match, PolicyDoc, PolicyEngine, PolicyError, Rule, Verdict
from .signing import SignedAction, Signer

__all__ = [
    "SCHEMA_VERSION",
    "GENESIS_HASH",
    "Action",
    "ActionContext",
    "AuditChain",
    "CanonicalizationError",
    "Decision",
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
    "digest",
    "sha256_hex",
]
