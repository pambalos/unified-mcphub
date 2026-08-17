"""OIDC identity ingestion, and how provenance reaches the action record.

The other half of "integrate, don't compete" with identity vendors: they
establish who the agent is, this plane enforces what it may do, and the seam
is a verified JWT resolving to a principal id with honest provenance —
`derived` for a bearer, `attested` for an mTLS SAN, `assigned` for topology.
"""

import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from unified_enforce import Enforcer, ExtAuthzCore, OIDCValidator, PolicyEngine
from unified_enforce.extauthz import CheckInput, bearer_of

ISSUER = "https://idp.internal"
AUDIENCE = "unified-enforce"

POLICY = """
version: 1
rules:
  - id: crew-reads-ok
    match: {principal: "agent:crew-*", tool: "https://api.internal/**", verb: get}
    effect: allow
"""


@pytest.fixture(scope="module")
def keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    jwk["kid"] = "test-key"
    return key, {"keys": [jwk]}


def mint(key, **overrides):
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "crew-1",
        "exp": int(time.time()) + 300,
        **overrides,
    }
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": "test-key"})


def validator(jwks, **kwargs):
    return OIDCValidator(issuer=ISSUER, audience=AUDIENCE, jwks=jwks, **kwargs)


# --- the validator ---


def test_valid_token_resolves_a_namespaced_principal(keypair):
    key, jwks = keypair
    identity, problem = validator(jwks).verify(mint(key))
    assert problem is None
    assert identity.principal_id == "agent:crew-1"


def test_spiffe_subjects_pass_through_with_an_empty_prefix(keypair):
    key, jwks = keypair
    token = mint(key, sub="spiffe://cluster.local/ns/prod/sa/crew-1")
    identity, problem = validator(jwks, principal_prefix="").verify(token)
    assert problem is None
    assert identity.principal_id == "spiffe://cluster.local/ns/prod/sa/crew-1"


@pytest.mark.parametrize(
    "overrides",
    [
        {"aud": "someone-else"},
        {"iss": "https://evil.example"},
        {"exp": int(time.time()) - 3600},
        {"exp": None},  # a token that cannot expire is not a credential
        {"sub": None},
    ],
)
def test_bad_claims_are_problems_not_identities(keypair, overrides):
    key, jwks = keypair
    identity, problem = validator(jwks).verify(mint(key, **overrides))
    assert identity is None
    assert problem


def test_a_token_signed_by_the_wrong_key_is_rejected(keypair):
    _, jwks = keypair
    stranger = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    identity, problem = validator(jwks).verify(mint(stranger))
    assert identity is None
    assert problem


def test_garbage_is_a_problem_not_an_exception(keypair):
    _, jwks = keypair
    identity, problem = validator(jwks).verify("not-a-jwt")
    assert identity is None
    assert problem


def test_exactly_one_key_source_is_required():
    with pytest.raises(ValueError, match="exactly one"):
        OIDCValidator(issuer=ISSUER, audience=AUDIENCE)


# --- resolution precedence and provenance ---


def core(jwks=None):
    oidc = validator(jwks) if jwks is not None else None
    return ExtAuthzCore(Enforcer(PolicyEngine.from_yaml(POLICY)), oidc=oidc)


def test_bearer_of_parses_the_authorization_header():
    assert bearer_of({"authorization": "Bearer abc.def.ghi"}) == "abc.def.ghi"
    assert bearer_of({"authorization": "Basic dXNlcg=="}) is None
    assert bearer_of({}) is None


def test_mtls_outranks_a_valid_bearer(keypair):
    key, jwks = keypair
    pid, attestation, problem = core(jwks).resolve_principal(
        mtls="spiffe://cluster.local/ns/prod/sa/other", bearer=mint(key)
    )
    assert pid == "spiffe://cluster.local/ns/prod/sa/other"
    assert attestation == "attested"
    assert problem is None


def test_a_verified_bearer_is_derived(keypair):
    key, jwks = keypair
    pid, attestation, problem = core(jwks).resolve_principal(bearer=mint(key))
    assert (pid, attestation, problem) == ("agent:crew-1", "derived", None)


def test_a_header_identity_stays_assigned(keypair):
    _, jwks = keypair
    pid, attestation, problem = core(jwks).resolve_principal(header="agent:crew-9")
    assert (pid, attestation, problem) == ("agent:crew-9", "assigned", None)


def test_an_invalid_bearer_is_a_problem_not_a_fallthrough(keypair):
    _, jwks = keypair
    _, _, problem = core(jwks).resolve_principal(bearer="expired.or.garbage")
    assert problem


def test_a_bearer_with_no_validator_is_a_problem():
    _, _, problem = core().resolve_principal(bearer="any.token.at-all")
    assert problem == "bearer presented but no oidc configured"


# --- the deny path through check() ---


def request_with(pid, attestation, problem):
    return CheckInput(
        principal_id=pid,
        attestation=attestation,
        identity_problem=problem,
        method="GET",
        host="api.internal",
        path="/v1/users",
    )


def test_an_identity_problem_is_a_structural_deny(keypair):
    key, jwks = keypair
    c = core(jwks)
    pid, attestation, problem = c.resolve_principal(bearer="bad-token")
    result = c.check(request_with(pid, attestation, problem))
    assert not result.allowed
    assert result.decision.source == "identity_invalid"
    # The action still records who the request would have been enforced as,
    # and the problem rides in context.extra for the auditor.
    assert result.action.context.extra["identity"]


def test_a_valid_bearer_flows_through_to_an_allow(keypair):
    key, jwks = keypair
    c = core(jwks)
    pid, attestation, problem = c.resolve_principal(bearer=mint(key))
    result = c.check(request_with(pid, attestation, problem))
    assert result.allowed
    assert result.action.principal.attestation == "derived"
