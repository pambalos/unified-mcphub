"""OIDC identity ingestion — verify who the identity vendor says is calling.

The plane's position is integrate, don't compete: agent-identity products
(and plain IdPs) mint workload tokens, and every rule this plane enforces
keys on `principal.id` — so the seam is small and exact. A caller presents a
bearer JWT, this module verifies it against ONE configured issuer, and the
principal it yields is recorded with `attestation="derived"`: proven to the
strength of a bearer secret, which is what a JWT is. An mTLS SAN still
outranks it (`attested` — possession of a channel, not a string).

No I/O on the decision path. Keys come from a static JWKS (the air-gapped
answer, and the reason `jwks` accepts a plain dict or file) or from
`jwks_uri`, fetched once at construction and cached by PyJWT's JWKS client —
a refresh happens only on an unknown key id, which is a rotation event, not
a request event.

Needs the [identity] extra: pip install 'unified-enforce[identity]'.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_INSTALL_HINT = "OIDC ingestion needs the identity extra — pip install 'unified-enforce[identity]'"

#: Claims every token must carry. `exp` is non-negotiable: a bearer token
#: that cannot expire is a credential leak with no end date.
_REQUIRED_CLAIMS = ["exp", "iss", "sub", "aud"]


@dataclass
class VerifiedIdentity:
    """What a valid token established. `principal_id` is ready for policy."""

    principal_id: str
    claims: dict[str, Any] = field(repr=False, default_factory=dict)


class OIDCValidator:
    """Verify bearer JWTs from one configured issuer.

    One issuer per validator on purpose: "accept tokens from anywhere
    plausible" is how audience-confusion bugs ship. A deployment trusting two
    identity providers configures two validators explicitly.

    `principal_prefix` namespaces the subject into the plane's principal
    scheme (`agent:<sub>` by default). Set it to `""` when the IdP already
    issues namespaced subjects — e.g. SPIFFE JWT-SVIDs, whose `sub` is the
    full `spiffe://...` ID that policy globs match directly.
    """

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        jwks: dict[str, Any] | str | Path | None = None,
        jwks_uri: str | None = None,
        principal_claim: str = "sub",
        principal_prefix: str = "agent:",
        leeway_seconds: float = 30.0,
    ) -> None:
        try:
            import jwt  # noqa: F401
        except ImportError as exc:  # pragma: no cover - exercised only without the extra
            raise RuntimeError(_INSTALL_HINT) from exc
        if (jwks is None) == (jwks_uri is None):
            raise ValueError("configure exactly one of jwks (static) or jwks_uri (fetched)")
        self._issuer = issuer
        self._audience = audience
        self._claim = principal_claim
        self._prefix = principal_prefix
        self._leeway = leeway_seconds
        self._static_keys: dict[str, Any] | None = None
        self._jwks_client: Any = None
        if jwks is not None:
            jwks_dict: dict[str, Any] = (
                json.loads(Path(jwks).read_text()) if isinstance(jwks, (str, Path)) else jwks
            )
            self._static_keys = self._index_jwks(jwks_dict)
        elif jwks_uri is not None:
            from jwt import PyJWKClient

            # Constructed eagerly so the first fetch happens at startup, where
            # an unreachable issuer is a loud deployment error rather than a
            # latency spike (or an outage) on the first enforced request.
            self._jwks_client = PyJWKClient(jwks_uri, cache_keys=True)
            self._jwks_client.get_jwk_set()

    @staticmethod
    def _index_jwks(jwks: dict[str, Any]) -> dict[str, Any]:
        from jwt import PyJWK

        keys = {}
        for entry in jwks.get("keys", []):
            key = PyJWK.from_dict(entry)
            keys[entry.get("kid")] = key
        if not keys:
            raise ValueError("static JWKS contains no keys")
        return keys

    def _key_for(self, token: str) -> Any:
        import jwt

        if self._jwks_client is not None:
            return self._jwks_client.get_signing_key_from_jwt(token).key
        keys = self._static_keys
        assert keys is not None  # ctor guarantees exactly one key source
        kid = jwt.get_unverified_header(token).get("kid")
        key = keys.get(kid) if kid else None
        if key is None and len(keys) == 1:
            # A single-key JWKS may serve tokens with no kid; ambiguity only
            # exists when there is more than one key to be ambiguous between.
            key = next(iter(keys.values()))
        if key is None:
            raise jwt.InvalidTokenError(f"no key for kid={kid!r}")
        return key.key

    def verify(self, token: str) -> tuple[VerifiedIdentity | None, str | None]:
        """(identity, None) for a valid token, (None, problem) otherwise.

        A problem string rather than an exception, because the caller's next
        move is to record a structural deny with it — presenting a credential
        that fails verification is an audit event, not a crash.
        """
        import jwt

        try:
            claims = jwt.decode(
                token,
                self._key_for(token),
                algorithms=["RS256", "ES256", "EdDSA"],
                audience=self._audience,
                issuer=self._issuer,
                leeway=self._leeway,
                options={"require": _REQUIRED_CLAIMS},
            )
        except jwt.PyJWTError as exc:
            return None, f"{type(exc).__name__}: {exc}"
        subject = claims.get(self._claim)
        if not isinstance(subject, str) or not subject:
            return None, f"claim {self._claim!r} is missing or not a string"
        return VerifiedIdentity(principal_id=f"{self._prefix}{subject}", claims=claims), None
