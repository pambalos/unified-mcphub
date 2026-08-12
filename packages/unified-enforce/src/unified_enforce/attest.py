"""Verifying signed distribution artifacts — policy bundles and revocation lists.

The canonical implementation. A sidecar runs this to decide whether to trust a
policy bundle it was handed, and the control plane vendors a copy so that both
ends of the wire are the same code rather than two implementations that agree
until they do not. See `specs/enforce/policy-distribution.v1.md`.

This module is the security boundary for the highest-value attack on the
architecture: an attacker who can push policy does not need to defeat the
enforcement plane, they push allow-all and walk through it, and the audit chain
faithfully records that nothing was violated.

Three things shape everything below.

**Signatures cover exact bytes.** The manifest travels verbatim inside a JWS
payload and the signature is over `BASE64URL(protected) || '.' ||
BASE64URL(payload)` per RFC 7515. There is no canonical form to agree on, so the
class of bug that hit decision signing — where a re-serialised field differed
between producer and consumer and the signature verified only where it was
made — cannot occur here at all.

**Nothing raises on hostile input.** Every check returns a `Verdict` carrying a
machine-readable reason. A verifier that throws invites a caller to wrap it in
`try/except`, and the except branch is where somebody eventually decides to let
the bundle through. The reasons are distinct because the failure matrix needs
different alarms for "cannot verify", "rolled back" and "expired" — they are not
the same event and must not collapse into one.

**Freshness needs a version *and* an expiry.** A monotonic version alone
protects neither a freshly started sidecar (no previous version, so no floor —
it accepts a genuine old bundle) nor against a freeze, where an attacker simply
stops serving updates and the fleet enforces last month's policy forever while
everything looks green.

Deliberately dependency-light: `cryptography` and the standard library. It is
vendored into another codebase, and a verifier that drags a dependency tree
behind it does not get vendored, it gets reimplemented.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MANIFEST_SCHEMA = "unified.policy-bundle/v1"
REVOCATIONS_SCHEMA = "unified.revocations/v1"
KEYSET_SCHEMA = "unified.keyset/v1"

#: The only signature algorithm accepted. Checked explicitly on every document
#: so a `"alg": "none"` header — or any other algorithm confusion — is rejected
#: before a key is even looked up.
ALG = "EdDSA"

#: A pinned root has no expiry of its own; see `load_key_set`.
_FOREVER = 2**62

#: Tolerated clock difference when checking expiry. Correctness depends on time
#: once expiry exists; this bounds how much disagreement is survivable.
DEFAULT_SKEW_MS = 60_000


class Reason(StrEnum):
    """Why a document was refused. Distinct values because §5 alarms differ."""

    MALFORMED = "malformed"
    BAD_ALGORITHM = "bad_algorithm"
    UNKNOWN_KEY = "unknown_key"
    WRONG_ROLE = "wrong_role"
    KEY_EXPIRED = "key_expired"
    BAD_SIGNATURE = "bad_signature"
    KEYSET_EXPIRED = "keyset_expired"
    WRONG_SCHEMA = "wrong_schema"
    WRONG_FLEET = "wrong_fleet"
    EXPIRED = "expired"
    ROLLBACK = "rollback"
    STALE_REFRESH = "stale_refresh"
    FILE_MISSING = "file_missing"
    FILE_TAMPERED = "file_tampered"
    FILE_UNEXPECTED = "file_unexpected"


@dataclass(frozen=True)
class Verdict:
    """Accepted, or refused with a reason. Never an exception."""

    ok: bool
    reason: Reason | None = None
    detail: str = ""
    payload: dict[str, Any] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return self.ok


def _refuse(reason: Reason, detail: str = "") -> Verdict:
    return Verdict(ok=False, reason=reason, detail=detail)


# --- base64url without padding -----------------------------------------------


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def unb64u(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


# --- JWS ----------------------------------------------------------------------


def signing_input(protected_b64: str, payload_b64: str) -> bytes:
    """RFC 7515 §5.1. Defined by the standard rather than by us on purpose."""
    return f"{protected_b64}.{payload_b64}".encode("ascii")


def sign_bytes(payload: bytes, signer: Any, kid: str) -> dict[str, Any]:
    """Produce a JWS General JSON Serialization envelope over `payload`.

    `signatures` is a list even with one entry, because a bundle eventually
    needs to carry both our signature and the customer's (spec §6) and that
    must not require a format change.
    """
    protected_b64 = b64u(json.dumps({"alg": ALG, "kid": kid}, separators=(",", ":")).encode())
    payload_b64 = b64u(payload)
    signature = signer.sign(signing_input(protected_b64, payload_b64))
    return {
        "payload": payload_b64,
        "signatures": [{"protected": protected_b64, "signature": b64u(signature)}],
    }


@dataclass(frozen=True)
class VerificationKey:
    kid: str
    public_key: str
    role: str
    expires_at_ms: int


def _verify_envelope(
    envelope: Any,
    keys: Mapping[str, VerificationKey],
    *,
    role: str,
    now_ms: int,
    required_kids: set[str] | None = None,
) -> Verdict:
    """Verify a JWS envelope and return its decoded payload.

    Accepts if **any** signature verifies against a permitted key. That is the
    right rule for a list whose purpose is multiple signers; when customer-held
    keys land, `required_kids` is how a deployment demands a specific one rather
    than settling for whichever it recognises.
    """
    if not isinstance(envelope, dict):
        return _refuse(Reason.MALFORMED, "envelope is not an object")

    payload_b64 = envelope.get("payload")
    signatures = envelope.get("signatures")
    if not isinstance(payload_b64, str) or not isinstance(signatures, list) or not signatures:
        return _refuse(Reason.MALFORMED, "missing payload or signatures")

    try:
        payload = json.loads(unb64u(payload_b64))
    except Exception:  # noqa: BLE001 — any decode failure is one refusal
        return _refuse(Reason.MALFORMED, "payload is not base64url JSON")
    if not isinstance(payload, dict):
        return _refuse(Reason.MALFORMED, "payload is not an object")

    last = _refuse(Reason.BAD_SIGNATURE, "no signature verified")

    for entry in signatures:
        if not isinstance(entry, dict):
            last = _refuse(Reason.MALFORMED, "signature entry is not an object")
            continue

        protected_b64 = entry.get("protected")
        signature_b64 = entry.get("signature")
        if not isinstance(protected_b64, str) or not isinstance(signature_b64, str):
            last = _refuse(Reason.MALFORMED, "signature entry missing fields")
            continue

        try:
            header = json.loads(unb64u(protected_b64))
        except Exception:  # noqa: BLE001
            last = _refuse(Reason.MALFORMED, "protected header is not base64url JSON")
            continue

        # Checked before any key lookup: `"alg": "none"` and algorithm
        # substitution are rejected on the header alone.
        if header.get("alg") != ALG:
            last = _refuse(Reason.BAD_ALGORITHM, f"alg {header.get('alg')!r} is not {ALG}")
            continue

        kid = header.get("kid")
        if not isinstance(kid, str) or kid not in keys:
            last = _refuse(Reason.UNKNOWN_KEY, f"kid {kid!r} is not in the key set")
            continue
        if required_kids is not None and kid not in required_kids:
            last = _refuse(Reason.UNKNOWN_KEY, f"kid {kid!r} is not a required signer")
            continue

        key = keys[kid]
        # A key issued for signing decisions must not be able to sign policy.
        # Compromise of one role should not silently confer the other.
        if key.role != role:
            last = _refuse(Reason.WRONG_ROLE, f"key {kid} has role {key.role!r}, needed {role!r}")
            continue
        if key.expires_at_ms <= now_ms:
            last = _refuse(Reason.KEY_EXPIRED, f"key {kid} expired")
            continue

        try:
            Ed25519PublicKey.from_public_bytes(unb64u(key.public_key)).verify(
                unb64u(signature_b64), signing_input(protected_b64, payload_b64)
            )
        except (InvalidSignature, ValueError, TypeError):
            last = _refuse(Reason.BAD_SIGNATURE, f"signature for {kid} did not verify")
            continue

        return Verdict(ok=True, payload=payload)

    return last


# --- key set ------------------------------------------------------------------


def key_id(public_key_b64: str) -> str:
    """A key's name, derived from the key itself.

    Same derivation as `signing.public_key_id`, so a `kid` cannot be claimed
    independently of the key material it refers to — and a root-signed key set
    can be checked against the root a sidecar actually pinned rather than
    against whatever name the document asserts.
    """
    return hashlib.sha256(unb64u(public_key_b64)).hexdigest()[:16]


def load_key_set(
    envelope: Any,
    *,
    root_public_key: str,
    now_ms: int,
    skew_ms: int = DEFAULT_SKEW_MS,
) -> tuple[Verdict, dict[str, VerificationKey]]:
    """Verify a root-signed key set and return the keys it authorises.

    The sidecar pins **only** the root public key, at enrolment. Every other key
    reaches it inside one of these. That is what makes rotation a signed message
    rather than a fleet-wide re-enrolment — and rotation that requires
    re-enrolling every sidecar is rotation that never happens.

    The root's own `kid` is derived from the pinned key, so a forged key set
    cannot nominate itself as root by claiming a different name.
    """
    root_kid = key_id(root_public_key)
    root = VerificationKey(
        kid=root_kid,
        public_key=root_public_key,
        role="root",
        # The pinned root is trusted for as long as an operator leaves it
        # pinned; rotating it is a re-enrolment, by design. The expiry that
        # matters operationally is on the key set it signs, checked below.
        expires_at_ms=_FOREVER,
    )

    verdict = _verify_envelope(envelope, {root_kid: root}, role="root", now_ms=now_ms)
    if not verdict:
        return verdict, {}

    payload = verdict.payload
    if payload.get("schema") != KEYSET_SCHEMA:
        return _refuse(Reason.WRONG_SCHEMA, str(payload.get("schema"))), {}

    expires = payload.get("expires_at_ms")
    if not isinstance(expires, int):
        return _refuse(Reason.MALFORMED, "key set has no integer expires_at_ms"), {}
    if expires + skew_ms <= now_ms:
        return _refuse(Reason.KEYSET_EXPIRED, "key set has expired"), {}

    keys: dict[str, VerificationKey] = {}
    for raw in payload.get("keys") or []:
        if not isinstance(raw, dict):
            return _refuse(Reason.MALFORMED, "key entry is not an object"), {}
        try:
            public_key = str(raw["public_key"])
            declared = str(raw["kid"])
            entry = VerificationKey(
                kid=declared,
                public_key=public_key,
                role=str(raw["role"]),
                expires_at_ms=int(raw["expires_at_ms"]),
            )
        except (KeyError, TypeError, ValueError):
            return _refuse(Reason.MALFORMED, "key entry is missing fields"), {}

        # The name must match the material. Otherwise two entries could share a
        # kid, or an entry could borrow the name of a key with a different role,
        # and which one a lookup finds becomes an ordering accident.
        if declared != key_id(public_key):
            return _refuse(Reason.MALFORMED, f"kid {declared!r} does not match its key"), {}

        keys[declared] = entry

    return Verdict(ok=True, payload=payload), keys


# --- manifests ----------------------------------------------------------------


@dataclass(frozen=True)
class BundleState:
    """What a sidecar currently holds. `None` means it holds nothing yet."""

    version: int
    expires_at_ms: int


def accept_manifest(
    envelope: Any,
    keys: Mapping[str, VerificationKey],
    *,
    fleet_id: str,
    current: BundleState | None,
    now_ms: int,
    skew_ms: int = DEFAULT_SKEW_MS,
    required_kids: set[str] | None = None,
    ignore_expiry: bool = False,
) -> Verdict:
    """A policy manifest. See `accept_document`."""
    return accept_document(
        envelope,
        keys,
        schema=MANIFEST_SCHEMA,
        fleet_id=fleet_id,
        current=current,
        now_ms=now_ms,
        skew_ms=skew_ms,
        required_kids=required_kids,
        ignore_expiry=ignore_expiry,
    )


def accept_revocations(
    envelope: Any,
    keys: Mapping[str, VerificationKey],
    *,
    fleet_id: str,
    current: BundleState | None,
    now_ms: int,
    skew_ms: int = DEFAULT_SKEW_MS,
    required_kids: set[str] | None = None,
    ignore_expiry: bool = False,
) -> Verdict:
    """A revocation list — the kill switch's wire format.

    Identical verification to a policy manifest, deliberately: one envelope,
    one set of freshness rules, one implementation to attack. What differs is
    what a caller does with a refusal, and that difference is the reason these
    are separate artifacts.

    An expired *policy* bundle means the rules are stale, and a sidecar keeps
    enforcing them. An expired *revocation list* means the sidecar cannot know
    whether an agent has been contained — so it must escalate rather than
    assume nothing was revoked. Getting those the same way round would make a
    kill switch fail silently open, which is the one failure it exists to
    prevent. That decision belongs to the caller; this function only refuses.
    """
    return accept_document(
        envelope,
        keys,
        schema=REVOCATIONS_SCHEMA,
        fleet_id=fleet_id,
        current=current,
        now_ms=now_ms,
        skew_ms=skew_ms,
        required_kids=required_kids,
        ignore_expiry=ignore_expiry,
    )


def accept_document(
    envelope: Any,
    keys: Mapping[str, VerificationKey],
    *,
    schema: str,
    fleet_id: str,
    current: BundleState | None,
    now_ms: int,
    skew_ms: int = DEFAULT_SKEW_MS,
    required_kids: set[str] | None = None,
    ignore_expiry: bool = False,
) -> Verdict:
    """The acceptance rule from spec §2, shared by every signed artifact.

    One implementation rather than one per document type. The freshness rule is
    the subtle part — the equal-version refresh branch in particular — and two
    copies of it would drift, leaving one artifact protected against rollback
    and the other not.

    `ignore_expiry` exists for exactly one caller: hydrating a cache at
    startup. Every other check still applies — signature, key role, fleet,
    schema, rollback — so an expired artifact is recovered for *what it said*
    without being treated as current. The distinction matters because a
    restart would otherwise forget which agents are contained: a hard `deny`
    containment would silently become whatever the caller does about an
    unknown list, and losing a containment during a restart is losing it at
    the worst moment. The caller is then responsible for marking the result
    stale, which is what turns "remembered" into "not trusted as current".

    Order matters: signature first, then identity, then freshness. Checking
    freshness on an unverified document would let an attacker learn a fleet's
    current policy version by watching which forgeries are rejected differently.
    """
    verdict = _verify_envelope(
        envelope, keys, role="policy", now_ms=now_ms, required_kids=required_kids
    )
    if not verdict:
        return verdict

    m = verdict.payload
    # Checked against the *expected* schema, so a validly signed revocation
    # list cannot be served in place of a policy manifest or vice versa. Both
    # are signed by the same role, so nothing else would separate them.
    if m.get("schema") != schema:
        return _refuse(Reason.WRONG_SCHEMA, str(m.get("schema")))

    # A `staging` bundle must never apply in `production`. Staging is always the
    # weakest environment, so without this its policy becomes everyone's.
    if m.get("fleet_id") != fleet_id:
        return _refuse(Reason.WRONG_FLEET, f"bundle is for {m.get('fleet_id')!r}")

    version = m.get("version")
    expires = m.get("expires_at_ms")
    if not isinstance(version, int) or not isinstance(expires, int):
        return _refuse(Reason.MALFORMED, "version and expires_at_ms must be integers")

    # Expiry, not the version, is what protects a freshly started sidecar: it
    # has no previous version to compare against, so a genuine old bundle would
    # otherwise be accepted. It is also what turns a freeze — an attacker who
    # simply stops serving updates — into a visible state rather than silence.
    if not ignore_expiry and expires + skew_ms <= now_ms:
        return _refuse(Reason.EXPIRED, "bundle has expired")

    if current is not None:
        if version < current.version:
            return _refuse(Reason.ROLLBACK, f"version {version} < current {current.version}")
        # Equal versions are the refresh path: the control plane re-signs the
        # same policy with a later expiry so freshness does not burn a version
        # number every few hours. An equal version with an equal or earlier
        # expiry is a replay of a refresh, and buys an attacker time.
        if version == current.version and expires <= current.expires_at_ms:
            return _refuse(Reason.STALE_REFRESH, "same version without a later expiry")

    return Verdict(ok=True, payload=m)


def verify_files(manifest: Mapping[str, Any], files: Mapping[str, bytes]) -> Verdict:
    """Check every file against the hash the manifest commits to.

    All or nothing. A partially applied bundle is a policy nobody wrote and
    nobody reviewed — worse than keeping the previous one, which at least
    someone approved.
    """
    listed = manifest.get("files") or []
    expected: dict[str, str] = {}

    for entry in listed:
        if not isinstance(entry, dict) or "path" not in entry or "sha256" not in entry:
            return _refuse(Reason.MALFORMED, "file entry is missing path or sha256")
        expected[str(entry["path"])] = str(entry["sha256"])

    for path, digest in expected.items():
        if path not in files:
            return _refuse(Reason.FILE_MISSING, path)
        if hashlib.sha256(files[path]).hexdigest() != digest:
            return _refuse(Reason.FILE_TAMPERED, path)

    # An unlisted file is refused rather than ignored. Ignoring it means a
    # directory the manifest never described can still be read by whatever
    # loads policy from disk, and "the signature covered everything" stops
    # being true.
    for path in files:
        if path not in expected:
            return _refuse(Reason.FILE_UNEXPECTED, path)

    return Verdict(ok=True, payload=dict(manifest))
