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

Approval resolutions are the exception and are handled at the bottom of this
file. They are signed over a canonical JSON form rather than a JWS envelope,
because the control plane stores the fields and composes the response from
them. That is a real difference in kind, so `canonical` and `verify_resolution`
are written to match the producer exactly and the producer's own test suite
runs against *this* code through the vendored copy — the byte-for-byte
agreement is checked rather than asserted in a comment.

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
#: The signed-decision payload version. `v1` carried the approver as a bare
#: string the console supplied; `v2` carries the derived approver object. Only
#: v2 is accepted, and that is the point of the version being inside the
#: signature: a verifier that accepted both would honour a self-declared name
#: from anything still speaking the old shape.
RESOLUTION_VERSION = 2
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
    NOT_RESOLVED = "not_resolved"
    WRONG_ACTION = "wrong_action"
    UNKNOWN_KIND = "unknown_kind"
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


# --- approval resolutions -------------------------------------------------------
#
# A resolved approval releases an action a policy floor deliberately held, so
# **anything able to produce the JSON below can unblock a blocked action**. TLS
# narrows who can and does not close it: a mis-issued certificate, an over-broad
# corporate trust store, DNS takeover, or a TLS-terminating proxy somebody added
# for observability all widen it again. TLS authenticates a peer; it says
# nothing about an artifact once that artifact is past the socket.
#
# So the object is verified, not the connection. Four bindings do the work, and
# each closes a specific attack:
#
#   action_digest  a genuine allow cannot be moved onto a different action
#   fleet_id       one tenant's decision cannot be served to another
#   expires_at_ms  a captured allow is an answer, not a standing credential
#   approver       who authorised it cannot be rewritten after the fact
#
# The nonce is deliberately *not* a replay defence here. A sidecar legitimately
# re-polls the same decision for the same action and must get the same answer;
# replay onto a different action is stopped by the digest and replay later by
# the expiry. It distinguishes two otherwise identical decisions, nothing more.


class CanonicalisationError(Exception):
    """A payload that cannot be canonicalised, and therefore cannot be checked."""


def canonical(payload: Mapping[str, Any]) -> bytes:
    """Deterministic bytes for a resolution payload.

    Must match the producer exactly: sorted keys, no incidental whitespace,
    UTF-8, and **floats refused**. A float has no portable textual
    representation, so a signature over one verifies on the machine that made it
    and fails elsewhere — an intermittent, environment-dependent authentication
    failure, which is both miserable to diagnose and likely to be "fixed" by
    disabling the check.

    Refusing floats here is not symmetry for its own sake. The producer cannot
    have signed a payload containing one, so a float arriving in a response
    means what is on the wire is not what was signed.
    """

    def check(value: Any) -> None:
        if isinstance(value, float):
            raise CanonicalisationError("floats are not signable")
        if isinstance(value, Mapping):
            for v in value.values():
                check(v)
        elif isinstance(value, (list, tuple)):
            for v in value:
                check(v)

    check(payload)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def resolution_payload(
    *,
    action_digest: str,
    kind: str,
    approver: Mapping[str, Any],
    scope: Mapping[str, Any] | None,
    resolved_at_ms: int,
    expires_at_ms: int,
    nonce: str,
    fleet_id: str,
) -> dict[str, Any]:
    """Exactly what is signed.

    One function on each side of the wire, and the vendored copy makes them the
    same function. A verifier that reconstructs the payload independently is a
    standing opportunity for a field to be added on one side only — and the
    failure mode is a signature that stops verifying, which somebody eventually
    "fixes" by not checking it.

    `approver` is passed through whole rather than rebuilt from its parts. The
    response carries it as a nested object precisely so there is no
    reconstruction step to get subtly wrong.
    """
    return {
        "v": RESOLUTION_VERSION,
        "action_digest": action_digest,
        "approver": dict(approver),
        "expires_at_ms": expires_at_ms,
        "fleet_id": fleet_id,
        "kind": kind,
        "nonce": nonce,
        "resolved_at_ms": resolved_at_ms,
        "scope": dict(scope) if scope is not None else None,
    }


#: What a resolution may say. An unrecognised value is refused rather than
#: treated as a deny: it means this sidecar and the control plane disagree about
#: the vocabulary, and guessing in either direction is worse than refusing.
RESOLUTION_KINDS = frozenset({"allow", "allow_session", "allow_always", "deny", "deny_always"})

#: Every field of the approver the signature covers. Listed so a response that
#: omits one is malformed rather than silently canonicalising to something the
#: producer never signed.
APPROVER_FIELDS = ("sub", "email", "sid", "auth_time_ms")


def accept_resolution(
    response: Mapping[str, Any],
    keys: Mapping[str, VerificationKey],
    *,
    fleet_id: str,
    action_digest: str,
    now_ms: int,
    skew_ms: int = DEFAULT_SKEW_MS,
) -> Verdict:
    """Decide whether a polled decision may release the action it names.

    Returns a `Verdict` and never raises, like everything else here. **False
    must mean deny** — an allow nobody can vouch for does not release a held
    action, and treating "cannot verify" as anything other than a refusal
    defeats the entire mechanism.

    `action_digest` is the digest of the action *this sidecar asked about*,
    supplied by the caller rather than read from the response. That is the
    binding: a response is only ever accepted as an answer to the question that
    was actually asked, so a captured allow for a trivial action cannot be
    replayed against a payout.
    """
    status = response.get("status")
    if status != "resolved":
        # Not an error. The overwhelmingly common case is a human who has not
        # answered yet, and the caller polls again.
        return _refuse(Reason.NOT_RESOLVED, str(status))

    kind = response.get("kind")
    if kind not in RESOLUTION_KINDS:
        return _refuse(Reason.UNKNOWN_KIND, str(kind))

    approver = response.get("approver")
    if not isinstance(approver, Mapping) or any(f not in approver for f in APPROVER_FIELDS):
        return _refuse(Reason.MALFORMED, "resolution names no complete approver")

    signature_b64 = response.get("signature")
    kid = response.get("key_id")
    nonce = response.get("nonce")
    if not isinstance(signature_b64, str) or not isinstance(kid, str) or not isinstance(nonce, str):
        # Includes the unsigned case, which is what an attacker serving plain
        # JSON produces.
        return _refuse(Reason.MALFORMED, "resolution is unsigned")

    resolved_at_ms = response.get("resolved_at_ms")
    expires_at_ms = response.get("expires_at_ms")
    if not isinstance(resolved_at_ms, int) or not isinstance(expires_at_ms, int):
        # Integers, not formatted timestamps. The first version of this scheme
        # signed `.isoformat()` and broke between SQLite and Postgres, which
        # return naive and aware datetimes for the same column.
        return _refuse(Reason.MALFORMED, "timestamps are not integer milliseconds")

    # Bindings first, before any cryptography. They are cheap, and a decision
    # that is correctly signed but answers a different question is a more
    # alarming event than a bad signature — worth its own distinct reason
    # rather than being buried behind one.
    if response.get("action_digest") != action_digest:
        return _refuse(
            Reason.WRONG_ACTION,
            f"resolution names {str(response.get('action_digest'))[:12]}…, asked about "
            f"{action_digest[:12]}…",
        )
    if response.get("fleet_id") != fleet_id:
        return _refuse(Reason.WRONG_FLEET, f"resolution is for {response.get('fleet_id')!r}")
    if expires_at_ms + skew_ms <= now_ms:
        return _refuse(Reason.EXPIRED, "resolution has expired")

    key = keys.get(kid)
    if key is None:
        return _refuse(Reason.UNKNOWN_KEY, f"kid {kid!r} is not in the key set")
    # A compromised policy key must not also be able to release held actions.
    if key.role != "decision":
        return _refuse(Reason.WRONG_ROLE, f"key {kid} has role {key.role!r}, needed 'decision'")
    if key.expires_at_ms + skew_ms <= now_ms:
        return _refuse(Reason.KEY_EXPIRED, f"key {kid} expired")

    try:
        payload = canonical(
            resolution_payload(
                action_digest=action_digest,
                kind=kind,
                approver=approver,
                scope=response.get("scope"),
                resolved_at_ms=resolved_at_ms,
                expires_at_ms=expires_at_ms,
                nonce=nonce,
                fleet_id=fleet_id,
            )
        )
    except CanonicalisationError as exc:
        return _refuse(Reason.MALFORMED, str(exc))

    try:
        Ed25519PublicKey.from_public_bytes(unb64u(key.public_key)).verify(
            unb64u(signature_b64), payload
        )
    except (InvalidSignature, ValueError, TypeError):
        return _refuse(Reason.BAD_SIGNATURE, f"signature for {kid} did not verify")

    return Verdict(ok=True, payload=dict(response))


# --- evidence attestation -------------------------------------------------------
#
# **What is signed, and why it is not the chain entry.**
#
# The obvious move is to ship the audit chain's own per-entry signature and
# verify that. It buys less than it looks. The chain signs an entry *hash*,
# which covers the full entry including action content — and evidence carries
# metadata only, by design, so a receiver holding a summary cannot recompute
# that hash. It could check the signature over the hash, learn that some entry
# exists, and still have no reason to believe the summary beside it describes
# that entry. A malicious receiver could pair a genuine signature with a
# fabricated summary and it would verify.
#
# So the sidecar signs **the summary it sends**, with the chain position and
# hash inside the signed payload. That gives the property the chain signature
# only appears to: the receiver's stored copy is verifiable by anyone holding
# the reporter's public key, including against the receiver itself, and the
# chain hash inside it is the join back to the customer's own log.
#
# **Timestamps are deliberately outside the signature.** Every field below is a
# string, an integer or null, so there is nothing whose textual form two
# implementations can disagree about. This project has twice shipped a
# signature over a formatted timestamp and watched it verify on the machine
# that made it and fail everywhere else; the digest and the chain hash are what
# identify an entry, and a timestamp adds nothing an attacker cannot already
# see.

#: The evidence payload version, inside the signature, so a change of shape is
#: a change of meaning rather than a silent reinterpretation.
#:
#: `v2` adds how the principal's identity was established. It has to be signed:
#: an attacker able to rewrite `assigned` to `attested` would upgrade an
#: identity's apparent trustworthiness after the fact, and the whole reason to
#: record the distinction is that somebody will read it later and decide how
#: much to believe.
EVIDENCE_VERSION = 2

#: Exactly what a reporter signs, in order. Named rather than derived from the
#: record, because "sign whatever was in the dict" makes the signature's
#: meaning depend on the sender's version — and the receiver would have no way
#: to know which fields were covered.
EVIDENCE_FIELDS = (
    "action_digest",
    "principal_id",
    "tool",
    "verb",
    "verdict",
    "rule_id",
    "source",
    "chain_seq",
    "chain_hash",
    "attestation",
    "parent_id",
)


def evidence_payload(record: Mapping[str, Any]) -> dict[str, Any]:
    """The signable form of one evidence record.

    One function, both ends of the wire, and the control plane vendors this
    file — so producer and verifier cannot drift into building different bytes
    and blaming each other's cryptography.
    """
    return {
        "v": EVIDENCE_VERSION,
        **{field: record.get(field) for field in EVIDENCE_FIELDS},
    }


def sign_evidence(record: Mapping[str, Any], signer: Any) -> dict[str, Any]:
    """Return `record` with a signature over its signable form attached.

    `signer` is the audit chain's own `Signer` — `sign_bytes(bytes) -> str` and
    a `key_id`. Deliberately the same key that signs chain entries: a reporter
    with two identities is a reporter whose evidence and whose chain can be
    attributed to different parties, which is one more thing to reconcile
    during an investigation and nothing to gain.

    `sig` and `key_id` sit beside the payload rather than inside it, for the
    ordinary reason that a signature cannot cover itself.
    """
    import base64

    # The chain signer returns standard base64; everything on this wire is
    # base64url. Converted here rather than at each end, so there is one place
    # that knows the two encodings differ.
    raw = base64.b64decode(signer.sign_bytes(canonical(evidence_payload(record))))
    return {**record, "sig": b64u(raw), "key_id": signer.key_id}


def accept_evidence(
    record: Mapping[str, Any],
    public_key_b64: str,
) -> Verdict:
    """Check one evidence record against the reporter's key.

    Returns a `Verdict` and never raises, like everything else here. A refusal
    is not a reason to discard the record — see `chains.py` in the control
    plane for why: dropping evidence that fails a check hands anyone able to
    report a way to suppress a record by making it fail. This says whether the
    record is *attested*, and that is a property to store and surface, not a
    filter.
    """
    signature_b64 = record.get("sig")
    if not isinstance(signature_b64, str):
        return _refuse(Reason.MALFORMED, "evidence carries no signature")

    try:
        payload = canonical(evidence_payload(record))
    except CanonicalisationError as exc:
        return _refuse(Reason.MALFORMED, str(exc))

    try:
        Ed25519PublicKey.from_public_bytes(unb64u(public_key_b64)).verify(
            unb64u(signature_b64), payload
        )
    except (InvalidSignature, ValueError, TypeError):
        return _refuse(Reason.BAD_SIGNATURE, "evidence signature did not verify")

    return Verdict(ok=True, payload=dict(record))


# --- binding a credential to the key that holds it ------------------------------
#
# The bearer credential is possession-is-identity: a stolen one works until it is
# revoked or expires, and nothing ties it to the party it was issued to. mTLS is
# the usual answer and is what UAI-154 originally asked for.
#
# **It does not fit where this actually runs.** The control plane sits behind a
# TLS-terminating load balancer and the sidecars sit inside customer networks
# with one outbound path. The application never sees a client certificate; it
# would read a forwarded header — and trusting a header the proxy is supposed to
# have stripped is exactly the UAI-137 failure, where route-level header removal
# ran *after* the check that depended on it and nobody could tell by reading the
# config. A binding whose correctness depends on a proxy behaving is a binding
# that is silently absent in the deployment that got it wrong.
#
# So the binding is done here, where it works in every topology and depends on
# nothing: the sidecar signs each request with a key it registered at enrolment.
# A stolen bearer token is then not enough — the holder needs the private key
# too, which never leaves the sidecar.
#
# What it covers is chosen so a captured proof is useless rather than merely
# short-lived:
#
#   htm, htu   the method and path, so a proof captured from a GET cannot
#              authorise a POST, and one for `/evidence` cannot resolve an
#              approval
#   bdg        a digest of the body, so the request it authorises cannot be
#              rewritten in flight
#   exp        sixty seconds, so a captured one dies quickly
#   jti        distinguishes two otherwise identical requests
#
# mTLS at the edge remains worth having as defence in depth. It is no longer
# what the binding *depends* on.

#: The JWS `typ`, so a proof cannot be presented as an operator assertion or the
#: reverse — the cross-protocol confusion that has broken many JWT deployments.
PROOF_TYP = "unified-proof+jws"

#: How long a proof may claim to be valid. A request is in flight for
#: milliseconds; a minute is generous and still leaves nothing worth stealing.
PROOF_MAX_LIFETIME = 60


def body_digest(body: bytes | None) -> str | None:
    """The digest a proof commits to, or None for a request with no body."""
    return hashlib.sha256(body).hexdigest() if body else None


def sign_request(
    *,
    signer: Any,
    credential_id: str,
    method: str,
    path: str,
    body: bytes | None,
    now: int,
) -> str:
    """A compact-JWS proof that the holder of this credential made this request.

    `signer` is the sidecar's channel key — `sign_bytes(bytes) -> str` and a
    `key_id`, the same interface the chain signer has.
    """
    import base64
    import uuid

    header = b64u(json.dumps({"alg": ALG, "typ": PROOF_TYP}, separators=(",", ":")).encode())
    claims = b64u(
        json.dumps(
            {
                "iss": credential_id,
                "htm": method.upper(),
                "htu": path,
                "bdg": body_digest(body),
                "iat": now,
                "exp": now + PROOF_MAX_LIFETIME,
                "jti": uuid.uuid4().hex,
            },
            separators=(",", ":"),
        ).encode()
    )
    raw = base64.b64decode(signer.sign_bytes(signing_input(header, claims)))
    return f"{header}.{claims}.{b64u(raw)}"


def accept_proof(
    raw: str,
    *,
    public_key_b64: str,
    credential_id: str,
    method: str,
    path: str,
    body: bytes | None,
    now: int,
    skew: int = 30,
) -> Verdict:
    """Check a request proof. Returns a `Verdict` and never raises.

    Verified before any claim is read, because anything decided from an
    unverified payload is decided from attacker-controlled input.
    """
    parts = raw.strip().split(".")
    if len(parts) != 3:
        return _refuse(Reason.MALFORMED, "proof is not a compact JWS")

    try:
        header = json.loads(unb64u(parts[0]))
        claims = json.loads(unb64u(parts[1]))
        signature = unb64u(parts[2])
    except Exception:  # noqa: BLE001 - hostile input arrives many ways
        return _refuse(Reason.MALFORMED, "proof is not decodable")

    if not isinstance(header, dict) or not isinstance(claims, dict):
        return _refuse(Reason.MALFORMED, "proof segments are not objects")
    if header.get("alg") != ALG:
        return _refuse(Reason.BAD_ALGORITHM, f"alg {header.get('alg')!r} is not {ALG}")
    if header.get("typ") != PROOF_TYP:
        return _refuse(Reason.MALFORMED, "not a request proof")

    try:
        Ed25519PublicKey.from_public_bytes(unb64u(public_key_b64)).verify(
            signature, signing_input(parts[0], parts[1])
        )
    except (InvalidSignature, ValueError, TypeError):
        return _refuse(Reason.BAD_SIGNATURE, "proof signature did not verify")

    if claims.get("iss") != credential_id:
        return _refuse(Reason.MALFORMED, "proof was not issued by this credential")

    issued, expires = claims.get("iat"), claims.get("exp")
    if not isinstance(issued, int) or not isinstance(expires, int):
        return _refuse(Reason.MALFORMED, "proof carries no integer timestamps")
    if expires - issued > PROOF_MAX_LIFETIME:
        return _refuse(Reason.EXPIRED, "proof claims a longer life than is permitted")
    if expires + skew <= now:
        return _refuse(Reason.EXPIRED, "proof has expired")
    if issued - skew > now:
        return _refuse(Reason.EXPIRED, "proof is not yet valid")

    # Bound to this exact request. Without these a proof captured from any
    # request would authorise any other, which is a bearer token again with
    # extra steps.
    if claims.get("htm") != method.upper():
        return _refuse(Reason.WRONG_ACTION, f"proof is for {claims.get('htm')!r}, not {method!r}")
    if claims.get("htu") != path:
        return _refuse(Reason.WRONG_ACTION, f"proof is for {claims.get('htu')!r}, not {path!r}")
    if claims.get("bdg") != body_digest(body):
        return _refuse(Reason.WRONG_ACTION, "proof does not cover this body")

    return Verdict(ok=True, payload=dict(claims))
