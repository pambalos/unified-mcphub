"""The hub's signing key, and the record of where signing began.

Before this, the hub's audit chain was tamper-*evident* and nothing more: an
account with write access to `audit/` could rewrite it end to end, recompute
every hash, and `audit verify` would call it pristine. Its fleet evidence was
unattested for the same reason — nothing the control plane received could be
tied to a key only this hub holds. One Ed25519 key closes both, and it is one
key on purpose (see `unified_enforce.attest.sign_evidence`): a reporter whose
chain and evidence are attributable to different keys is one more thing to
reconcile during an investigation.

**Where the key lives.** In the hub's encrypted secrets store, under
`audit.signing_key_secret_ref`, as a base64 32-byte seed — beside the
credentials the hub already guards the same way, behind the same master key
and the same start-up gate. Not a file of its own: a key file readable by the
hub's account is readable by whatever runs as that account, which is exactly
the party a signature is meant to hold to account. Absent, the hub runs
unsigned, which is what it did before.

**Where signing began** (`signing.json`). A hub that ran unsigned for months
and is then given a key has a chain that is unsigned up to some entry and
signed after it. Verifying that needs to know *which* entry, and the answer
cannot come from the chain itself — "the first entry carrying a signature" is
whatever an attacker who stripped the earlier signatures says it is. So the
hub writes it down when it happens: the key id, the public key, and the `seq`
of the first signed entry, 0600 beside the config. `audit verify` then holds
every entry from that seq to a valid signature (`HashChainWriter.verify`,
`signed_from_seq`). The record holds a public key only; losing it costs the
signature check, never the key.
"""

from __future__ import annotations

import base64
import json
import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from unified_enforce.attest import b64u, key_id
from unified_enforce.signing import Signer

from .config import mcphub_home
from .util import secure_write

logger = logging.getLogger(__name__)


def signing_record_path() -> Path:
    return mcphub_home() / "signing.json"


def generate_seed() -> str:
    """A new signing key, in the form it is stored: base64 of the raw seed."""
    return base64.b64encode(Signer.generate("new").private_bytes()).decode("ascii")


def signer_from_secret(value: str) -> Signer:
    """Build the hub's `Signer` from its stored seed.

    The key id is derived from the public key (`attest.key_id`), the same
    derivation the control plane uses, so the id on a signed record cannot be
    claimed independently of the key that made it.
    """
    raw = base64.b64decode(value.strip(), validate=True)
    if len(raw) != 32:
        raise ValueError(f"signing key must be a 32-byte Ed25519 seed, got {len(raw)} bytes")
    probe = Signer.from_private_bytes(raw, "probe")
    return Signer.from_private_bytes(raw, key_id(b64u(probe.public_bytes())))


def public_key_b64u(signer: Signer) -> str:
    """The public half as the control plane takes it at enrolment
    (`evidence_key`): base64url, unpadded."""
    return b64u(signer.public_bytes())


@dataclass(frozen=True)
class SigningRecord:
    key_id: str
    public_key: str  # base64url, unpadded
    since_seq: int

    def public_bytes(self) -> bytes:
        from unified_enforce.attest import unb64u

        return unb64u(self.public_key)


def load_record(path: Path | None = None) -> SigningRecord | None:
    """The current signing record, or None when the hub has never signed.

    A file that exists but does not parse raises: silently treating it as
    absent would downgrade `audit verify` to hash-only, which is the exact
    outcome an attacker editing this file would want.
    """
    path = path or signing_record_path()
    if not path.exists():
        return None
    data = json.loads(path.read_text())
    return SigningRecord(
        key_id=str(data["key_id"]),
        public_key=str(data["public_key"]),
        since_seq=int(data["since_seq"]),
    )


def note_first_signed(signer: Signer, seq: int, path: Path | None = None) -> bool:
    """Record that `signer` signed entry `seq`, unless already recorded.

    Returns True when this call wrote the record. Idempotent for a key that
    is already the current one: its start point is the *first* entry it
    signed, and a later restart must not move it forward (that would excuse
    any unsigned entries in between). A different key — a rotation — becomes
    current from `seq`, and the record it replaces is kept under `previous`
    rather than discarded, so the history of which key signed when is not
    lost; `audit verify` checks the current key's range.
    """
    path = path or signing_record_path()
    current: dict[str, Any] = {}
    if path.exists():
        current = json.loads(path.read_text())
        if current.get("key_id") == signer.key_id:
            return False
    record = SigningRecord(key_id=signer.key_id, public_key=public_key_b64u(signer), since_seq=seq)
    data: dict[str, Any] = asdict(record)
    if current:
        previous = list(current.pop("previous", []))
        previous.append(current)
        data["previous"] = previous
    secure_write(path, (json.dumps(data, indent=2) + "\n").encode())
    logger.info("audit: signing with key %s from seq %d (recorded in %s)", signer.key_id, seq, path)
    return True
