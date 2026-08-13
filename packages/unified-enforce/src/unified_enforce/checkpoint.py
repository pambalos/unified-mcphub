"""Merkle checkpoints, so the log can be pinned outside the writer. UAI-134.

The audit chain proves three different things depending on what is layered on
it, and the whole point of this module is that the third one was missing:

| layer | what it proves | what defeats it |
|---|---|---|
| hash chain | internal consistency | an attacker who controls the writer rewrites the whole history and every hash recomputes |
| Ed25519 signature | attributable authorship | a compromised *live* writer, which holds the key by definition |
| **checkpoint anchored externally** | **this log looked like this at time T** | nothing the writer alone can do |

A checkpoint is a Merkle root over a range of entry hashes, signed, carrying the
previous checkpoint's root so the checkpoints themselves form a chain. Handed to
somebody the writer does not control, it becomes the fixed point a later rewrite
cannot move: the attacker can produce a perfectly consistent, perfectly signed
history, and it will not match the root that was published on Tuesday.

**Why a Merkle tree and not just the chain head.** The head alone would pin the
history equally well, and would be one line of code. What a tree adds is
*inclusion proofs*: an investigator can prove one specific action was in the log
at time T by handing over that entry and about twenty hashes, without disclosing
anything else in it. For a log of agent actions across a customer's business
that difference is the difference between "here is the evidence for this
dispute" and "here is our entire operational history".

**RFC 6962 domain separation**, and not as ceremony. Hashing leaves and internal
nodes identically lets an attacker present an internal node as if it were a
leaf, which is a real second-preimage attack on naive Merkle trees. Leaves are
`H(0x00 || data)` and internal nodes are `H(0x01 || left || right)`.

**Odd nodes are promoted, not duplicated.** Duplicating the last node to pad a
level is the CVE-2012-2459 shape — two different trees producing one root. A
promoted node cannot collide with a duplicated one because there is no
duplication.

What this does *not* do is decide where a checkpoint goes; `anchors.py` is that,
and the choice is a trust question rather than a cryptographic one.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

#: RFC 6962 domain separation. See the module docstring: without these an
#: internal node can be replayed as a leaf.
LEAF = b"\x00"
NODE = b"\x01"

SCHEMA = "unified.checkpoint/v1"


def _h(*parts: bytes) -> bytes:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part)
    return digest.digest()


def leaf_hash(entry_hash: str) -> bytes:
    """A log entry's place in the tree.

    Takes the entry's own `hash`, which already covers its payload and — via
    `prev_hash` — everything before it. So a leaf here is a commitment to the
    whole prefix of the log, and the tree is a commitment to a set of those.
    """
    return _h(LEAF, bytes.fromhex(entry_hash))


def merkle_root(entry_hashes: list[str]) -> str:
    """The root over a range of entries, as hex.

    An empty range has no root and is an error rather than a conventional zero:
    a checkpoint over nothing is a statement that says nothing, and publishing
    one on a schedule would produce a stream of anchors that look like evidence
    and are not.
    """
    if not entry_hashes:
        raise ValueError("a checkpoint over no entries would attest to nothing")

    level = [leaf_hash(h) for h in entry_hashes]
    while len(level) > 1:
        nxt: list[bytes] = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(_h(NODE, level[i], level[i + 1]))
        if len(level) % 2:
            # Promoted, not duplicated. See the module docstring.
            nxt.append(level[-1])
        level = nxt
    return level[0].hex()


def inclusion_proof(entry_hashes: list[str], index: int) -> list[dict[str, str]]:
    """The sibling hashes needed to recompute the root from one leaf.

    `{"side": "left"|"right", "hash": hex}` rather than bare hashes, because the
    order of concatenation is part of the computation and a proof that omitted
    it would verify against a tree the prover chose. Roughly log2(n) entries:
    twenty for a million-entry checkpoint.
    """
    if not 0 <= index < len(entry_hashes):
        raise IndexError(f"no entry at {index} in a range of {len(entry_hashes)}")

    path: list[dict[str, str]] = []
    level = [leaf_hash(h) for h in entry_hashes]
    position = index

    while len(level) > 1:
        nxt: list[bytes] = []
        for i in range(0, len(level) - 1, 2):
            if i == position - (position % 2):
                if position % 2:
                    path.append({"side": "left", "hash": level[i].hex()})
                else:
                    path.append({"side": "right", "hash": level[i + 1].hex()})
            nxt.append(_h(NODE, level[i], level[i + 1]))
        if len(level) % 2:
            nxt.append(level[-1])
            # A promoted node has no sibling at this level, so nothing is
            # appended to the path -- which is exactly what makes promotion
            # verifiable and duplication not.
        position //= 2
        level = nxt

    return path


def verify_inclusion(entry_hash: str, path: list[dict[str, str]], root: str) -> bool:
    """Recompute the root from one entry and its path.

    The verifier an investigator or a counterparty runs, and the reason it takes
    no tree: whoever is checking holds one entry, a handful of hashes and a root
    they got from somewhere trustworthy. They do not need — and should not be
    given — the rest of the log.
    """
    try:
        current = leaf_hash(entry_hash)
        for step in path:
            sibling = bytes.fromhex(step["hash"])
            if step["side"] == "left":
                current = _h(NODE, sibling, current)
            elif step["side"] == "right":
                current = _h(NODE, current, sibling)
            else:
                return False
        return current.hex() == root
    except (ValueError, KeyError, TypeError):
        # A malformed proof is a failed proof. Raising would let a caller
        # distinguish "bad input" from "does not verify", and both mean the
        # claim was not established.
        return False


@dataclass(frozen=True)
class Checkpoint:
    """A signed statement that a range of the log had this root at this time.

    Carries `prev_root` so checkpoints chain: an attacker who wants to replace
    Tuesday's checkpoint has to replace every one after it too, and the
    anchoring party is holding those.
    """

    fleet_id: str
    reporter_id: str
    #: Inclusive chain positions this covers. A gap between one checkpoint's
    #: `to_seq` and the next's `from_seq` is a range nobody attested to, which
    #: an auditor should be able to see rather than infer.
    from_seq: int
    to_seq: int
    entries: int
    root: str
    prev_root: str | None
    issued_at_ms: int
    #: The log's head at `to_seq`. Redundant with the root for tamper detection
    #: and cheap, and it lets a verifier holding the log confirm the checkpoint
    #: describes the chain they have without building the tree.
    head: str

    def payload(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "fleet_id": self.fleet_id,
            "reporter_id": self.reporter_id,
            "from_seq": self.from_seq,
            "to_seq": self.to_seq,
            "entries": self.entries,
            "root": self.root,
            "prev_root": self.prev_root,
            "issued_at_ms": self.issued_at_ms,
            "head": self.head,
        }

    def signing_bytes(self) -> bytes:
        return json.dumps(self.payload(), sort_keys=True, separators=(",", ":")).encode()


@dataclass
class SignedCheckpoint:
    """A checkpoint plus who says so. What actually gets anchored."""

    checkpoint: Checkpoint
    signature: str
    key_id: str
    #: Countersignatures from anchoring parties, added as they arrive. A
    #: checkpoint with none is a claim; a checkpoint countersigned by somebody
    #: who does not answer to the writer is evidence.
    countersignatures: list[dict[str, str]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "payload": self.checkpoint.payload(),
            "signature": self.signature,
            "key_id": self.key_id,
            "countersignatures": self.countersignatures,
        }

    @classmethod
    def from_dict(cls, doc: dict[str, Any]) -> SignedCheckpoint:
        payload = doc["payload"]
        return cls(
            checkpoint=Checkpoint(
                fleet_id=payload["fleet_id"],
                reporter_id=payload["reporter_id"],
                from_seq=payload["from_seq"],
                to_seq=payload["to_seq"],
                entries=payload["entries"],
                root=payload["root"],
                prev_root=payload.get("prev_root"),
                issued_at_ms=payload["issued_at_ms"],
                head=payload["head"],
            ),
            signature=doc["signature"],
            key_id=doc["key_id"],
            countersignatures=list(doc.get("countersignatures") or []),
        )


def build(
    entries: list[dict[str, Any]],
    *,
    fleet_id: str,
    reporter_id: str,
    signer: Any,
    prev_root: str | None = None,
    now: datetime | None = None,
) -> SignedCheckpoint:
    """Checkpoint a run of chain entries.

    `entries` must be contiguous and in order — they come off the chain that
    way, and checking rather than assuming is what stops a caller from
    accidentally checkpointing a filtered view. A checkpoint over a subset would
    verify perfectly and attest to a log that never existed.
    """
    if not entries:
        raise ValueError("a checkpoint over no entries would attest to nothing")

    seqs = [int(e["seq"]) for e in entries]
    if seqs != list(range(seqs[0], seqs[0] + len(seqs))):
        raise ValueError(
            f"entries are not contiguous ({seqs[0]}..{seqs[-1]} with {len(seqs)} rows). "
            "A checkpoint over a filtered view attests to a log that never existed."
        )

    hashes = [e["hash"] for e in entries]
    checkpoint = Checkpoint(
        fleet_id=fleet_id,
        reporter_id=reporter_id,
        from_seq=seqs[0],
        to_seq=seqs[-1],
        entries=len(entries),
        root=merkle_root(hashes),
        prev_root=prev_root,
        issued_at_ms=int((now or datetime.now(UTC)).timestamp() * 1000),
        head=hashes[-1],
    )

    return SignedCheckpoint(
        checkpoint=checkpoint,
        # `sign_bytes` already returns base64, and the chain's entry signatures
        # are stored the same way -- so a checkpoint signature and an entry
        # signature verify through the same function.
        signature=signer.sign_bytes(checkpoint.signing_bytes()),
        key_id=signer.key_id,
    )


def verify_signature(signed: SignedCheckpoint, public_key: bytes) -> bool:
    """Whether the named writer really issued this checkpoint.

    Verifies with `cryptography` directly rather than through this package's
    `signing` module, so this file depends on nothing else in the package. That
    matters because it is vendored: the control plane copies it verbatim to
    reconstruct the exact bytes a sidecar signed, and a sibling import would
    resolve to a module that does not exist over there — an error that waits
    until somebody calls this function to appear.
    """
    import base64

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        raw = signed.signature
        padded = raw + "=" * (-len(raw) % 4)
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            base64.urlsafe_b64decode(padded), signed.checkpoint.signing_bytes()
        )
    except (InvalidSignature, ValueError):
        return False
    return True


def conflicts(a: Checkpoint, b: Checkpoint) -> str | None:
    """Whether two checkpoints from one reporter cannot both be true.

    This is the payoff, and it is worth being explicit that the *detection*
    lives with whoever holds the checkpoints rather than with the writer. A
    compromised writer rewrites its log and issues a fresh, internally perfect
    checkpoint for the same range; the anchoring party already has the old one,
    and the two roots differ. Nothing the writer can do reconciles them.

    Returns a description, or `None` when they are consistent.
    """
    if a.reporter_id != b.reporter_id or a.fleet_id != b.fleet_id:
        return None
    if a.to_seq < b.from_seq or b.to_seq < a.from_seq:
        return None  # disjoint ranges say nothing about each other

    if a.from_seq == b.from_seq and a.to_seq == b.to_seq:
        if a.root != b.root:
            return (
                f"two checkpoints cover {a.from_seq}..{a.to_seq} with different roots "
                f"({a.root[:12]}… and {b.root[:12]}…). The log was rewritten."
            )
        return None

    # Overlapping but not identical ranges. One contains the other's start, so
    # the shorter one's head must appear in the longer one -- which cannot be
    # checked from the checkpoints alone. Reported as needing the log rather
    # than asserted either way, because a false accusation of tampering is
    # expensive and this is exactly where one would come from.
    return (
        f"checkpoints {a.from_seq}..{a.to_seq} and {b.from_seq}..{b.to_seq} overlap "
        "without matching. This needs the log to resolve: it is either a reporter "
        "that re-checkpointed a range or a rewrite."
    )
