"""Verify an evidence pack offline — the auditor's half of `evidence_pack`.

**Who runs this.** Somebody who does not work for the customer and does not
trust the vendor: an ISO/IEC 42001 auditor sampling A.6.2.8 event logs and
A.9 human-oversight records. So it is written to run *from inside the pack*
with nothing installed but `cryptography`: the builder copies this file,
`attest.py` and `detach.py` into `verify/`, the manifest records their hashes, and
`python verify/verify.py` checks everything else. `unified-enforce` is not on
PyPI yet, and a verifier that needs the vendor's package to be installed is a
verifier that asks to be trusted.

**One verifier, not two.** The approval check below reuses `attest.py` — the
same module the sidecar uses to accept a resolution and the control plane
vendors by hash — rather than re-deriving the signed payload. Two
implementations of "what was signed" drifting apart is the one failure in this
area that looks like an attack from both ends.

**What is checked, and what each check proves:**

1. *Manifest* — every file hashes to what the builder recorded, and no file was
   added. Proves the pack is the one that was produced, not that its contents
   are true.
2. *Chains* — each excerpt links entry to entry and every hash recomputes;
   every signature present verifies against the reporter's key; once an entry
   is signed, no later entry is unsigned. Proves the excerpt is an unaltered,
   contiguous run of what the reporter wrote. The first `prev_hash` is the
   anchor: it ties the excerpt to the history before it, which the auditor can
   ask the customer to produce. *Payloads* — the inputs and outputs recorded
   in each entry — are committed to by salted digest inside the signed body
   (detach.py): every one present must match its digest, or the chain FAILS;
   any withheld (a digests-only pack) is counted, and the customer can produce
   it later for the auditor to check against the same digest.
3. *Approvals* — each human resolution recorded in a chain carries the control
   plane's signature over exactly who decided, what, and when; it is checked
   against a decision key that a root-signed key set vouches for. Proves the
   named, authenticated person made that decision — not just that a log says so.
4. *Policies* — each policy file hashes to the `policy_digest` the decisions
   carry. Proves which rules were in force for each decision.
5. *Export rows* — every row of the control plane's CSV is joined to its chain
   entry and must agree with it. Proves the summary an auditor reads in a
   spreadsheet says what the signed record says.

Exit status is non-zero if any check fails. Warnings (an export row whose
reporter's chain was not included, a digest with no policy file) do not fail
the pack; they say what it does not cover.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:  # inside the package
    from . import attest, detach
except ImportError:  # inside a pack's verify/ directory
    import attest  # type: ignore[import-not-found,no-redef]
    import detach  # type: ignore[import-not-found,no-redef]

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MANIFEST = "manifest.json"

#: The hub's audit vocabulary, mapped to the verdict it ships. For a `prompt`
#: the hub records the outcome (`prompt_allowed`, …) and ships the *resolved*
#: decision — ALLOW or DENY with source `approval*`, never the DEFER
#: (`AuthzResolver.ship`) — so the control plane's export says `allow` or
#: `deny` for these rows, and the row check must compare against that.
#: `approval_disabled` is the master switch off (ADR-0018): the call ran, and
#: the shipped verdict is ALLOW.
_HUB_TO_VERDICT = {
    "allow": "allow",
    "deny": "deny",
    "prompt_allowed": "allow",
    "prompt_denied": "deny",
    "approval_disabled": "allow",
}


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""
    warning: bool = False


@dataclass
class Report:
    checks: list[Check] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)

    def add(self, name: str, ok: bool, detail: str = "", *, warning: bool = False) -> None:
        self.checks.append(Check(name, ok, detail, warning))

    @property
    def ok(self) -> bool:
        return all(c.ok or c.warning for c in self.checks)


# --- primitives ---------------------------------------------------------------


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _entry_hash(entry: dict[str, Any]) -> str:
    """The chain's own hashing rule (unified_enforce.audit / canonical, lenient):
    sorted keys, no whitespace, UTF-8, unknown types stringified. Re-serialising
    parsed JSON this way is deterministic, which is what lets one verifier cover
    strict (sidecar) and lenient (hub) chains alike — and what lets a
    digests-only pack re-serialise its lines without changing a single hash.

    Applied to a chain entry, pass `detach.hashable_body(entry)`: the hash
    covers each detached value's digest, not the value."""
    return hashlib.sha256(detach.canonical(entry)).hexdigest()


def _verify_chain_signature(public_key_raw: bytes, signature_b64: str, entry_hash: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public_key_raw).verify(
            base64.b64decode(signature_b64), entry_hash.encode("ascii")
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def _decode_key(value: str) -> bytes:
    """Chain keys are recorded as standard base64; tolerate the URL-safe form the
    control plane uses for enrolment, since both name the same 32 bytes."""
    padded = value + "=" * (-len(value) % 4)
    try:
        return base64.b64decode(padded, validate=True)
    except ValueError:
        return base64.urlsafe_b64decode(padded)


# --- 1. manifest -------------------------------------------------------------


def check_manifest(root: Path, report: Report) -> dict[str, Any] | None:
    path = root / MANIFEST
    if not path.is_file():
        report.add("manifest", False, "manifest.json is missing")
        return None
    manifest = json.loads(path.read_text(encoding="utf-8"))
    listed = {f["path"]: f["sha256"] for f in manifest.get("files", [])}
    bad = [
        p
        for p, digest in listed.items()
        if not (root / p).is_file() or _sha256_file(root / p) != digest
    ]
    present = {
        str(p.relative_to(root)).replace("\\", "/")
        for p in root.rglob("*")
        if p.is_file() and p.name != MANIFEST and "__pycache__" not in p.parts
    }
    extra = sorted(present - set(listed))
    report.add(
        "manifest",
        not bad and not extra,
        f"{len(listed)} files hash-checked"
        + (f"; altered or missing: {bad}" if bad else "")
        + (f"; not in manifest: {extra}" if extra else ""),
    )
    report.facts["pack"] = {
        k: manifest.get(k) for k in ("title", "fleet_id", "window", "created_at", "payloads")
    }
    return manifest


# --- 2. chains -------------------------------------------------------------------


@dataclass
class Chain:
    name: str
    meta: dict[str, Any]
    entries: list[dict[str, Any]]


def check_chains(root: Path, report: Report) -> list[Chain]:
    chains: list[Chain] = []
    for meta_path in sorted((root / "chains").glob("*/meta.json")):
        name = meta_path.parent.name
        # A chain whose files cannot be read is a FAILED chain, never a
        # traceback: the auditor running this is owed a verdict on every
        # other part of the pack, and an unreadable line is itself the finding.
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            raw_lines = (meta_path.parent / "chain.jsonl").read_text(encoding="utf-8").splitlines()
            entries = [json.loads(line) for line in raw_lines if line.strip()]
            if not isinstance(meta, dict) or not all(isinstance(e, dict) for e in entries):
                raise ValueError("meta.json and every chain line must be JSON objects")
        except (OSError, ValueError) as exc:
            report.add(f"chain {name}", False, f"unreadable: {exc}")
            continue
        chains.append(Chain(name, meta, entries))
        try:
            report.add(f"chain {name}", *_verify_chain(meta, entries))
            _note_payload_mode(name, meta, entries, report)
        except Exception as exc:  # noqa: BLE001 - see above
            report.add(f"chain {name}", False, f"could not be checked: {type(exc).__name__}: {exc}")
    if not chains:
        report.add("chains", False, "the pack contains no chain excerpts")
    return chains


def _note_payload_mode(
    name: str, meta: dict[str, Any], entries: list[dict[str, Any]], report: Report
) -> None:
    """Say what the pack's payload mode means for this chain, as notes.

    Never a failure: whether content is present is a matter of what the
    customer chose to disclose, not of integrity — integrity is `_verify_chain`.
    But a digests-only pack that still shows content contradicts its README,
    and entries written before payloads were detachable *cannot* have their
    content withheld without breaking the chain, so the reader is told both.
    """
    mode = meta.get("payloads", "include")
    if mode != "digests-only":
        return
    present = sum(detach.check(e).present for e in entries)
    if present:
        report.add(
            f"payloads {name}",
            True,
            f"the pack says digests-only, yet {present} payload(s) are present (they verified "
            "against their digests, so they are genuine — but more was disclosed than stated)",
            warning=True,
        )
    legacy = int(meta.get("legacy_inline_entries") or 0)
    if legacy:
        report.add(
            f"payloads {name}",
            True,
            f"{legacy} entr(y/ies) predate detachable payloads and carry their (write-time "
            "shaped) content inline: it is covered by the entry hash directly and cannot be "
            "withheld without breaking the chain",
            warning=True,
        )


@dataclass(frozen=True)
class _KeyRange:
    """One signing key and the first `seq` it is responsible for.

    `since` None means "from the start": a chain that was signed from its
    first entry, or a pack built before key ranges existed."""

    since: int | None
    key: bytes
    key_id: str | None = None


def _key_ranges(meta: dict[str, Any]) -> list[_KeyRange]:
    """The keys a chain was signed with, oldest range first.

    `keys` (a list of `{public_key, key_id, since_seq}`) is how a pack records
    a reporter that rotated its key — the hub's `signing.json` keeps the
    current key and every previous one with the seq it took over from. A pack
    with only `public_key`/`signed_from_seq` is one range, read exactly as
    before. Each range is enforced for its own seqs: an entry is checked
    against the key that was current when it was written, so rewriting an old
    range and re-signing it with a newer key fails, just as stripping its
    signatures does."""
    listed = meta.get("keys")
    if isinstance(listed, list) and listed:
        ranges = []
        for item in listed:
            if not isinstance(item, dict) or not item.get("public_key"):
                raise ValueError("meta.keys entries need a public_key")
            since = item.get("since_seq")
            ranges.append(
                _KeyRange(
                    since=int(since) if since is not None else None,
                    key=_decode_key(str(item["public_key"])),
                    key_id=item.get("key_id"),
                )
            )
        return sorted(ranges, key=lambda r: -1 if r.since is None else r.since)
    key_b64 = meta.get("public_key")
    if not key_b64:
        return []
    signed_from = meta.get("signed_from_seq")
    return [
        _KeyRange(
            since=int(signed_from) if signed_from is not None else None,
            key=_decode_key(key_b64),
            key_id=meta.get("key_id"),
        )
    ]


def _range_for(ranges: list[_KeyRange], seq: Any) -> _KeyRange | None:
    """The range responsible for `seq`, or None when it predates every range.

    An entry with no usable seq cannot be shown to sit before signing began,
    so it is held to the newest key — the stricter reading, as in
    `HashChainWriter.verify`."""
    if not isinstance(seq, int) or isinstance(seq, bool):
        return ranges[-1]
    chosen = None
    for r in ranges:
        if r.since is None or r.since <= seq:
            chosen = r
    return chosen


def _verify_chain(meta: dict[str, Any], entries: list[dict[str, Any]]) -> tuple[bool, str]:
    ranges = _key_ranges(meta)
    prev = meta.get("anchor")
    signed = unsigned = 0
    present = withheld = unrecorded = 0
    seen_signed = False
    for i, entry in enumerate(entries):
        sig = entry.get("sig")
        claimed = entry.get("hash")
        where = f"entry {i} (seq {entry.get('seq')})"
        if entry.get("prev_hash") != prev:
            return False, f"{where}: chain break — prev_hash does not follow the previous entry"
        if _entry_hash(detach.hashable_body(entry)) != claimed:
            return False, f"{where}: hash mismatch — the entry was altered"
        # The hash covers each payload's digest, not the payload: this is the
        # check that catches an input or output edited in the pack.
        payloads = detach.check(entry)
        if not payloads.ok:
            return False, f"{where}: payload — {payloads.problem}"
        present += payloads.present
        withheld += payloads.withheld
        unrecorded += payloads.unrecorded
        responsible = _range_for(ranges, entry.get("seq")) if ranges else None
        if sig is None:
            # A signature that stops part-way is what stripping them looks like.
            if seen_signed:
                return False, f"{where}: unsigned after signed entries (signatures stripped?)"
            # A chain the pack supplies a key for is a chain that was signed:
            # from the start, or from where signing began. Without this, an
            # excerpt with every signature removed verifies as "unsigned" — the
            # hash chain still links, because hashes are not secret.
            if responsible is not None:
                since = "the start" if responsible.since is None else f"seq {responsible.since}"
                return False, f"{where}: unsigned, but this chain is signed from {since}"
            unsigned += 1
        else:
            if not ranges:
                return False, f"{where}: signed, but the pack has no public key for this chain"
            # Before every range, a signature is checked against the first
            # key (an early entry signed is no weaker for it).
            key = (responsible or ranges[0]).key
            if not isinstance(claimed, str) or not _verify_chain_signature(key, sig, claimed):
                owner = responsible or ranges[0]
                return False, (
                    f"{where}: bad signature"
                    + (
                        f" — this seq is in key {owner.key_id}'s range"
                        if len(ranges) > 1 and owner.key_id
                        else ""
                    )
                )
            seen_signed = True
            signed += 1
        prev = claimed
    first = entries[0].get("seq") if entries else None
    last = entries[-1].get("seq") if entries else None
    detail = (
        f"{len(entries)} entries (seq {first}–{last}), {signed} signed, {unsigned} unsigned; "
        f"payloads: {present} verified against their digests, {withheld} withheld"
        + (f", {unrecorded} never recorded (record_payloads off)" if unrecorded else "")
    )
    if not ranges:
        detail += "; no public key — integrity only, not authorship"
    elif len(ranges) > 1:
        detail += f"; {len(ranges)} signing keys, each checked over its own seq range"
    return True, detail


# --- 3. approvals ------------------------------------------------------------------


def _trusted_keys(root: Path, report: Report, at_ms: int) -> dict[str, Any]:
    root_key_path = root / "trust" / "root_public_key.txt"
    keyset_path = root / "trust" / "keyset.json"
    if not root_key_path.is_file() or not keyset_path.is_file():
        return {}
    envelope = json.loads(keyset_path.read_text(encoding="utf-8"))
    envelope = envelope.get("keyset", envelope)
    verdict, keys = attest.load_key_set(
        envelope, root_public_key=root_key_path.read_text().strip(), now_ms=at_ms
    )
    report.add(
        "key set",
        bool(verdict.ok),
        f"root-signed key set authorises {sorted(keys)} (validity evaluated at pack time)"
        if verdict.ok
        else f"refused: {verdict.reason} {verdict.detail}",
    )
    return keys if verdict.ok else {}


def _approvals_in(chain: Chain) -> list[dict[str, Any]]:
    """Resolutions with a control-plane signature, in either chain shape: the
    sidecar's `{kind: approval, payload: {...}}` or a hub entry that carries
    `approver` and `attestation` beside its own fields.

    The hub entry's `kind` is the entry's own business (it has none; `phase`
    names it), so the resolution kind and scope the control plane signed are
    recorded under `resolution` (unified_mcphub.audit). They are lifted into
    the same shape as the sidecar's here, so one check covers both — and a hub
    entry *without* them is passed on as it is, to fail that check as
    incomplete rather than be skipped."""
    found = []
    for e in chain.entries:
        payload = e.get("payload") if e.get("kind") == "approval" else e
        if isinstance(payload, dict) and payload.get("attestation") and payload.get("approver"):
            if "phase" in payload:
                resolution = payload.get("resolution")
                payload = {
                    k: v for k, v in payload.items() if k not in ("kind", "scope", "resolution")
                }
                if isinstance(resolution, dict):
                    if "kind" in resolution:
                        payload["kind"] = resolution["kind"]
                    if "scope" in resolution:
                        payload["scope"] = resolution["scope"]
            found.append(payload)
    return found


class _Incomplete(Exception):
    """An approval record missing something its signature covers."""


def _field(record: Any, name: str, kind: type | tuple[type, ...]) -> Any:
    if not isinstance(record, dict) or name not in record:
        raise _Incomplete(f"no {name!r}")
    value = record[name]
    if not isinstance(value, kind) or isinstance(value, bool) and kind is not bool:
        raise _Incomplete(
            f"{name!r} is {type(value).__name__}, not {getattr(kind, '__name__', kind)}"
        )
    return value


def _check_one_approval(a: dict[str, Any], keys: dict[str, Any]) -> tuple[bool, str]:
    """Verify one recorded resolution. Raises `_Incomplete` for a record that
    cannot even be checked; the caller reports that as a failure."""
    ap = _field(a, "approver", dict)
    at = _field(a, "attestation", dict)
    kid = at.get("key_id")
    key = keys.get(kid) if isinstance(kid, str) else None
    if key is None:
        return False, f"signed by {kid!r}, which the key set does not vouch for"
    if key.role != "decision":
        return False, f"key {key.kid} has role {key.role!r}; only a decision key may sign approvals"
    kind = _field(a, "kind", str)
    if "scope" not in a:
        # Absent and null are different claims: a sidecar always records the
        # field, and a hub records it under `resolution`. A record with no
        # scope at all lost part of what was signed.
        raise _Incomplete("no 'scope' (the resolution's scope is part of what was signed)")
    scope = a["scope"]
    if scope is not None and not isinstance(scope, dict):
        raise _Incomplete(f"'scope' is {type(scope).__name__}, not an object or null")
    # The chain stores the approver under readable names; the control plane
    # signed the wire form. Rebuilt field for field, then signed bytes are
    # produced by attest's own payload function — never re-derived here.
    wire = {
        "sub": _field(ap, "subject", str),
        "email": ap.get("email", ""),
        "sid": ap.get("session_id", ""),
        "auth_time_ms": _field(ap, "authenticated_at_ms", int),
    }
    resolved_at = _field(at, "resolved_at_ms", int)
    payload = attest.canonical(
        attest.resolution_payload(
            action_digest=_field(a, "action_digest", str),
            kind=kind,
            approver=wire,
            scope=scope,
            resolved_at_ms=resolved_at,
            expires_at_ms=_field(at, "expires_at_ms", int),
            nonce=_field(at, "nonce", str),
            fleet_id=_field(at, "fleet_id", str),
        )
    )
    try:
        Ed25519PublicKey.from_public_bytes(attest.unb64u(key.public_key)).verify(
            attest.unb64u(_field(at, "signature", str)), payload
        )
    except (InvalidSignature, ValueError, TypeError):
        return False, "the control plane's signature does not verify"
    if key.expires_at_ms <= resolved_at:
        return False, f"key {key.kid} had expired when this was signed"
    return True, (
        f"{kind} by {ap.get('email') or ap['subject']} ({ap['subject']}), signed by {key.kid}"
    )


def check_approvals(root: Path, chains: list[Chain], report: Report, at_ms: int) -> None:
    approvals = [(c.name, a) for c in chains for a in _approvals_in(c)]
    if not approvals:
        report.add("approvals", True, "no signed human resolutions in these excerpts", warning=True)
        return
    keys = _trusted_keys(root, report, at_ms)
    for name, a in approvals:
        digest = a.get("action_digest")
        label = f"approval {digest[:12] if isinstance(digest, str) else '?'}… in {name}"
        try:
            ok, detail = _check_one_approval(a, keys)
        except _Incomplete as exc:
            ok, detail = False, f"incomplete approval record, cannot be re-verified: {exc}"
        except Exception as exc:  # noqa: BLE001 - a bad record is a FAILED check, never a crash
            ok, detail = False, f"approval record could not be checked: {type(exc).__name__}: {exc}"
        report.add(label, ok, detail)


# --- 4. policies ---------------------------------------------------------------------


def _digests_in(chains: list[Chain], rows: list[dict[str, str]]) -> set[str]:
    found = {r["policy_digest"] for r in rows if r.get("policy_digest")}
    for c in chains:
        for e in c.entries:
            payload = e.get("payload")
            body: dict[str, Any] = payload if isinstance(payload, dict) else e
            if body.get("policy_digest"):
                found.add(body["policy_digest"])
    return found


def check_policies(
    root: Path, chains: list[Chain], rows: list[dict[str, str]], report: Report
) -> None:
    index_path = root / "policies" / "index.json"
    index = json.loads(index_path.read_text(encoding="utf-8")) if index_path.is_file() else {}
    for digest, info in sorted(index.items()):
        doc = json.loads((root / "policies" / info["normalized"]).read_text(encoding="utf-8"))
        ok = _entry_hash(doc) == digest
        report.add(
            f"policy {digest[:12]}…",
            ok,
            f"{info['normalized']} hashes to its digest ({info.get('label', '')})"
            if ok
            else f"{info['normalized']} does NOT hash to {digest}",
        )
    missing = sorted(_digests_in(chains, rows) - set(index))
    if missing:
        report.add(
            "policy coverage",
            True,
            f"decisions cite {len(missing)} digest(s) with no policy file in this pack: "
            + ", ".join(d[:12] + "…" for d in missing),
            warning=True,
        )


# --- 5. export rows ----------------------------------------------------------------------


def _load_rows(root: Path) -> list[dict[str, str]]:
    path = root / "export" / "evidence.csv"
    if not path.is_file():
        return []
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _index(chains: list[Chain]) -> dict[str, dict[str, dict[str, Any]]]:
    """reporter_id -> action_digest -> {decision, approval} from the chains.

    Hub entries are indexed by every digest a shipped row can carry while
    citing them: a `received` entry by its `action_digest` (a call, or the
    structural Action of an identity refusal), and a `completed` entry by its
    `injection_action_digest` (the `ingest` finding shipped against it). An
    entry of a shape this does not know is skipped, never a crash: the chain
    check has already passed judgement on its integrity."""
    out: dict[str, dict[str, dict[str, Any]]] = {}
    for c in chains:
        by_digest = out.setdefault(c.meta.get("reporter_id") or c.name, {})
        for e in c.entries:
            common = {"_hash": e.get("hash"), "_seq": e.get("seq"), "_signed": "sig" in e}
            p = e.get("payload")
            if e.get("kind") in ("decision", "approval"):
                if not isinstance(p, dict) or not isinstance(p.get("action_digest"), str):
                    continue
                slot = by_digest.setdefault(p["action_digest"], {})
                slot[e["kind"]] = {**p, **common}
            elif e.get("phase") == "received" and isinstance(e.get("action_digest"), str):
                slot = by_digest.setdefault(e["action_digest"], {})
                decided = e.get("authz_decision", "")
                slot["decision"] = {
                    "verdict": _HUB_TO_VERDICT.get(decided, decided),
                    "policy_digest": e.get("policy_digest"),
                    **common,
                    "_hub": True,
                }
                approver = e.get("approver")
                if isinstance(approver, dict):
                    slot["approval"] = {"decided_by": approver.get("subject")}
            elif e.get("phase") == "completed" and isinstance(
                e.get("injection_action_digest"), str
            ):
                # A finding, not a verdict on the call: the call already ran,
                # so the structural decision shipped for it is ALLOW.
                slot = by_digest.setdefault(e["injection_action_digest"], {})
                slot["decision"] = {"verdict": "allow", **common, "_hub": True}
    return out


def check_rows(chains: list[Chain], rows: list[dict[str, str]], report: Report) -> None:
    if not rows:
        report.add("export rows", True, "no export CSV in this pack", warning=True)
        return
    index = _index(chains)
    matched, mismatched, uncovered = 0, [], 0
    for n, row in enumerate(rows, start=2):  # line 1 is the header
        chain = index.get(row.get("reporter_id") or "")
        if chain is None:
            uncovered += 1
            continue
        found = chain.get(row.get("action_digest") or "", {})
        decision, approval = found.get("decision"), found.get("approval")
        problems = []
        if row.get("decision_reported") == "true":
            if decision is None:
                problems.append("no chain entry for this action in the excerpt")
            else:
                if row.get("verdict") and decision.get("verdict") != row["verdict"]:
                    problems.append(
                        f"verdict {row['verdict']!r} vs chain {decision.get('verdict')!r}"
                    )
                if row.get("chain_hash") and row["chain_hash"] != decision.get("_hash"):
                    problems.append("chain_hash differs from the chain entry")
                if (
                    row.get("policy_digest")
                    and decision.get("policy_digest")
                    and row["policy_digest"] != decision["policy_digest"]
                ):
                    problems.append("policy_digest differs from the chain entry")
        # The control plane verified this row's signature against the key the
        # reporter registered at enrolment. If the chain entry it cites is
        # unsigned here, the pack has been altered — this is what catches a
        # pack whose public key was simply deleted along with the signatures.
        if row.get("attested") == "true" and decision is not None and not decision.get("_signed"):
            problems.append(
                "the control plane attested this row, but its chain entry is unsigned here"
            )
        if row.get("decided_by"):
            if approval is None:
                problems.append("the export names an approver the chain does not record")
            elif approval.get("decided_by") != row["decided_by"]:
                problems.append(
                    f"approver {row['decided_by']!r} vs chain {approval.get('decided_by')!r}"
                )
        if problems:
            mismatched.append(f"line {n} ({row.get('tool')}): " + "; ".join(problems))
        else:
            matched += 1
    report.add(
        "export rows",
        not mismatched,
        f"{matched} of {len(rows)} rows agree with their chain entry"
        + (f"; {len(mismatched)} disagree: " + " | ".join(mismatched[:10]) if mismatched else ""),
    )
    # The other direction: decisions the chains hold that the export does not.
    # Not a failure — the export may be filtered, or cover a narrower window —
    # but an auditor reading only the spreadsheet should know it is not the
    # whole record.
    in_rows = {(r.get("reporter_id"), r.get("action_digest")) for r in rows}
    unreported = sum(
        1
        for reporter, by_digest in index.items()
        for digest, found in by_digest.items()
        if "decision" in found and (reporter, digest) not in in_rows
    )
    if unreported:
        report.add(
            "chain coverage",
            True,
            f"{unreported} decision(s) in the chain excerpts have no row in the export",
            warning=True,
        )
    if uncovered:
        report.add(
            "export coverage",
            True,
            f"{uncovered} row(s) come from reporters whose chain is not in this pack",
            warning=True,
        )


# --- entry point -----------------------------------------------------------------------------


def _stage(report: Report, name: str, fn: Any, *args: Any, default: Any = None) -> Any:
    """Run one check stage; an exception is that stage FAILING, not a crash.

    Each stage handles the records it knows how to judge. This is the
    backstop for the ones nobody anticipated: an auditor running the verifier
    on a damaged or doctored pack is owed a FAILED verdict naming the stage,
    and every other stage's result, rather than a traceback."""
    try:
        return fn(*args)
    except Exception as exc:  # noqa: BLE001 - see docstring
        report.add(name, False, f"could not be checked: {type(exc).__name__}: {exc}")
        return default


def verify_pack(root: Path) -> Report:
    report = Report()
    manifest = _stage(report, "manifest", check_manifest, root, report) or {}
    try:
        at_ms = int(manifest.get("created_at_ms") or 0)
    except (TypeError, ValueError):
        at_ms = 0
    chains = _stage(report, "chains", check_chains, root, report, default=[])
    rows = _stage(report, "export rows", _load_rows, root, default=[])
    _stage(report, "approvals", check_approvals, root, chains, report, at_ms)
    _stage(report, "policies", check_policies, root, chains, rows, report)
    _stage(report, "export rows", check_rows, chains, rows, report)
    return report


def render(report: Report) -> str:
    lines = []
    pack = report.facts.get("pack") or {}
    if pack:
        lines.append(
            f"Evidence pack: {pack.get('title')} — fleet {pack.get('fleet_id')}, window {pack.get('window')}"
        )
        lines.append(
            "Payloads: "
            + (
                "withheld (digests only) — each input/output is committed to by a salted digest "
                "inside its signed entry; any one can be produced and checked against it"
                if pack.get("payloads") == "digests-only"
                else "included — each input/output is checked against its digest"
            )
        )
    for c in report.checks:
        mark = "PASS" if c.ok and not c.warning else ("NOTE" if c.warning else "FAIL")
        lines.append(f"[{mark}] {c.name}: {c.detail}")
    lines.append("RESULT: " + ("VERIFIED" if report.ok else "FAILED"))
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify an evidence pack offline.")
    parser.add_argument(
        "pack",
        nargs="?",
        default=str(Path(__file__).resolve().parent.parent),
        help="the pack directory (default: the pack this script sits in)",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)
    report = verify_pack(Path(args.pack))
    if args.json:
        print(
            json.dumps({"ok": report.ok, "checks": [c.__dict__ for c in report.checks]}, indent=2)
        )
    else:
        print(render(report))
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())
