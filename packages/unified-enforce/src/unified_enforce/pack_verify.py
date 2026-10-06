"""Verify an evidence pack offline — the auditor's half of `evidence_pack`.

**Who runs this.** Somebody who does not work for the customer and does not
trust the vendor: an ISO/IEC 42001 auditor sampling A.6.2.8 event logs and
A.9 human-oversight records. So it is written to run *from inside the pack*
with nothing installed but `cryptography`: the builder copies this file and
`attest.py` into `verify/`, the manifest records their hashes, and
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
   ask the customer to produce.
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
    from . import attest
except ImportError:  # inside a pack's verify/ directory
    import attest  # type: ignore[import-not-found,no-redef]

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MANIFEST = "manifest.json"

#: The hub records a `prompt` call's outcome rather than the DEFER that caused
#: it; the control plane's export records the DEFER. Same decision, two
#: vocabularies — mapped here so the row check compares like with like.
_HUB_TO_VERDICT = {
    "allow": "allow",
    "deny": "deny",
    "prompt_allowed": "defer",
    "prompt_denied": "defer",
    "approval_disabled": "defer",
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
    strict (sidecar) and lenient (hub) chains alike."""
    body = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


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
        k: manifest.get(k) for k in ("title", "fleet_id", "window", "created_at")
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
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        name = meta_path.parent.name
        raw_lines = (meta_path.parent / "chain.jsonl").read_text(encoding="utf-8").splitlines()
        entries = [json.loads(line) for line in raw_lines if line.strip()]
        chains.append(Chain(name, meta, entries))
        report.add(f"chain {name}", *_verify_chain(meta, entries))
    if not chains:
        report.add("chains", False, "the pack contains no chain excerpts")
    return chains


def _verify_chain(meta: dict[str, Any], entries: list[dict[str, Any]]) -> tuple[bool, str]:
    key_b64 = meta.get("public_key")
    key = _decode_key(key_b64) if key_b64 else None
    signed_from = meta.get("signed_from_seq")
    prev = meta.get("anchor")
    signed = unsigned = 0
    seen_signed = False
    for i, original in enumerate(entries):
        entry = dict(original)
        sig = entry.pop("sig", None)
        entry.pop("key_id", None)
        claimed = entry.pop("hash", None)
        where = f"entry {i} (seq {entry.get('seq')})"
        if entry.get("prev_hash") != prev:
            return False, f"{where}: chain break — prev_hash does not follow the previous entry"
        if _entry_hash(entry) != claimed:
            return False, f"{where}: hash mismatch — the entry was altered"
        if sig is None:
            # A signature that stops part-way is what stripping them looks like.
            if seen_signed:
                return False, f"{where}: unsigned after signed entries (signatures stripped?)"
            # A chain the pack supplies a key for is a chain that was signed:
            # from the start, or from where signing began. Without this, an
            # excerpt with every signature removed verifies as "unsigned" — the
            # hash chain still links, because hashes are not secret.
            if key is not None and (
                signed_from is None or int(entry.get("seq", -1)) >= int(signed_from)
            ):
                since = "the start" if signed_from is None else f"seq {signed_from}"
                return False, f"{where}: unsigned, but this chain is signed from {since}"
            unsigned += 1
        else:
            if key is None:
                return False, f"{where}: signed, but the pack has no public key for this chain"
            if not _verify_chain_signature(key, sig, claimed):
                return False, f"{where}: bad signature"
            seen_signed = True
            signed += 1
        prev = claimed
    first = entries[0].get("seq") if entries else None
    last = entries[-1].get("seq") if entries else None
    detail = f"{len(entries)} entries (seq {first}–{last}), {signed} signed, {unsigned} unsigned"
    if key is None:
        detail += "; no public key — integrity only, not authorship"
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
    `approver` and `attestation` beside its own fields."""
    found = []
    for e in chain.entries:
        payload = e.get("payload") if e.get("kind") == "approval" else e
        if isinstance(payload, dict) and payload.get("attestation") and payload.get("approver"):
            found.append(payload)
    return found


def check_approvals(root: Path, chains: list[Chain], report: Report, at_ms: int) -> None:
    approvals = [(c.name, a) for c in chains for a in _approvals_in(c)]
    if not approvals:
        report.add("approvals", True, "no signed human resolutions in these excerpts", warning=True)
        return
    keys = _trusted_keys(root, report, at_ms)
    for name, a in approvals:
        ap, at = a["approver"], a["attestation"]
        label = f"approval {a.get('action_digest', '')[:12]}… in {name}"
        key = keys.get(at.get("key_id"))
        if key is None:
            report.add(
                label,
                False,
                f"signed by {at.get('key_id')!r}, which the key set does not vouch for",
            )
            continue
        if key.role != "decision":
            report.add(
                label,
                False,
                f"key {key.kid} has role {key.role!r}; only a decision key may sign approvals",
            )
            continue
        # The chain stores the approver under readable names; the control plane
        # signed the wire form. Rebuilt field for field, then signed bytes are
        # produced by attest's own payload function — never re-derived here.
        wire = {
            "sub": ap["subject"],
            "email": ap.get("email", ""),
            "sid": ap.get("session_id", ""),
            "auth_time_ms": ap["authenticated_at_ms"],
        }
        payload = attest.canonical(
            attest.resolution_payload(
                action_digest=a["action_digest"],
                kind=a["kind"],
                approver=wire,
                scope=a.get("scope"),
                resolved_at_ms=at["resolved_at_ms"],
                expires_at_ms=at["expires_at_ms"],
                nonce=at["nonce"],
                fleet_id=at["fleet_id"],
            )
        )
        try:
            Ed25519PublicKey.from_public_bytes(attest.unb64u(key.public_key)).verify(
                attest.unb64u(at["signature"]), payload
            )
        except (InvalidSignature, ValueError, TypeError):
            report.add(label, False, "the control plane's signature does not verify")
            continue
        if key.expires_at_ms <= at["resolved_at_ms"]:
            report.add(label, False, f"key {key.kid} had expired when this was signed")
            continue
        report.add(
            label,
            True,
            f"{a['kind']} by {ap.get('email') or ap['subject']} ({ap['subject']}), signed by {key.kid}",
        )


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
    """reporter_id -> action_digest -> {decision, approval} from the chains."""
    out: dict[str, dict[str, dict[str, Any]]] = {}
    for c in chains:
        by_digest = out.setdefault(c.meta.get("reporter_id") or c.name, {})
        for e in c.entries:
            if e.get("kind") in ("decision", "approval"):
                p = e["payload"]
                slot = by_digest.setdefault(p["action_digest"], {})
                slot[e["kind"]] = {
                    **p,
                    "_hash": e["hash"],
                    "_seq": e.get("seq"),
                    "_signed": "sig" in e,
                }
            elif e.get("phase") == "received" and e.get("action_digest"):
                slot = by_digest.setdefault(e["action_digest"], {})
                slot["decision"] = {
                    "verdict": _HUB_TO_VERDICT.get(
                        e.get("authz_decision", ""), e.get("authz_decision")
                    ),
                    "policy_digest": e.get("policy_digest"),
                    "_hash": e["hash"],
                    "_seq": e.get("seq"),
                    "_signed": "sig" in e,
                    "_hub": True,
                }
                if e.get("approver"):
                    slot["approval"] = {"decided_by": e["approver"].get("subject")}
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
        found = chain.get(row["action_digest"], {})
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
                if row.get("chain_hash") and row["chain_hash"] != decision["_hash"]:
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
    in_rows = {(r.get("reporter_id"), r["action_digest"]) for r in rows}
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


def verify_pack(root: Path) -> Report:
    report = Report()
    manifest = check_manifest(root, report) or {}
    at_ms = int(manifest.get("created_at_ms") or 0)
    chains = check_chains(root, report)
    rows = _load_rows(root)
    check_approvals(root, chains, report, at_ms)
    check_policies(root, chains, rows, report)
    check_rows(chains, rows, report)
    return report


def render(report: Report) -> str:
    lines = []
    pack = report.facts.get("pack") or {}
    if pack:
        lines.append(
            f"Evidence pack: {pack.get('title')} — fleet {pack.get('fleet_id')}, window {pack.get('window')}"
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
