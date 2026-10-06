"""Build an evidence pack: one artifact an auditor can check without trusting us.

**Why a pack and not the CSV.** The control plane's export is metadata and
digests only, by design (specs/evidence-retention.v1.md): agent traffic does not
leave the customer's environment. But ISO/IEC 42001's event-log guidance
(A.6.2.8, B.6.2.8) is about reconstructing what the system did — including the
data it acted on — and 7.5.3 asks that such records be protected from loss of
integrity. The CSV answers "what was decided"; the signed chains in the
customer's environment answer "and here is the record, unaltered". A pack puts
the two side by side, with the keys and policies needed to check one against
the other, and a verifier that runs with nothing but `cryptography` installed.

**Built where the evidence lives.** This runs on the customer's machine, next to
the sidecar or hub chains. Nothing here reaches the network: the CSV is the
file an operator downloaded from the console, the key set is the document the
sidecar already holds, and the policies are the files on disk.

**What goes in** (see README.md inside a pack for the auditor's version):

    README.md                 what this is, how to verify, control map, gaps
    control-map.json          ISO/IEC 42001 clause/control -> files and fields
    manifest.json             sha256 of every file; written last
    export/evidence.csv       the console export, byte for byte
    chains/<name>/chain.jsonl contiguous excerpt covering the window, verbatim
    chains/<name>/meta.json   anchor, seq range, reporter id, public key
    trust/root_public_key.txt the pinned root
    trust/keyset.json         the root-signed key set naming the decision key
    policies/<digest>.json    normalised policy document, hashes to its digest
    policies/<digest>.yaml    the authored source, where there is one
    policies/index.json       digest -> files
    verify/verify.py          entry point; `python verify/verify.py`
    verify/pack_verify.py     the verifier (this package's, copied)
    verify/attest.py          the canonical signature verifier (copied)
    verify/detach.py          the payload-digest rule (copied)

**Excerpts are verbatim and contiguous.** Lines are copied byte for byte, from
the first entry at or after `--from` to the last before `--to`, with everything
between — never filtered by content. A filtered excerpt would not chain, and an
excerpt that chains is the only kind whose completeness can be checked.

**Payloads: include or digests-only.** Chains record every input and output
raw, each committed to by a salted digest inside the signed entry (detach.py).
`--payloads include` (the default) ships them; an auditor sees exactly what the
agent sent and got back, and the verifier checks each one against its digest.
`--payloads digests-only` withholds them: each line is rewritten through
`detach.redact`, which removes the values and their salts but not the digests,
so the line hashes to the same value and every link and signature still
verifies. That is the one exception to "byte for byte": the line is
re-serialised, which the verifier is indifferent to because it hashes canonical
bytes of the parsed entry, never the line as written. What the auditor gets is
a commitment: the customer can later produce any single value with its salt,
and it either matches the signed digest or it does not. Entries written before
payloads were detachable carry their (write-time shaped) content inside the
hash itself and cannot be withheld; the builder counts them into meta.json and
the verifier says so.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shutil
import sys
import tempfile
import time
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import attest as _attest_module
from . import detach as _detach_module
from . import pack_verify
from .policy import PolicyDoc, PolicyEngine, policy_digest

GENERATOR = "unified-enforce evidence_pack v1"
PAYLOAD_MODES = ("include", "digests-only")


def _parse_ts(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# --- chains ---------------------------------------------------------------------


@dataclass
class ChainSource:
    name: str
    directory: Path
    public_key: str | None = None
    reporter_id: str | None = None
    signed_from_seq: int | None = None
    #: Every key the chain was signed with, as `{public_key, key_id,
    #: since_seq}` — for a reporter that rotated its key. One `public_key`
    #: cannot describe that chain: the entries before the rotation are signed
    #: by a key the pack would not hold, and would fail as forged. See
    #: `key_ranges_from_signing_record` for the hub's `signing.json`.
    key_ranges: list[dict[str, Any]] | None = None


def key_ranges_from_signing_record(path: Path) -> list[dict[str, Any]]:
    """A hub's `signing.json` as key ranges, oldest first.

    The hub writes the current key and the `seq` of the first entry it signed,
    and keeps each key it replaced under `previous` with that key's own start
    (unified_mcphub.signing.note_first_signed). Every range goes into the
    pack, so each stretch of the chain is checked against the key that was
    current when it was written. A record that does not parse raises: a pack
    built as if the chain were unsigned would be the wrong answer, quietly.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    records = [*(data.get("previous") or []), data]
    ranges = []
    for r in records:
        ranges.append(
            {
                "public_key": str(r["public_key"]),
                "key_id": r.get("key_id"),
                "since_seq": int(r["since_seq"]),
            }
        )
    return sorted(ranges, key=lambda r: r["since_seq"])


def _legacy_inline(entry: dict[str, Any]) -> bool:
    """An entry that predates detachable payloads *and* carries content.

    Only these cannot have their content withheld without breaking the chain.
    An entry with no `detached` that never held content — an engine approval,
    a hub `interdicted` line, a received entry with no arguments — is not
    "legacy" in any sense that matters to a reader, and counting it made a
    digests-only pack of a perfectly modern chain report undisclosable content
    that was never there.
    """
    if _detach_module.DETACHED in entry:
        return False
    phase = entry.get("phase")
    if phase == "received":
        return bool(entry.get("args"))
    if phase == "completed":
        return entry.get("result") not in (None, "", {}, [])
    if entry.get("kind") == "decision":
        action = (entry.get("payload") or {}).get("action") or {}
        return bool(action.get("params")) or bool((action.get("context") or {}).get("extra"))
    return False


def excerpt(
    source: ChainSource, start: datetime, end: datetime, *, payloads: str = "include"
) -> tuple[list[str], dict[str, Any]]:
    """The contiguous run of raw lines covering [start, end).

    Day files are read in the order the chain writer wrote them (sorted names),
    exactly as `HashChainWriter.verify` walks them, so the excerpt's links are
    the chain's links.

    `payloads="digests-only"` re-serialises each line through `detach.redact`
    (see module docstring); the selection of lines is identical either way.
    """
    if payloads not in PAYLOAD_MODES:
        raise ValueError(f"payloads must be one of {PAYLOAD_MODES}, got {payloads!r}")
    lines: list[str] = []
    for path in sorted(source.directory.glob("*.jsonl")):
        lines.extend(line for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
    parsed = [json.loads(line) for line in lines]
    inside = [i for i, e in enumerate(parsed) if "ts" in e and start <= _parse_ts(e["ts"]) < end]
    if not inside:
        return [], {"entries": 0}
    first, last = inside[0], inside[-1]
    chosen = lines[first : last + 1]
    legacy_inline = 0
    if payloads == "digests-only":
        chosen = [
            json.dumps(
                _detach_module.redact(entry),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                default=str,
            )
            for entry in parsed[first : last + 1]
        ]
        legacy_inline = sum(1 for e in parsed[first : last + 1] if _legacy_inline(e))
    meta = {
        "name": source.name,
        "reporter_id": source.reporter_id,
        "anchor": parsed[first].get("prev_hash"),
        "first_seq": parsed[first].get("seq"),
        "last_seq": parsed[last].get("seq"),
        "first_ts": parsed[first].get("ts"),
        "last_ts": parsed[last].get("ts"),
        "entries": len(chosen),
        "public_key": source.public_key,
        "key_id": next(
            (e.get("key_id") for e in parsed[first : last + 1] if e.get("key_id")), None
        ),
        "signed_from_seq": source.signed_from_seq,
        "payloads": payloads,
        #: Present when the reporter rotated keys: each key and the seq it
        #: signed from (pack_verify checks each range with its own key).
        **({"keys": source.key_ranges} if source.key_ranges else {}),
        #: Entries that predate detachable payloads and still carry content
        #: inline (`_legacy_inline`). In a digests-only excerpt their content
        #: could not be withheld — see the module docstring.
        "legacy_inline_entries": legacy_inline,
    }
    return chosen, meta


# --- policies ---------------------------------------------------------------------


@dataclass
class PolicySource:
    label: str
    doc: PolicyDoc
    authored: bytes | None = None  # the YAML as written, when there is one


def policy_from_yaml(path: Path) -> PolicySource:
    text = path.read_text(encoding="utf-8")
    return PolicySource(
        label=path.name, doc=PolicyEngine.from_yaml(text)._doc, authored=text.encode()
    )


def policy_from_hub() -> PolicySource:
    """The hub compiles workspace rules, danger floors and constitutional rules
    into one document; that compiled document is what its `policy_digest` names,
    so it is what goes in the pack. Imported lazily: the engine never depends on
    the hub, and a sidecar-only deployment has no hub to read. By name rather
    than an import statement for the same reason: the engine is type-checked on
    its own, where the hub is an untyped stranger."""
    import importlib

    authz = importlib.import_module("unified_mcphub.authz")
    config = importlib.import_module("unified_mcphub.config")
    hub = config.load_hub_config()
    resolver = authz.AuthzResolver(
        config.load_workspace(hub.active_workspace),
        config.load_dangerous_commands(),
        deployment=hub.deployment,
    )
    return PolicySource(
        label=f"hub workspace {hub.active_workspace!r} (compiled)", doc=resolver._engine._doc
    )


# --- control map --------------------------------------------------------------------

#: Which parts of the pack evidence which ISO/IEC 42001:2023 requirements.
#: Paraphrased deliberately — the standard's text is the customer's licensed
#: copy, and the reader has it. `gaps` is as important as `evidence`: an auditor
#: who discovers an omission the pack did not admit stops trusting the rest.
CONTROL_MAP: list[dict[str, Any]] = [
    {
        "ref": "A.6.2.8 / B.6.2.8",
        "topic": "AI system recording of event logs",
        "evidence": [
            "chains/*/chain.jsonl — every decision, written automatically at decision time by the "
            "enforcement layer (not by the agent), including the data acted on: each input and output is "
            "recorded raw and committed to by a salted digest inside the signed entry",
            "with payloads included, every input/output in the pack is checked against that digest; with "
            "payloads withheld (digests-only), each remains committed to and can be produced on request "
            "and checked against the same signed entry",
            "export/evidence.csv — one row per action for the window",
        ],
        "gaps": [
            "retention period is the customer's policy; this pack records the window, not the retention",
            "in a digests-only pack the data acted on is evidenced by commitment, not shown: "
            "reconstructing it needs the customer to produce the withheld values",
            "entries written before payloads were detachable hold their content as shaped at write "
            "time (audit_level), not raw",
        ],
    },
    {
        "ref": "7.5.3",
        "topic": "Control of documented information (integrity, retention, version control)",
        "evidence": [
            "chains — hash-linked; altering, inserting or removing an entry breaks every later link",
            "chains — Ed25519-signed per entry where the reporter has a key; signature covers all history",
            "chains — each payload's salted digest is inside the signed body, so an input or output "
            "edited after the fact fails verification, and withholding one does not break the chain",
            "manifest.json — sha256 of every file in this pack",
            "policies/ + policy_digest — the exact policy version behind each decision",
        ],
        "gaps": [],
    },
    {
        "ref": "A.9.2, A.9.3 / B.9.3",
        "topic": "Responsible use: required approvals, human oversight with authority to override",
        "evidence": [
            "approval entries in chains — who decided (authenticated subject, email, session, sign-in time), "
            "what, and when, signed by the control plane's decision key",
            "export/evidence.csv — decided_how=human rows with approver and timestamps",
            "trust/ — root key and key set, so the approval signature is checkable back to a pinned root",
        ],
        "gaps": [
            "approver training and competence (7.2) are HR records, not in this pack",
            "terminal-answered hub prompts are unattributed until the hub routes them through the console",
        ],
    },
    {
        "ref": "A.9.4 / B.9.4",
        "topic": "Use according to intended use",
        "evidence": [
            "every allow and deny names the rule that decided it (rule_id) and the policy in force (policy_digest)",
            "policies/ — the rules themselves, i.e. the intended use made executable",
        ],
        "gaps": [
            "mapping each agent to its documented intended-use statement (agent register) is not yet included"
        ],
    },
    {
        "ref": "8.1",
        "topic": "Operational controls implemented and monitored; records that processes ran as planned",
        "evidence": [
            "the whole pack: per-action proof that the configured controls ran on each action"
        ],
        "gaps": [],
    },
    {
        "ref": "9.1 / B.6.2.7",
        "topic": "Monitoring results documented; log review procedure",
        "evidence": ["export/evidence.csv and the console's export report are monitoring results"],
        "gaps": ["a signed 'reviewed by / on' attestation for this window is not yet produced"],
    },
    {
        "ref": "A.6.2.5 / 6.3",
        "topic": "Deployment and planned changes",
        "evidence": ["policy_digest per decision shows exactly when the policy in force changed"],
        "gaps": ["who approved each policy change (policy change log) is not yet included"],
    },
]

OUT_OF_SCOPE = (
    "Clauses 4–6 (context, leadership, risk assessment and treatment, statement of applicability), "
    "7.1–7.4, 9.2 (internal audit), 9.3 (management review), 10 (improvement); Annex A.2 (AI policy), "
    "A.4 (resource documentation), A.5 (impact assessment), A.6.1–A.6.2.4 (development objectives, "
    "requirements, design, verification and validation), A.7 (data), A.8 (information for interested "
    "parties), A.10.2/A.10.4. These are the organisation's management-system documents; this pack is "
    "evidence that its operational controls ran."
)


_PAYLOADS_README = {
    "include": (
        "**Payloads included.** Every input an agent sent and every output it got back is in the "
        "chain entries, raw. Each is committed to by a salted digest inside its signed entry, and "
        "the verifier checks every one against it: an input or output altered in this pack fails."
    ),
    "digests-only": (
        "**Payloads withheld (digests only).** Inputs and outputs have been removed from the chain "
        "entries in this pack; each is committed to by a salted digest inside the signed entry, so "
        "every link and signature still verifies. The customer can produce any of them — the value "
        "and its salt — and the auditor can check it against the signed entry: "
        "`sha256(base64-decoded salt + canonical JSON of the value)` must equal the entry's "
        "`detached[<path>]` (`verify/detach.py`, `digest`). The salt is withheld with the value "
        "because many inputs are guessable, and an unsalted digest would let anyone holding this "
        "pack confirm a guess."
    ),
}


def _readme(
    manifest: dict[str, Any], chains: list[dict[str, Any]], policies: dict[str, Any], rows: int
) -> str:
    lines = [
        f"# Evidence pack — {manifest['title']}",
        "",
        f"Fleet `{manifest['fleet_id']}`, window `{manifest['window']['from']}` to `{manifest['window']['to']}` "
        f"(from inclusive, to exclusive). Built {manifest['created_at']} by {GENERATOR}.",
        "",
        "## Verify it yourself",
        "",
        "```",
        "pip install cryptography",
        "python verify/verify.py",
        "```",
        "",
        "No network access and no vendor software needed. The verifier checks: every file against "
        "`manifest.json`; every chain excerpt link by link and signature by signature; every human "
        "approval's signature back to the pinned root key; every policy file against the digest the "
        "decisions cite; and every export row against its signed chain entry. It exits non-zero on any failure.",
        "",
        "**What to confirm independently.** The manifest proves the pack arrived as it was built; it is "
        "not a signature, and whoever built the pack could rebuild it. The security rests on keys, so "
        "confirm them out of band: the root key fingerprint with the control-plane operator, and each "
        "chain's key id against the reporter's enrolment record. Then re-download the export for the same "
        "window from the console yourself — every row the control plane marked `attested` must match a "
        "signed chain entry here, which the verifier checks.",
        "",
        "## What is in it",
        "",
        _PAYLOADS_README[manifest.get("payloads", "include")],
        "",
        f"- `export/evidence.csv` — {rows} rows, the control plane's export, unmodified.",
    ]
    for c in chains:
        lines.append(
            f"- `chains/{c['name']}/` — {c['entries']} entries, seq {c['first_seq']}–{c['last_seq']}, "
            f"reporter `{c.get('reporter_id') or 'unknown'}`, "
            + (
                "signed"
                if c.get("public_key")
                else "**no public key: integrity only, not authorship**"
            )
            + f". Anchor `{(c.get('anchor') or '')[:16]}…` ties it to the history before the window."
        )
    for digest, info in policies.items():
        lines.append(f"- `policies/{info['normalized']}` — {info['label']} (`{digest[:12]}…`)")
    lines += [
        "- `trust/` — the root public key and the root-signed key set naming the approval-signing key.",
        "",
        "## ISO/IEC 42001:2023 — what this evidences",
        "",
        "| Ref | Topic | Evidence here | Not covered |",
        "|---|---|---|---|",
    ]
    for item in CONTROL_MAP:
        lines.append(
            f"| {item['ref']} | {item['topic']} | "
            + "<br>".join(item["evidence"])
            + " | "
            + ("<br>".join(item["gaps"]) or "—")
            + " |"
        )
    lines += [
        "",
        "**Out of scope:** " + OUT_OF_SCOPE,
        "",
        "## Reading the CSV",
        "",
        "`decided_how` is `policy` where a rule decided, `human` where a person answered, `structural` "
        "where no rule could (containment, an unverifiable revocation list, an unreadable request). "
        "`attested=true` means the reporter's signature over that row verified at the control plane. "
        "Action parameters are deliberately absent from the CSV; they are in the chain entries "
        "(or, in a digests-only pack, committed to there by digest).",
        "",
    ]
    return "\n".join(lines)


# --- assembly --------------------------------------------------------------------------------


def build(
    *,
    out: Path,
    title: str,
    fleet_id: str,
    start: datetime,
    end: datetime,
    csv_path: Path | None,
    chains: list[ChainSource],
    policies: list[PolicySource],
    root_key: str | None,
    keyset_path: Path | None,
    payloads: str = "include",
) -> Path:
    if payloads not in PAYLOAD_MODES:
        raise ValueError(f"payloads must be one of {PAYLOAD_MODES}, got {payloads!r}")
    staging = Path(tempfile.mkdtemp(prefix="evidence-pack-"))
    try:
        rows = 0
        if csv_path is not None:
            (staging / "export").mkdir()
            shutil.copyfile(csv_path, staging / "export" / "evidence.csv")
            with csv_path.open(newline="", encoding="utf-8") as fh:
                rows = sum(1 for _ in csv.DictReader(fh))

        chain_meta = []
        for source in chains:
            lines, meta = excerpt(source, start, end, payloads=payloads)
            if not lines:
                print(
                    f"warning: chain {source.name!r} has no entries in the window", file=sys.stderr
                )
                continue
            target = staging / "chains" / source.name
            target.mkdir(parents=True)
            (target / "chain.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
            (target / "meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
            chain_meta.append(meta)

        index: dict[str, Any] = {}
        if policies:
            (staging / "policies").mkdir()
        for p in policies:
            digest = policy_digest(p.doc)
            info = {"label": p.label, "normalized": f"{digest}.json"}
            (staging / "policies" / info["normalized"]).write_text(
                json.dumps(p.doc.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            if p.authored is not None:
                info["authored"] = f"{digest}.yaml"
                (staging / "policies" / info["authored"]).write_bytes(p.authored)
            index[digest] = info
        if index:
            (staging / "policies" / "index.json").write_text(
                json.dumps(index, indent=2) + "\n", encoding="utf-8"
            )

        if root_key and keyset_path:
            (staging / "trust").mkdir()
            (staging / "trust" / "root_public_key.txt").write_text(
                root_key.strip() + "\n", encoding="utf-8"
            )
            shutil.copyfile(keyset_path, staging / "trust" / "keyset.json")

        verify_dir = staging / "verify"
        verify_dir.mkdir()
        shutil.copyfile(Path(pack_verify.__file__), verify_dir / "pack_verify.py")
        shutil.copyfile(Path(_attest_module.__file__), verify_dir / "attest.py")
        shutil.copyfile(Path(_detach_module.__file__), verify_dir / "detach.py")
        (verify_dir / "verify.py").write_text(
            '"""Run: python verify/verify.py  (needs only `pip install cryptography`)."""\n'
            "import sys\nfrom pathlib import Path\n\n"
            "sys.path.insert(0, str(Path(__file__).resolve().parent))\n"
            "import pack_verify  # noqa: E402\n\n"
            "sys.exit(pack_verify.main([str(Path(__file__).resolve().parent.parent), *sys.argv[1:]]))\n",
            encoding="utf-8",
        )

        now = datetime.now(UTC)
        manifest: dict[str, Any] = {
            "generator": GENERATOR,
            "title": title,
            "fleet_id": fleet_id,
            "window": {"from": start.isoformat(), "to": end.isoformat()},
            "payloads": payloads,
            "created_at": now.isoformat(timespec="seconds"),
            "created_at_ms": int(time.time() * 1000),
        }
        (staging / "control-map.json").write_text(
            json.dumps(
                {
                    "standard": "ISO/IEC 42001:2023",
                    "controls": CONTROL_MAP,
                    "out_of_scope": OUT_OF_SCOPE,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        (staging / "README.md").write_text(
            _readme(manifest, chain_meta, index, rows), encoding="utf-8"
        )

        # Last, so it covers everything above — including the verifier itself,
        # whose integrity is part of what an auditor is trusting.
        manifest["files"] = [
            {"path": str(p.relative_to(staging)).replace("\\", "/"), "sha256": _sha256(p)}
            for p in sorted(staging.rglob("*"))
            if p.is_file()
        ]
        (staging / pack_verify.MANIFEST).write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )

        if out.suffix == ".zip":
            out.parent.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
                for path in sorted(staging.rglob("*")):
                    if path.is_file():
                        zf.write(path, Path(out.stem) / path.relative_to(staging))
        else:
            if out.exists():
                raise SystemExit(f"{out} already exists; refusing to overwrite evidence")
            shutil.copytree(staging, out)
        return out
    finally:
        shutil.rmtree(staging, ignore_errors=True)


# --- CLI ---------------------------------------------------------------------------------------


def _pairs(values: list[str] | None, flag: str) -> dict[str, str]:
    out = {}
    for v in values or []:
        name, sep, rest = v.partition("=")
        if not sep:
            raise SystemExit(f"{flag} expects NAME=VALUE, got {v!r}")
        out[name] = rest
    return out


def _read_value(value: str) -> str:
    return Path(value[1:]).read_text(encoding="utf-8").strip() if value.startswith("@") else value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="unified-evidence", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("pack", help="build an evidence pack")
    p.add_argument("--out", required=True, type=Path, help="directory, or a path ending in .zip")
    p.add_argument("--from", dest="start", required=True, help="ISO time, inclusive")
    p.add_argument("--to", dest="end", required=True, help="ISO time, exclusive")
    p.add_argument("--title", default="AI system event-log evidence")
    p.add_argument("--fleet", default="", help="fleet id, for the record")
    p.add_argument("--csv", type=Path, help="the console's export CSV for the same window")
    p.add_argument("--chain", action="append", help="NAME=DIR of a sidecar or hub audit chain")
    p.add_argument("--chain-key", action="append", help="NAME=PUBLIC_KEY (base64, or @file)")
    p.add_argument(
        "--chain-reporter", action="append", help="NAME=CREDENTIAL_ID as in the CSV's reporter_id"
    )
    p.add_argument(
        "--chain-signed-from", action="append", help="NAME=SEQ where that chain began signing"
    )
    p.add_argument(
        "--chain-signing",
        action="append",
        help="NAME=PATH of a hub's signing.json: every key the chain was signed with and the "
        "seq each took over from (needed for a hub that rotated its key)",
    )
    p.add_argument(
        "--policy", action="append", type=Path, help="an engine policy YAML in force in the window"
    )
    p.add_argument(
        "--hub-policy", action="store_true", help="include this machine's compiled hub policy"
    )
    p.add_argument("--root-key", help="the pinned root public key (base64url, or @file)")
    p.add_argument("--keyset", type=Path, help="the root-signed key set document")
    p.add_argument(
        "--payloads",
        choices=PAYLOAD_MODES,
        default="include",
        help="include tool inputs/outputs (default), or withhold them and ship only their "
        "salted digests — the pack still verifies end to end",
    )

    v = sub.add_parser("verify", help="verify a pack directory")
    v.add_argument("pack", type=Path)
    v.add_argument("--json", action="store_true")

    args = parser.parse_args(argv)
    if args.cmd == "verify":
        return pack_verify.main([str(args.pack), *(["--json"] if args.json else [])])

    keys = _pairs(args.chain_key, "--chain-key")
    reporters = _pairs(args.chain_reporter, "--chain-reporter")
    signed_from = _pairs(args.chain_signed_from, "--chain-signed-from")
    signing = _pairs(args.chain_signing, "--chain-signing")
    chains = []
    for name, directory in _pairs(args.chain, "--chain").items():
        ranges = (
            key_ranges_from_signing_record(Path(signing[name]).expanduser())
            if name in signing
            else None
        )
        public_key = _read_value(keys[name]) if name in keys else None
        start_seq = int(signed_from[name]) if name in signed_from else None
        if ranges:
            # The record names the current key and where signing began;
            # explicit flags still win for anything they set.
            public_key = public_key or ranges[-1]["public_key"]
            start_seq = start_seq if start_seq is not None else ranges[0]["since_seq"]
        chains.append(
            ChainSource(
                name=name,
                directory=Path(directory).expanduser(),
                public_key=public_key,
                reporter_id=reporters.get(name),
                signed_from_seq=start_seq,
                key_ranges=ranges,
            )
        )
    policies = [policy_from_yaml(p) for p in args.policy or []]
    if args.hub_policy:
        policies.append(policy_from_hub())
    out = build(
        out=args.out,
        title=args.title,
        fleet_id=args.fleet,
        start=_parse_ts(args.start),
        end=_parse_ts(args.end),
        csv_path=args.csv,
        chains=chains,
        policies=policies,
        root_key=_read_value(args.root_key) if args.root_key else None,
        keyset_path=args.keyset,
        payloads=args.payloads,
    )
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
