"""Audit-log reader — spec §6.5 (SEC-MCP-3 CLI half).

Pure read-side functions over an audit directory of <UTC-date>.jsonl files
written by audit.py. Backs `audit show | pair | search | tail | lint | prune |
verify`.

The readers return entries exactly as written: `args` and `result` raw (see
audit.py). `view` is the display step the CLI applies before printing — it
shows each payload at the entry's recorded `audit_level` and drops the salts —
so `audit tail` on a terminal or in a screen share does not print a secret
just because the record, correctly, kept it. `--raw` skips it.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from unified_enforce import detach
from unified_enforce.audit import HashChainWriter, VerifyResult

from .audit import capture

_ALLOWED_DECISIONS = {"allow", "prompt_allowed", "approval_disabled"}
#: The phases that close a `received` bracket. `interdicted` (build-04) is a
#: forward the plane cancelled in flight; it is a closing phase so that a
#: contained agent's interrupted call reads as closed, not as a crash or a
#: hub that died mid-call.
_CLOSING_PHASES = {"completed", "interdicted"}


def _day_files(audit_dir: Path) -> list[Path]:
    if not audit_dir.is_dir():
        return []
    return sorted(audit_dir.glob("*.jsonl"))


def _iter_entries(audit_dir: Path):
    for path in _day_files(audit_dir):
        for lineno, line in enumerate(path.read_text().splitlines(), start=1):
            if not line.strip():
                continue
            try:
                yield path.name, lineno, json.loads(line)
            except json.JSONDecodeError:
                yield path.name, lineno, None  # malformed; lint reports, others skip


#: Shown in place of a payload that the entry commits to but does not hold.
WITHHELD = "«withheld: committed to by digest, not present in this copy»"
NOT_RECORDED = "«not recorded: audit.record_payloads was off»"


def view(entry: dict[str, Any] | None) -> dict[str, Any] | None:
    """An entry as the CLI shows it by default.

    Each detached payload is shaped by the entry's own `audit_level` (the rule
    that decided the call said how sensitive it is); an absent one is replaced
    by a marker saying why it is absent; salts are dropped (they are noise to a
    reader, and printing one beside a withheld value would undo the point of
    salting). Entries written before payloads were detachable were already
    shaped when written and are returned as they are — applying the level
    again would be harmless, but it would also suggest they were raw.
    """
    if entry is None or detach.DETACHED not in entry:
        return entry
    level = str(entry.get("audit_level") or "standard")
    unrecorded = set(entry.get(detach.UNRECORDED) or ())
    out = {k: v for k, v in entry.items() if k != detach.SALTS}
    for path in entry[detach.DETACHED]:
        if "." in path:
            continue  # hub payloads are top-level; nothing else is shaped here
        found, value = detach.get(entry, path)
        if found:
            out[path] = capture(value, level)
        else:
            out[path] = NOT_RECORDED if path in unrecorded else WITHHELD
    return out


def read_day(audit_dir: Path, date_str: str) -> list[dict]:
    path = audit_dir / f"{date_str}.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def pair(audit_dir: Path, request_id: str) -> dict:
    result: dict = {"received": None, "completed": None, "interdicted": None}
    for _, _, entry in _iter_entries(audit_dir):
        if entry and entry.get("request_id") == request_id:
            result[entry.get("phase")] = entry
    return result


def search(
    audit_dir: Path,
    *,
    caller: str | None = None,
    tool: str | None = None,
    server: str | None = None,
    decision: str | None = None,
    status: str | None = None,
    since: str | None = None,
    until: str | None = None,
    phase: str | None = None,
    limit: int | None = None,
) -> list[dict]:
    matches: list[dict] = []
    for _, _, entry in _iter_entries(audit_dir):
        if entry is None:
            continue
        if phase and entry.get("phase") != phase:
            continue
        if caller and entry.get("caller_id") != caller:
            continue
        if tool and entry.get("tool") != tool:
            continue
        if server and entry.get("mcp_server") != server:
            continue
        if decision and entry.get("authz_decision") != decision:
            continue
        if status and entry.get("result_status") != status:
            continue
        ts = entry.get("ts", "")
        if since and ts < since:
            continue
        if until and ts > until:
            continue
        matches.append(entry)
    return matches[:limit] if limit else matches


def tail(audit_dir: Path, n: int = 20) -> list[dict]:
    files = _day_files(audit_dir)
    if not files:
        return []
    lines = [line for line in files[-1].read_text().splitlines() if line.strip()]
    return [json.loads(line) for line in lines[-n:]]


def lint(audit_dir: Path) -> list[str]:
    problems: list[str] = []
    received: dict[str, str] = {}  # request_id -> decision
    closed: dict[str, str] = {}  # request_id -> the phase that closed the bracket
    for filename, lineno, entry in _iter_entries(audit_dir):
        if entry is None:
            problems.append(f"{filename}:{lineno}: malformed JSON")
            continue
        phase = entry.get("phase")
        rid = entry.get("request_id")
        if phase == "received":
            received[rid] = entry.get("authz_decision", "")
        elif phase in _CLOSING_PHASES:
            if rid in closed:
                problems.append(f"request {rid}: closed twice ({closed[rid]}, then {phase})")
            closed[rid] = phase
        else:
            problems.append(f"{filename}:{lineno}: unknown phase {phase!r}")
    for rid, dec in received.items():
        if dec in _ALLOWED_DECISIONS and rid not in closed:
            problems.append(f"request {rid}: '{dec}' received with no completed entry")
    for rid, phase in closed.items():
        if rid not in received:
            problems.append(f"request {rid}: {phase} with no received entry")
    return problems


def verify(audit_dir: Path, signing: Any = None) -> VerifyResult:
    """Replay the hash chain offline: any edited or deleted entry breaks it.

    `signing` is the hub's `signing.SigningRecord`, when it has signed. Given,
    every entry from its `since_seq` must also carry a valid signature by its
    key — which is what turns "consistent" into "written by this hub": a hash
    chain alone is happily recomputed end to end by anyone who can write the
    files. Entries before `since_seq` predate the key and are checked by hash,
    and are still covered by the first signature after them (see
    `HashChainWriter.verify`).
    """
    if signing is None:
        return HashChainWriter.verify(audit_dir)
    return HashChainWriter.verify(
        audit_dir, public_key=signing.public_bytes(), signed_from_seq=signing.since_seq
    )


def signed_entries(audit_dir: Path) -> int:
    """How many entries carry a signature (`sig`).

    `audit verify` asks this when there is no `signing.json`: a chain that
    carries signatures was written by a hub that had a key and recorded where
    signing began, so a missing record is not "this hub never signed" — it is
    the record having been removed, and checking only the hash would let the
    signed history be rewritten by anyone who also deletes one file. The same
    reading `unified-evidence verify` takes of a signed chain with no key.
    """
    return sum(1 for _, _, entry in _iter_entries(audit_dir) if entry and "sig" in entry)


def prune(audit_dir: Path, retention_days: int) -> list[str]:
    cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).date()
    removed: list[str] = []
    for path in _day_files(audit_dir):
        try:
            file_date = datetime.strptime(path.stem, "%Y-%m-%d").date()
        except ValueError:
            continue  # not a dated audit file; leave it
        if file_date < cutoff:
            path.unlink()
            removed.append(path.name)
    return removed
