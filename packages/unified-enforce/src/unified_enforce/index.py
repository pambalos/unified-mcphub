"""SQLite read index over the audit chain — spec §3 (specs/enforce/e2.v1.md).

The JSONL chain stays the source of truth (and the only thing `verify()`
trusts); the index is a derived, rebuildable projection for queries like
"every DENY for agent:x against mcp://payments/* this week". Incremental:
`refresh()` only parses lines appended since the last run, so it can be called
after every batch or from a cron without rescanning history.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

_SCHEMA = """
CREATE TABLE IF NOT EXISTS entries (
    seq           INTEGER PRIMARY KEY,
    ts            TEXT NOT NULL,
    kind          TEXT NOT NULL,
    hash          TEXT NOT NULL UNIQUE,
    prev_hash     TEXT NOT NULL,
    file          TEXT NOT NULL,
    line          INTEGER NOT NULL,
    action_digest TEXT,
    principal     TEXT,
    tool          TEXT,
    verb          TEXT,
    resource      TEXT,
    verdict       TEXT,
    rule_id       TEXT,
    source        TEXT
);
CREATE INDEX IF NOT EXISTS idx_entries_principal ON entries(principal);
CREATE INDEX IF NOT EXISTS idx_entries_tool ON entries(tool);
CREATE INDEX IF NOT EXISTS idx_entries_verdict ON entries(verdict);
CREATE INDEX IF NOT EXISTS idx_entries_ts ON entries(ts);
CREATE TABLE IF NOT EXISTS indexed_files (
    file          TEXT PRIMARY KEY,
    lines_indexed INTEGER NOT NULL
);
"""

_QUERY_COLUMNS = ("principal", "tool", "verb", "resource", "verdict", "rule_id", "kind", "source")


class AuditIndex:
    def __init__(self, db_path: str | Path) -> None:
        self._db = sqlite3.connect(str(db_path))
        self._db.row_factory = sqlite3.Row
        self._db.executescript(_SCHEMA)

    def close(self) -> None:
        self._db.close()

    def __enter__(self) -> "AuditIndex":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # --- ingest ---

    def refresh(self, audit_dir: str | Path) -> int:
        """Index entries appended since the last refresh. Returns rows added."""
        added = 0
        for path in sorted(Path(audit_dir).glob("*.jsonl")):
            row = self._db.execute(
                "SELECT lines_indexed FROM indexed_files WHERE file = ?", (path.name,)
            ).fetchone()
            skip = row["lines_indexed"] if row else 0
            lineno = 0
            with path.open("rb") as fh:
                for raw in fh:
                    lineno += 1
                    if lineno <= skip or not raw.strip():
                        continue
                    self._insert(json.loads(raw), path.name, lineno)
                    added += 1
            self._db.execute(
                "INSERT INTO indexed_files (file, lines_indexed) VALUES (?, ?) "
                "ON CONFLICT(file) DO UPDATE SET lines_indexed = excluded.lines_indexed",
                (path.name, lineno),
            )
        self._db.commit()
        return added

    def _insert(self, entry: dict[str, Any], file: str, line: int) -> None:
        payload = entry.get("payload") or {}
        action = payload.get("action") or {}
        self._db.execute(
            "INSERT OR IGNORE INTO entries (seq, ts, kind, hash, prev_hash, file, line, "
            "action_digest, principal, tool, verb, resource, verdict, rule_id, source) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                entry["seq"],
                entry["ts"],
                entry["kind"],
                entry["hash"],
                entry["prev_hash"],
                file,
                line,
                payload.get("action_digest"),
                (action.get("principal") or {}).get("id"),
                action.get("tool"),
                action.get("verb"),
                action.get("resource"),
                payload.get("verdict"),
                payload.get("rule_id"),
                payload.get("source"),
            ),
        )

    # --- queries ---

    def query(
        self,
        *,
        since: str | None = None,  # ISO-8601 lower bound on ts (inclusive)
        until: str | None = None,  # ISO-8601 upper bound on ts (exclusive)
        limit: int = 100,
        **filters: str,
    ) -> list[dict[str, Any]]:
        for key in filters:
            if key not in _QUERY_COLUMNS:
                raise ValueError(f"unknown filter: {key} (allowed: {', '.join(_QUERY_COLUMNS)})")
        clauses, params = [], []
        for key, value in filters.items():
            clauses.append(f"{key} = ?")
            params.append(value)
        if since is not None:
            clauses.append("ts >= ?")
            params.append(since)
        if until is not None:
            clauses.append("ts < ?")
            params.append(until)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = self._db.execute(
            f"SELECT * FROM entries {where} ORDER BY seq DESC LIMIT ?", (*params, limit)
        ).fetchall()
        return [dict(r) for r in rows]

    def locate(self, seq: int) -> tuple[str, int] | None:
        """(file, line) of an entry — to pull the full record from the chain."""
        row = self._db.execute("SELECT file, line FROM entries WHERE seq = ?", (seq,)).fetchone()
        return (row["file"], row["line"]) if row else None
