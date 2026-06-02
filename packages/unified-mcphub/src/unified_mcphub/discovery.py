"""Shared discovery file — spec §12, ADR-0013.

Each daemon publishes its own entry to ~/.unified-ai/discovery/daemons.json and
reads it to find the others. We only own the `unified-mcphub` entry. fcntl
advisory lock guards concurrent writes; stale entries (>90s) are ignored by
readers. (Built hub-local for M0; lifts into adapter-common at M1 — ADR-0023.)
"""

from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path

from .config import discovery_path
from .util import now_iso

DAEMON = "unified-mcphub"


def _with_lock(path: Path, mutate) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        raw = os.read(fd, 1 << 20).decode() or ""
        data = json.loads(raw) if raw.strip() else {"version": 1, "daemons": {}}
        data = mutate(data)
        data["updated_at"] = now_iso()
        os.lseek(fd, 0, os.SEEK_SET)
        os.ftruncate(fd, 0)
        os.write(fd, json.dumps(data, indent=2).encode())
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def publish(*, listen: dict, servers: list[str], config_hash: str, started_at: str) -> None:
    def mutate(data: dict) -> dict:
        data.setdefault("daemons", {})[DAEMON] = {
            "version": "0.0.1",
            "pid": os.getpid(),
            "listen": listen,
            "servers": servers,
            "started_at": started_at,
            "config_hash": config_hash,
            "updated_at": now_iso(),
        }
        return data

    _with_lock(discovery_path(), mutate)


def refresh() -> None:
    def mutate(data: dict) -> dict:
        entry = data.get("daemons", {}).get(DAEMON)
        if entry:
            entry["updated_at"] = now_iso()
        return data

    _with_lock(discovery_path(), mutate)


def remove() -> None:
    def mutate(data: dict) -> dict:
        data.get("daemons", {}).pop(DAEMON, None)
        return data

    _with_lock(discovery_path(), mutate)
