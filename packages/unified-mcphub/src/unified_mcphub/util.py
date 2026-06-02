"""Small shared utilities: UTC time + secure file writes.

Single home for the `datetime.now(timezone.utc)` and `mkdir 0700 + open 0600 +
write` patterns that were repeated across modules (security-relevant — one site
getting the mode wrong is a leak).
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def now_iso() -> str:
    return utcnow().isoformat()


def secure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)


def secure_write(path: Path, data: bytes) -> None:
    """Atomically (re)write `path` with mode 0600 under a 0700 parent."""
    secure_dir(path.parent)
    fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
