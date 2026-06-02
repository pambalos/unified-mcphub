"""Per-caller bearer tokens for the TCP transport — spec §3.2, §3.3.

Unix-socket callers are authed by filesystem perms; TCP callers present
`Authorization: Bearer <token>`. Each caller has a `<caller>.token` file (0600);
the hub maps a presented token back to the caller name. The token itself is
never logged — `caller_token_id` (sha256 hex[:8]) is the loggable handle.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import stat
from pathlib import Path

from .config import mcphub_home
from .util import secure_write


class TokenStore:
    def __init__(self, tokens_dir: Path | None = None) -> None:
        self._dir = tokens_dir or (mcphub_home() / "caller-tokens")

    def mint(self, caller_id: str) -> str:
        token = secrets.token_hex(32)
        secure_write(self._dir / f"{caller_id}.token", token.encode())
        return token

    @staticmethod
    def caller_token_id(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()[:8]

    def resolve(self, presented_token: str) -> str | None:
        if not self._dir.is_dir():
            return None
        for path in sorted(self._dir.glob("*.token")):
            if stat.S_IMODE(path.stat().st_mode) != 0o600:
                continue  # refuse tokens in world/group-accessible files
            if hmac.compare_digest(path.read_text().strip(), presented_token):
                return path.stem
        return None

    def list_callers(self) -> list[str]:
        if not self._dir.is_dir():
            return []
        return sorted(p.stem for p in self._dir.glob("*.token"))

    def revoke(self, caller_id: str) -> None:
        (self._dir / f"{caller_id}.token").unlink(missing_ok=True)
