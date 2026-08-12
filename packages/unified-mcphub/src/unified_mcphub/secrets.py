"""Encrypted secrets store — spec §9.

A JSON {name: value} blob encrypted with Fernet. Config references secrets by
name (`auth_secret_ref`); decrypted at use. The actual credentials live in
`secrets.enc`; the **only** thing held outside that file is the Fernet master key
that decrypts it.

Where the master key lives is pluggable (`secrets.key_backend`):

  - `keyring` — OS keychain (macOS Keychain / Windows DPAPI / Linux Secret Service)
  - `file`    — a 0600 key file beside secrets.enc (no OS prompt; good for headless
                Linux / containers where there is no Secret Service)
  - `env`     — read from $UNIFIED_MCPHUB_SECRETS_KEY (best for CI / automation)
  - `auto`    — env-if-set → keyring on macOS/Windows → keyring on Linux iff a real
                backend is wired up, else file

The resolved key is **memoized per process** (module-level cache), so the backend
is touched at most once per run regardless of how many servers resolve secrets —
this is what stops the macOS keychain from prompting once per server per reconnect.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path

import keyring
from cryptography.fernet import Fernet

from .config import SecretsConfig, load_secrets_config, mcphub_home
from .util import secure_write

logger = logging.getLogger(__name__)

_KEYRING_SERVICE = "unified-mcphub"
_KEYRING_USER = "secrets-key"
ENV_KEY_VAR = "UNIFIED_MCPHUB_SECRETS_KEY"

# Process-wide cache of resolved master keys, keyed by backend identity. Touching
# the backend (and any OS keychain prompt) happens once per key per process.
_key_cache: dict[str, str] = {}


def _reset_key_cache() -> None:
    """Test hook — drop the memoized keys so a fresh fake backend is re-read."""
    _key_cache.clear()


def _keyring_available() -> bool:
    """True when a real keyring backend is configured (not the no-op `fail` one).

    Headless Linux without a Secret Service daemon resolves to `fail.Keyring`,
    whose reads raise — `auto` falls back to the file backend in that case.
    """
    try:
        from keyring.backends import fail

        return not isinstance(keyring.get_keyring(), fail.Keyring)
    except Exception:  # noqa: BLE001 - any keyring import/probe issue → treat as unavailable
        return False


def resolve_backend(cfg: SecretsConfig) -> str:
    """Resolve `auto` to a concrete backend; pass explicit choices through."""
    backend = cfg.key_backend
    if backend != "auto":
        return backend
    if os.environ.get(ENV_KEY_VAR):
        return "env"  # an env key always wins — zero-config headless override
    if sys.platform in ("darwin", "win32"):
        return "keyring"
    return "keyring" if _keyring_available() else "file"


class SecretsStore:
    def __init__(
        self,
        path: Path | None = None,
        *,
        backend: str = "keyring",
        key_file: str | None = None,
    ) -> None:
        self._path = path or (mcphub_home() / "secrets.enc")
        self.backend = backend
        self._key_file = (
            Path(key_file).expanduser() if key_file else (mcphub_home() / "secrets.key")
        )

    @classmethod
    def from_config(
        cls, cfg: SecretsConfig | None = None, path: Path | None = None
    ) -> SecretsStore:
        """Build a store whose key backend is resolved from config (the real entry
        point — the bare constructor defaults to `keyring` for back-compat/tests)."""
        cfg = cfg or load_secrets_config()
        return cls(path, backend=resolve_backend(cfg), key_file=cfg.key_file)

    # --- public API ---

    def set(self, name: str, value: str) -> None:
        data = self._load()
        data[name] = value
        self._save(data)

    def get(self, name: str) -> str | None:
        return self._load().get(name)

    def remove(self, name: str) -> None:
        data = self._load()
        data.pop(name, None)
        self._save(data)

    def list(self) -> list[str]:
        return sorted(self._load())

    def exists(self) -> bool:
        """Whether an encrypted store is present (i.e. there is anything to unlock)."""
        return self._path.exists()

    def unlock(self) -> None:
        """Warm the key cache with a single backend read, so subsequent `get()`s
        don't re-hit the backend. No-op when no store exists yet (a fresh install
        with no secrets never touches the key backend)."""
        if self._path.exists():
            self._get_or_create_key()

    def read_key(self) -> str | None:
        """The current master key from this backend, or None if unset (CLI: export)."""
        return self._read_key()

    def write_key(self, key: str) -> None:
        """Persist a master key into this backend (CLI: import / migrate)."""
        self._write_key(key)
        _key_cache[self._cache_id()] = key

    # --- key backend ---

    def _cache_id(self) -> str:
        if self.backend == "file":
            return f"file:{self._key_file}"
        if self.backend == "env":
            return f"env:{ENV_KEY_VAR}"
        return f"keyring:{_KEYRING_SERVICE}/{_KEYRING_USER}"

    def _read_key(self) -> str | None:
        if self.backend == "file":
            return self._key_file.read_text().strip() if self._key_file.exists() else None
        if self.backend == "env":
            return os.environ.get(ENV_KEY_VAR)
        return keyring.get_password(_KEYRING_SERVICE, _KEYRING_USER)

    def _write_key(self, key: str) -> None:
        if self.backend == "file":
            secure_write(self._key_file, key.encode())
        elif self.backend == "env":
            # The hub can't persist an env var into the parent shell — surface the
            # value so the operator can export it, and use it for this process.
            logger.warning(
                "secrets: env backend can't persist the master key; set it in your "
                "environment so it survives restarts:\n    export %s=%s",
                ENV_KEY_VAR,
                key,
            )
        else:
            keyring.set_password(_KEYRING_SERVICE, _KEYRING_USER, key)

    def _get_or_create_key(self) -> str:
        cid = self._cache_id()
        cached = _key_cache.get(cid)
        if cached is not None:
            return cached
        key = self._read_key()
        if key is None:
            key = Fernet.generate_key().decode()
            self._write_key(key)
        _key_cache[cid] = key
        return key

    def _fernet(self) -> Fernet:
        return Fernet(self._get_or_create_key().encode())

    def _load(self) -> dict[str, str]:
        if not self._path.exists():
            return {}
        return json.loads(self._fernet().decrypt(self._path.read_bytes()).decode())

    def _save(self, data: dict[str, str]) -> None:
        secure_write(self._path, self._fernet().encrypt(json.dumps(data).encode()))
