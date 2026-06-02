"""Encrypted secrets store — spec §9.

A JSON {name: value} blob encrypted with Fernet; the Fernet key lives in the OS
keyring (macOS Keychain / Linux Secret Service / Windows DPAPI via `keyring`).
Config references secrets by name (`auth_secret_ref`); decrypted at use.
"""

from __future__ import annotations

import json
from pathlib import Path

import keyring
from cryptography.fernet import Fernet

from .config import mcphub_home
from .util import secure_write

_KEYRING_SERVICE = "unified-mcphub"
_KEYRING_USER = "secrets-key"


class SecretsStore:
    def __init__(self, path: Path | None = None) -> None:
        self._path = path or (mcphub_home() / "secrets.enc")

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

    # --- internals ---

    def _fernet(self) -> Fernet:
        key = keyring.get_password(_KEYRING_SERVICE, _KEYRING_USER)
        if key is None:
            key = Fernet.generate_key().decode()
            keyring.set_password(_KEYRING_SERVICE, _KEYRING_USER, key)
        return Fernet(key.encode())

    def _load(self) -> dict[str, str]:
        if not self._path.exists():
            return {}
        return json.loads(self._fernet().decrypt(self._path.read_bytes()).decode())

    def _save(self, data: dict[str, str]) -> None:
        secure_write(self._path, self._fernet().encrypt(json.dumps(data).encode()))
