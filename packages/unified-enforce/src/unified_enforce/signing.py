"""Ed25519 action signing — spec §3 (specs/enforce/e1.v1.md).

Signatures cover the action's canonical bytes, so a verified SignedAction is
proof of exactly what was decided — replayable offline. Key storage (OS keyring
locally, KMS/HSM in enterprise) is the caller's concern; this module only does
raw key bytes.
"""

from __future__ import annotations

import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, ConfigDict

from .action import Action


class Signer:
    def __init__(self, private_key: Ed25519PrivateKey, key_id: str) -> None:
        self._key = private_key
        self.key_id = key_id

    @classmethod
    def generate(cls, key_id: str) -> "Signer":
        return cls(Ed25519PrivateKey.generate(), key_id)

    @classmethod
    def from_private_bytes(cls, raw: bytes, key_id: str) -> "Signer":
        return cls(Ed25519PrivateKey.from_private_bytes(raw), key_id)

    def private_bytes(self) -> bytes:
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
        )

        return self._key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

    def public_bytes(self) -> bytes:
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        return self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def sign(self, action: Action) -> "SignedAction":
        canonical = action.canonical()
        sig = self._key.sign(canonical)
        return SignedAction(
            action=action,
            key_id=self.key_id,
            signature=base64.b64encode(sig).decode("ascii"),
        )


class SignedAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: Action
    key_id: str
    signature: str  # base64 Ed25519 over action.canonical()

    def verify(self, public_key_raw: bytes) -> bool:
        key = Ed25519PublicKey.from_public_bytes(public_key_raw)
        try:
            key.verify(base64.b64decode(self.signature), self.action.canonical())
            return True
        except InvalidSignature:
            return False
