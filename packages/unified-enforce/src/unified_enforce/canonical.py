"""Deterministic JSON canonicalization — spec §2 (specs/enforce/e1.v1.md).

Same data → same bytes → same digest, across processes and machines. This is the
foundation for action ids, signatures, and the audit hash chain, so the rules are
deliberately rigid:

- keys sorted, no whitespace, ensure_ascii=False (UTF-8 bytes)
- floats forbidden in canonical payloads (non-deterministic repr across
  serializers; money/amounts must be strings or ints at the schema boundary)
- non-JSON scalars rejected rather than coerced (a silent str() fallback would
  let two writers disagree on the same payload)
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

GENESIS_HASH = "0" * 64


class CanonicalizationError(ValueError):
    """Payload contains something canonical JSON cannot represent deterministically."""


def _check(value: Any, path: str) -> None:
    if isinstance(value, float):
        raise CanonicalizationError(f"float at {path}: use str or int in canonical payloads")
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise CanonicalizationError(f"non-string key at {path}: {k!r}")
            _check(v, f"{path}.{k}")
    elif isinstance(value, list):
        for i, v in enumerate(value):
            _check(v, f"{path}[{i}]")
    elif value is not None and not isinstance(value, (str, int, bool)):
        raise CanonicalizationError(f"non-JSON value at {path}: {type(value).__name__}")


def canonical_bytes(payload: dict[str, Any]) -> bytes:
    _check(payload, "$")
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(payload: dict[str, Any]) -> str:
    return sha256_hex(canonical_bytes(payload))
