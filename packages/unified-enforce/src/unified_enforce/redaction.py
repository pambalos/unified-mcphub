"""Capture levels for chain payloads — spec §2 (specs/enforce/e2.v1.md).

Ports the hub's secret-shape redaction (audit.py, ADR-0009) to the engine.
The rule split that makes this court-grade-compatible:

- `action_digest` is always computed over the FULL action — proof of exactly
  what happened without storing it.
- the STORED action copy is shaped by the rule's audit_level:
    minimal        → params and context.extra dropped (None)
    standard       → secret-shaped strings scrubbed (defense-in-depth, leaky
                     by design — real secrecy comes from `minimal`)
    detailed/full  → raw
- the hash chain covers the stored (post-capture) entry, so redaction is part
  of the tamper-evident record, not something applied after the fact.
"""

from __future__ import annotations

import re
from typing import Any

_SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9]{16,}"),
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),  # JWT
]
_REDACTED = "«redacted»"


def scrub(value: Any) -> Any:
    if isinstance(value, str):
        out = value
        for pat in _SECRET_PATTERNS:
            out = pat.sub(_REDACTED, out)
        return out
    if isinstance(value, dict):
        return {k: scrub(v) for k, v in value.items()}
    if isinstance(value, list):
        return [scrub(v) for v in value]
    return value


def capture_action(action_dump: dict[str, Any], level: str) -> tuple[dict[str, Any], bool]:
    """Shape a dumped action for storage. Returns (stored_copy, redacted) where
    `redacted` is True only when the copy differs from the original."""
    if level == "minimal":
        out = {**action_dump, "params": None}
        out["context"] = {**action_dump["context"], "extra": None}
        return out, True
    if level == "standard":
        params = scrub(action_dump["params"])
        extra = scrub(action_dump["context"]["extra"])
        changed = params != action_dump["params"] or extra != action_dump["context"]["extra"]
        if not changed:
            return action_dump, False
        return {
            **action_dump,
            "params": params,
            "context": {**action_dump["context"], "extra": extra},
        }, True
    return action_dump, False  # detailed / full
