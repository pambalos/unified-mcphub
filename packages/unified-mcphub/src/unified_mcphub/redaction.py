"""Result redaction — spec §10.2.

A workspace-configurable filter that scrubs secret-shaped strings out of tool
*results* before the hub returns them to a harness and before they reach the
audit log. Harness-agnostic: every connected harness benefits at once, and it
catches leaks the per-harness install hooks never see (e.g. a `read_file` that
returns a `.env`). Default-off and pattern-scoped to keep false positives — a
legitimate sha256 digest, say — from being mangled.
"""

from __future__ import annotations

import logging
import re

from .config import RedactConfig

logger = logging.getLogger(__name__)


class Redactor:
    def __init__(self, cfg: RedactConfig) -> None:
        self.enabled = cfg.enabled
        self.replacement = cfg.replacement
        self._patterns: list[re.Pattern[str]] = []
        if cfg.enabled:
            for raw in cfg.patterns:
                try:
                    self._patterns.append(re.compile(raw))
                except re.error as exc:  # a bad pattern must not break tool calls
                    logger.error("ignoring invalid redact pattern %r: %s", raw, exc)

    def text(self, value: str) -> str:
        for pattern in self._patterns:
            value = pattern.sub(self.replacement, value)
        return value

    def result(self, result: dict) -> dict:
        """Redact the text of every text content block in a CallToolResult dict.

        Mutates and returns `result`; a no-op when disabled or shape is unexpected.
        """
        if not self.enabled or not isinstance(result, dict):
            return result
        content = result.get("content")
        if isinstance(content, list):
            for item in content:
                if isinstance(item, dict) and isinstance(item.get("text"), str):
                    item["text"] = self.text(item["text"])
        return result
