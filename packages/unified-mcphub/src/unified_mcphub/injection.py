"""Injection at ingress — build-14 D-12, the deterministic pass.

Content entering the agent — a tool result, a fetched page, a message — is
the vector by which an authorized agent becomes rogue. The hub sees every
tool result it forwards, so it is the place to look. This pass is a set of
named patterns for instruction shapes addressed to a model: not a judgement
about the content, a statement that it *contains the shape*. The analyzer's
second pass (build-13) reads the ones this flags.

What leaves the hub is the pattern ids, never the text: the control plane
stores decision metadata and digests, and a finding that carried the
injected paragraph would be shipping attacker-authored content into the
place people read.
"""

from __future__ import annotations

import re
from typing import Any

#: Bytes of each text block examined. Bounded and stated: a 40 MB tool
#: result is not going to be scanned in the hot path.
SCAN_LIMIT = 65_536

PATTERNS: dict[str, re.Pattern[str]] = {
    # "Ignore all previous instructions" and its paraphrases.
    "ignore-previous": re.compile(
        r"\b(ignore|disregard|forget)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all)\b"
        r"[^.\n]{0,20}\b(instructions?|directions?|rules?|prompts?|guidance)\b",
        re.IGNORECASE,
    ),
    # A new persona or system prompt delivered as content.
    "system-override": re.compile(
        r"(\byou are now\b|\bfrom now on,? you (are|will|must)\b|\bnew (system )?instructions?:"
        r"|^\s*system:\s|<\|im_start\|>\s*system|\[INST\]|<<SYS>>)",
        re.IGNORECASE | re.MULTILINE,
    ),
    # An instruction to exfiltrate: send/post secrets to somewhere.
    "exfil-directive": re.compile(
        r"\b(send|post|upload|forward|email|transmit|exfiltrate)\b[^.\n]{0,60}"
        r"\b(secrets?|credentials?|tokens?|api[ _-]?keys?|passwords?|private keys?|\.env)\b"
        r"[^.\n]{0,60}(https?://|\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b)",
        re.IGNORECASE,
    ),
    # Content that addresses the model as a tool operator.
    "tool-directive": re.compile(
        r"\b(call|run|execute|invoke|use)\b[^.\n]{0,30}\b(tool|function|command|shell)\b"
        r"[^.\n]{0,80}\b(curl|wget|nc\b|bash -c|powershell|base64 -d)",
        re.IGNORECASE,
    ),
    # A transcript turn smuggled into content.
    "role-injection": re.compile(
        r"^\s*(assistant|human|user|tool)\s*:\s*\S", re.IGNORECASE | re.MULTILINE
    ),
    # Instructions hidden from a human reader: zero-width runs, HTML comments
    # addressed to the model.
    "hidden-directive": re.compile(
        r"([​‌‍⁠⁢⁣]{4,})|(<!--[^>]{0,200}\b(assistant|ai|model|llm)\b[^>]{0,200}-->)",
        re.IGNORECASE,
    ),
    # A large encoded block: instructions that survive a skim.
    "encoded-block": re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{240,}={0,2}(?![A-Za-z0-9+/=])"),
}


def scan_text(text: str) -> list[str]:
    """The ids of the shapes present in one piece of text, in pattern order."""
    sample = text[:SCAN_LIMIT]
    return [name for name, pattern in PATTERNS.items() if pattern.search(sample)]


def _text_of(item: Any) -> str | None:
    """The text a content block carries: a `text` block's own, or an embedded
    resource's (`{"type": "resource", "resource": {"uri", "text"}}`) — the
    form a fetched page or a `resources/read` arrives in, and the one an
    injection is most likely to ride."""
    if not isinstance(item, dict):
        return None
    text = item.get("text")
    if isinstance(text, str):
        return text
    resource = item.get("resource")
    if isinstance(resource, dict) and isinstance(resource.get("text"), str):
        return resource["text"]
    return None


def scan(result: Any) -> list[str]:
    """Every text-bearing content block of a CallToolResult dict, unique ids
    in order."""
    if not isinstance(result, dict):
        return []
    content = result.get("content")
    if not isinstance(content, list):
        return []
    found: list[str] = []
    for item in content:
        text = _text_of(item)
        if text is None:
            continue
        for name in scan_text(text):
            if name not in found:
                found.append(name)
    return found
