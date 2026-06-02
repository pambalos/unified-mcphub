"""Result redaction — spec §10.2."""

from __future__ import annotations

from unified_mcphub.config import RedactConfig
from unified_mcphub.redaction import Redactor

TOKEN = "a" * 64


def _result(text: str) -> dict:
    return {"content": [{"type": "text", "text": text}], "isError": False}


def test_disabled_is_noop():
    r = Redactor(RedactConfig(enabled=False))
    out = r.result(_result(f"Bearer {TOKEN}"))
    assert out["content"][0]["text"] == f"Bearer {TOKEN}"


def test_default_pattern_masks_bearer_token():
    r = Redactor(RedactConfig(enabled=True))  # default patterns
    out = r.result(_result(f"Authorization: Bearer {TOKEN} trailing"))
    assert TOKEN not in out["content"][0]["text"]
    # the whole "Bearer <hex>" match is replaced by the configured replacement
    assert out["content"][0]["text"] == "Authorization: [REDACTED] trailing"


def test_bare_hex_is_not_masked_by_default():
    # A 64-hex sha digest in tool output must survive the conservative default.
    r = Redactor(RedactConfig(enabled=True))
    out = r.result(_result(TOKEN))
    assert out["content"][0]["text"] == TOKEN


def test_custom_pattern_and_replacement():
    r = Redactor(RedactConfig(enabled=True, patterns=[r"sk-[A-Za-z0-9]+"], replacement="***"))
    out = r.result(_result("key=sk-abc123 end"))
    assert out["content"][0]["text"] == "key=*** end"


def test_invalid_pattern_is_ignored_not_fatal():
    r = Redactor(RedactConfig(enabled=True, patterns=["(unclosed", r"Bearer\s+\w+"]))
    out = r.result(_result("Bearer deadbeef"))
    assert out["content"][0]["text"] == "[REDACTED]"


def test_non_text_content_untouched():
    r = Redactor(RedactConfig(enabled=True))
    result = {"content": [{"type": "image", "data": f"Bearer {TOKEN}"}], "isError": False}
    out = r.result(result)
    assert out["content"][0]["data"] == f"Bearer {TOKEN}"  # only text blocks are scrubbed
