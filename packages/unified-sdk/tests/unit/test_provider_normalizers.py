"""Provider tool-call normalizers — OpenAI / OpenRouter, Anthropic, Bedrock.

The payloads here are the real wire shapes, written out literally rather than
built with the provider SDKs: that keeps the test honest about what arrives,
and keeps four large optional dependencies out of the suite.

The failure these exist to prevent is quiet. A loop written against Anthropic
and pointed at OpenAI gets `params={}` — because OpenAI ships arguments as a
JSON string — so every value-based rule stops matching and the call is allowed.
"""

from __future__ import annotations

import pytest

from unified_enforce import PolicyEngine
from unified_sdk import Denied, UnifiedAI
from unified_sdk.adapters.providers import (
    denial_message,
    from_anthropic,
    from_bedrock,
    from_openai,
    tool_calls,
)
from unified_sdk.adapters.toolloop import Toolbox, toolloop_guard

# Two rules in file order: the first only matches under the cap, so an
# oversized refund falls through to an explicit deny. That gives denials a real
# `rule_id` — a refusal that can only name "default" tells an operator nothing
# about *which* policy stopped it.
POLICY = """
version: 1
rules:
  - id: small-refunds
    match: {tool: "tool://issue_refund", verb: call}
    when: 'double(params.amount) <= 5000.0'
    effect: allow
  - id: large-refunds-blocked
    match: {tool: "tool://issue_refund", verb: call}
    effect: deny
"""

# --- the literal wire shapes ---

OPENAI_CALL = {
    "id": "call_abc123",
    "type": "function",
    "function": {"name": "issue_refund", "arguments": '{"amount": 100, "currency": "USD"}'},
}
ANTHROPIC_BLOCK = {
    "type": "tool_use",
    "id": "toolu_abc123",
    "name": "issue_refund",
    "input": {"amount": 100, "currency": "USD"},
}
BEDROCK_BLOCK = {
    "toolUse": {
        "toolUseId": "tooluse_abc123",
        "name": "issue_refund",
        "input": {"amount": 100, "currency": "USD"},
    }
}


class _Obj:
    """An SDK response object rather than a dict — providers return models."""

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, _wrap(value))


def _wrap(value):
    if isinstance(value, dict):
        return _Obj(**value)
    if isinstance(value, list):
        return [_wrap(v) for v in value]
    return value


# --- one shape out, whatever went in ---


@pytest.mark.parametrize(
    "parse,payload",
    [(from_openai, OPENAI_CALL), (from_anthropic, ANTHROPIC_BLOCK), (from_bedrock, BEDROCK_BLOCK)],
    ids=["openai", "anthropic", "bedrock"],
)
def test_every_provider_normalizes_to_the_same_call(parse, payload):
    call = parse(payload)
    assert call.name == "issue_refund"
    assert call.args == {"amount": 100, "currency": "USD"}
    assert call.id is not None
    assert call.malformed is False


@pytest.mark.parametrize(
    "parse,payload",
    [(from_openai, OPENAI_CALL), (from_anthropic, ANTHROPIC_BLOCK), (from_bedrock, BEDROCK_BLOCK)],
    ids=["openai", "anthropic", "bedrock"],
)
def test_sdk_objects_work_as_well_as_dicts(parse, payload):
    """Providers return model objects; nothing here may assume a mapping."""
    call = parse(_wrap(payload))
    assert call.name == "issue_refund"
    assert call.args == {"amount": 100, "currency": "USD"}


def test_openai_arguments_are_json_and_must_be_parsed():
    """The whole reason this module exists.

    Forwarding OpenAI's `arguments` unparsed hands policy a string where a
    mapping belongs — `params.amount` stops resolving and a value-based rule
    silently stops matching.
    """
    assert isinstance(OPENAI_CALL["function"]["arguments"], str)
    assert from_openai(OPENAI_CALL).args == {"amount": 100, "currency": "USD"}


def test_malformed_model_output_is_flagged_not_raised():
    """A model emitting invalid JSON is a model failure, not a policy question,
    so the caller decides — but it must be visible, since empty params mean
    every params-based rule stops applying."""
    call = from_openai({"id": "c1", "function": {"name": "issue_refund", "arguments": "{not json"}})
    assert call.malformed is True
    assert call.args == {}


def test_a_json_scalar_is_also_malformed():
    """`"5"` parses as JSON but is not a mapping of arguments."""
    call = from_openai({"id": "c1", "function": {"name": "t", "arguments": "5"}})
    assert call.malformed is True
    assert call.args == {}


def test_a_provider_that_already_decoded_arguments_is_accepted():
    """Some OpenAI-compatible servers hand back a dict."""
    call = from_openai({"id": "c1", "function": {"name": "t", "arguments": {"amount": 1}}})
    assert call.args == {"amount": 1}
    assert call.malformed is False


# --- finding the calls in a whole response ---


def test_tool_calls_are_extracted_from_each_providers_response_shape():
    openai_response = {"choices": [{"message": {"tool_calls": [OPENAI_CALL]}}]}
    anthropic_response = {"content": [{"type": "text", "text": "thinking"}, ANTHROPIC_BLOCK]}
    bedrock_response = {"output": {"message": {"content": [{"text": "hi"}, BEDROCK_BLOCK]}}}

    for response, provider in [
        (openai_response, "openai"),
        (anthropic_response, "anthropic"),
        (bedrock_response, "bedrock"),
    ]:
        (call,) = tool_calls(response, provider=provider)
        assert call.name == "issue_refund", provider
        assert call.args["amount"] == 100, provider


def test_a_response_with_no_tool_calls_is_empty_not_an_error():
    assert (
        tool_calls({"choices": [{"message": {"content": "just talking"}}]}, provider="openai") == []
    )
    assert tool_calls({"content": [{"type": "text", "text": "hi"}]}, provider="anthropic") == []


# --- denials, in each provider's dialect ---


def _denial(provider: str):
    ua = UnifiedAI.local(PolicyEngine.from_yaml(POLICY), principal="agent:crew-1")
    box = Toolbox(toolloop_guard(ua))
    box.register("issue_refund", lambda **kw: "refunded")
    call = from_openai(OPENAI_CALL)
    with pytest.raises(Denied) as caught:
        box.dispatch("issue_refund", {"amount": 9000})
    return denial_message(caught.value, call, provider=provider)


def test_anthropic_denials_are_tool_result_blocks():
    message = _denial("anthropic")
    assert message["type"] == "tool_result"
    assert message["tool_use_id"] == "call_abc123"
    assert message["is_error"] is True
    assert "policy decision" in message["content"]


def test_openai_denials_are_tool_role_messages():
    """This shape has no error flag at all, so the text has to carry it."""
    message = _denial("openai")
    assert message["role"] == "tool"
    assert message["tool_call_id"] == "call_abc123"
    assert "is_error" not in message
    assert "policy decision" in message["content"]


def test_bedrock_denials_are_toolresult_with_error_status():
    message = _denial("bedrock")
    result = message["toolResult"]
    assert result["toolUseId"] == "call_abc123"
    assert result["status"] == "error"
    assert "policy decision" in result["content"][0]["text"]


def test_every_denial_names_the_rule_and_discourages_retry():
    """A bare error invites the model to retry the identical call."""
    for provider in ("openai", "anthropic", "bedrock"):
        text = str(_denial(provider))
        assert "large-refunds-blocked" in text, provider
        assert "retrying" in text.lower(), provider


# --- the loop this is all for ---


def test_a_denied_openai_tool_call_never_reaches_the_function():
    """End to end in the shape a hand-written loop actually has."""
    ua = UnifiedAI.local(PolicyEngine.from_yaml(POLICY), principal="agent:crew-1")
    box = Toolbox(toolloop_guard(ua))
    executed: list[dict] = []
    box.register("issue_refund", lambda **kw: executed.append(kw) or "refunded")

    big = {
        "id": "call_x",
        "function": {"name": "issue_refund", "arguments": '{"amount": 9000}'},
    }
    call = from_openai(big)
    try:
        box.dispatch(call.name, call.args)
    except Denied as exc:
        message = denial_message(exc, call, provider="openai")

    assert executed == [], "the refund executed despite being denied"
    assert message["tool_call_id"] == "call_x"
