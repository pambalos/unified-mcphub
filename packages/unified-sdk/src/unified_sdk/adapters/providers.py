"""Provider tool-call normalizers — OpenAI, OpenRouter, Bedrock, Anthropic.

These are **not** agent frameworks. They are inference APIs: the model emits a
tool call, and your own loop dispatches it. There is no framework to adapt, so
what is missing is smaller and more annoying than an adapter — the same tool
call is spelled four different ways, and a denial has to be spelled back in the
matching dialect or the model cannot read it.

    call = from_openai(tool_call)
    try:
        result = box.dispatch(call.name, call.args)
    except EnforcementError as exc:
        messages.append(denial_message(exc, call, provider="openai"))

Nothing here decides anything. Normalizing in one place matters because the
differences are exactly the kind that fail quietly: OpenAI ships arguments as a
**JSON string** while the others ship a dict, so a loop written against
Anthropic and pointed at OpenAI would hand policy `params={}` — every
value-based rule silently unmatchable, and the request allowed.

Provider support:

* `openai` — also **OpenRouter**, **Azure OpenAI**, Together, Groq, and the
  rest of the OpenAI-compatible fleet. One shape, one normalizer.
* `anthropic` — `tool_use` / `tool_result` content blocks.
* `bedrock` — the Converse API's `toolUse` / `toolResult`.

Responses are SDK objects, not dicts, so everything here reads attributes and
keys interchangeably rather than depending on any provider package.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Literal

from ..errors import EnforcementError

Provider = Literal["openai", "anthropic", "bedrock"]

#: Said to the model, not to a human. It names the rule and states that the
#: refusal is a policy decision, because a bare error invites the model to
#: retry the identical call — burning tokens and filling the audit log with
#: identical denials.
DENIAL_TEXT = (
    "Blocked by policy ({rule}). This is a policy decision, not a transient "
    "failure — retrying the same call will be blocked again. Choose a different "
    "approach or tell the user this action requires authorization."
)


@dataclass(frozen=True)
class ProviderToolCall:
    """One tool call, in the same shape whoever emitted it."""

    name: str
    args: dict[str, Any]
    id: str | None = None
    #: True when the model's arguments could not be parsed (see from_openai).
    malformed: bool = False
    raw: Any = field(default=None, repr=False)


def _get(obj: Any, key: str, default: Any = None) -> Any:
    """Read `key` from a dict or an attribute off an SDK model object."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _as_dict(value: Any) -> dict[str, Any]:
    """Coerce a provider's argument payload into a plain mapping.

    Usually already a dict. But provider SDKs model responses differently and
    change how deeply they do it between releases, so an object-shaped payload
    must not become a `TypeError` on the enforcement path — `dict(obj)` raises
    for anything that isn't iterable, and a crash here would take down the tool
    call rather than decide it.
    """
    if not value:
        return {}
    if isinstance(value, dict):
        return dict(value)
    for attr in ("model_dump", "dict", "to_dict"):
        method = getattr(value, attr, None)
        if callable(method):
            try:
                dumped = method()
            except Exception:  # noqa: BLE001 - fall through to the next strategy
                continue
            if isinstance(dumped, dict):
                return dumped
    return {k: v for k, v in vars(value).items() if not k.startswith("_")}


def from_openai(tool_call: Any) -> ProviderToolCall:
    """`choices[].message.tool_calls[]` — OpenAI, OpenRouter, Azure, and friends.

    The trap: `function.arguments` is a **JSON string**, not an object. A loop
    that forwards it unparsed hands policy a string where a mapping belongs,
    and every `params.*` rule stops matching.

    A model can also emit arguments that are not valid JSON. That is a model
    failure rather than a policy question, so it is flagged (`malformed`) with
    empty args instead of raising — the caller decides whether to refuse the
    call or ask the model to try again. Note that dispatching a malformed call
    means policy sees no params, so treat `malformed` as a refusal unless the
    tool genuinely takes none.
    """
    function = _get(tool_call, "function") or {}
    raw_args = _get(function, "arguments")
    args: dict[str, Any] = {}
    malformed = False
    if isinstance(raw_args, dict):
        args = dict(raw_args)  # some compatible servers already decode it
    elif raw_args:
        try:
            parsed = json.loads(raw_args)
            args = parsed if isinstance(parsed, dict) else {}
            malformed = not isinstance(parsed, dict)
        except (TypeError, ValueError):
            malformed = True
    return ProviderToolCall(
        name=_get(function, "name") or "",
        args=args,
        id=_get(tool_call, "id"),
        malformed=malformed,
        raw=tool_call,
    )


def from_anthropic(block: Any) -> ProviderToolCall:
    """A `tool_use` content block from a Messages response."""
    return ProviderToolCall(
        name=_get(block, "name") or "",
        args=_as_dict(_get(block, "input")),
        id=_get(block, "id"),
        raw=block,
    )


def from_bedrock(block: Any) -> ProviderToolCall:
    """A Converse API content block. Accepts the block or its `toolUse` body."""
    tool_use = _get(block, "toolUse") or block
    return ProviderToolCall(
        name=_get(tool_use, "name") or "",
        args=_as_dict(_get(tool_use, "input")),
        id=_get(tool_use, "toolUseId"),
        raw=block,
    )


_PARSERS = {"openai": from_openai, "anthropic": from_anthropic, "bedrock": from_bedrock}


def tool_calls(response: Any, *, provider: Provider) -> list[ProviderToolCall]:
    """Every tool call in one model response, normalized.

    Saves each caller from rediscovering where their provider hides them:
    OpenAI on `choices[0].message.tool_calls`, Anthropic in `content` blocks of
    type `tool_use`, Bedrock in `output.message.content` blocks with `toolUse`.
    """
    if provider == "openai":
        choices = _get(response, "choices") or []
        if not choices:
            return []
        message = _get(choices[0], "message") or {}
        return [from_openai(c) for c in (_get(message, "tool_calls") or [])]

    if provider == "anthropic":
        content = _get(response, "content") or []
        return [from_anthropic(b) for b in content if _get(b, "type") == "tool_use"]

    output = _get(response, "output") or {}
    message = _get(output, "message") or {}
    content = _get(message, "content") or _get(response, "content") or []
    return [from_bedrock(b) for b in content if _get(b, "toolUse")]


def denial_message(
    exc: EnforcementError, call: ProviderToolCall, *, provider: Provider
) -> dict[str, Any]:
    """A refusal in the shape this provider expects a tool result to take.

    The three dialects genuinely differ — Anthropic wants a `tool_result`
    content block with `is_error`, OpenAI wants a `role: "tool"` message with
    no error flag at all, and Bedrock wants a `toolResult` with
    `status: "error"`. Appending the wrong one is an API error at best and a
    confused model at worst.
    """
    text = DENIAL_TEXT.format(rule=exc.decision.rule_id or exc.decision.source)

    if provider == "anthropic":
        return {
            "type": "tool_result",
            "tool_use_id": call.id,
            "content": text,
            "is_error": True,
        }
    if provider == "openai":
        # No error flag exists in this shape; the text has to carry it.
        return {"role": "tool", "tool_call_id": call.id, "content": text}
    return {
        "toolResult": {
            "toolUseId": call.id,
            "content": [{"text": text}],
            "status": "error",
        }
    }
