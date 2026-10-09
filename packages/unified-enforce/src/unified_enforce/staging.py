"""Staged approval attachments -- evidence an agent offers before it acts.

Spec: `specs/enforce/approval-attachments.v1.md` §4 (P2).

An MCP `tools/call` that defers is held in-line until a person answers, and the
agent's session can make no other call meanwhile (§4.1). So "call approve_claim,
then attach the invoice" cannot happen inside one blocked call. The agent's
path is the other way round: **stage the evidence first, then make the call**.
If the call defers, what was staged for it rides along in the approval request;
if policy settles the call alone, nobody ever sees it and it expires unused.

Three properties this module exists to hold:

**Evidence never crosses principals or sessions.** A staged item is keyed by
the principal that staged it and the session it was staged in, and `take`
hands it only to a deferred call of that same principal in that same session.
An agent staging "supervisor pre-approved this" for someone else's payout is
the attack, and a shared pool would be the way in.

**Evidence never rides on the wrong call.** `match` is a subset of params the
deferred call must carry (`{"claim_id": "CLM-2001"}`), so the invoice staged
for one claim cannot be shown beside another claim's approval.

**Provenance is set here, never by the agent** (§6.1). Content an agent typed
or uploaded is `agent`, always. The only way to `observed` is `from_call`
naming a tool result this enforcement point itself recorded; a call it did not
record gives an `unavailable` entry, not agent content wearing the stronger
badge. No tool argument sets the source -- an unknown argument (`source`
included) is refused outright.

Held in memory only, bounded per (principal, session) and in total, and sent
nowhere until a DEFER consumes it: a staged item that is never needed is
evidence nobody had a reason to read.

`AttachmentTools` is the reserved `unified__*` tool surface itself, shared by
the hub and by MCP servers built on the SDK (`unified_sdk.adapters.mcp`), so
the two cannot drift on what an argument means or which badge it earns.

Standard library only, like the rest of the decision-adjacent engine.
"""

from __future__ import annotations

import base64
import binascii
import json as _json
import threading
import time
import uuid
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from re import Pattern
from typing import Any

from .action import Action
from .attachments import (
    MAX_ATTACHMENT_BYTES,
    MAX_REQUEST_BYTES,
    Attachment,
    AttachmentSource,
    check_media_type,
    sniff,
)

#: How long a staged item waits for the call it was staged for (§10
#: `staging_ttl_seconds`). Long enough for an agent to stage three documents
#: and make the call; short enough that evidence staged for a call that never
#: came does not sit in memory all day.
STAGING_TTL_SECONDS = 900.0
#: Per (principal, session): the per-request limits of §3.3. Staging more than
#: one request could carry would only queue up `unavailable` entries.
MAX_STAGED_ITEMS = 20
MAX_STAGED_BYTES = MAX_REQUEST_BYTES
#: Across every principal and session. The per-key bounds stop one agent
#: filling memory; this stops many identities doing it together.
MAX_STAGED_TOTAL_BYTES = 128 * 1024 * 1024

#: Recorded tool results kept for `from_call`, and their total size. Oldest go
#: first: the call an agent wants to cite is nearly always a recent one.
MAX_RECORDED_RESULTS = 256
MAX_RECORDED_BYTES = 64 * 1024 * 1024

#: Reserved tool names, `<server>__<tool>` as the hub namespaces every tool,
#: so their policy URIs are `mcp://unified/<tool>` on every surface.
RESERVED_SERVER = "unified"
STAGE_ATTACHMENT = "stage_attachment"
LIST_STAGED = "list_staged"
DISCARD_STAGED = "discard_staged"
ATTACH_TO_APPROVAL = "attach_to_approval"
RESERVED_TOOLS = (STAGE_ATTACHMENT, LIST_STAGED, DISCARD_STAGED, ATTACH_TO_APPROVAL)

#: The `_meta` key under which an enforcement point reports a call's action
#: digest, so an agent has a value to pass as `from_call`.
ACTION_DIGEST_META = "unified/action_digest"


class StagingError(ValueError):
    """A staging request was refused. The message is meant for the agent."""


@dataclass(frozen=True)
class StagedItem:
    """What the agent is told about a staged attachment. Never the content."""

    staged_id: str
    sha256: str | None
    size: int
    media_type: str
    label: str
    for_tool: str
    source: str
    #: Epoch milliseconds, like every other timestamp on the approval wire.
    expires_at: int
    #: `staged`, or `unavailable` for a placeholder (`from_call` unrecorded).
    status: str

    def public(self) -> dict[str, Any]:
        """The tool-result shape (`expires_at` as ISO-8601 UTC, for an agent)."""
        return {
            "staged_id": self.staged_id,
            "sha256": self.sha256,
            "size": self.size,
            "media_type": self.media_type,
            "label": self.label,
            "for_tool": self.for_tool,
            "source": self.source,
            "expires_at": _iso(self.expires_at),
            "status": self.status,
        }


@dataclass
class _Staged:
    item: StagedItem
    principal: str
    session: str
    pattern: Pattern[str]
    match: dict[str, Any]
    attachment: Attachment


def _iso(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, UTC).isoformat().replace("+00:00", "Z")


def _norm(value: Any) -> Any:
    """A param value as `match` compares it: strings, the SDK's way.

    The SDK turns floats and Decimals into strings before an Action is built
    (`unified_sdk.client._normalize`), so an amount is `"4200.0"` there and a
    float in a hub call. Comparing both sides as strings makes `match` mean
    the same thing on both surfaces, and an agent writing `"CLM-2001"` or
    `4200.0` gets the answer it expects. Structures compare as canonical JSON.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, (int, Decimal, str)):
        return str(value)
    try:
        return _json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    except (TypeError, ValueError):
        return repr(value)


class StagedAttachments:
    """In-memory staging, keyed by (principal, session). Thread-safe.

    One instance per enforcement point. `take` is the only way out to an
    approver, and it consumes: an item rides on exactly one deferred call.
    """

    def __init__(
        self,
        *,
        ttl_seconds: float = STAGING_TTL_SECONDS,
        max_items: int = MAX_STAGED_ITEMS,
        max_bytes: int = MAX_STAGED_BYTES,
        max_total_bytes: int = MAX_STAGED_TOTAL_BYTES,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._ttl = ttl_seconds
        self._max_items = max_items
        self._max_bytes = max_bytes
        self._max_total = max_total_bytes
        self._clock = clock
        self._lock = threading.Lock()
        self._items: dict[tuple[str, str], list[_Staged]] = {}

    def _now_ms(self) -> int:
        return int(self._clock() * 1000)

    def _purge(self, now_ms: int) -> None:
        for key in list(self._items):
            live = [s for s in self._items[key] if s.item.expires_at > now_ms]
            if live:
                self._items[key] = live
            else:
                del self._items[key]

    def stage(
        self,
        principal: str,
        session: str,
        for_tool: str,
        match: Mapping[str, Any] | None,
        attachment: Attachment,
        ttl: float | None = None,
    ) -> StagedItem:
        """Hold `attachment` for the next deferred call of `for_tool` (a policy
        glob) by `principal` in `session` whose params include `match`.

        Refuses (StagingError) rather than truncating: the agent is still
        there to hear about it, unlike an approver later finding the evidence
        silently missing.
        """
        from .policy import _glob_to_regex

        if not isinstance(for_tool, str) or "://" not in for_tool:
            raise StagingError("for_tool must be a tool URI such as mcp://insurance/approve_claim")
        if match is not None and not isinstance(match, Mapping):
            raise StagingError("match must be an object of param names to values")
        try:
            pattern = _glob_to_regex(for_tool)
        except Exception as exc:  # noqa: BLE001 - a bad glob is the agent's error
            raise StagingError(f"for_tool is not a valid tool pattern: {exc}") from exc
        if attachment.unavailable is None:
            if attachment.size > MAX_ATTACHMENT_BYTES:
                raise StagingError(
                    f"attachment is {attachment.size} bytes; the limit is {MAX_ATTACHMENT_BYTES}"
                )
            if not check_media_type(attachment.media_type, attachment.data):
                raise StagingError(
                    f"content is not {attachment.media_type or 'an allowed type'}: attachments "
                    "must be PDF, PNG, JPEG, WebP, plain text, CSV or JSON, and the content "
                    "must match the declared type (HTML and SVG are refused)"
                )

        now = self._now_ms()
        ttl_s = self._ttl if ttl is None else ttl
        key = (principal, session)
        with self._lock:
            self._purge(now)
            held = self._items.get(key, [])
            if len(held) >= self._max_items:
                raise StagingError(
                    f"{len(held)} attachments are already staged in this session (limit "
                    f"{self._max_items}); discard some or make the call they are for first"
                )
            held_bytes = sum(s.attachment.size for s in held)
            if held_bytes + attachment.size > self._max_bytes:
                raise StagingError(
                    f"staging this would hold {held_bytes + attachment.size} bytes in this "
                    f"session (limit {self._max_bytes}); discard some first"
                )
            total = sum(s.attachment.size for items in self._items.values() for s in items)
            if total + attachment.size > self._max_total:
                raise StagingError("the staging area is full; try again later")
            unavailable = attachment.unavailable is not None
            item = StagedItem(
                staged_id=uuid.uuid4().hex,
                sha256=None if unavailable else attachment.sha256,
                size=attachment.size,
                media_type=attachment.media_type,
                label=attachment.label,
                for_tool=for_tool,
                source=attachment.source.value,
                expires_at=now + int(ttl_s * 1000),
                status="unavailable" if unavailable else "staged",
            )
            self._items.setdefault(key, []).append(
                _Staged(item, principal, session, pattern, dict(match or {}), attachment)
            )
        return item

    def list(self, principal: str, session: str) -> list[StagedItem]:
        with self._lock:
            self._purge(self._now_ms())
            return [s.item for s in self._items.get((principal, session), [])]

    def discard(self, principal: str, session: str, staged_id: str) -> bool:
        """Remove one item; False if there was no such item *for this caller*.

        Another principal's id answers exactly like an unknown one, so ids
        are not an oracle for what someone else staged.
        """
        with self._lock:
            held = self._items.get((principal, session), [])
            kept = [s for s in held if s.item.staged_id != staged_id]
            if len(kept) == len(held):
                return False
            if kept:
                self._items[(principal, session)] = kept
            else:
                self._items.pop((principal, session), None)
            return True

    def take(self, action: Action, session: str) -> tuple[Attachment, ...]:
        """Consume every live item staged for this deferred `action`, in order.

        Matches on all three of principal, session and tool glob, plus `match`
        as a subset of `action.params`. Consumed even if the approval then
        fails: the evidence was put to the request it was staged for, and
        replaying it onto the agent's next attempt is the agent's call to make
        by staging again.
        """
        principal = action.principal.id
        params = action.params or {}
        with self._lock:
            self._purge(self._now_ms())
            held = self._items.get((principal, session))
            if not held:
                return ()
            taken: list[Attachment] = []
            kept: list[_Staged] = []
            for staged in held:
                if staged.principal == principal and self._matches(staged, action.tool, params):
                    taken.append(staged.attachment)
                else:
                    kept.append(staged)
            if kept:
                self._items[(principal, session)] = kept
            else:
                del self._items[(principal, session)]
            return tuple(taken)

    @staticmethod
    def _matches(staged: _Staged, tool: str, params: Mapping[str, Any]) -> bool:
        if staged.pattern.match(tool) is None:
            return False
        for name, want in staged.match.items():
            if name not in params or _norm(params[name]) != _norm(want):
                return False
        return True


class RecordedResults:
    """Tool results this enforcement point relayed, for `from_call` (§4.2).

    Keyed by (principal, session, action digest), so an agent can cite only a
    result that came back to *it*, in *this* session: another agent's
    `get_claim` is not this agent's evidence, and naming its digest gets
    "not recorded", the same as a digest that never existed.

    Stores the canonical JSON bytes (what `Attachment.json` would produce),
    bounded by count and size, oldest dropped first. A result too large to
    attach is not kept at all.
    """

    def __init__(
        self, *, max_items: int = MAX_RECORDED_RESULTS, max_bytes: int = MAX_RECORDED_BYTES
    ) -> None:
        self._max_items = max_items
        self._max_bytes = max_bytes
        self._lock = threading.Lock()
        self._items: OrderedDict[tuple[str, str, str], bytes] = OrderedDict()
        self._bytes = 0

    def record(self, principal: str, session: str, action_digest: str, result: Any) -> bool:
        try:
            data = _json.dumps(
                result, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
            ).encode("utf-8")
        except (TypeError, ValueError):
            return False
        if len(data) > MAX_ATTACHMENT_BYTES:
            return False
        key = (principal, session, action_digest)
        with self._lock:
            old = self._items.pop(key, None)
            if old is not None:
                self._bytes -= len(old)
            self._items[key] = data
            self._bytes += len(data)
            while self._items and (
                len(self._items) > self._max_items or self._bytes > self._max_bytes
            ):
                _, dropped = self._items.popitem(last=False)
                self._bytes -= len(dropped)
        return True

    def recorded_result(self, principal: str, session: str, action_digest: str) -> bytes | None:
        with self._lock:
            return self._items.get((principal, session, action_digest))


# --- the reserved tool surface ---------------------------------------------------------

_CONTENT_PROPS: dict[str, Any] = {
    "label": {
        "type": "string",
        "description": "What the approver sees this called, e.g. 'Plumber invoice'.",
    },
    "content": {"type": "string", "description": "Text content (plain text, CSV or JSON)."},
    "content_base64": {
        "type": "string",
        "description": "Binary content, base64: PDF, PNG, JPEG or WebP.",
    },
    "from_call": {
        "type": "string",
        "description": (
            "The action digest of an earlier tool call in this session (reported in that "
            f"call's result under _meta['{ACTION_DIGEST_META}']). Its recorded result is "
            "attached as captured by the gateway -- stronger evidence than retyping it."
        ),
    },
    "media_type": {
        "type": "string",
        "description": (
            "Optional; checked against the content, never trusted. One of application/pdf, "
            "image/png, image/jpeg, image/webp, text/plain, text/csv, application/json."
        ),
    },
    "note": {"type": "string", "description": "Why this is attached (shown to the approver)."},
}

TOOL_SPECS: dict[str, tuple[str, dict[str, Any]]] = {
    STAGE_ATTACHMENT: (
        "Stage evidence (an invoice, a photo, a report) for a tool call you are about to "
        "make. Stage FIRST, then make the call. If that call needs human approval, the staged "
        "evidence is shown to the approver with it; if it does not, nobody sees it and it "
        "expires after 15 minutes. `for_tool` is the tool URI (e.g. "
        "mcp://insurance/approve_claim); `match` limits it to calls with those argument "
        'values (e.g. {"claim_id": "CLM-2001"}). Give exactly one of content, '
        "content_base64 or from_call. Content you supply is shown as provided by the agent "
        "and unverified; from_call attaches a result the gateway itself recorded.",
        {
            "type": "object",
            "properties": {
                "for_tool": {"type": "string", "description": "Tool URI or glob it is for."},
                "match": {
                    "type": "object",
                    "description": "Argument values the call must have for this to attach.",
                },
                **_CONTENT_PROPS,
            },
            "required": ["for_tool", "label"],
            "additionalProperties": False,
        },
    ),
    LIST_STAGED: (
        "List the evidence you have staged in this session and not yet used: id, label, "
        "hash, size, type, which tool it is for and when it expires. Never the content.",
        {"type": "object", "properties": {}, "additionalProperties": False},
    ),
    DISCARD_STAGED: (
        "Discard one staged attachment by its staged_id, so it is not shown with your next "
        "matching call.",
        {
            "type": "object",
            "properties": {"staged_id": {"type": "string"}},
            "required": ["staged_id"],
            "additionalProperties": False,
        },
    ),
    ATTACH_TO_APPROVAL: (
        "Add evidence to an approval request that is already waiting for a person, by the "
        "approval_ref reported when the call was deferred. Only works while the request is "
        "still pending and only for your own requests; the approver sees it marked as added "
        "late. Prefer stage_attachment before the call -- it is shown from the start. Give "
        "exactly one of content, content_base64 or from_call.",
        {
            "type": "object",
            "properties": {
                "approval_ref": {
                    "type": "string",
                    "description": "The approval_ref of the pending request.",
                },
                **_CONTENT_PROPS,
            },
            "required": ["approval_ref", "label"],
            "additionalProperties": False,
        },
    ),
}

#: Late attachment, as the surface provides it: `(approval_ref, attachments,
#: principal) -> {"attachments_digest", "count"}`. Raises for a ref that is not
#: this principal's pending request.
AttachFn = Callable[[str, Sequence[Attachment], str], Awaitable[Mapping[str, Any]]]


class AttachmentTools:
    """The four reserved tools, framework-free. The hub and the SDK's MCP
    helper both call these after their own policy check, with the principal
    and session *they* established -- never ones taken from the arguments.

    Every method raises `StagingError` with a message for the agent.
    """

    def __init__(
        self,
        staging: StagedAttachments,
        *,
        recorded: RecordedResults | None = None,
        attach: AttachFn | None = None,
    ) -> None:
        self.staging = staging
        self.recorded = recorded
        self.attach = attach

    async def call(self, tool: str, args: Mapping[str, Any], principal: str, session: str) -> dict:
        if tool == STAGE_ATTACHMENT:
            return self.stage(args, principal, session)
        if tool == LIST_STAGED:
            _only(args, set())
            return {"staged": [i.public() for i in self.staging.list(principal, session)]}
        if tool == DISCARD_STAGED:
            _only(args, {"staged_id"})
            staged_id = args.get("staged_id")
            if not isinstance(staged_id, str) or not staged_id:
                raise StagingError("staged_id is required")
            if not self.staging.discard(principal, session, staged_id):
                raise StagingError(f"no staged attachment {staged_id!r} in this session")
            return {"discarded": staged_id}
        if tool == ATTACH_TO_APPROVAL:
            return await self.attach_to_approval(args, principal, session)
        raise StagingError(f"unknown tool {tool!r}")

    def stage(self, args: Mapping[str, Any], principal: str, session: str) -> dict:
        _only(args, set(_CONTENT_PROPS) | {"for_tool", "match"})
        for_tool = args.get("for_tool")
        if not isinstance(for_tool, str) or not for_tool:
            raise StagingError("for_tool is required: the tool URI this evidence is for")
        attachment = self.attachment_from(args, principal, session)
        item = self.staging.stage(principal, session, for_tool, args.get("match"), attachment)
        return item.public()

    async def attach_to_approval(
        self, args: Mapping[str, Any], principal: str, session: str
    ) -> dict:
        _only(args, set(_CONTENT_PROPS) | {"approval_ref"})
        ref = args.get("approval_ref")
        if not isinstance(ref, str) or not ref:
            raise StagingError("approval_ref is required")
        if self.attach is None:
            raise StagingError(
                "late attachment needs console approvals: this enforcement point does not "
                "queue approvals at a control plane, so there is no pending request to add to"
            )
        attachment = self.attachment_from(args, principal, session)
        try:
            result = await self.attach(ref, (attachment,), principal)
        except StagingError:
            raise
        except Exception as exc:  # noqa: BLE001 - reported to the agent, decides nothing
            status = getattr(exc, "status", None)
            if status == 409:
                raise StagingError(f"approval {ref!r} is no longer pending") from exc
            if status == 404:
                raise StagingError(f"no pending approval {ref!r} of yours") from exc
            raise StagingError(f"could not attach to {ref!r}: {type(exc).__name__}") from exc
        return {
            "approval_ref": ref,
            "attachments_digest": result.get("attachments_digest"),
            "count": len(result.get("attachments") or ()),
        }

    def attachment_from(self, args: Mapping[str, Any], principal: str, session: str) -> Attachment:
        """The `Attachment` an agent's arguments describe, with its source set here.

        `agent` for anything the agent supplied; `observed` only for a
        `from_call` this enforcement point recorded for this principal and
        session; an `unavailable` entry (source `agent`, since the agent is
        the only one claiming it existed) when it did not.
        """
        label = args.get("label")
        if not isinstance(label, str) or not label.strip():
            raise StagingError("label is required: it is what the approver sees")
        note = args.get("note") or ""
        if not isinstance(note, str):
            raise StagingError("note must be a string")
        given = [k for k in ("content", "content_base64", "from_call") if args.get(k) is not None]
        if len(given) != 1:
            raise StagingError("give exactly one of content, content_base64 or from_call")
        media_type = args.get("media_type")
        if media_type is not None and not isinstance(media_type, str):
            raise StagingError("media_type must be a string")
        agent = AttachmentSource.AGENT

        if given == ["from_call"]:
            digest = args["from_call"]
            if not isinstance(digest, str) or not digest:
                raise StagingError("from_call must be an action digest")
            if media_type is not None:
                raise StagingError("media_type cannot be set with from_call (it is JSON)")
            data = (
                self.recorded.recorded_result(principal, session, digest)
                if self.recorded is not None
                else None
            )
            if data is None:
                return Attachment.unavailable_entry(
                    label, "from_call_not_recorded", note=note, origin_ref=digest, source=agent
                )
            return Attachment.bytes(
                data,
                "application/json",
                label,
                note=note,
                origin_ref=digest,
                source=AttachmentSource.OBSERVED,
            )

        if given == ["content"]:
            content = args["content"]
            if not isinstance(content, str):
                raise StagingError("content must be a string; use content_base64 for binary")
            data = content.encode("utf-8")
            declared = media_type or (
                "application/json" if sniff(data) == "application/json" else "text/plain"
            )
        else:
            encoded = args["content_base64"]
            if not isinstance(encoded, str):
                raise StagingError("content_base64 must be a base64 string")
            try:
                data = base64.b64decode(encoded, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise StagingError("content_base64 is not valid base64") from exc
            declared = media_type or sniff(data) or ""
        if not declared or not check_media_type(declared, data):
            raise StagingError(
                f"content is not {declared or 'an allowed type'}: attachments must be PDF, PNG, "
                "JPEG, WebP, plain text, CSV or JSON, and match the declared media_type "
                "(HTML and SVG are refused)"
            )
        return Attachment.bytes(data, declared, label, note=note, source=agent)


def _only(args: Mapping[str, Any], allowed: set[str]) -> None:
    """Refuse unknown arguments -- `source` above all. An argument the tool
    does not define is never silently ignored, because the one an agent most
    wants honoured is the one that would make its upload look `observed`."""
    unknown = sorted(set(args) - allowed)
    if unknown:
        raise StagingError(f"unknown argument(s): {', '.join(unknown)}")


def channel_attach(channel_of: Callable[[], Any]) -> AttachFn:
    """An `AttachFn` over an approvals channel that supports late attachment
    (`RemoteApprovals`, or a shell delegating to one).

    Agent-facing, so stricter than `RemoteApprovals.attach` itself: the ref
    must be a request this process is waiting on, raised by the *calling*
    principal. A ref the agent read somewhere -- another agent's 202, a log
    line -- must not let it put evidence in front of someone else's approver;
    an unknown ref and another principal's ref get the same answer.
    `channel_of` is called per use, because a hub binds its channel late.
    """

    async def attach(
        ref: str, attachments: Sequence[Attachment], principal: str
    ) -> Mapping[str, Any]:
        channel = channel_of()
        waiting = getattr(channel, "waiting_request", None)
        if channel is None or waiting is None or not hasattr(channel, "attach"):
            raise StagingError(
                "late attachment needs console approvals: approvals here are not queued at a "
                "control plane, so there is no pending request to add to"
            )
        request = waiting(ref)
        if request is None or request.principal != principal:
            raise StagingError(f"no pending approval {ref!r} of yours is waiting here")
        return await channel.attach(ref, attachments)

    return attach
