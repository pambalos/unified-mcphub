"""Approval attachments — what a person sees before answering a DEFER.

Spec: `specs/enforce/approval-attachments.v1.md` (P1: §2, §3, §5, §7, §8).

A DEFER asks a person to decide, and today the person sees the tool, the rule,
a summary and (unless withheld) the params: the amount of a claim without the
reason for it. An `Attachment` is the reason -- an invoice, a photo, an
adjuster's report -- carried with the request so the reviewer does not either
rubber-stamp or leave the queue to look it up elsewhere.

Three things shape this module.

**Attachments are content.** `Attachment.data` is never logged and never put in
a repr. What travels with the request is the *manifest* (`build_manifest`):
hash, size, type, label, provenance, status. The bytes are uploaded separately,
only when the deployment lets content leave (`remote_approvals.py`), and the
manifest is what the approver's decision is signed over (attest
`attachments_digest`), so "approved having seen the invoice" is provable by
hash afterwards.

**Missing evidence is not a decision.** A provider that raises or overruns its
budget, a file over the size limit, a type the console must not render: each
becomes an `unavailable` manifest entry carrying the reason, and the request is
still asked. The approver sees that something was meant to be attached and is
missing -- which is a reason for *them* to deny. It is never a reason for the
engine to deny on their behalf, and it must never be silently absent: an
approver who cannot tell "no invoice was attached" from "the invoice failed to
load" is being asked a different question than the one they think.

**The media type is sniffed, never trusted.** The console renders what it is
given, and HTML and SVG are script containers. A declared type is accepted only
when the bytes agree with it (`check_media_type`); everything else is refused
here, before anything leaves, and refused again by the control plane.

Standard library only, like the rest of the decision-adjacent engine.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json as _json
import logging
from collections.abc import Awaitable, Callable, Iterable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from functools import cached_property
from pathlib import Path
from re import Pattern
from typing import Any, NamedTuple, TypeAlias

from .action import Action

log = logging.getLogger("unified_enforce.attachments")

# --- limits (§3.3) ------------------------------------------------------------
#
# Enforced here, re-enforced by the control plane. Over a limit, the attachment
# becomes an `unavailable` entry rather than failing the request -- the same
# "missing evidence is not a decision" reasoning as a provider failure.

#: Largest single attachment, in bytes.
MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024
#: Largest total of stored content in one request, in bytes.
MAX_REQUEST_BYTES = 25 * 1024 * 1024
#: Most attachments in one request. Entries past it are listed, not stored.
MAX_ATTACHMENTS = 20
#: Labels and notes are shown to a person; past these they are truncated (an
#: ellipsis says so) rather than refused, since a long label is not a reason to
#: lose the evidence it names.
MAX_LABEL_CHARS = 120
MAX_NOTE_CHARS = 500
#: Total time budget for resolving `attachments=` and every matching provider.
DEFAULT_PROVIDER_TIMEOUT = 5.0

#: Manifest `status` values (the wire contract).
STORED = "stored"
WITHHELD = "withheld"
UNAVAILABLE = "unavailable"

#: What the console may render (§6.3). Anything else is refused.
ALLOWED_MEDIA_TYPES = frozenset(
    {
        "application/pdf",
        "image/png",
        "image/jpeg",
        "image/webp",
        "application/json",
        "text/csv",
        "text/plain",
    }
)
_BINARY_TYPES = frozenset({"application/pdf", "image/png", "image/jpeg", "image/webp"})
_TEXT_TYPES = frozenset({"application/json", "text/csv", "text/plain"})


class AttachmentSource(StrEnum):
    """Who produced an attachment (§6.1), shown to the approver as a badge.

    Set by the surface that receives the attachment, never by whoever supplies
    it: an agent that could label its own upload `observed` would make the
    badge decorative. The SDK sets `APPLICATION`.
    """

    OBSERVED = "observed"  # captured by the enforcement point from an upstream response
    APPLICATION = "application"  # supplied by application code via the SDK
    AGENT = "agent"  # supplied by the agent (MCP staging tools, P2)


# --- sniffing ---------------------------------------------------------------------


def _strip_leading(data: bytes) -> bytes:
    """Bytes after a UTF-8 BOM and leading whitespace -- where markup would start."""
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    return data.lstrip(b" \t\r\n\f\v")


def _as_text(data: bytes) -> str | None:
    """The bytes as text when they are plausibly text: valid UTF-8, no NUL."""
    if b"\x00" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def sniff(data: bytes) -> str | None:
    """The allowlisted media type the bytes *are*, or None.

    From content only. An extension or a declared type is a claim by whoever
    produced the file, and the console's safety rests on what it actually
    renders. Order matters: binary magic first; then markup is refused before
    anything is called text, because an HTML or SVG document is valid UTF-8
    and would otherwise pass as `text/plain` -- the one disguise that turns a
    reviewer's preview pane into a script host.
    """
    if data.startswith(b"%PDF-"):
        return "application/pdf"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    text = _as_text(data)
    if text is None:
        return None
    lead = _strip_leading(data)
    if lead.startswith(b"<"):
        # HTML, SVG, XML: script containers, or close enough that a browser's
        # own sniffing could make them one. Refused whatever was declared.
        return None
    if lead[:1] in (b"{", b"["):
        try:
            _json.loads(text)
        except ValueError:
            pass
        else:
            return "application/json"
    # CSV cannot be told from plain text by content alone. Both are rendered
    # as escaped text, so a declared `text/csv` on valid text is accepted
    # (`check_media_type`) and the sniff itself answers the plainer type.
    return "text/plain"


def check_media_type(declared: str, data: bytes) -> bool:
    """Whether `data` may be presented to an approver as `declared`.

    Binary types must match the sniff exactly: a PNG is a PNG. The text types
    are a family -- JSON is text, a CSV is text -- so `text/plain` or
    `text/csv` declared on bytes that sniff as any text type is fine, while
    `application/json` declared requires bytes that actually parse as JSON
    (the console pretty-prints it). Markup sniffs as nothing at all, so no
    declaration can carry it through.
    """
    if declared not in ALLOWED_MEDIA_TYPES:
        return False
    sniffed = sniff(data)
    if sniffed is None:
        return False
    if declared in _BINARY_TYPES:
        return sniffed == declared
    if declared == "application/json":
        return sniffed == "application/json"
    return sniffed in _TEXT_TYPES


def _clip(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[: limit - 1] + "…"


# --- the model ----------------------------------------------------------------------


@dataclass(frozen=True)
class Attachment:
    """One piece of evidence for an approver (§2).

    Frozen, like the `ApprovalRequest` that carries it: what the approver is
    shown is fixed once the request is built. `data` is excluded from `repr`
    and never logged -- it is customer content, governed like a payload.

    `unavailable` marks a placeholder: something was meant to be attached and
    is not (a provider failed, a file could not be read). It carries the
    reason, and becomes an `unavailable` manifest entry. Placeholders are how
    a failure stays visible to the approver instead of silently absent.
    """

    label: str
    media_type: str
    data: bytes = field(repr=False)
    source: AttachmentSource = AttachmentSource.APPLICATION
    note: str = ""
    origin_ref: str | None = None
    unavailable: str | None = None

    def __post_init__(self) -> None:
        # Truncated rather than refused: an over-long label is not a reason to
        # lose the evidence. Done once, here, so the manifest -- and so the
        # digest the approver's answer is signed over -- sees one value.
        object.__setattr__(self, "label", _clip(str(self.label), MAX_LABEL_CHARS))
        object.__setattr__(self, "note", _clip(str(self.note or ""), MAX_NOTE_CHARS))
        object.__setattr__(self, "source", AttachmentSource(self.source))
        if not isinstance(self.data, bytes):
            raise TypeError(f"Attachment.data must be bytes, not {type(self.data).__name__}")

    @cached_property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()

    @property
    def size(self) -> int:
        return len(self.data)

    # --- constructors -----------------------------------------------------------
    #
    # Defined after the fields on purpose: `bytes` and `json` shadow the
    # builtin and the module inside the class body from here on.

    @classmethod
    def file(cls, path: str | Path, label: str, note: str = "", **kwargs: Any) -> "Attachment":
        """Read a file; its type is sniffed from content, never the extension.

        A file that cannot be read becomes a placeholder rather than raising:
        this runs inside a provider or a call-site callable after policy has
        already deferred, where an exception would only become the same
        placeholder one level up -- with a less useful label.
        """
        try:
            data = Path(path).read_bytes()
        except OSError as exc:
            return cls.unavailable_entry(label, f"unreadable: {type(exc).__name__}", note=note)
        return cls(
            label=label,
            media_type=sniff(data) or "application/octet-stream",
            data=data,
            note=note,
            **kwargs,
        )

    @classmethod
    def bytes(cls, data: bytes, media_type: str, label: str, **kwargs: Any) -> "Attachment":
        """Raw bytes with a declared type. The declaration is checked against
        the content when the manifest is built (`check_media_type`)."""
        return cls(label=label, media_type=media_type, data=data, **kwargs)

    @classmethod
    def json(cls, obj: Any, label: str, **kwargs: Any) -> "Attachment":
        """Canonical JSON (sorted keys, compact, UTF-8), so the same object
        always hashes the same and a re-attached report is recognisably the
        same evidence. `NaN`/`Infinity` are refused: they are not JSON."""
        data = _json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
        return cls(label=label, media_type="application/json", data=data, **kwargs)

    @classmethod
    def text(cls, text: str, label: str, **kwargs: Any) -> "Attachment":
        return cls(label=label, media_type="text/plain", data=text.encode("utf-8"), **kwargs)

    @classmethod
    def unavailable_entry(cls, label: str, detail: str, **kwargs: Any) -> "Attachment":
        """A placeholder: evidence that was meant to be here and is not."""
        return cls(label=label, media_type="", data=b"", unavailable=detail, **kwargs)


# --- the manifest ---------------------------------------------------------------------


def _entry(
    a: Attachment, now_ms: int, *, status: str, detail: str, content_known: bool
) -> dict[str, Any]:
    """One manifest entry, with every key of `attest.ATTACHMENT_FIELDS`.

    Always every key: two producers that disagree about which optional keys to
    omit produce different digests for one manifest, and a digest mismatch
    refuses the approver's answer.
    """
    return {
        "sha256": a.sha256 if content_known else None,
        "size": a.size if content_known else 0,
        "media_type": a.media_type if content_known else "",
        "label": a.label,
        "source": a.source.value,
        "note": a.note,
        "origin_ref": a.origin_ref,
        "added_at_ms": now_ms,
        "status": status,
        "detail": detail,
    }


def build_manifest(attachments: Sequence[Attachment], now_ms: int) -> list[dict[str, Any]]:
    """The manifest for a request: **one entry per attachment, in order**.

    Order is preserved (the digest sorts its own copy) so a caller can zip the
    entries back to the attachments whose bytes it must upload.

    Every entry starts `stored` -- meaning "may be stored" -- unless something
    here rules it out: a placeholder, a refused media type, a size or count
    limit. Those become `unavailable` with the reason, and keep the hash,
    size and type when the content is known, so the approver sees *which*
    document was refused and not just that one was. Whether content then
    actually leaves is the transport's decision (`withheld`, `not_accepted`).
    """
    manifest: list[dict[str, Any]] = []
    total = 0
    for index, a in enumerate(attachments):
        if a.unavailable is not None:
            manifest.append(
                _entry(a, now_ms, status=UNAVAILABLE, detail=a.unavailable, content_known=False)
            )
            continue
        detail = ""
        if index >= MAX_ATTACHMENTS:
            detail = "too_many"
        elif not check_media_type(a.media_type, a.data):
            detail = "media_type_refused"
        elif a.size > MAX_ATTACHMENT_BYTES or total + a.size > MAX_REQUEST_BYTES:
            detail = "too_large"
        if detail:
            manifest.append(
                _entry(a, now_ms, status=UNAVAILABLE, detail=detail, content_known=True)
            )
            continue
        total += a.size
        manifest.append(_entry(a, now_ms, status=STORED, detail="", content_known=True))
    return manifest


# --- resolving `attachments=` and providers (§3.1, §3.2) -----------------------------

AttachmentsCallable: TypeAlias = Callable[
    [Action], "Iterable[Attachment] | Attachment | Awaitable[Iterable[Attachment] | None] | None"
]
#: What `attachments=` accepts: nothing, a fixed sequence, or a callable over
#: the built `Action` that runs only if the action is going to a person.
AttachmentsSpec: TypeAlias = "Sequence[Attachment] | AttachmentsCallable | None"


class AttachmentProvider(NamedTuple):
    """A registered source of attachments for tools matching `glob` (§3.2).

    `pattern` is the glob compiled with the policy engine's own segment-aware
    matcher, so "which tools does this provider cover" is answered exactly as
    "which tools does this rule cover" -- one glob language, not two that
    agree until a `/` turns up.
    """

    glob: str
    fn: AttachmentsCallable
    name: str
    pattern: Pattern[str]

    @classmethod
    def build(
        cls, glob: str, fn: AttachmentsCallable, name: str | None = None
    ) -> "AttachmentProvider":
        from .policy import _glob_to_regex

        return cls(glob, fn, name or _name_of(fn), _glob_to_regex(glob))

    def matches(self, tool: str) -> bool:
        return self.pattern.match(tool) is not None


def _name_of(fn: Any) -> str:
    name = getattr(fn, "__name__", None)
    return name if isinstance(name, str) and name != "<lambda>" else "attachments"


def _materialise(result: Any) -> list[Attachment]:
    """A callable's result as a list of attachments, or TypeError.

    A single `Attachment` is accepted for convenience; `None` means "nothing
    to attach". Anything that is not an `Attachment` is a programming error,
    and becomes a placeholder like any other provider failure.
    """
    if result is None:
        return []
    if isinstance(result, Attachment):
        return [result]
    if isinstance(result, (str, bytes, dict)):
        raise TypeError(f"expected Attachment(s), got {type(result).__name__}")
    items = list(result)
    for item in items:
        if not isinstance(item, Attachment):
            raise TypeError(f"expected Attachment, got {type(item).__name__}")
    return items


def _call_sync(fn: Callable[[Action], Any], action: Action) -> Any:
    """Run a sync callable and drain its result, both off the event loop.

    Drained here, in the worker thread, because a generator that reads files
    as it yields would otherwise do its I/O on the loop the agent shares.
    """
    result = fn(action)
    if inspect.isawaitable(result):
        return result
    return _materialise(result)


async def _run_one(fn: Callable[[Action], Any], action: Action) -> list[Attachment]:
    if inspect.iscoroutinefunction(fn):
        return _materialise(await fn(action))
    result = await asyncio.to_thread(_call_sync, fn, action)
    if inspect.isawaitable(result):
        result = _materialise(await result)
    return result


async def resolve_attachments(
    spec: AttachmentsSpec,
    action: Action,
    *,
    providers: Sequence[AttachmentProvider] = (),
    timeout: float = DEFAULT_PROVIDER_TIMEOUT,
) -> tuple[Attachment, ...]:
    """Everything to attach to the request for `action`. Never raises.

    Call-site attachments first, then every provider whose glob matches
    `action.tool`, in registration order (§3.2).

    One `timeout` budget covers them all, not one each: the agent is blocked
    while this runs, and twenty providers at five seconds apiece is a hundred
    seconds before anybody is even asked. A callable that raises, returns
    something that is not an attachment, or runs out of budget contributes a
    single placeholder labelled with its name (`provider_error: <ExcType>`),
    and the request is still asked -- a failure to gather evidence is the
    approver's to weigh, not the engine's to decide.

    A sync callable that overruns keeps running in its worker thread after
    its result stops being awaited (Python cannot cancel a thread). It is
    abandoned, not stopped; what it eventually returns is discarded.

    `asyncio.CancelledError` propagates: that is shutdown, not a verdict.
    """
    sources: list[tuple[str, Any]] = []
    if spec is not None:
        if callable(spec):
            sources.append((_name_of(spec), spec))
        else:
            sources.append(("attachments", spec))
    for provider in providers:
        try:
            matched = provider.matches(action.tool)
        except Exception:  # noqa: BLE001 - a broken matcher is a provider failure
            matched = True
        if matched:
            sources.append((provider.name, provider.fn))

    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    out: list[Attachment] = []
    for name, source in sources:
        try:
            if not callable(source):
                out.extend(_materialise(source))
                continue
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise TimeoutError
            out.extend(await asyncio.wait_for(_run_one(source, action), remaining))
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - missing evidence is not a decision
            log.warning(
                "attachment source %r failed for %s: %s; the request is asked without it",
                name,
                action.tool,
                type(exc).__name__,
            )
            out.append(Attachment.unavailable_entry(name, f"provider_error: {type(exc).__name__}"))
    return tuple(out)
