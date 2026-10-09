"""Asking a control plane for a human decision. UAI-109.

The missing half. `approval.py` defined what a DEFER needs — a way to reach a
human — and the control plane has been able to answer one, sign the answer, and
attribute it to an authenticated person for some time. Nothing connected them:
no sidecar posted a DEFER, polled it, or verified a signature, so signed
decisions had no consumer outside the control plane's own tests. This module is
the client.

**It verifies the artifact, not the connection.** A resolved approval releases
an action a policy floor deliberately held, so anything able to produce that
JSON can unblock a blocked action. TLS narrows who can and does not close it —
a mis-issued certificate, an over-broad trust store, DNS takeover, or a
TLS-terminating proxy somebody added for observability all widen it again. So
every response goes through `attest.accept_resolution`, which is the same code
the control plane vendors, and an unverifiable allow is a denial.

**Nothing here decides to allow.** This is an `ApprovalChannel`: it asks and
returns what it heard. Every failure — unreachable, unverifiable, expired,
answering a different action — raises, and `Approvals` turns that into a deny
with the reason attached. Keeping the fail-closed logic in one place is what
stops a new channel introducing a fail-open path, and this channel is the one
most able to fail in interesting ways.

**Polling, not a callback.** The data plane sits behind the customer's egress
lock with exactly one outbound path. Requiring the control plane to reach *into*
their network would invert the whole trust arrangement, and is the thing a
security review refuses. The sidecar owns its timeout and fails closed on it.

**Attachments are uploaded, then referenced, then bound** (approval-attachments
.v1 §8). Bytes go to their own route first, so they never sit in the approval
JSON; the request then carries a manifest of hashes; and the resolution is
verified against a manifest that must contain, unaltered, every entry *this
client* attached. A control plane that showed the approver a substituted
document -- or dropped one -- cannot produce a decision this client honours.

**Late evidence** (§4.3) is the one way the manifest grows after queueing:
`attach` adds entries to a pending request through this same credential. The
control plane accepts them only from the credential that queued the request,
so entries beyond this client's own are this deployment's late attachments
(another process or session of the same principal). The resolution's digest
then covers the manifest as the control plane returns it -- checked to contain
everything this client attached, and its digest recomputed here, never read.

Standard library plus `cryptography`, like the rest of the package: this runs in
every sidecar, and the decision path stays import-light.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import math
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any

from .approval import (
    ApprovalKind,
    ApprovalRequest,
    ApprovalResponse,
    Approver,
    SignedResolution,
    gate_forced,
)
from .attachments import STORED, UNAVAILABLE, WITHHELD, Attachment, build_manifest
from .evidence import payload_transport_ok
from .attest import (
    ATTACHMENT_FIELDS,
    DEFAULT_SKEW_MS,
    Reason,
    VerificationKey,
    accept_resolution,
    attachments_digest,
)

log = logging.getLogger("unified_enforce.remote_approvals")

#: How often to ask again. A human is deciding, so sub-second polling buys
#: nothing and costs a request per sidecar per second across a fleet.
DEFAULT_POLL_SECONDS = 2.0

#: How long to keep asking before giving up. Deliberately finite: an agent
#: blocked on an approval nobody will ever answer should fail closed rather
#: than hold a connection open until something else times out.
DEFAULT_DEADLINE_SECONDS = 300.0

#: Per-request network timeout. Separate from the deadline above, because a
#: single stuck socket must not consume the whole window in one call.
DEFAULT_HTTP_TIMEOUT = 10.0

#: Largest base64 body this client will upload for one attachment. The
#: manifest limits (10 MiB per attachment) keep every real upload far below
#: it; this is the backstop if those limits are ever raised or bypassed, so a
#: single request cannot become an unbounded POST.
MAX_UPLOAD_B64_BYTES = 36 * 1024 * 1024

#: Statuses on the upload route that mean "this control plane cannot take
#: attachments at all" (no route, wrong credential) rather than "not this
#: one". Those raise: queueing anyway would ask a person a question whose
#: answer is certain to be refused (the resolution will name no manifest),
#: and the deny is better delivered now than after they have read it.
_UPLOAD_FATAL_STATUSES = frozenset({401, 403, 404, 405})


class ApprovalTransportError(Exception):
    """The control plane could not be reached, or answered incomprehensibly."""


class ApprovalHTTPError(ApprovalTransportError):
    """The control plane answered with an HTTP error status.

    Kept distinct so the attachment upload can tell "refused this document"
    (a 4xx with a reason, which becomes an `unavailable` entry) from
    "unreachable" (which fails the request closed). Everywhere else it is an
    `ApprovalTransportError` like any other.
    """

    def __init__(self, status: int, reason: str, detail: str = "") -> None:
        super().__init__(f"HTTP {status}: {reason}")
        self.status = status
        self.detail = detail


class ApprovalTimeout(ApprovalTransportError, TimeoutError):
    """Nobody answered within the deadline.

    A `TimeoutError`, so `Approvals` records it as what it is
    (`approval_timeout`, "silence is not consent") rather than as a broken
    channel (`approval_error`). The deadline lives here, not in an outer
    `wait_for`, because this client polls and must stop between polls; before
    this subclass the two failures were indistinguishable in the audit.
    """


class NoVerificationKeys(ApprovalTransportError):
    """There is no key to verify a resolution with, so the request is not queued."""


class UnverifiedResolution(Exception):
    """A resolution arrived and could not be trusted.

    Deliberately its own type, and logged at error level wherever it is raised.
    It is categorically different from "unreachable": something produced a
    decision for this action that did not verify, which is either a serious
    misconfiguration or somebody attempting exactly the attack the signature
    exists to stop. Both deserve an alarm; only one of them is an outage.
    """

    def __init__(self, reason: Reason | None, detail: str) -> None:
        super().__init__(f"{reason}: {detail}" if reason else detail)
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class _Queued:
    approval_id: str
    already_resolved: bool
    #: What the receipt *claims* the manifest digest is. Never used to verify
    #: -- only compared, so a control plane that recorded a different
    #: manifest is caught before a person is asked rather than after.
    attachments_digest: str | None = None


@dataclass
class _Waiting:
    """A request `ask` is polling for, and the evidence this client attached to it."""

    request: ApprovalRequest
    #: Every manifest entry this client attached, initially and late. The
    #: resolution must cover all of them, unaltered.
    own: list[dict[str, Any]] = field(default_factory=list)


#: `on_queued(approval_id, request)`: told the control plane's id for a
#: request as soon as it is queued, so a surface that does not block can hand
#: the agent an `approval_ref` for late attachment (§4.3).
OnQueued = Callable[[str, ApprovalRequest], None]


class RemoteApprovals:
    """An `ApprovalChannel` backed by a control plane's approval queue.

    Construct with either a live key source or a pinned decision key:

        RemoteApprovals(base_url, credential, fleet_id="acme", keys=dist.verification_keys)
        RemoteApprovals(base_url, credential, fleet_id="acme", decision_key="<base64>")

    The first is preferred. Keys reach a sidecar inside a root-signed key set,
    so rotating the decision key is a signed message rather than a fleet-wide
    re-enrolment — and rotation that requires touching every sidecar is rotation
    that does not happen. The pinned form exists for deployments not running
    policy distribution at all, and it cannot rotate.
    """

    def __init__(
        self,
        base_url: str,
        credential: str,
        *,
        fleet_id: str,
        keys: Callable[[], Mapping[str, VerificationKey]] | None = None,
        decision_key: str | None = None,
        poll_seconds: float = DEFAULT_POLL_SECONDS,
        deadline_seconds: float = DEFAULT_DEADLINE_SECONDS,
        http_timeout: float = DEFAULT_HTTP_TIMEOUT,
        skew_ms: int = DEFAULT_SKEW_MS,
        channel: Any = None,
        share_params: bool = True,
        on_queued: OnQueued | None = None,
    ) -> None:
        """`share_params=False` never sends an action's arguments to the
        approver (see `_queue`); `minimal` rules withhold them regardless.

        `on_queued(approval_id, request)` is called once per request, right
        after it is queued and before the first poll. It is how an
        application learns the `approval_ref` to return with a 202 or to pass
        to `attach`. It is a notification: an exception from it is logged and
        the request still waits for its answer."""
        if keys is None and decision_key is None:
            raise ValueError(
                "RemoteApprovals needs a key source: pass `keys` (preferred, "
                "rotates with the signed key set) or `decision_key` (pinned). "
                "Without one, no resolution could ever be verified and every "
                "deferred action would deny."
            )

        #: Binds each request to the key this sidecar registered. Without it a
        #: stolen bearer token could queue approvals and read decisions in this
        #: sidecar's name.
        self._channel = channel
        self._base = base_url.rstrip("/")
        self._credential = credential
        self._fleet = fleet_id
        self._poll = poll_seconds
        self._deadline = deadline_seconds
        self._http_timeout = http_timeout
        self._skew_ms = skew_ms
        self._share_params = share_params
        self.on_queued = on_queued
        #: approval id -> the asks currently polling it. A list, because the
        #: queue is idempotent on the action digest: two identical calls
        #: waiting at once share one approval.
        self._waiting: dict[str, list[_Waiting]] = {}

        if keys is not None:
            self._keys = keys
        else:
            assert decision_key is not None
            from .attest import key_id

            # A pinned key never expires on its own. Giving it a fabricated
            # expiry would be worse than none: it would come due on a date
            # nobody chose, and present as approvals silently ceasing to work.
            pinned = {
                key_id(decision_key): VerificationKey(
                    kid=key_id(decision_key),
                    public_key=decision_key,
                    role="decision",
                    expires_at_ms=2**62,
                )
            }
            self._keys = lambda: pinned

    # --- the channel contract ---------------------------------------------------

    async def ask(self, request: ApprovalRequest) -> ApprovalResponse:
        """Queue the DEFER, wait for a human, and return a verified answer.

        Raises on every failure path. `Approvals` catches and denies, which is
        where that decision belongs — a channel that decided for itself would be
        a second place a fail-open could be introduced.
        """
        digest = request.digest
        if not self._keys():
            # No decision key this client could verify a resolution with --
            # no key set has verified yet (an un-polled or unprovisioned
            # sidecar), or the last one stopped verifying. Queueing anyway
            # would put a question in front of an approver whose answer is
            # certain to be refused, for as long as the deadline. Refused here,
            # before anything leaves: `Approvals` turns this into a DENY.
            raise NoVerificationKeys(
                "no verified decision key: cannot verify any resolution, so nothing is queued "
                "(the fleet's key set has not verified yet)"
            )
        manifest: list[dict[str, Any]] | None = None
        expected: str | None = None
        if request.attachments:
            manifest = build_manifest(request.attachments, _now_ms())
            withheld = self._withheld(request)
            if withheld is None and not payload_transport_ok(self._base):
                # Content goes over https, or plain http to this machine
                # (payload-evidence.v1's rule). The request proof protects the
                # integrity of what is sent, not its confidentiality.
                withheld = "insecure_transport"
            if withheld is not None:
                # No content leaves. The manifest still does: the approver
                # sees that the evidence exists, what it is called and its
                # hash -- "withheld" and "there was nothing" must look
                # different to a reviewer.
                manifest = [_withhold(entry, withheld) for entry in manifest]
            else:
                manifest = await asyncio.to_thread(self._upload_all, manifest, request.attachments)
            # Computed here, from what this client is about to send, and
            # never read back from the control plane: the receipt is checked
            # against it below, and the resolution later against a manifest
            # that must still contain every one of these entries
            # (`_expected_digest`) -- taking either from the other side would
            # let that side choose what it is checked against.
            expected = attachments_digest(manifest)

        queued = await asyncio.to_thread(self._queue, request, manifest)
        claimed = getattr(queued, "attachments_digest", None)
        if claimed is not None and claimed != expected:
            log.error(
                "control plane recorded evidence %s… for %s; this client sent %s…",
                str(claimed)[:12],
                digest[:12],
                str(expected)[:12],
            )
            raise UnverifiedResolution(
                Reason.ATTACHMENTS_MISMATCH,
                "the control plane recorded a different evidence manifest than was sent",
            )

        if queued.already_resolved:
            # The control plane is idempotent on (fleet, digest), so a retry
            # after a network blip returns the existing row rather than queueing
            # a second copy of the same question. Worth naming: the alternative
            # is an operator seeing one action twice and possibly answering it
            # two different ways.
            log.debug("approval %s was already queued for %s", queued.approval_id, digest[:12])

        waiting = _Waiting(request, list(manifest or ()))
        self._waiting.setdefault(queued.approval_id, []).append(waiting)
        try:
            self._notify_queued(queued.approval_id, request)
            return await self._await_resolution(queued.approval_id, digest, waiting)
        finally:
            asks = self._waiting.get(queued.approval_id, [])
            if waiting in asks:
                asks.remove(waiting)
            if not asks:
                self._waiting.pop(queued.approval_id, None)

    async def _await_resolution(
        self, approval_id: str, digest: str, waiting: _Waiting
    ) -> ApprovalResponse:
        loop = asyncio.get_running_loop()
        expires = loop.time() + self._deadline

        while True:
            response = await asyncio.to_thread(self._poll_once, approval_id)
            expected = None
            if response.get("status") == "resolved":
                # Read `own` at resolution time, not at queue time: an
                # `attach` made while this was waiting is evidence this
                # client added, and the answer must cover it too.
                expected = _expected_digest(response, waiting.own, digest)
            verdict = accept_resolution(
                response,
                self._keys(),
                fleet_id=self._fleet,
                action_digest=digest,
                now_ms=_now_ms(),
                skew_ms=self._skew_ms,
                attachments_digest=expected,
            )

            if verdict.ok:
                return replace(_response_from(response), attachments_digest=expected)

            if verdict.reason is not Reason.NOT_RESOLVED:
                # Anything other than "nobody has answered yet" is a decision
                # this sidecar must not honour, and polling again would not
                # improve it — the same bytes would arrive with the same
                # signature. Fail now and loudly.
                log.error(
                    "refusing a resolution for %s: %s (%s)",
                    digest[:12],
                    verdict.reason,
                    verdict.detail,
                )
                raise UnverifiedResolution(verdict.reason, verdict.detail)

            if loop.time() >= expires:
                raise ApprovalTimeout(f"no answer within {self._deadline:.0f}s for {digest[:12]}…")

            # `sleep`, not a blocking wait: this coroutine shares an event loop
            # with whatever the agent is doing, and holding it for five minutes
            # would stall every other decision in the process.
            await asyncio.sleep(min(self._poll, max(0.0, expires - loop.time())))

    def _notify_queued(self, approval_id: str, request: ApprovalRequest) -> None:
        if self.on_queued is None:
            return
        try:
            self.on_queued(approval_id, request)
        except Exception:  # noqa: BLE001 - a notification is never a decision
            log.exception("on_queued raised for approval %s; still waiting for it", approval_id)

    # --- late attachment (§4.3) -------------------------------------------------

    def waiting_request(self, approval_id: str) -> ApprovalRequest | None:
        """The request an `ask` on this instance is waiting on under
        `approval_id`, or None. Lets an agent-facing surface refuse a late
        attachment to a request that is not the caller's own."""
        asks = self._waiting.get(approval_id)
        return asks[0].request if asks else None

    async def attach(self, approval_id: str, attachments: Sequence[Attachment]) -> dict[str, Any]:
        """Add evidence to a request that is still pending (§4.3).

        Built, limited and uploaded exactly as `ask` does for the initial
        evidence, then posted to the request. The control plane accepts it
        only from the credential that queued the request, and only while
        pending (404 / 409 otherwise, raised as `ApprovalHTTPError`).

        Content is withheld by the same rules as the request's params. When
        this instance is not the one waiting on the request it cannot know
        the rule's `audit_level` or whether distribution state forced the
        DEFER, so content is withheld (`request_not_local`) rather than
        guessed: a `minimal` rule's evidence leaving this machine because a
        different process attached it is the export the rule exists to stop.
        The manifest still goes, so the approver sees the evidence exists.

        When an `ask` on this instance is waiting on `approval_id`, the new
        entries become part of what its resolution must cover. Returns the
        control plane's `{"attachments": [...], "attachments_digest": ...}`.
        """
        if not attachments:
            raise ValueError("attach needs at least one attachment")
        manifest = build_manifest(list(attachments), _now_ms())
        asks = self._waiting.get(approval_id, [])
        if asks:
            withheld = self._withheld(asks[0].request)
        else:
            withheld = None if self._share_params else "payloads_off"
            withheld = withheld or "request_not_local"
        if withheld is None and not payload_transport_ok(self._base):
            withheld = "insecure_transport"
        if withheld is not None:
            manifest = [_withhold(entry, withheld) for entry in manifest]
        else:
            manifest = await asyncio.to_thread(self._upload_all, manifest, list(attachments))

        result = await asyncio.to_thread(
            self._post, f"/api/v1/approvals/{approval_id}/attachments", {"attachments": manifest}
        )
        returned = result.get("attachments")
        if not isinstance(returned, list) or _missing(manifest, returned):
            raise UnverifiedResolution(
                Reason.ATTACHMENTS_MISMATCH,
                "the control plane did not record the late attachment as sent",
            )
        claimed = result.get("attachments_digest")
        if claimed is not None and claimed != attachments_digest(returned):
            raise UnverifiedResolution(
                Reason.ATTACHMENTS_MISMATCH,
                "the control plane's digest does not describe the manifest it returned",
            )
        # Only after the control plane confirmed them: an entry recorded here
        # but not there would make every resolution of this request refuse.
        for waiting in self._waiting.get(approval_id, []):
            waiting.own.extend(manifest)
        return result

    # --- HTTP -------------------------------------------------------------------

    def _withheld(self, request: ApprovalRequest) -> str | None:
        """Why no content may leave for this request, or None (see `_queue`).

        One answer for params and attachments alike: a request whose arguments
        are withheld must not ship the invoice those arguments describe.
        """
        if request.decision.audit_level == "minimal":
            return "audit_level_minimal"
        if not self._share_params:
            return "payloads_off"
        if gate_forced(request.decision):
            return "distribution_state"
        return None

    def _upload_all(
        self, manifest: list[dict[str, Any]], attachments: Sequence[Attachment]
    ) -> list[dict[str, Any]]:
        """Upload every `stored` entry's bytes; return the manifest as it now stands.

        `manifest` is `build_manifest(attachments)`, one entry per attachment
        in order. Each sha256 is uploaded once per request (the route is
        content-addressed, so a duplicate would be a no-op anyway, and two
        identical photos should not cost two uploads). An entry the control
        plane would not take becomes `unavailable` with its reason; it stays
        in the manifest, because the approver is owed the knowledge that it
        was meant to be there.

        Raises on transport failure and on a response that does not describe
        the bytes sent: `Approvals` denies, which is the right answer when
        this client cannot tell what the approver will be shown.
        """
        out: list[dict[str, Any]] = []
        outcome: dict[str, tuple[str, str]] = {}
        for entry, attachment in zip(manifest, attachments, strict=True):
            if entry["status"] != STORED:
                out.append(entry)
                continue
            sha = entry["sha256"]
            if sha not in outcome:
                outcome[sha] = self._upload_one(entry, attachment)
            status, detail = outcome[sha]
            out.append(entry if status == STORED else {**entry, "status": status, "detail": detail})
        return out

    def _upload_one(self, entry: Mapping[str, Any], attachment: Attachment) -> tuple[str, str]:
        """POST one attachment's bytes: `(status, detail)` for its manifest entry."""
        encoded = base64.b64encode(attachment.data).decode("ascii")
        if len(encoded) > MAX_UPLOAD_B64_BYTES:
            return UNAVAILABLE, "too_large"
        try:
            receipt = self._post(
                "/api/v1/approvals/attachments",
                {"sha256": entry["sha256"], "media_type": entry["media_type"], "data_b64": encoded},
            )
        except ApprovalHTTPError as exc:
            if exc.status in _UPLOAD_FATAL_STATUSES or not 400 <= exc.status < 500:
                raise
            # Refused this document (too large, type, validation): the
            # request goes ahead without its content, and says why.
            return UNAVAILABLE, f"refused: {exc.detail or exc.status}"[:200]
        status = receipt.get("status")
        if status == "not_accepted":
            # The fleet does not take content (hosted without opt-in). The
            # approver sees the hash and label, without the document.
            return UNAVAILABLE, "not_accepted"
        if status != STORED:
            raise ApprovalTransportError(f"attachment upload returned status {status!r}")
        if receipt.get("sha256") != entry["sha256"] or receipt.get("size") != entry["size"]:
            # Stored *something*, and not what was sent. The approver would
            # be shown a document this client never attached.
            raise ApprovalTransportError("attachment upload receipt does not match the bytes sent")
        return STORED, ""

    def _queue(
        self, request: ApprovalRequest, attachments: list[dict[str, Any]] | None = None
    ) -> _Queued:
        """Post the DEFER, carrying only what an approver needs to see.

        **What leaves, and why it can.** The control plane binds an approval
        to `action_digest` (it is the queue key, and it is what the decision
        key signs); it does not recompute the digest from the posted action,
        and this client verifies the signed resolution against the digest *it*
        computed. So the posted action is display, not evidence, and content
        can be withheld from it without weakening the binding:

        - `context.extra` is never sent: it is the integration's own
          bookkeeping (gateway headers, session metadata), not what the agent
          asked to do, and payload evidence excludes it for the same reason.
        - `params` are withheld for a rule marked `audit_level: minimal` (the
          customer marked that traffic sensitive; a copy to another system is
          an export) and when the deployment said no content leaves
          (`share_params=False`, the hub's `control_plane.payloads: off`),
          and for a DEFER that distribution state forced (`gate_forced`: a
          revocation list not yet fetched or stale, a `defer` containment).
          That prompt exists because this principal may be contained; its
          arguments are the last thing to copy to another system on the
          strength of a rule that never asked for review of them.
          The `summary` is replaced too, because a caller's summary usually
          renders the arguments. The approver then decides on the tool, the
          principal, the rule and the reason -- and is told the arguments
          were withheld, and why.

        `attachments` is the evidence manifest (already uploaded, or marked
        withheld/unavailable). The key is omitted entirely when the request has
        none, so a control plane that predates attachments sees exactly the
        body it always did.

        `deadline_seconds` tells the control plane how long this client will
        wait, so it can expire the pending item rather than leave a question
        nobody is waiting on; `policy_digest` names the policy that deferred.
        Both are optional fields an older control plane ignores.
        """
        action = request.action.model_dump(mode="json")
        context = action.get("context")
        if isinstance(context, dict):
            context["extra"] = {}
        withheld = self._withheld(request)
        summary = request.summary
        if withheld is not None:
            action["params"] = {}
            summary = f"{request.action.tool} (arguments withheld: {withheld})"
        body: dict[str, Any] = {
            "action": action,
            "decision": {
                "verdict": request.decision.verdict.value,
                "rule_id": request.decision.rule_id,
                "source": request.decision.source,
                "audit_level": request.decision.audit_level,
                "reason": request.decision.reason,
                "policy_digest": request.decision.policy_digest,
            },
            "action_digest": request.digest,
            "summary": summary,
            "floored": request.floored,
            # An integer, rounded up: the control plane treats it as advisory
            # and accepts floats now, but an older one validates an int, and
            # rounding down could expire the item before this client stops.
            "deadline_seconds": math.ceil(self._deadline),
        }
        if withheld is not None:
            body["params_withheld"] = withheld
        if attachments:
            body["attachments"] = attachments
        # Note what is absent: `fleet_id`. It is derived from the credential and
        # rejected in the body, so a sidecar cannot queue into another tenant.
        payload = self._post("/api/v1/approvals", body)

        approval_id = payload.get("id")
        if not isinstance(approval_id, str) or not approval_id:
            raise ApprovalTransportError("control plane returned no approval id")
        claimed = payload.get("attachments_digest")
        return _Queued(
            approval_id=approval_id,
            already_resolved=payload.get("status") != "pending",
            attachments_digest=claimed if isinstance(claimed, str) else None,
        )

    def _poll_once(self, approval_id: str) -> dict[str, Any]:
        return self._get(f"/api/v1/approvals/{approval_id}/decision")

    def _proof(self, method: str, path: str, body: bytes | None) -> dict[str, str]:
        return {} if self._channel is None else self._channel.headers(method, path, body)

    def _request(self, req: Any) -> dict[str, Any]:
        # Imported here rather than at module scope, matching `evidence.py`:
        # `urllib.request` drags in http.client, email and ssl, and this module
        # is not on the in-process decision path.
        import urllib.error

        req.add_header("authorization", f"Bearer {self._credential}")
        try:
            with urllib.request.urlopen(req, timeout=self._http_timeout) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            raise ApprovalHTTPError(exc.code, str(exc.reason), _error_detail(exc)) from exc
        except urllib.error.URLError as exc:
            raise ApprovalTransportError(f"cannot reach the control plane: {exc.reason}") from exc

        try:
            decoded = json.loads(raw)
        except ValueError as exc:
            raise ApprovalTransportError("control plane returned invalid JSON") from exc
        if not isinstance(decoded, dict):
            raise ApprovalTransportError("control plane returned a non-object")
        return decoded

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        import urllib.request

        raw = json.dumps(body).encode()
        return self._request(
            urllib.request.Request(
                self._base + path,
                data=raw,
                headers={"content-type": "application/json", **self._proof("POST", path, raw)},
                method="POST",
            )
        )

    def _get(self, path: str) -> dict[str, Any]:
        import urllib.request

        return self._request(
            urllib.request.Request(
                self._base + path, headers=self._proof("GET", path, None), method="GET"
            )
        )


def _normalised(entry: Mapping[str, Any]) -> str:
    """An entry as the digest sees it, as a comparable key."""
    return json.dumps({f: entry.get(f) for f in ATTACHMENT_FIELDS}, sort_keys=True)


def _missing(own: Sequence[Mapping[str, Any]], returned: Sequence[Any]) -> bool:
    """Whether any of `own` is absent from `returned` (as a multiset: two
    identical entries this client attached need two in the manifest)."""
    if not all(isinstance(e, Mapping) for e in returned):
        return True
    have = Counter(_normalised(e) for e in returned)
    need = Counter(_normalised(e) for e in own)
    return any(have[k] < n for k, n in need.items())


def _expected_digest(
    response: Mapping[str, Any], own: Sequence[Mapping[str, Any]], digest: str
) -> str | None:
    """The manifest digest a resolved `response` must be signed over.

    Every entry this client attached must be in the returned manifest,
    unaltered; anything more is a late attachment the control plane accepted
    from this same credential, and is part of what the approver saw. The
    digest is then computed *here* over the returned manifest and handed to
    `accept_resolution`, which checks the signature covers exactly that.

    Raises `UnverifiedResolution` when the manifest is absent (and this
    client attached something), malformed, or missing or altering one of
    this client's entries: the approver was not shown what was attached.
    """
    returned = response.get("attachments")
    if returned is None:
        if own:
            log.error("resolution for %s carries no manifest; evidence was attached", digest[:12])
            raise UnverifiedResolution(
                Reason.ATTACHMENTS_MISMATCH,
                "the resolution names no evidence manifest, and evidence was attached",
            )
        return None
    if not isinstance(returned, list) or _missing(own, returned):
        log.error("resolution for %s omits or alters evidence this client attached", digest[:12])
        raise UnverifiedResolution(
            Reason.ATTACHMENTS_MISMATCH,
            "the resolution's manifest omits or alters evidence this client attached",
        )
    return attachments_digest(returned) if returned else None


def _withhold(entry: Mapping[str, Any], reason: str) -> dict[str, Any]:
    """A `stored` entry whose content may not leave: hash and label kept."""
    if entry["status"] != STORED:
        return dict(entry)
    return {**entry, "status": WITHHELD, "detail": reason}


def _error_detail(exc: Any) -> str:
    """The `detail` of an error response, as short text. Best effort: an error
    body is the server's to shape, and failing to read it must not mask the
    status that was already decided on."""
    try:
        body = json.loads(exc.read() or b"{}")
    except Exception:  # noqa: BLE001
        return ""
    detail = body.get("detail") if isinstance(body, dict) else None
    if detail is None:
        return ""
    text = detail if isinstance(detail, str) else json.dumps(detail, separators=(",", ":"))
    return text[:180]


def _now_ms() -> int:
    return int(datetime.now(UTC).timestamp() * 1000)


def _response_from(payload: Mapping[str, Any]) -> ApprovalResponse:
    """Turn a verified resolution into what the channel contract returns.

    Everything here is already inside the signature, so nothing in this function
    can be influenced without invalidating it. That is why the approver is built
    from the response rather than looked up anywhere: the response *is* the
    attested record.
    """
    approver_raw = payload["approver"]
    approver = Approver(
        subject=str(approver_raw["sub"]),
        email=str(approver_raw.get("email", "")),
        session_id=str(approver_raw.get("sid", "")),
        authenticated_at_ms=int(approver_raw["auth_time_ms"]),
    )
    return ApprovalResponse(
        kind=ApprovalKind(payload["kind"]),
        # The stable IdP subject, not the address. Addresses are reassigned; a
        # record naming one stops resolving to a person once they leave.
        decided_by=approver.subject,
        scope=payload.get("scope"),
        approver=approver,
        attestation=SignedResolution(
            signature=str(payload["signature"]),
            key_id=str(payload["key_id"]),
            nonce=str(payload["nonce"]),
            resolved_at_ms=int(payload["resolved_at_ms"]),
            expires_at_ms=int(payload["expires_at_ms"]),
            fleet_id=str(payload["fleet_id"]),
        ),
    )
