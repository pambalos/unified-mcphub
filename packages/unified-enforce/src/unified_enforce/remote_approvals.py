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

Standard library plus `cryptography`, like the rest of the package: this runs in
every sidecar, and the decision path stays import-light.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .approval import (
    ApprovalKind,
    ApprovalRequest,
    ApprovalResponse,
    Approver,
    SignedResolution,
)
from .attest import DEFAULT_SKEW_MS, Reason, VerificationKey, accept_resolution

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


class ApprovalTransportError(Exception):
    """The control plane could not be reached, or answered incomprehensibly."""


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
    ) -> None:
        if keys is None and decision_key is None:
            raise ValueError(
                "RemoteApprovals needs a key source: pass `keys` (preferred, "
                "rotates with the signed key set) or `decision_key` (pinned). "
                "Without one, no resolution could ever be verified and every "
                "deferred action would deny."
            )

        self._base = base_url.rstrip("/")
        self._credential = credential
        self._fleet = fleet_id
        self._poll = poll_seconds
        self._deadline = deadline_seconds
        self._http_timeout = http_timeout
        self._skew_ms = skew_ms

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
        queued = await asyncio.to_thread(self._queue, request)

        if queued.already_resolved:
            # The control plane is idempotent on (fleet, digest), so a retry
            # after a network blip returns the existing row rather than queueing
            # a second copy of the same question. Worth naming: the alternative
            # is an operator seeing one action twice and possibly answering it
            # two different ways.
            log.debug("approval %s was already queued for %s", queued.approval_id, digest[:12])

        loop = asyncio.get_running_loop()
        expires = loop.time() + self._deadline

        while True:
            response = await asyncio.to_thread(self._poll_once, queued.approval_id)
            verdict = accept_resolution(
                response,
                self._keys(),
                fleet_id=self._fleet,
                action_digest=digest,
                now_ms=_now_ms(),
                skew_ms=self._skew_ms,
            )

            if verdict.ok:
                return _response_from(response)

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
                raise ApprovalTransportError(
                    f"no answer within {self._deadline:.0f}s for {digest[:12]}…"
                )

            # `sleep`, not a blocking wait: this coroutine shares an event loop
            # with whatever the agent is doing, and holding it for five minutes
            # would stall every other decision in the process.
            await asyncio.sleep(min(self._poll, max(0.0, expires - loop.time())))

    # --- HTTP -------------------------------------------------------------------

    def _queue(self, request: ApprovalRequest) -> _Queued:
        body = {
            "action": request.action.model_dump(mode="json"),
            "decision": {
                "verdict": request.decision.verdict.value,
                "rule_id": request.decision.rule_id,
                "source": request.decision.source,
                "audit_level": request.decision.audit_level,
                "reason": request.decision.reason,
            },
            "action_digest": request.digest,
            "summary": request.summary,
            "floored": request.floored,
        }
        # Note what is absent: `fleet_id`. It is derived from the credential and
        # rejected in the body, so a sidecar cannot queue into another tenant.
        payload = self._post("/api/v1/approvals", body)

        approval_id = payload.get("id")
        if not isinstance(approval_id, str) or not approval_id:
            raise ApprovalTransportError("control plane returned no approval id")
        return _Queued(approval_id=approval_id, already_resolved=payload.get("status") != "pending")

    def _poll_once(self, approval_id: str) -> dict[str, Any]:
        return self._get(f"/api/v1/approvals/{approval_id}/decision")

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
            raise ApprovalTransportError(f"HTTP {exc.code}: {exc.reason}") from exc
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

        return self._request(
            urllib.request.Request(
                self._base + path,
                data=json.dumps(body).encode(),
                headers={"content-type": "application/json"},
                method="POST",
            )
        )

    def _get(self, path: str) -> dict[str, Any]:
        import urllib.request

        return self._request(urllib.request.Request(self._base + path, method="GET"))


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
