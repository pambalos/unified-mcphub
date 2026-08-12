"""The approval contract — what turns a DEFER into a decision. UAI-133.

DEFER is the verdict that says "a human decides this one". Without a consumer
it is just a deny with a nicer label, which is what it was everywhere outside
the hub. This module is that consumer, and it lives in the engine so every
surface — hub, gateway, SDK, control plane — shares one contract instead of
re-implementing the security-critical parts four times.

The split matters. `ApprovalChannel` is *only* a way to reach a human: ask, and
return what they said. Everything that can go wrong on the way — no channel at
all, a channel that raises, a human who never answers, a master switch that is
off — is decided here, so a new channel cannot accidentally introduce a
fail-open path.

Every failure mode resolves to DENY. A deferred action is one policy has
already declined to allow on its own; being unable to ask about it is not a
reason to proceed.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Literal, Protocol

from .action import Action
from .policy import Decision, Verdict


class ApprovalKind(str, Enum):
    """What the human chose.

    The `*_always` variants ask the caller to persist a policy rule; the engine
    does not write policy itself, because where rules live is a property of the
    deployment (a hub workspace file, a control-plane API) rather than of the
    decision.
    """

    ALLOW = "allow"
    ALLOW_SESSION = "allow_session"  # remember until this process restarts
    ALLOW_ALWAYS = "allow_always"  # persist an allow rule, optionally scoped
    DENY = "deny"
    DENY_ALWAYS = "deny_always"  # persist a deny rule


_ALLOWING = {ApprovalKind.ALLOW, ApprovalKind.ALLOW_SESSION, ApprovalKind.ALLOW_ALWAYS}
_PERSISTENT = {ApprovalKind.ALLOW_ALWAYS, ApprovalKind.DENY_ALWAYS}


@dataclass(frozen=True)
class ApprovalRequest:
    """What a human is being asked to decide."""

    action: Action
    decision: Decision  # the DEFER that triggered this
    summary: str = ""  # human-readable one-liner
    floored: bool = False  # deferred by a floor rather than an explicit rule

    @property
    def principal(self) -> str:
        return self.action.principal.id

    @property
    def digest(self) -> str:
        """Ties the request to its audit entry — the id an approver can quote."""
        return self.action.digest(strict=False)


@dataclass(frozen=True)
class Approver:
    """Who authorised a deferred action, as the control plane attested it.

    Every field is derived from an authenticated session and covered by the
    signature on the resolution. That is the difference between this and the
    `decided_by` string beside it: a name a channel supplies is whatever that
    channel chose to say, and for a local TTY channel that is honest and
    sufficient. For anything releasing an action across a network it is not,
    because it cannot be disproved and cannot be relied on.

    `subject` is a stable IdP id (`google:117…`), not an address. Addresses get
    reassigned, and a record naming one stops resolving to a person the moment
    they leave the company — which is exactly when somebody asks.

    `authenticated_at_ms` is when that human last authenticated, not when they
    clicked. An approval made eleven hours into a session is visibly that.
    """

    subject: str
    email: str = ""
    session_id: str = ""
    authenticated_at_ms: int = 0


@dataclass(frozen=True)
class SignedResolution:
    """The proof, kept so the audit chain records it rather than the belief.

    Without this the chain says "allowed, by alice" and an auditor has only our
    word for it. With it, the entry contains the signature and the key that made
    it, so the claim can be re-verified years later against a key set — by
    somebody who does not trust us, which is the only kind of verification worth
    having.
    """

    signature: str
    key_id: str
    nonce: str
    resolved_at_ms: int
    expires_at_ms: int
    fleet_id: str


@dataclass(frozen=True)
class ApprovalResponse:
    """What a channel returns. Nothing more than the operator's raw decision."""

    kind: ApprovalKind
    decided_by: str | None = None  # responder identity, for the audit trail
    scope: dict[str, Any] | None = None  # persistence filter for *_always

    #: Set by channels that carry an attested identity — currently the control
    #: plane. A local TTY channel leaves both None, and that is not a lesser
    #: form of the same thing: nobody authenticated, and the record should not
    #: imply otherwise by carrying an empty approver object.
    approver: Approver | None = None
    attestation: SignedResolution | None = None


@dataclass
class ApprovalOutcome:
    """The resolved verdict plus everything a caller needs to act on it."""

    decision: Decision  # final ALLOW or DENY — never DEFER
    kind: ApprovalKind | None = None  # None when no human was asked
    decided_by: str | None = None
    persistent: bool = False  # caller should write a rule
    session: bool = False
    scope: dict[str, Any] | None = None
    reason: str | None = None
    elapsed_ms: float = 0.0
    approver: Approver | None = None
    attestation: SignedResolution | None = None

    @property
    def allowed(self) -> bool:
        return self.decision.verdict is Verdict.ALLOW


class ApprovalChannel(Protocol):
    """A way to reach a human.

    Implementations do one thing: ask, and return the answer. They must NOT
    implement the master switch, the session cache, or any fallback — that
    logic lives in `Approvals`, so a channel cannot introduce a fail-open path.
    A channel that cannot reach anyone should raise; `Approvals` denies.
    """

    async def ask(self, request: ApprovalRequest) -> ApprovalResponse: ...


def _resolved(
    verdict: Verdict, source: str, request: ApprovalRequest, reason: str | None = None
) -> Decision:
    """A final decision that keeps the deferring rule's identity.

    `rule_id` and `audit_level` carry over from the DEFER so an auditor can see
    which rule demanded review; `source` records how it was settled.
    """
    return Decision(
        verdict=verdict,
        rule_id=request.decision.rule_id,
        source=source,
        audit_level=request.decision.audit_level,
        reason=reason,
    )


class Approvals:
    """Resolves DEFER verdicts, failing closed on every path that isn't a human
    saying yes.

    `when_disabled` is the one place a fail-open is even expressible, and it is
    not the default. The hub's `approval.enabled: false` master switch (ADR-0018)
    means "don't prompt, run it" — a deliberate local-development affordance
    that predates this module and that its e2e matrix depends on. Any new
    deployment wanting that behaviour has to ask for it in writing.
    """

    def __init__(
        self,
        channel: ApprovalChannel | None = None,
        *,
        enabled: bool = True,
        when_disabled: Literal["deny", "allow"] = "deny",
        timeout_s: float | None = None,
        session_key: Any = None,  # callable(Action) -> str; defaults to the tool URI
    ) -> None:
        self.channel = channel
        self.enabled = enabled
        self._when_disabled = when_disabled
        self._timeout_s = timeout_s
        self._session_key = session_key or (lambda action: action.tool)
        self._session_allows: set[str] = set()

    def clear_session(self) -> None:
        self._session_allows.clear()

    async def resolve(self, request: ApprovalRequest) -> ApprovalOutcome:
        start = time.monotonic()

        def done(outcome: ApprovalOutcome) -> ApprovalOutcome:
            outcome.elapsed_ms = (time.monotonic() - start) * 1000
            return outcome

        if not self.enabled:
            allow = self._when_disabled == "allow"
            return done(
                ApprovalOutcome(
                    decision=_resolved(
                        Verdict.ALLOW if allow else Verdict.DENY,
                        "approval_disabled",
                        request,
                        None if allow else "approvals_disabled",
                    ),
                    reason=None if allow else "approvals_disabled",
                )
            )

        if self.channel is None:
            # Headless with no bridge configured. Denying is the whole point:
            # an unattended process must not become an implicit approver.
            return done(
                ApprovalOutcome(
                    decision=_resolved(
                        Verdict.DENY, "approval_unavailable", request, "no_approval_channel"
                    ),
                    reason="no_approval_channel",
                )
            )

        key = self._session_key(request.action)
        if key in self._session_allows:
            return done(
                ApprovalOutcome(
                    decision=_resolved(Verdict.ALLOW, "approval_session", request),
                    kind=ApprovalKind.ALLOW_SESSION,
                    decided_by="session",
                    session=True,
                )
            )

        try:
            if self._timeout_s is None:
                response = await self.channel.ask(request)
            else:
                response = await asyncio.wait_for(self.channel.ask(request), self._timeout_s)
        except asyncio.TimeoutError:
            # Nobody answered. Silence is not consent.
            return done(
                ApprovalOutcome(
                    decision=_resolved(
                        Verdict.DENY, "approval_timeout", request, "approval_timed_out"
                    ),
                    reason="approval_timed_out",
                )
            )
        except asyncio.CancelledError:
            raise  # shutdown, not a verdict — let it propagate
        except Exception as exc:  # noqa: BLE001 — a broken channel must not allow
            return done(
                ApprovalOutcome(
                    decision=_resolved(
                        Verdict.DENY, "approval_error", request, f"approval_channel_error: {exc}"
                    ),
                    reason="approval_channel_error",
                )
            )

        kind = response.kind
        if kind is ApprovalKind.ALLOW_SESSION:
            self._session_allows.add(key)
        allowed = kind in _ALLOWING
        return done(
            ApprovalOutcome(
                decision=_resolved(Verdict.ALLOW if allowed else Verdict.DENY, "approval", request),
                kind=kind,
                decided_by=response.decided_by,
                persistent=kind in _PERSISTENT,
                session=kind is ApprovalKind.ALLOW_SESSION,
                scope=response.scope,
                approver=response.approver,
                attestation=response.attestation,
            )
        )


@dataclass
class RecordedApproval:
    """The audit shape for a resolved deferral (audit.py writes it as `approval`).

    Recorded as its own entry rather than by rewriting the DEFER: the fact that
    review was demanded, and the fact that a named human resolved it, are two
    separate events, and an evidence log that collapses them cannot answer "who
    approved this?".
    """

    action_digest: str
    verdict: str
    source: str
    rule_id: str | None = None
    kind: str | None = None
    decided_by: str | None = None
    reason: str | None = None
    # Integer microseconds, matching the decision entry: floats are refused by
    # strict canonicalization, and how long a human took is not worth a
    # non-portable digest.
    elapsed_us: int = 0
    scope: dict[str, Any] | None = field(default=None)

    #: The attested approver and the signature over their decision, when the
    #: channel had one. Present in the chain entry rather than only in the
    #: control plane's `approvals` table, because that table is a queue and
    #: this is the evidence: it lives in the customer's environment, it is
    #: hash-chained, and it can be re-verified by somebody who does not trust
    #: whoever operates the control plane.
    approver: dict[str, Any] | None = field(default=None)
    attestation: dict[str, Any] | None = field(default=None)

    @classmethod
    def build(cls, request: ApprovalRequest, outcome: ApprovalOutcome) -> "RecordedApproval":
        return cls(
            action_digest=request.digest,
            verdict=outcome.decision.verdict.value,
            source=outcome.decision.source,
            rule_id=outcome.decision.rule_id,
            kind=outcome.kind.value if outcome.kind else None,
            decided_by=outcome.decided_by,
            reason=outcome.reason,
            elapsed_us=int(outcome.elapsed_ms * 1000),
            scope=outcome.scope,
            approver=asdict(outcome.approver) if outcome.approver else None,
            attestation=asdict(outcome.attestation) if outcome.attestation else None,
        )
