"""Joining a hub to a fleet — build-04 / build-07.

The engine's distribution and evidence pieces (`unified_enforce.distribution`,
`unified_enforce.evidence`) are libraries. Until this module nothing in the
hub assembled them, so a hub started with `unified-mcphub start` decided every
call from its workspace policy alone and never consulted the control plane's
revocation list. The Envoy ext_authz sidecar gated on containment; the hub did
not. "A contained agent is stopped at its next action" was therefore proven in
the integration harness and not true of the enforcement point most
deployments actually run.

`FleetLink` is the assembly: one `Distribution` (verified policy bundle +
revocation list, polled and cached), one `EvidenceShipper` over `HttpSink`,
and the credential bound at `start()` so both can exist — and the authorizer
can hold them — before the secrets store is unlocked.

`ConsoleApprovals` is the third piece a joined hub holds: the engine's
`RemoteApprovals` client, bound to the same credential at the same moment, so
a `prompt` is answered by an authenticated approver at the control plane
rather than at the hub's terminal (`control_plane.approvals: console`).

What this module does not do: decide anything. Containment is enforced where
it always was, in `Enforcer.enforce()`, ordered before policy; this only makes
sure the hub's Enforcer has a `Distribution` to ask. Likewise an approval is
resolved — and every failure denied — in `unified_enforce.Approvals`; the
channel here only asks.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from unified_enforce.distribution import (
    ControlPlaneSource,
    Distribution,
    Poller,
    SourceUnavailable,
    StaleAction,
)
from unified_enforce.evidence import EvidenceShipper, HttpSink
from unified_enforce.remote_approvals import ApprovalTransportError, RemoteApprovals

from .config import ControlPlaneConfig, mcphub_home

logger = logging.getLogger(__name__)


class _BoundLater:
    """A `Source` and a `Sink` whose credential arrives at `start()`.

    `Distribution` and `EvidenceShipper` take their transport at construction,
    but the hub's authorizer — which must hold the `Distribution` — is built
    before the secrets store is unlocked. Rather than reorder the hub's boot
    around one credential, the transport is a stand-in that refuses until
    bound. A refusal is the failure mode `Distribution.refresh` already
    handles (unreachable: keep the cached snapshot, alarm on nothing), and the
    shipper's spool holds evidence until the sink exists.
    """

    def __init__(self, cfg: ControlPlaneConfig) -> None:
        self._cfg = cfg
        self._source: ControlPlaneSource | None = None
        self._sink: HttpSink | None = None

    def bind(self, credential: str) -> None:
        assert self._cfg.url is not None
        self._source = ControlPlaneSource(self._cfg.url, credential)
        self._sink = HttpSink(self._cfg.url, credential)

    @property
    def bound(self) -> bool:
        return self._source is not None

    # Source
    def fetch_keyset(self) -> Any:
        return self._require_source().fetch_keyset()

    def fetch_bundle(self) -> Any:
        return self._require_source().fetch_bundle()

    def fetch_revocations(self) -> Any:
        return self._require_source().fetch_revocations()

    def _require_source(self) -> ControlPlaneSource:
        if self._source is None:
            raise SourceUnavailable("control plane credential not yet bound")
        return self._source

    # Sink
    def send(self, batch: list[dict[str, Any]]) -> Any:
        if self._sink is None:
            raise ConnectionError("control plane credential not yet bound")
        return self._sink.send(batch)


class ConsoleApprovals:
    """An engine `ApprovalChannel` that asks the fleet's control plane.

    A thin late-binding shell over `RemoteApprovals`, for the same reason
    `_BoundLater` exists: the hub's `Approval` is built in `Hub.__init__`, and
    the credential the client needs is read from the secrets store in
    `Hub.start`. Until `bind()`, `ask` raises — and a raising channel is a
    *deny* in `unified_enforce.Approvals` (`approval_channel_error`), so a hub
    that never obtained its credential fails closed on every prompt rather
    than quietly falling back to some other way of saying yes. It does not
    fall back to the terminal either: which approver a joined hub answers to
    is configuration, and a missing credential is not a reason to change it.

    The verification keys are the `Distribution`'s live accessor rather than a
    copy, so a decision-key rotation published in a root-signed key set is
    picked up at the next poll (see `Distribution.verification_keys`). Before
    the first key set verifies the set is empty, and every resolution is
    refused as signed by an unknown key — again a deny, never an allow.
    """

    def __init__(
        self,
        cfg: ControlPlaneConfig,
        keys: Any,
        *,
        factory: Any = RemoteApprovals,
    ) -> None:
        self._cfg = cfg
        self._keys = keys
        self._factory = factory
        self._remote: Any = None

    def bind(self, credential: str) -> None:
        assert self._cfg.url is not None and self._cfg.fleet_id is not None
        self._remote = self._factory(
            self._cfg.url,
            credential,
            fleet_id=self._cfg.fleet_id,
            keys=self._keys,
            # The client's own deadline, not an outer `wait_for`: it polls
            # with `asyncio.sleep` and checks the deadline between polls, so
            # the whole wait is one bounded loop with a single reason to end.
            deadline_seconds=self._cfg.approval_timeout_seconds,
        )

    @property
    def bound(self) -> bool:
        return self._remote is not None

    async def ask(self, request: Any) -> Any:
        if self._remote is None:
            raise ApprovalTransportError(
                "control plane credential not yet bound; console approvals unavailable"
            )
        return await self._remote.ask(request)


class FleetLink:
    """Everything a joined hub holds about its fleet. `None` for a standalone hub."""

    def __init__(
        self,
        cfg: ControlPlaneConfig,
        *,
        on_containment: Any = None,
        transport: Any = None,
    ) -> None:
        if not cfg.enabled:
            raise ValueError("FleetLink needs control_plane.url; standalone hubs hold None")
        assert cfg.fleet_id and cfg.root_public_key
        self.config = cfg
        self._transport = transport if transport is not None else _BoundLater(cfg)
        cache = Path(cfg.cache_dir) if cfg.cache_dir else mcphub_home() / "fleet-cache"
        self.distribution = Distribution(
            self._transport,
            fleet_id=cfg.fleet_id,
            root_public_key=cfg.root_public_key,
            cache_dir=cache,
            on_stale=StaleAction(cfg.on_stale),
            on_containment=on_containment,
        )
        self.evidence: EvidenceShipper | None = (
            EvidenceShipper(self._transport, interval_seconds=cfg.evidence_interval_seconds)
            if cfg.evidence
            else None
        )
        self._poller = Poller(self.distribution, interval_seconds=cfg.poll_seconds)
        #: The approval channel for `approvals: console`; None in terminal mode,
        #: where the hub keeps choosing its local channel exactly as standalone.
        self.approvals: ConsoleApprovals | None = (
            ConsoleApprovals(cfg, self.distribution.verification_keys)
            if cfg.console_approvals
            else None
        )

    @property
    def credential_secret_ref(self) -> str:
        return self.config.credential_secret_ref

    async def start(self, credential: str | None, *, signer: Any = None) -> None:
        """Bind the credential and start polling and shipping.

        `signer` is the hub's audit signer, when it has one. Attached to the
        evidence shipper *before* it starts, so no record ships unsigned from
        a hub that signs: a credential enrolled with an `evidence_key` has its
        unsigned batches refused outright, and a race here would cost the
        first batch after every restart.
        """
        if self.evidence is not None and signer is not None:
            self.evidence.signer = signer
        if credential is None:
            # Not fatal, and not silent. The cached snapshot still enforces
            # (containment included, from the last verified list); what the
            # hub loses is *learning anything new* — the exact failure the
            # poller's docstring warns about, so it is logged at error.
            logger.error(
                "control plane: no credential under secret ref %r; "
                "enforcing from the cached snapshot only and shipping no evidence%s",
                self.config.credential_secret_ref,
                "; every console approval will be denied" if self.approvals is not None else "",
            )
        else:
            if isinstance(self._transport, _BoundLater):
                self._transport.bind(credential)
            if self.approvals is not None:
                self.approvals.bind(credential)
        await self._poller.start()
        if self.evidence is not None:
            self.evidence.start()

    async def stop(self) -> None:
        await self._poller.stop()
        if self.evidence is not None:
            self.evidence.stop()

    async def wait_polled(self) -> None:
        """Block until one poll has completed. For tests and readiness probes."""
        assert self._poller.polled is not None, "start() first"
        await self._poller.polled.wait()

    def status(self) -> dict[str, Any]:
        snap = self.distribution.snapshot
        return {
            "fleet_id": self.config.fleet_id,
            "url": self.config.url,
            "policy": {"health": snap.health.value, "version": snap.version},
            "revocations": {
                "health": snap.revocations_health.value,
                "version": snap.revocations_version,
                "contained": sorted(snap.containment),
            },
            "evidence": self.evidence is not None,
            "evidence_signed": self.evidence is not None and self.evidence.signer is not None,
            "approvals": self.config.approvals,
        }
