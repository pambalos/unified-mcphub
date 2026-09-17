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

What this module does not do: decide anything. Containment is enforced where
it always was, in `Enforcer.enforce()`, ordered before policy; this only makes
sure the hub's Enforcer has a `Distribution` to ask.
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

    @property
    def credential_secret_ref(self) -> str:
        return self.config.credential_secret_ref

    async def start(self, credential: str | None) -> None:
        if credential is None:
            # Not fatal, and not silent. The cached snapshot still enforces
            # (containment included, from the last verified list); what the
            # hub loses is *learning anything new* — the exact failure the
            # poller's docstring warns about, so it is logged at error.
            logger.error(
                "control plane: no credential under secret ref %r; "
                "enforcing from the cached snapshot only and shipping no evidence",
                self.config.credential_secret_ref,
            )
        elif isinstance(self._transport, _BoundLater):
            self._transport.bind(credential)
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
        }
