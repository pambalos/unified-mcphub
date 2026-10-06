"""A joined hub copying arguments and results to its fleet (payload-evidence.v1).

Through the real assembly -- `Hub._handle_call` → `AuditLog` → `AuthzResolver`
→ `FleetLink`'s shippers -- against a fake control plane that answers receipts
the way the contract says. Every shipped record is checked with
`attest.accept_payload_evidence`, the verifier the control plane runs, and
against the chain entry it names: a copy that would be refused there is a
defect here.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

from unified_enforce import attest
from unified_enforce.signing import Signer

from unified_mcphub import audit_reader
from unified_mcphub.config import ControlPlaneConfig, audit_dir, load_config
from unified_mcphub.fleet import FleetLink
from unified_mcphub.hub import Hub

sys.path.insert(0, str(Path(__file__).parent))
from test_fleet import (  # noqa: E402  (shared fake plane and hub assembly)
    FLEET,
    NOW,
    FakeControlPlane,
    Key,
    _joined_hub,
    _message,
    _permissive,
)

RESULT = {"content": [{"type": "text", "text": "rows: 3"}]}


class _PayloadEndpoint:
    def __init__(self, plane: PayloadPlane) -> None:
        self._plane = plane

    def send(self, batch):
        self._plane.payload_records.extend(batch)
        return {"accepted": len(batch), "refused": [], **self._plane.gate()}


class PayloadPlane(FakeControlPlane):
    """The fleet fake, plus the payload endpoint and the receipt's gate."""

    def __init__(self, root: Key, policy_key: Key, *, accept: bool = True) -> None:
        super().__init__(root, policy_key)
        self.accept = accept
        self.max_payload_bytes = 65_536
        self.payload_records: list[dict] = []
        self.payloads = _PayloadEndpoint(self)

    def gate(self) -> dict:
        return {
            "payloads": "accept" if self.accept else "refuse",
            "max_payload_bytes": self.max_payload_bytes if self.accept else 0,
        }

    def send(self, batch):
        return {**super().send(batch), **self.gate()}


@pytest.fixture
def keys():
    return Key(), Key()


def _hub(
    hub_home, plane: PayloadPlane, root: Key, *, extra: str = "", audit_level: str | None = None
) -> Hub:
    """`test_fleet._joined_hub`, with config lines added first.

    `extra` is YAML appended to config.yaml after the control_plane block,
    which `_permissive` writes last -- so an indented line lands inside it.
    `audit_level` is set on the workspace's one (allow-all) rule.
    """
    _permissive(hub_home, control_plane=True)
    if audit_level is not None:
        ws = hub_home / "workspaces" / "default.yaml"
        ws.write_text(
            ws.read_text().replace(
                "effect: allow\n", f"effect: allow\n      audit_level: {audit_level}\n"
            )
        )
    cfg = hub_home / "config.yaml"
    cfg.write_text(cfg.read_text() + extra)
    config = load_config()
    config.hub.control_plane.root_public_key = root.public
    config.hub.control_plane.fleet_id = FLEET
    original = FleetLink.__init__

    def patched(self, cfg, *, on_containment=None, transport=None):
        original(self, cfg, on_containment=on_containment, transport=plane)

    FleetLink.__init__ = patched  # type: ignore[method-assign]
    try:
        return Hub(config)
    finally:
        FleetLink.__init__ = original  # type: ignore[method-assign]


async def _call(
    hub: Hub, caller: str = "crew-1", req_id: int = 1, arguments: dict | None = None
) -> dict:
    async def forward(*a):
        return RESULT

    hub._forward = forward  # type: ignore[method-assign]
    message = _message(caller, req_id)
    if arguments is not None:
        message["params"]["arguments"] = arguments
    return await hub._handle_call(message, caller)


def _ship(hub: Hub) -> None:
    assert hub.fleet is not None and hub.fleet.evidence is not None
    hub.fleet.evidence.flush()  # decisions; the receipt opens (or shuts) the gate
    if hub.fleet.payloads is not None:
        hub.fleet.payloads.flush()


# --- shipped, and provably the chain's -----------------------------------------


@pytest.mark.asyncio
async def test_args_and_result_ship_bound_to_their_entries(hub_home, keys):
    root, policy_key = keys
    plane = PayloadPlane(root, policy_key)
    hub = _hub(hub_home, plane, root)
    signer = Signer.generate("hub")
    public = attest.b64u(signer.public_bytes())
    hub.audit.start()
    try:
        assert hub.fleet is not None and hub.fleet.evidence is not None
        hub.fleet.evidence.signer = signer
        hub.fleet.distribution.refresh(now=NOW)

        body = await _call(hub)
        assert "result" in body
        _ship(hub)

        (received,) = audit_reader.search(audit_dir(), phase="received")
        (completed,) = audit_reader.search(audit_dir(), phase="completed")
        by_path = {r["path"]: r for r in plane.payload_records}
        assert set(by_path) == {"args", "result"}

        for record, written, path in (
            (by_path["args"], received, "args"),
            (by_path["result"], completed, "result"),
        ):
            assert attest.accept_payload_evidence(record, public), path
            assert record["chain_seq"] == written["seq"]
            assert record["chain_hash"] == written["hash"]
            assert record["digest"] == written["detached"][path]
            assert record["value"] == written[path]
            # Both halves of the call are attached to the same action, the one
            # the decision row carries -- the completed line has no digest of
            # its own.
            assert record["action_digest"] == received["action_digest"]

        assert by_path["args"]["value"] == {"path": "x"}
        assert "rows: 3" in str(by_path["result"]["value"])  # as the hub recorded it
        (decision,) = plane.evidence
        assert decision["action_digest"] == received["action_digest"]
        assert "rows: 3" not in str(plane.evidence), "decision rows stay metadata"
        assert audit_reader.lint(audit_dir()) == []
    finally:
        hub.audit.stop()


@pytest.mark.asyncio
async def test_a_denied_call_ships_its_args_and_no_result(hub_home, keys):
    """What an agent *tried* is what a reviewer of a denial needs."""
    root, policy_key = keys
    plane = PayloadPlane(root, policy_key)
    plane.contain("agent:crew-1", mode="deny")
    hub = _hub(hub_home, plane, root)
    hub.audit.start()
    try:
        assert hub.fleet is not None and hub.fleet.evidence is not None
        hub.fleet.evidence.signer = Signer.generate("hub")
        hub.fleet.distribution.refresh(now=NOW)

        body = await _call(hub)
        assert body["error"]["code"] == -32003
        _ship(hub)

        assert [r["path"] for r in plane.payload_records] == ["args"]
    finally:
        hub.audit.stop()


# --- not shipped ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_control_plane_that_refuses_gets_nothing(hub_home, keys):
    root, policy_key = keys
    plane = PayloadPlane(root, policy_key, accept=False)
    hub = _hub(hub_home, plane, root)
    hub.audit.start()
    try:
        assert hub.fleet is not None and hub.fleet.evidence is not None
        hub.fleet.evidence.signer = Signer.generate("hub")
        hub.fleet.distribution.refresh(now=NOW)

        await _call(hub)
        _ship(hub)

        assert plane.evidence, "decisions still ship"
        assert plane.payload_records == []
        assert hub.fleet.status()["payloads"]["mode"] == "refuse"
        assert hub.fleet.status()["payloads"]["declined"] == 2
    finally:
        hub.audit.stop()


@pytest.mark.asyncio
async def test_payloads_off_is_a_local_veto(hub_home, keys):
    """Whatever the control plane says. Written as an operator would write it:
    a bare YAML `off`, which YAML reads as false."""
    root, policy_key = keys
    plane = PayloadPlane(root, policy_key)
    hub = _hub(hub_home, plane, root, extra="  payloads: off\n")
    hub.audit.start()
    try:
        assert hub.fleet is not None and hub.fleet.evidence is not None
        assert hub.fleet.config.payloads == "off"
        assert hub.fleet.payloads is None, "no stream exists that could send"
        hub.fleet.evidence.signer = Signer.generate("hub")
        hub.fleet.distribution.refresh(now=NOW)

        await _call(hub)
        _ship(hub)

        assert plane.evidence and plane.payload_records == []
        assert hub.fleet.status()["payloads"] == {"configured": "off", "mode": "off"}
    finally:
        hub.audit.stop()


@pytest.mark.asyncio
async def test_an_unsigned_hub_ships_no_payloads(hub_home, keys):
    root, policy_key = keys
    plane = PayloadPlane(root, policy_key)
    hub = _hub(hub_home, plane, root)
    hub.audit.start()
    try:
        assert hub.fleet is not None
        hub.fleet.distribution.refresh(now=NOW)

        await _call(hub)
        _ship(hub)

        assert plane.evidence and plane.payload_records == []
        assert hub.fleet.status()["payloads"]["unsigned"] == 2
    finally:
        hub.audit.stop()


@pytest.mark.asyncio
async def test_record_payloads_off_ships_nothing(hub_home, keys):
    """The chain kept digests, not values; there is nothing to copy."""
    root, policy_key = keys
    plane = PayloadPlane(root, policy_key)
    hub = _hub(hub_home, plane, root, extra="audit:\n  record_payloads: false\n")
    hub.audit.start()
    try:
        assert hub.config.hub.audit.record_payloads is False
        assert hub.fleet is not None and hub.fleet.evidence is not None
        hub.fleet.evidence.signer = Signer.generate("hub")
        hub.fleet.distribution.refresh(now=NOW)

        await _call(hub)
        _ship(hub)

        assert plane.evidence and plane.payload_records == []
        assert hub.fleet.status()["payloads"]["unrecorded"] == 2
    finally:
        hub.audit.stop()


@pytest.mark.asyncio
async def test_an_interdicted_call_ships_no_result(hub_home, keys):
    root, policy_key = keys
    plane = PayloadPlane(root, policy_key)
    hub = _hub(hub_home, plane, root)
    hub.audit.start()
    hub._loop = asyncio.get_running_loop()
    release = asyncio.Event()

    async def slow(*a):
        await release.wait()
        return RESULT

    hub._forward = slow  # type: ignore[method-assign]
    try:
        assert hub.fleet is not None and hub.fleet.evidence is not None
        hub.fleet.evidence.signer = Signer.generate("hub")
        hub.fleet.distribution.refresh(now=NOW)
        task = asyncio.create_task(hub._handle_call(_message("crew-1"), "crew-1"))
        for _ in range(20):
            await asyncio.sleep(0)

        plane.contain("agent:crew-1", mode="defer")
        await asyncio.to_thread(hub.fleet.distribution.refresh, now=NOW)
        body = await asyncio.wait_for(task, timeout=5)
        assert body["error"]["code"] == -32004
        release.set()
        _ship(hub)

        assert [r["path"] for r in plane.payload_records] == ["args"]
    finally:
        hub.audit.stop()


# --- config -----------------------------------------------------------------------


def test_payloads_defaults_to_auto_and_is_validated():
    cfg = ControlPlaneConfig(url="https://cp.example", fleet_id="a", root_public_key="k")
    assert cfg.payloads == "auto" and cfg.ship_payloads
    assert not ControlPlaneConfig(
        url="https://cp.example", fleet_id="a", root_public_key="k", evidence=False
    ).ship_payloads
    with pytest.raises(ValueError, match="payloads"):
        ControlPlaneConfig(
            url="https://cp.example", fleet_id="a", root_public_key="k", payloads="always"
        )


def test_a_transport_without_a_payload_endpoint_builds_no_stream(hub_home, keys):
    """An older fake (or custom transport) is still a valid fleet transport."""
    root, policy_key = keys
    hub = _joined_hub(hub_home, FakeControlPlane(root, policy_key), root)
    assert hub.fleet is not None and hub.fleet.payloads is None
    assert hub.fleet.evidence is not None and hub.fleet.evidence.payloads is None


def test_the_real_transport_carries_a_payload_sink(hub_home):
    _permissive(hub_home, control_plane=True)
    config = load_config()
    link = FleetLink(config.hub.control_plane)
    assert link.payloads is not None
    assert link.evidence is not None and link.evidence.payloads is link.payloads


# --- the decision row and its payloads agree --------------------------------------


@pytest.mark.asyncio
async def test_a_float_argument_ships_its_row_and_payloads_under_one_digest(hub_home, keys):
    """The hub records `action.digest(strict=False)`, because MCP arguments may
    hold floats. The decision summary used the strict digest, which raises on
    a float: the row was silently lost, and the payloads -- offered anyway --
    pointed at an action digest no row carried."""
    root, policy_key = keys
    plane = PayloadPlane(root, policy_key)
    hub = _hub(hub_home, plane, root)
    signer = Signer.generate("hub")
    public = attest.b64u(signer.public_bytes())
    hub.audit.start()
    try:
        assert hub.fleet is not None and hub.fleet.evidence is not None
        hub.fleet.evidence.signer = signer
        hub.fleet.distribution.refresh(now=NOW)

        body = await _call(hub, arguments={"path": "x", "temp": 0.7})
        assert "result" in body
        _ship(hub)

        (received,) = audit_reader.search(audit_dir(), phase="received")
        (decision,) = plane.evidence
        assert decision["action_digest"] == received["action_digest"]
        assert decision["chain_hash"] == received["hash"]
        assert {r["path"] for r in plane.payload_records} == {"args", "result"}
        for record in plane.payload_records:
            assert record["action_digest"] == decision["action_digest"]
            assert attest.accept_payload_evidence(record, public)
        (args,) = [r for r in plane.payload_records if r["path"] == "args"]
        assert args["value"] == {"path": "x", "temp": 0.7}
    finally:
        hub.audit.stop()


@pytest.mark.asyncio
async def test_a_decision_that_fails_to_record_ships_no_payloads(hub_home, keys, monkeypatch):
    import unified_enforce.evidence as evidence_mod

    def broken(*a, **k):
        raise RuntimeError("summary bug")

    root, policy_key = keys
    plane = PayloadPlane(root, policy_key)
    hub = _hub(hub_home, plane, root)
    hub.audit.start()
    try:
        assert hub.fleet is not None and hub.fleet.evidence is not None
        hub.fleet.evidence.signer = Signer.generate("hub")
        hub.fleet.distribution.refresh(now=NOW)
        monkeypatch.setattr(evidence_mod, "summarise", broken)

        body = await _call(hub)
        assert "result" in body, "the call is unaffected"
        hub.fleet.evidence.submit({"probe": 1})  # a receipt to open the gate
        _ship(hub)

        assert hub.fleet.payloads is not None and hub.fleet.payloads.accepting
        assert plane.payload_records == [], "payloads for a row that never left"
    finally:
        hub.audit.stop()


@pytest.mark.asyncio
async def test_a_minimal_rule_ships_no_payloads(hub_home, keys):
    """`audit_level: minimal` marks the traffic sensitive. The chain still
    records it raw; no copy leaves. The decision row (metadata) still ships."""
    root, policy_key = keys
    plane = PayloadPlane(root, policy_key)
    hub = _hub(hub_home, plane, root, audit_level="minimal")
    hub.audit.start()
    try:
        assert hub.fleet is not None and hub.fleet.evidence is not None
        hub.fleet.evidence.signer = Signer.generate("hub")
        hub.fleet.distribution.refresh(now=NOW)

        body = await _call(hub)
        assert "result" in body
        _ship(hub)

        assert len(plane.evidence) == 1
        assert plane.payload_records == []
        (received,) = audit_reader.search(audit_dir(), phase="received")
        assert received["audit_level"] == "minimal"
    finally:
        hub.audit.stop()


@pytest.mark.asyncio
async def test_a_payload_shipper_that_raises_cannot_fail_a_call(hub_home, keys):
    root, policy_key = keys
    plane = PayloadPlane(root, policy_key)
    hub = _hub(hub_home, plane, root)

    class Hostile:
        on_receipt = None

        def record(self, *a, **k):
            return True

        def record_payload(self, *a, **k):
            raise RuntimeError("custom shipper bug")

    hub.authz._evidence = Hostile()  # noqa: SLF001
    hub.audit.start()
    try:
        assert hub.fleet is not None
        hub.fleet.distribution.refresh(now=NOW)
        body = await _call(hub)
        assert "result" in body and "rows: 3" in str(body["result"])
    finally:
        hub.audit.stop()


# --- https only ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "url,built",
    [
        ("https://cp.example", True),
        ("http://cp.example", False),
        ("http://127.0.0.1:8443", True),
        ("http://localhost:8443", True),
    ],
)
def test_payloads_need_an_https_control_plane(keys, url, built, caplog):
    root, policy_key = keys
    cfg = ControlPlaneConfig(url=url, fleet_id=FLEET, root_public_key=root.public)
    with caplog.at_level("WARNING", logger="unified_mcphub.fleet"):
        link = FleetLink(cfg, transport=PayloadPlane(root, policy_key))

    assert (link.payloads is not None) is built
    if not built:
        assert link.status()["payloads"]["reason"] == "insecure_transport"
        assert sum("not https" in r.message for r in caplog.records) == 1


def test_the_real_transport_has_no_payload_sink_over_http():
    from unified_mcphub.fleet import _BoundLater

    cfg = ControlPlaneConfig(url="http://cp.example", fleet_id="a", root_public_key="k")
    transport = _BoundLater(cfg)
    transport.bind("uai_test")
    with pytest.raises(ConnectionError):
        transport.payloads.send([{"value": "secret"}])
