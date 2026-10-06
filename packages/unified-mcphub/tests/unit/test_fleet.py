"""A hub joined to a fleet — build-04 / build-07.

Standalone, the hub decides from its workspace policy alone (unchanged).
Joined, its Enforcer gates on the fleet's verified revocation list *before*
policy, and a containment that arrives while a call is in flight cancels it.
The fake control plane here serves the same signed artifacts the engine's own
distribution tests use, so what is verified is the hub's assembly, not the
signature code.
"""

from __future__ import annotations

import asyncio
import sys
import textwrap
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from unified_mcphub import audit_reader
from unified_mcphub.config import ControlPlaneConfig, audit_dir, load_config
from unified_mcphub.fleet import FleetLink
from unified_mcphub.hub import Hub

sys.path.insert(0, str(Path(__file__).parents[3] / "unified-enforce" / "tests"))
from test_distribution import (  # noqa: E402  (the engine's signed-fixture builders)
    Key,
    bundle,
    keyset,
    revocations,
)

FAKE_SERVER = Path(__file__).parent.parent / "fixtures" / "fake_mcp_server.py"
FLEET = "acme"
NOW = datetime.now(UTC)


class FakeControlPlane:
    """Serves signed artifacts and remembers the evidence it receives."""

    def __init__(self, root: Key, policy_key: Key) -> None:
        self.root = root
        self.policy_key = policy_key
        self.keyset_doc = keyset(root, policy_key, now=NOW)
        self.bundle_doc = bundle(policy_key, now=NOW)
        self.version = 1
        self.revocations_doc = revocations(policy_key, version=1, now=NOW)
        self.evidence: list[dict] = []

    def contain(self, principal: str, mode: str = "defer") -> None:
        self.version += 1
        self.revocations_doc = revocations(
            self.policy_key,
            version=self.version,
            entries=[{"principal_id": principal, "mode": mode, "allow": []}],
            now=NOW,
            ttl=timedelta(minutes=15),
        )

    def fetch_keyset(self):
        return self.keyset_doc

    def fetch_bundle(self):
        return self.bundle_doc

    def fetch_revocations(self):
        return self.revocations_doc

    def send(self, batch):
        self.evidence.extend(batch)
        return {"accepted": len(batch), "revocations_version": self.version}


def _permissive(hub_home, control_plane: bool):
    (hub_home / "workspaces" / "default.yaml").write_text(
        textwrap.dedent(
            f"""
            servers:
              filesystem:
                upstream:
                  command: {sys.executable}
                  args: ["{FAKE_SERVER}"]
            authz:
              rules:
                - tool: "mcp://*/*"
                  effect: allow
            """
        ).strip()
        + "\n"
    )
    if control_plane:
        cfg = hub_home / "config.yaml"
        cfg.write_text(
            cfg.read_text()
            + textwrap.dedent(
                """
                control_plane:
                  url: https://control-plane.invalid
                  fleet_id: acme
                  root_public_key: placeholder
                  poll_seconds: 0.05
                  evidence_interval_seconds: 0.05
                """
            )
        )


@pytest.fixture
def keys():
    root, policy_key = Key(), Key()
    return root, policy_key


@pytest.fixture
def plane(keys):
    return FakeControlPlane(*keys)


def _joined_hub(hub_home, plane: FakeControlPlane, root: Key) -> Hub:
    _permissive(hub_home, control_plane=True)
    config = load_config()
    config.hub.control_plane.root_public_key = root.public
    config.hub.control_plane.fleet_id = FLEET
    hub = Hub.__new__(Hub)
    # Build with the fake transport in place of the HTTP one: the assembly
    # under test is FleetLink → Distribution → Enforcer → hub, not urllib.
    original = FleetLink.__init__

    def patched(self, cfg, *, on_containment=None, transport=None):
        original(self, cfg, on_containment=on_containment, transport=plane)

    FleetLink.__init__ = patched  # type: ignore[method-assign]
    try:
        Hub.__init__(hub, config)
    finally:
        FleetLink.__init__ = original  # type: ignore[method-assign]
    return hub


def _message(caller: str, req_id: int = 1) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "tools/call",
        "params": {"name": "filesystem__read_file", "arguments": {"path": "x"}},
    }


async def _settle() -> None:
    for _ in range(20):
        await asyncio.sleep(0)


# --- config --------------------------------------------------------------------


def test_the_block_is_off_unless_a_url_is_given():
    assert not ControlPlaneConfig().enabled


def test_a_url_without_the_pinned_root_key_is_refused():
    with pytest.raises(ValueError, match="root_public_key"):
        ControlPlaneConfig(url="https://cp.example", fleet_id="acme")


def test_on_stale_is_validated():
    with pytest.raises(ValueError, match="on_stale"):
        ControlPlaneConfig(
            url="https://cp.example", fleet_id="a", root_public_key="k", on_stale="allow"
        )


def test_the_evidence_interval_is_validated_like_the_poll():
    """Zero is a shipping thread spinning at full tilt against the control
    plane for the life of the hub; a typo is refused at load."""
    for bad in (0, -5):
        with pytest.raises(ValueError, match="evidence_interval_seconds"):
            ControlPlaneConfig(
                url="https://cp.example",
                fleet_id="a",
                root_public_key="k",
                evidence_interval_seconds=bad,
            )
    with pytest.raises(ValueError, match="poll_seconds"):
        ControlPlaneConfig(
            url="https://cp.example", fleet_id="a", root_public_key="k", poll_seconds=0
        )


def test_a_standalone_hub_has_no_fleet(hub_home):
    _permissive(hub_home, control_plane=False)
    hub = Hub(load_config())
    assert hub.fleet is None
    assert hub.status()["fleet"] is None
    assert "control-plane-credential" not in hub._required_secret_refs()


def test_a_joined_hub_reads_its_credential_from_the_secrets_store(hub_home, plane, keys):
    root, _ = keys
    hub = _joined_hub(hub_home, plane, root)
    assert hub.fleet is not None
    assert "control-plane-credential" in hub._required_secret_refs()


# --- gating --------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_contained_principal_is_stopped_before_workspace_policy(hub_home, plane, keys):
    """The workspace allows everything; the fleet says this agent is contained.
    Containment wins, in the Enforcer, without the hub's policy being asked."""
    root, _ = keys
    plane.contain("agent:crew-1", mode="deny")
    hub = _joined_hub(hub_home, plane, root)
    hub.audit.start()
    try:
        hub.fleet.distribution.refresh(now=NOW)
        forwarded = []

        async def forward(*a):
            forwarded.append(a)
            return {"content": []}

        hub._forward = forward  # type: ignore[method-assign]

        denied = await hub._handle_call(_message("crew-1"), "crew-1")
        assert denied["error"]["code"] == -32003
        assert forwarded == [], "a contained agent's call never reaches the upstream"

        allowed = await hub._handle_call(_message("crew-2", 2), "crew-2")
        assert "result" in allowed

        received = audit_reader.search(audit_dir(), phase="received")
        by_caller = {e["caller_id"]: e["authz_decision"] for e in received}
        assert by_caller == {"crew-1": "deny", "crew-2": "allow"}
    finally:
        hub.audit.stop()


@pytest.mark.asyncio
async def test_a_hub_with_no_verified_policy_denies_until_it_has_one(hub_home, plane, keys):
    """Joined but never fetched: deny, not allow. An unprotected hub is what an
    attacker who can block one fetch would otherwise get."""
    root, _ = keys
    hub = _joined_hub(hub_home, plane, root)
    hub.audit.start()
    try:
        body = await hub._handle_call(_message("crew-1"), "crew-1")
        assert body["error"]["code"] == -32003
    finally:
        hub.audit.stop()


# --- in flight -----------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_containment_that_lands_mid_call_cancels_it(hub_home, plane, keys):
    """The whole build-04 loop through the hub: a call is in flight, the fleet's
    verified list changes, the hub cancels the call, the bracket closes as
    `interdicted`, and the principal's next call is stopped before policy."""
    root, _ = keys
    hub = _joined_hub(hub_home, plane, root)
    hub.audit.start()
    hub._loop = asyncio.get_running_loop()
    release = asyncio.Event()

    async def slow(*a):
        await release.wait()
        return {"content": [{"type": "text", "text": "late"}]}

    hub._forward = slow  # type: ignore[method-assign]
    try:
        hub.fleet.distribution.refresh(now=NOW)
        task = asyncio.create_task(hub._handle_call(_message("crew-1"), "crew-1"))
        await _settle()
        assert len(hub.in_flight()) == 1

        # The control plane contains the agent; the next poll (on its worker
        # thread, as in production) verifies the new list and announces it.
        plane.contain("agent:crew-1", mode="defer")
        await asyncio.to_thread(hub.fleet.distribution.refresh, now=NOW)

        body = await asyncio.wait_for(task, timeout=5)
        assert body["error"]["code"] == -32004
        entry = audit_reader.search(audit_dir(), phase="interdicted")[0]
        assert entry["interdicted_by"] == "control-plane"
        assert entry["reason"] == "agent:crew-1 is contained (defer)"

        # And the next action: DEFER, decided before policy, no forward.
        release.set()
        nxt = await hub._handle_call(_message("crew-1", 2), "crew-1")
        assert nxt["error"]["code"] == -32003
        assert nxt["error"]["message"].startswith("denied by policy (")
        assert audit_reader.lint(audit_dir()) == []
    finally:
        hub.audit.stop()


@pytest.mark.asyncio
async def test_the_receipt_path_contains_before_the_next_poll(hub_home, plane, keys):
    """Piece 2 through the hub: evidence ships, the receipt says the list
    moved, the hub refreshes at once — no poll needed — and cancels."""
    root, _ = keys
    hub = _joined_hub(hub_home, plane, root)
    hub.audit.start()
    hub._loop = asyncio.get_running_loop()
    release = asyncio.Event()

    async def slow(*a):
        await release.wait()
        return {"content": []}

    hub._forward = slow  # type: ignore[method-assign]
    try:
        hub.fleet.distribution.refresh(now=NOW)
        task = asyncio.create_task(hub._handle_call(_message("crew-1"), "crew-1"))
        await _settle()

        # The Guardian, reading the evidence for that call, contains the agent
        # and says so in the receipt.
        plane.contain("agent:crew-1", mode="defer")
        assert hub.fleet.evidence is not None
        await asyncio.to_thread(hub.fleet.evidence.flush)
        assert plane.evidence, "the decision was shipped"

        body = await asyncio.wait_for(task, timeout=5)
        assert body["error"]["code"] == -32004
        assert hub.fleet.distribution.snapshot.revocations_version == plane.version
    finally:
        hub.audit.stop()


@pytest.mark.asyncio
async def test_a_reload_cannot_leave_the_fleet(hub_home, plane, keys):
    """Editing `control_plane` out of config.yaml and reloading must not drop
    containment: joining or leaving a fleet takes a restart, like `locked`."""
    root, _ = keys
    hub = _joined_hub(hub_home, plane, root)
    cfg = hub_home / "config.yaml"
    text = cfg.read_text()
    cfg.write_text(text[: text.index("control_plane:")])
    fleet_before = hub.fleet
    assert await hub._reload() is True
    assert hub.fleet is fleet_before
    assert hub.authz._enforcer._distribution is fleet_before.distribution  # noqa: SLF001
