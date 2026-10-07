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


@pytest.mark.asyncio
async def test_a_hub_in_a_fleet_with_no_bundle_published_still_serves(
    hub_home, plane, keys, monkeypatch
):
    """The control plane 404s /policy/bundle until one is published. The hub's
    policy is its workspace, so that must not deny every call -- and the key
    set and revocation list (containment, console approval keys) must still
    apply."""
    from unified_enforce.distribution import NotPublished

    def not_published():
        raise NotPublished("HTTP 404 for /api/v1/policy/bundle: nothing published")

    monkeypatch.setattr(plane, "fetch_bundle", not_published)
    root, _ = keys
    hub = _joined_hub(hub_home, plane, root)
    hub.audit.start()
    try:
        report = hub.fleet.distribution.refresh(now=NOW)
        assert report.no_bundle and report.applied_revocations
        assert hub.fleet.distribution.verification_keys()
        policy = hub.fleet.status()["policy"]
        assert policy["state"] == "no_bundle_published" and policy["alarming"] is False
        hub._forward = lambda *a: asyncio.sleep(0, {"content": []})  # type: ignore[method-assign]
        assert "result" in await hub._handle_call(_message("crew-1"), "crew-1")

        plane.contain("agent:crew-1", mode="deny")
        hub.fleet.distribution.refresh(now=NOW)
        assert (await hub._handle_call(_message("crew-1", 2), "crew-1"))["error"]["code"] == -32003
    finally:
        hub.audit.stop()


def test_every_hub_request_carries_a_channel_proof(hub_home, monkeypatch):
    """With a channel key, the source, both evidence sinks and the console
    approval client sign each request (x-unified-proof) under the enrolled
    credential id; without one, the hub stays bearer-only, as joined hubs
    did before channel binding."""
    import io
    import json as _json
    import urllib.request

    from unified_enforce.attest import accept_proof, b64u
    from unified_enforce.approval import ApprovalRequest
    from unified_enforce.policy import Decision, Verdict
    from unified_enforce import Action, Principal

    from unified_mcphub import signing

    seed = signing.generate_seed()
    public = b64u(signing.signer_from_secret(seed).public_bytes())
    seen: list = []

    class Response(io.BytesIO):
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def urlopen(request, timeout):
        seen.append(request)
        path = request.full_url.split("cp.example", 1)[1]
        body = {"id": "01A", "status": "pending"} if path.endswith("approvals") else {}
        return Response(_json.dumps(body).encode())

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)

    def link(channel_seed):
        cfg = ControlPlaneConfig(
            url="https://cp.example",
            fleet_id="acme",
            root_public_key="k",
            credential_id="cred-123",
        )
        fl = FleetLink(cfg)
        channel = fl._channel(channel_seed)  # noqa: SLF001
        fl._transport.bind("uai_cred", channel)  # noqa: SLF001
        fl.approvals.bind("uai_cred", channel)
        return fl

    def exercise(fl):
        seen.clear()
        fl._transport.fetch_revocations()  # noqa: SLF001
        fl._transport.send([{"r": 1}])  # noqa: SLF001
        fl._transport.payloads.send([{"v": 1}])  # noqa: SLF001
        action = Action.build(principal=Principal(id="agent:a"), tool="t", verb="v", resource="*")
        fl.approvals._remote._queue(  # noqa: SLF001
            ApprovalRequest(action, Decision(verdict=Verdict.DEFER, rule_id=None, source="x"))
        )
        return list(seen)

    requests = exercise(link(seed))
    assert len(requests) == 4
    for request in requests:
        proof = request.get_header("X-unified-proof")
        assert proof, request.full_url
        path = request.full_url.split("cp.example", 1)[1]
        verdict = accept_proof(
            proof,
            public_key_b64=public,
            credential_id="cred-123",
            method=request.get_method(),
            path=path,
            body=request.data,
            now=int(__import__("time").time()),
        )
        assert verdict.ok, (path, verdict)

    assert all(r.get_header("X-unified-proof") is None for r in exercise(link(None)))


def test_status_counts_every_decision_row_that_did_not_reach_the_plane(hub_home, plane, keys):
    from unified_enforce import Action, Principal
    from unified_enforce.policy import Decision, Verdict

    root, _ = keys
    hub = _joined_hub(hub_home, plane, root)
    evidence = hub.fleet.evidence
    allow = Decision(verdict=Verdict.ALLOW, rule_id=None, source="exact")

    def act(principal="agent:a", tool="mcp://fs/read"):
        return Action.build(principal=Principal(id=principal), tool=tool, verb="call", resource="*")

    assert evidence.record(act(tool=""), allow) is False
    assert evidence.record(act(principal="agent:" + "p" * 300), allow) is True
    evidence.spool.stats.rejected = 3
    stats = hub.fleet.status()["evidence_stats"]
    assert stats["invalid"] == 1 and stats["truncated"] == 1 and stats["rejected"] == 3
    assert stats["queued"] == 1


# --- Hub.start wires the channel key -------------------------------------------


def _started_joined_hub(hub_home, fake_keyring, monkeypatch, *, credential_id):
    """A joined hub whose store holds a credential and a channel key, with
    every control-plane request captured instead of sent."""
    import urllib.error
    import urllib.request

    from unified_mcphub import signing
    from unified_mcphub.secrets import SecretsStore

    seen: list = []

    def urlopen(request, timeout):
        seen.append(request)
        raise urllib.error.URLError("captured, not sent")

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    _permissive(hub_home, control_plane=True)
    config = load_config()
    config.hub.secrets.access_mode = "auto"
    config.hub.control_plane.root_public_key = Key().public
    config.hub.control_plane.credential_id = credential_id
    store = SecretsStore(backend="keyring")
    seed = signing.generate_seed()
    store.set(config.hub.control_plane.credential_secret_ref, "uai_cred")
    store.set(config.hub.control_plane.channel_key_secret_ref, seed)
    hub = Hub(config)
    hub.secrets = store
    return hub, seen, signing.signer_from_secret(seed)


@pytest.mark.asyncio
async def test_hub_start_binds_the_stored_channel_key(hub_home, fake_keyring, monkeypatch):
    """The whole wiring, from the secrets store through `Hub.start` to the
    request on the wire: a start that dropped the channel seed would run
    bearer-only, and every request it made would be refused."""
    import time

    from unified_enforce.attest import accept_proof, b64u
    from unified_enforce.distribution import SourceUnavailable

    hub, seen, channel = _started_joined_hub(
        hub_home, fake_keyring, monkeypatch, credential_id="cred-123"
    )
    await hub.start()
    try:
        assert hub.fleet.channel_bound is True
        assert hub.status()["fleet"]["channel_bound"] is True
        seen.clear()
        with pytest.raises(SourceUnavailable):
            hub.fleet._transport.fetch_revocations()  # noqa: SLF001
        (request,) = seen
        verdict = accept_proof(
            request.get_header("X-unified-proof") or "",
            public_key_b64=b64u(channel.public_bytes()),
            credential_id="cred-123",
            method="GET",
            path="/api/v1/policy/revocations",
            body=None,
            now=int(time.time()),
        )
        assert verdict.ok, verdict
    finally:
        await hub.stop()


@pytest.mark.asyncio
async def test_a_channel_key_without_a_credential_id_stops_start_up(
    hub_home, fake_keyring, monkeypatch
):
    hub, _, _ = _started_joined_hub(hub_home, fake_keyring, monkeypatch, credential_id=None)
    with pytest.raises(SystemExit, match="fleet join .*--force"):
        await hub.start()
    hub.audit.stop()
