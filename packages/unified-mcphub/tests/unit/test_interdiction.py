"""In-flight interdiction — build-04.

The hub keeps a registry of forwards between `received` and their closing
audit entry, and can cancel them: by an operator (`/interdict`), or because
the fleet's verified revocation list changed (`Distribution.on_containment`).
A cancelled forward closes its bracket with `phase: interdicted` — a reader
can tell "the plane stopped this" from "the upstream crashed" — and whatever
the upstream returns afterwards is neither audited nor returned.

These tests drive `Hub._handle_call` directly with a stand-in `_forward` so
they need no upstream process; the e2e suite covers the socket path.
"""

from __future__ import annotations

import asyncio
import sys
import textwrap
from pathlib import Path

import pytest

from unified_mcphub import audit_reader
from unified_mcphub.config import audit_dir, load_config
from unified_mcphub.hub import Hub

FAKE_SERVER = Path(__file__).parent.parent / "fixtures" / "fake_mcp_server.py"


def _permissive(hub_home):
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


class SlowUpstream:
    """A forward that takes as long as the test says, and remembers whether
    its result was ever produced."""

    def __init__(self) -> None:
        self.release = asyncio.Event()
        self.produced = 0

    async def __call__(self, server_name: str, tool: str, args: dict):
        await self.release.wait()
        self.produced += 1
        return {"content": [{"type": "text", "text": "the secret result"}]}


@pytest.fixture
async def hub(hub_home):
    _permissive(hub_home)
    h = Hub(load_config())
    h.audit.start()
    h._loop = asyncio.get_running_loop()
    upstream = SlowUpstream()
    h._forward = upstream  # type: ignore[method-assign]
    h.upstream = upstream  # type: ignore[attr-defined]
    try:
        yield h
    finally:
        h.audit.stop()


def _call(hub: Hub, caller: str, req_id: int = 1) -> asyncio.Task:
    message = {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "tools/call",
        "params": {"name": "filesystem__read_file", "arguments": {"path": "x"}},
    }
    return asyncio.create_task(hub._handle_call(message, caller))


async def _settle() -> None:
    for _ in range(20):
        await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_a_call_in_flight_is_registered_and_then_gone(hub):
    task = _call(hub, "crew-1")
    await _settle()
    flights = hub.in_flight()
    assert len(flights) == 1
    assert flights[0]["principal"] == "agent:crew-1"
    assert flights[0]["tool"] == "mcp://filesystem/read_file"

    hub.upstream.release.set()
    body = await task
    assert "result" in body
    assert hub.in_flight() == []


@pytest.mark.asyncio
async def test_interdiction_cancels_the_call_and_closes_the_bracket_honestly(hub):
    task = _call(hub, "crew-1")
    await _settle()

    hit = hub.interdict("agent:crew-1", by="operator:alice", reason="tripwire")
    assert len(hit) == 1
    body = await task

    assert body["error"]["code"] == -32004
    assert "interdicted" in body["error"]["message"]
    assert hub.in_flight() == []

    pair = audit_reader.pair(audit_dir(), hit[0])
    assert pair["received"]["authz_decision"] == "allow"
    assert pair["completed"] is None, "never completed: the plane stopped it"
    assert pair["interdicted"]["result_status"] == "interdicted"
    assert pair["interdicted"]["interdicted_by"] == "operator:alice"
    assert pair["interdicted"]["reason"] == "tripwire"
    assert pair["interdicted"]["result"] is None
    assert audit_reader.lint(audit_dir()) == [], "an interdicted bracket is a closed bracket"


@pytest.mark.asyncio
async def test_a_late_upstream_result_never_reaches_the_caller_or_the_log(hub):
    task = _call(hub, "crew-1")
    await _settle()
    hub.interdict("agent:crew-1", by="control-plane", reason="contained (deny)")
    body = await task
    assert "error" in body

    # The upstream "finishes" after the cancellation.
    hub.upstream.release.set()
    await _settle()
    assert hub.upstream.produced == 0, "a cancelled forward does not run to completion"
    assert "the secret result" not in (audit_dir() / f"{_today()}.jsonl").read_text()
    completed = audit_reader.search(audit_dir(), phase="completed")
    assert completed == []


@pytest.mark.asyncio
async def test_interdiction_is_scoped_to_the_named_principal(hub):
    """The negative control that matters: stopping one agent must not stop another."""
    bad = _call(hub, "crew-bad", req_id=1)
    good = _call(hub, "crew-good", req_id=2)
    await _settle()
    assert len(hub.in_flight()) == 2

    hit = hub.interdict("agent:crew-bad", by="control-plane", reason="contained (defer)")
    assert len(hit) == 1
    assert (await bad)["error"]["code"] == -32004

    assert len(hub.in_flight()) == 1, "the other principal's call is untouched"
    hub.upstream.release.set()
    assert "result" in (await good)


@pytest.mark.asyncio
async def test_fleet_wide_containment_stops_every_call(hub):
    tasks = [_call(hub, f"crew-{i}", req_id=i) for i in range(3)]
    await _settle()
    hit = hub.interdict("*", by="control-plane", reason="fleet contained (deny)")
    assert len(hit) == 3
    for t in tasks:
        assert (await t)["error"]["code"] == -32004


@pytest.mark.asyncio
async def test_interdicting_a_principal_with_nothing_in_flight_is_a_noop(hub):
    assert hub.interdict("agent:nobody", by="operator:x", reason="r") == []
    assert audit_reader.search(audit_dir(), phase="interdicted") == []


@pytest.mark.asyncio
async def test_a_completed_call_is_never_written_as_interdicted(hub):
    task = _call(hub, "crew-1")
    await _settle()
    hub.upstream.release.set()
    body = await task
    assert "result" in body
    # Too late: nothing in flight, nothing to stop, nothing rewritten.
    assert hub.interdict("agent:crew-1", by="operator:x", reason="late") == []
    assert audit_reader.search(audit_dir(), phase="interdicted") == []
    assert len(audit_reader.search(audit_dir(), phase="completed")) == 1


@pytest.mark.asyncio
async def test_a_containment_announcement_from_another_thread_cancels_on_the_loop(hub):
    """`Distribution` announces on the poller's worker thread; the hub must
    hand the cancellation to its loop rather than touch tasks cross-thread."""
    task = _call(hub, "crew-1")
    await _settle()

    await asyncio.to_thread(hub._on_containment_change, frozenset({"agent:crew-1"}), frozenset())
    body = await asyncio.wait_for(task, timeout=5)
    assert body["error"]["code"] == -32004
    entries = audit_reader.search(audit_dir(), phase="interdicted")
    assert len(entries) == 1
    assert entries[0]["interdicted_by"] == "control-plane"
    assert "agent:crew-1 is contained" in entries[0]["reason"]


@pytest.mark.asyncio
async def test_a_release_does_nothing_to_a_call_in_flight(hub):
    task = _call(hub, "crew-1")
    await _settle()
    await asyncio.to_thread(hub._on_containment_change, frozenset(), frozenset({"agent:crew-1"}))
    await _settle()
    assert len(hub.in_flight()) == 1
    hub.upstream.release.set()
    assert "result" in (await task)


@pytest.mark.asyncio
async def test_a_hub_shutdown_cancellation_is_not_an_interdiction(hub):
    """Only the plane writes `interdicted`. A request task cancelled for any
    other reason (client gone, hub stopping) propagates as before and leaves
    no false containment record."""
    task = _call(hub, "crew-1")
    await _settle()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await _settle()
    assert hub.in_flight() == []
    assert audit_reader.search(audit_dir(), phase="interdicted") == []


def _today() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).date().isoformat()


@pytest.mark.asyncio
async def test_a_finished_call_still_in_the_registry_is_not_reported_interdicted(hub):
    """Between the forward finishing and `_handle_call` popping it, the entry
    is still registered. Stopping it does nothing — the result is on its way
    — so it must not be reported as stopped, or the operator's answer and
    the audit disagree."""
    from unified_mcphub.hub import InFlight

    done = asyncio.get_running_loop().create_future()
    done.set_result({"content": []})
    hub._inflight["late"] = InFlight(
        request_id="late", principal="agent:crew-1", tool_uri="t", task=done, started=0.0
    )
    try:
        assert hub.interdict("agent:crew-1", by="operator:x", reason="late") == []
        assert hub._inflight["late"].interdiction is None
    finally:
        del hub._inflight["late"]


@pytest.mark.asyncio
async def test_a_principal_released_before_the_loop_runs_does_not_abort_the_rest(hub):
    """The announcement runs on the loop some time after the refresh that
    made it; a later refresh can have replaced the snapshot by then. A
    principal no longer in it must not raise inside the callback and leave
    the principals after it uncontained."""
    from types import SimpleNamespace

    hub.fleet = SimpleNamespace(  # type: ignore[assignment]
        distribution=SimpleNamespace(snapshot=SimpleNamespace(containment={}))
    )
    t1, t2 = _call(hub, "crew-1", 1), _call(hub, "crew-2", 2)
    await _settle()
    await asyncio.to_thread(
        hub._on_containment_change,
        frozenset({"agent:crew-0", "agent:crew-1", "agent:crew-2"}),
        frozenset(),
    )
    b1, b2 = await asyncio.wait_for(asyncio.gather(t1, t2), timeout=5)
    assert b1["error"]["code"] == -32004 and b2["error"]["code"] == -32004
    assert len(audit_reader.search(audit_dir(), phase="interdicted")) == 2


def test_the_fleet_wide_sentinel_is_the_engines():
    from unified_enforce import distribution
    from unified_mcphub import hub as hub_mod

    assert hub_mod.FLEET_WIDE is distribution.FLEET_WIDE
