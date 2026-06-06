"""Unit tests for the approval control plane — UAI-107 / UAI-109.

Covers the security-critical first-responder-wins / single-use `pending_id`
contract, the fail-closed paths (timeout, shutdown), event emission, and the
end-to-end flow through `Approval` with a `ControlApiChannel`.
"""

from __future__ import annotations

import asyncio

import pytest

from unified_mcphub.approval import Approval, DecisionKind
from unified_mcphub.control import ControlApiChannel, PendingRegistry

SHELL = "mcp://shell/execute_command"
ARGS = {"command": "git status"}


async def _wait_registered(reg: PendingRegistry) -> str:
    """Yield until the pending task has registered, then return its id."""
    for _ in range(100):
        await asyncio.sleep(0)
        pending = reg.list_pending()
        if pending:
            return pending[0].pending_id
    raise AssertionError("nothing registered")


# --- first-responder-wins / single-use pending_id -----------------------------


@pytest.mark.asyncio
async def test_first_responder_wins_and_late_submit_is_already_resolved():
    events: list[tuple[str, dict]] = []
    reg = PendingRegistry(publish=lambda e, d: events.append((e, d)))
    ch = ControlApiChannel(reg, timeout_s=5)

    task = asyncio.create_task(ch.ask(SHELL, "caller", "summary", ARGS, False))
    pid = await _wait_registered(reg)

    # First decision wins.
    assert reg.submit(pid, DecisionKind.ALLOW, decided_by="discord") == "accepted"
    # A second decision (TUI, duplicate, late reaction) loses — anti-replay.
    assert reg.submit(pid, DecisionKind.DENY, decided_by="tui") == "already_resolved"

    decision = await task
    assert decision.kind is DecisionKind.ALLOW
    assert decision.args_filter is None
    assert decision.decided_by == "discord"
    assert reg.list_pending() == []
    assert [name for name, _ in events] == ["pending.created", "pending.resolved"]
    assert events[1][1] == {"pending_id": pid, "kind": "allow", "decided_by": "discord"}


def test_submit_unknown_pending_is_already_resolved():
    reg = PendingRegistry()
    assert reg.submit("ulid-that-never-existed", DecisionKind.ALLOW, decided_by="x") == (
        "already_resolved"
    )


# --- scoped allow-always carries the args_filter back through Approval ---------


@pytest.mark.asyncio
async def test_approval_with_control_channel_scoped_allow_always():
    reg = PendingRegistry()
    appr = Approval(enabled=True, channel=ControlApiChannel(reg, timeout_s=5))

    task = asyncio.create_task(appr.resolve(SHELL, "caller", "summary", ARGS))
    pid = await _wait_registered(reg)
    args_filter = {"command": {"equals": ["git status"]}}
    assert (
        reg.submit(
            pid, DecisionKind.ALLOW_ALWAYS_COMMAND, decided_by="tui", args_filter=args_filter
        )
        == "accepted"
    )

    outcome = await task
    assert outcome.allowed and outcome.persistent
    assert outcome.args_filter == args_filter
    assert outcome.authz_decision == "prompt_allowed"


@pytest.mark.asyncio
async def test_approval_with_control_channel_deny():
    reg = PendingRegistry()
    appr = Approval(enabled=True, channel=ControlApiChannel(reg, timeout_s=5))

    task = asyncio.create_task(appr.resolve(SHELL, "caller", "summary", ARGS))
    pid = await _wait_registered(reg)
    reg.submit(pid, DecisionKind.DENY, decided_by="discord")

    outcome = await task
    assert not outcome.allowed
    assert outcome.authz_decision == "prompt_denied"


# --- fail-closed paths --------------------------------------------------------


@pytest.mark.asyncio
async def test_timeout_fails_closed_to_deny():
    events: list[tuple[str, dict]] = []
    reg = PendingRegistry(publish=lambda e, d: events.append((e, d)))
    ch = ControlApiChannel(reg, timeout_s=0.01)

    decision = await ch.ask(SHELL, "caller", "summary", ARGS, False)
    assert decision.kind is DecisionKind.DENY and decision.args_filter is None
    assert decision.decided_by == "timeout"
    assert reg.list_pending() == []
    # subscribers see the pending get retracted
    assert events[-1][0] == "pending.resolved"
    assert events[-1][1]["decided_by"] == "timeout"


@pytest.mark.asyncio
async def test_shutdown_denies_outstanding_pending():
    reg = PendingRegistry()
    ch = ControlApiChannel(reg, timeout_s=30)

    task = asyncio.create_task(ch.ask(SHELL, "caller", "summary", ARGS, False))
    await _wait_registered(reg)
    reg.shutdown()

    decision = await task
    assert decision.kind is DecisionKind.DENY
    assert decision.decided_by == "system"
    assert reg.list_pending() == []
