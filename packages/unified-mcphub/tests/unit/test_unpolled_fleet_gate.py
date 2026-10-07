"""A joined hub that has not polled yet -- or whose revocation list went stale
-- cannot confirm containment. That may hold back an ALLOW for a human; it
must never turn a curated DENY into an approvable prompt, and a human's
`*_always` answer to such a prompt must not become a learned rule (which
would then override the curated deny forever).

Drives `Hub._handle_call` with a stand-in `_forward`, like test_interdiction.
"""

from __future__ import annotations

import asyncio
import sys
import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest

from unified_enforce.distribution import Distribution
from unified_mcphub.approval import ChannelDecision, DecisionKind, build_arg_filter
from unified_mcphub.config import dangerous_commands_path, load_config, load_learned_rules
from unified_mcphub.hub import Hub

FAKE_SERVER = Path(__file__).parent.parent / "fixtures" / "fake_mcp_server.py"


class Unreachable:
    """A control plane the hub has never managed to reach."""

    def fetch_keyset(self):
        raise RuntimeError("unreachable")

    fetch_bundle = fetch_revocations = fetch_keyset


class Recording:
    def __init__(self, decision: ChannelDecision) -> None:
        self.decision = decision
        self.asked: list[tuple[str, dict, bool]] = []

    async def ask(self, tool_uri, caller, summary, args, floored):
        self.asked.append((tool_uri, dict(args), floored))
        return self.decision


@pytest.fixture
async def hub(hub_home):
    (hub_home / "workspaces" / "default.yaml").write_text(
        textwrap.dedent(
            f"""
            servers:
              shell:
                upstream:
                  command: {sys.executable}
                  args: ["{FAKE_SERVER}"]
            authz:
              rules:
                - tool: "mcp://shell/run"
                  effect: deny
                - tool: "mcp://shell/*"
                  effect: allow
            """
        ).strip()
        + "\n"
    )
    dangerous_commands_path().write_text('require_approval:\n  - "mcp://shell/exec:rm -rf*"\n')
    h = Hub(load_config())
    h.audit.start()

    async def forward(server_name, tool, args):
        return {"content": [{"type": "text", "text": "ran"}]}

    h._forward = forward  # type: ignore[method-assign]
    dist = Distribution(Unreachable(), fleet_id="f", root_public_key="x" * 43, require_bundle=False)
    # A joined hub's distribution, never polled (fleet.py builds it bundle-optional).
    h.fleet = SimpleNamespace(distribution=dist, evidence=None)  # type: ignore[assignment]
    h.authz = h._build_authz(h.config)
    try:
        yield h
    finally:
        h.audit.stop()


async def _call(hub: Hub, tool: str, args: dict) -> dict:
    message = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": f"shell__{tool}", "arguments": args},
    }
    return await asyncio.wait_for(hub._handle_call(message, "crew"), 5)


async def test_a_curated_deny_stays_a_deny_before_the_first_poll(hub):
    channel = Recording(ChannelDecision(DecisionKind.ALLOW_ALWAYS_COMMAND, None, "op"))
    hub.approval.channel = channel
    body = await _call(hub, "run", {"command": "rm -rf /"})
    assert body["error"]["message"] == "denied by policy (deny)"
    assert channel.asked == [], "nobody may be asked to approve a curated deny"


async def test_a_floor_stays_a_floor_before_the_first_poll(hub):
    channel = Recording(ChannelDecision(DecisionKind.DENY, None, "op"))
    hub.approval.channel = channel
    await _call(hub, "exec", {"command": "rm -rf /tmp/x"})
    assert channel.asked and channel.asked[0][2] is True, "the floor warning still shows"


@pytest.mark.parametrize(
    "decision",
    [
        ChannelDecision(
            DecisionKind.ALLOW_ALWAYS_COMMAND,
            build_arg_filter("command", "ls", prefix=False),
            "op",
        ),
        ChannelDecision(DecisionKind.DENY_ALWAYS, None, "op"),
    ],
)
async def test_an_always_answer_to_a_gate_forced_prompt_is_one_time(hub, decision):
    channel = Recording(decision)
    hub.approval.channel = channel
    rules_before = list(hub.config.workspace.authz.rules)

    body = await _call(hub, "list", {"command": "ls"})
    assert channel.asked, "the gate held the allow back for a human"
    allowed = decision.kind is DecisionKind.ALLOW_ALWAYS_COMMAND
    assert ("result" in body) is allowed

    assert hub.config.workspace.authz.rules == rules_before, "no learned rule in memory"
    assert load_learned_rules(hub.config.workspace_name) == [], "and none on disk"

    await _call(hub, "list", {"command": "ls"})
    assert len(channel.asked) == 2, "asked again: the answer covered one call"
