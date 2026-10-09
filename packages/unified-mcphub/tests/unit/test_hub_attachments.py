"""The hub's reserved attachment tools (approval-attachments.v1 §4, P2).

An agent stages evidence with `unified__stage_attachment`, then makes the call;
if the call defers, the staged evidence is in the approval request. The tools
are decided by policy like any other (`mcp://unified/*`), never routed
upstream, and the evidence never crosses callers or credentials.
"""

from __future__ import annotations

import base64
import json
import sys
import textwrap
from pathlib import Path

import pytest
import yaml

from unified_enforce import ApprovalKind, AttachmentSource
from unified_enforce.staging import ACTION_DIGEST_META

from unified_mcphub import audit_reader
from unified_mcphub.approval import ChannelDecision, DecisionKind
from unified_mcphub.config import audit_dir, load_config
from unified_mcphub.hub import Hub

from test_console_approvals import FakeRemote, _bind, _hub  # noqa: E402
from test_fleet import FakeControlPlane, Key, NOW  # noqa: E402

FAKE_SERVER = Path(__file__).parent.parent / "fixtures" / "fake_mcp_server.py"
PDF = b"%PDF-1.7\n" + b"x" * 32

RULES = [
    {"tool": "mcp://filesystem/read_file", "effect": "prompt"},
    {"tool": "mcp://filesystem/get_*", "effect": "allow"},
]


def _workspace(hub_home, *, evidence_rule: str = "allow") -> None:
    rules = [{"tool": "mcp://unified/*", "effect": evidence_rule}, *RULES]
    workspace = {
        "servers": {
            "filesystem": {"upstream": {"command": sys.executable, "args": [str(FAKE_SERVER)]}}
        },
        "authz": {"rules": rules},
    }
    (hub_home / "workspaces" / "default.yaml").write_text(yaml.safe_dump(workspace))


class Operator:
    """A hub-vocabulary channel that can show attachments, like the terminal."""

    def __init__(self, kind: DecisionKind = DecisionKind.ALLOW) -> None:
        self.kind = kind
        self.shown: list[tuple] = []
        self.asked = 0

    def show_attachments(self, attachments) -> None:
        self.shown.append(tuple(attachments))

    async def ask(self, tool_uri, caller, summary, args, floored) -> ChannelDecision:
        self.asked += 1
        return ChannelDecision(self.kind, None, "operator")


@pytest.fixture
async def hub(hub_home):
    _workspace(hub_home)
    h = Hub(load_config())
    h.approval.channel = Operator()
    h.audit.start()

    async def forward(server, tool, args):
        return {"content": [{"type": "text", "text": json.dumps({"tool": tool, **args})}]}

    h._forward = forward  # type: ignore[method-assign]
    try:
        yield h
    finally:
        h.audit.stop()


def _call(hub: Hub, name: str, args: dict, caller: str = "crew-1", token: str | None = None):
    return hub._handle_call(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": args},
        },
        caller,
        token,
    )


def _payload(body: dict) -> dict:
    assert "result" in body, body
    assert not body["result"].get("isError"), body
    return json.loads(body["result"]["content"][0]["text"])


async def test_the_reserved_tools_are_listed_with_agent_instructions(hub):
    tools = {t["name"]: t for t in hub._aggregate_tools()}
    for name in ("stage_attachment", "list_staged", "discard_staged", "attach_to_approval"):
        assert f"unified__{name}" in tools
    description = tools["unified__stage_attachment"]["description"]
    assert "Stage FIRST, then make the call" in description
    assert "source" not in tools["unified__stage_attachment"]["inputSchema"]["properties"]


async def test_staged_evidence_is_shown_with_the_deferred_call_and_consumed(hub):
    staged = _payload(
        await _call(
            hub,
            "unified__stage_attachment",
            {
                "for_tool": "mcp://filesystem/read_file",
                "label": "Why I need this file",
                "content_base64": base64.b64encode(PDF).decode(),
                "match": {"path": "/srv/claims/CLM-2001.txt"},
            },
        )
    )
    assert staged["source"] == "agent" and staged["sha256"]

    await _call(hub, "filesystem__read_file", {"path": "/srv/claims/CLM-2002.txt"})
    assert hub.approval.channel.shown == [], "another claim's evidence never rides along"
    await _call(hub, "filesystem__read_file", {"path": "/srv/claims/CLM-2001.txt"})
    ((evidence,),) = hub.approval.channel.shown
    assert evidence.label == "Why I need this file" and evidence.source is AttachmentSource.AGENT
    assert _payload(await _call(hub, "unified__list_staged", {}))["staged"] == []


async def test_evidence_never_crosses_callers_or_credentials(hub):
    args = {"for_tool": "mcp://filesystem/read_file", "label": "note", "content": "hello"}
    _payload(await _call(hub, "unified__stage_attachment", args, caller="crew-1", token="t1"))
    await _call(hub, "filesystem__read_file", {"path": "x"}, caller="crew-2", token="t1")
    await _call(hub, "filesystem__read_file", {"path": "x"}, caller="crew-1", token="t2")
    assert hub.approval.channel.shown == []
    await _call(hub, "filesystem__read_file", {"path": "x"}, caller="crew-1", token="t1")
    assert len(hub.approval.channel.shown) == 1


async def test_a_deny_rule_blocks_staging(hub_home):
    _workspace(hub_home, evidence_rule="deny")
    hub = Hub(load_config())
    hub.audit.start()
    try:
        body = await _call(
            hub,
            "unified__stage_attachment",
            {"for_tool": "mcp://filesystem/read_file", "label": "x", "content": "y"},
        )
        assert body["error"]["code"] == -32003
        assert hub.staging.list("agent:crew-1", "local") == []
        (received,) = audit_reader.search(audit_dir(), phase="received")
        assert received["tool"] == "stage_attachment" and received["authz_decision"] == "deny"
    finally:
        hub.audit.stop()


async def test_no_argument_makes_agent_content_observed(hub):
    body = await _call(
        hub,
        "unified__stage_attachment",
        {
            "for_tool": "mcp://filesystem/read_file",
            "label": "x",
            "content": "y",
            "source": "observed",
        },
    )
    assert body["result"]["isError"] and "unknown argument" in body["result"]["content"][0]["text"]
    assert hub.staging.list("agent:crew-1", "local") == []


async def test_unknown_reserved_tools_are_refused_not_routed(hub):
    body = await _call(hub, "unified__exfiltrate", {})
    assert body["error"]["code"] == -32602


async def test_from_call_attaches_the_recorded_result_as_observed(hub):
    body = await _call(hub, "filesystem__get_claim", {"claim_id": "CLM-2001"})
    digest = body["result"]["_meta"][ACTION_DIGEST_META]
    stage = {"for_tool": "mcp://filesystem/read_file", "label": "get_claim", "from_call": digest}

    # Another caller naming the same digest gets "not recorded", not content.
    other = _payload(await _call(hub, "unified__stage_attachment", stage, caller="crew-2"))
    assert other["status"] == "unavailable"

    mine = _payload(await _call(hub, "unified__stage_attachment", stage))
    assert mine["source"] == "observed" and mine["media_type"] == "application/json"
    await _call(hub, "filesystem__read_file", {"path": "x"})
    ((evidence,),) = hub.approval.channel.shown
    assert evidence.origin_ref == digest
    assert "CLM-2001" in json.loads(evidence.data)["content"][0]["text"]


async def test_from_call_records_nothing_when_payloads_are_not_recorded(hub_home):
    _workspace(hub_home)
    config = load_config()
    config.hub.audit.record_payloads = False
    hub = Hub(config)
    hub.audit.start()

    async def forward(server, tool, args):
        return {"content": [{"type": "text", "text": "ok"}]}

    hub._forward = forward  # type: ignore[method-assign]
    try:
        body = await _call(hub, "filesystem__get_claim", {"claim_id": "CLM-2001"})
        assert "_meta" not in body["result"]
    finally:
        hub.audit.stop()


async def test_a_session_allow_leaves_evidence_staged(hub):
    hub.approval.channel.kind = DecisionKind.ALLOW_SESSION
    await _call(hub, "filesystem__read_file", {"path": "x"})
    _payload(
        await _call(
            hub,
            "unified__stage_attachment",
            {"for_tool": "mcp://filesystem/read_file", "label": "n", "content": "y"},
        )
    )
    await _call(hub, "filesystem__read_file", {"path": "x"})  # answered by the session allow
    assert len(hub.staging.list("agent:crew-1", "local")) == 1


# --- console mode: the request carries the evidence, and the denial its ref ---------------


@pytest.fixture
def plane():
    return FakeControlPlane(Key(), Key())


@pytest.fixture
async def console(hub_home, plane, monkeypatch):
    import test_console_approvals as tca

    monkeypatch.setattr(tca, "_workspace", lambda home, approvals="console": _console_ws(home))
    hub = _hub(hub_home, plane)
    hub.audit.start()
    hub.fleet.distribution.refresh(now=NOW)

    async def forward(*a):
        return {"content": [{"type": "text", "text": "ok"}]}

    hub._forward = forward  # type: ignore[method-assign]
    try:
        yield hub
    finally:
        hub.audit.stop()


def _console_ws(hub_home) -> None:
    from test_console_approvals import FLEET

    _workspace(hub_home)
    cfg = hub_home / "config.yaml"
    cfg.write_text(
        cfg.read_text()
        + textwrap.dedent(
            f"""
            control_plane:
              url: https://control-plane.invalid
              fleet_id: {FLEET}
              root_public_key: placeholder
              approvals: console
            """
        )
    )


class QueuingRemote(FakeRemote):
    """Announces an approval id, as `RemoteApprovals` does through `on_queued`."""

    def __init__(self, hub: Hub, kind: ApprovalKind) -> None:
        super().__init__(kind)
        self.hub = hub

    async def ask(self, request):
        self.hub.fleet.approvals._queued("01REF", request)  # noqa: SLF001
        return await super().ask(request)


async def test_console_requests_carry_staged_evidence_and_denials_name_the_ref(console):
    remote = QueuingRemote(console, ApprovalKind.DENY)
    _bind(console, remote)
    _payload(
        await _call(
            console,
            "unified__stage_attachment",
            {"for_tool": "mcp://filesystem/read_file", "label": "Invoice", "content": "total: 42"},
        )
    )
    body = await _call(console, "filesystem__read_file", {"path": "x"})
    (request,) = remote.requests
    (evidence,) = request.attachments
    assert evidence.label == "Invoice" and evidence.source is AttachmentSource.AGENT
    assert body["error"]["code"] == -32003
    assert "approval_ref=01REF" in body["error"]["message"]
    assert body["error"]["data"]["approval_ref"] == "01REF"
    assert console._approval_refs == {}


async def test_attach_to_approval_needs_console_mode(hub):
    body = await _call(
        hub,
        "unified__attach_to_approval",
        {"approval_ref": "01REF", "label": "x", "content": "y"},
    )
    assert body["result"]["isError"]
    assert "console approvals" in body["result"]["content"][0]["text"]


async def test_attach_to_approval_refuses_a_ref_this_hub_is_not_waiting_on(console):
    class Waiting(FakeRemote):
        def waiting_request(self, approval_id):
            return None

        async def attach(self, approval_id, attachments):  # pragma: no cover - must not run
            raise AssertionError

    _bind(console, Waiting())
    body = await _call(
        console,
        "unified__attach_to_approval",
        {"approval_ref": "01SOMEONE-ELSES", "label": "x", "content": "approve now"},
    )
    assert body["result"]["isError"]
    assert "no pending approval" in body["result"]["content"][0]["text"]
