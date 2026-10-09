"""SDK approval attachments P2 (approval-attachments.v1 §4, A2): the reserved
attachment tools for an MCP server built on `mcp_guard`, and programmatic late
attachment."""

from __future__ import annotations

import base64
from typing import Any

import pytest

from unified_enforce import ApprovalKind, ApprovalResponse, Approvals, PolicyEngine
from unified_sdk import Attachment, AttachmentSource, Denied, UnifiedAI
from unified_sdk.adapters.mcp import attachment_tools, register_attachment_tools

PDF = b"%PDF-1.7\n" + b"x" * 32

POLICY = """
version: 1
rules:
  - id: evidence-tools
    match: {tool: "mcp://unified/*", verb: call}
    effect: allow
  - id: claims-need-a-human
    match: {tool: "mcp://insurance/approve_claim", verb: call}
    effect: defer
"""

DENY_STAGING = """
version: 1
rules:
  - id: no-staging
    match: {tool: "mcp://unified/stage_attachment", verb: call}
    effect: deny
  - id: evidence-tools
    match: {tool: "mcp://unified/*", verb: call}
    effect: allow
"""


class Operator:
    def __init__(self) -> None:
        self.asked: list[Any] = []

    async def ask(self, request):
        self.asked.append(request)
        return ApprovalResponse(ApprovalKind.ALLOW, decided_by="csr")


def client(policy: str = POLICY, operator: Any = None) -> UnifiedAI:
    return UnifiedAI.local(
        PolicyEngine.from_yaml(policy),
        principal="agent:claims-1",
        approvals=Approvals(operator or Operator()),
    )


def by_name(ua: UnifiedAI, **kwargs: Any) -> dict[str, Any]:
    return {name: fn for name, fn, _ in attachment_tools(ua, **kwargs)}


async def test_staged_evidence_reaches_the_deferred_call_it_matches():
    operator = Operator()
    ua = client(operator=operator)
    tools = by_name(ua)
    staged = await tools["unified__stage_attachment"](
        for_tool="mcp://insurance/approve_claim",
        label="Plumber invoice",
        content_base64=base64.b64encode(PDF).decode(),
        match={"claim_id": "CLM-2001"},
    )
    assert staged["source"] == "agent" and staged["status"] == "staged"

    await ua.check_async(
        "mcp://insurance/approve_claim", verb="call", params={"claim_id": "CLM-2002"}
    )
    assert operator.asked[-1].attachments == (), "another claim's evidence never rides along"
    await ua.check_async(
        "mcp://insurance/approve_claim", verb="call", params={"claim_id": "CLM-2001"}
    )
    (invoice,) = operator.asked[-1].attachments
    assert invoice.label == "Plumber invoice" and invoice.source is AttachmentSource.AGENT
    assert (await tools["unified__list_staged"]())["staged"] == [], "consumed"
    ua.close()


async def test_registering_twice_does_not_attach_twice():
    operator = Operator()
    ua = client(operator=operator)
    tools = by_name(ua)
    by_name(ua)
    await tools["unified__stage_attachment"](
        for_tool="mcp://insurance/*", label="note", content="hello"
    )
    await ua.check_async("mcp://insurance/approve_claim", verb="call", params={})
    assert len(operator.asked[-1].attachments) == 1
    ua.close()


async def test_the_tools_are_decided_by_policy_first():
    ua = client(DENY_STAGING)
    tools = by_name(ua)
    with pytest.raises(Denied):
        await tools["unified__stage_attachment"](
            for_tool="mcp://insurance/approve_claim", label="x", content="y"
        )
    assert ua.staging.list("agent:claims-1", "stdio") == []
    assert (await tools["unified__list_staged"]())["staged"] == []
    ua.close()


async def test_from_call_without_a_recorder_is_unavailable_not_agent_content():
    operator = Operator()
    ua = client(operator=operator)
    tools = by_name(ua)
    out = await tools["unified__stage_attachment"](
        for_tool="mcp://insurance/approve_claim", label="get_claim", from_call="d" * 64
    )
    assert out["status"] == "unavailable"
    await ua.check_async("mcp://insurance/approve_claim", verb="call", params={})
    (entry,) = operator.asked[-1].attachments
    assert entry.unavailable == "from_call_not_recorded"
    ua.close()


async def test_register_on_fastmcp_lists_the_four_tools():
    from mcp.server.fastmcp import FastMCP

    ua = client()
    server = FastMCP("claims")
    register_attachment_tools(server, ua)
    names = {t.name for t in await server.list_tools()}
    assert names >= {
        "unified__stage_attachment",
        "unified__list_staged",
        "unified__discard_staged",
        "unified__attach_to_approval",
    }
    with pytest.raises(TypeError):
        register_attachment_tools(object(), ua)
    ua.close()


async def test_attach_to_approval_needs_console_approvals():
    ua = client()
    with pytest.raises(RuntimeError, match="console approvals"):
        await ua.attach_to_approval("01A", Attachment.text("x", label="note"))
    ua.close()


async def test_attach_to_approval_delegates_to_the_remote_channel():
    class Remote:
        def __init__(self) -> None:
            self.attached: list[tuple[str, tuple]] = []

        async def ask(self, request):  # pragma: no cover - not asked here
            raise AssertionError

        async def attach(self, approval_id, attachments):
            self.attached.append((approval_id, tuple(attachments)))
            return {"attachments": [], "attachments_digest": "d"}

    remote = Remote()
    ua = client(operator=remote)
    note = Attachment.text("revised estimate", label="Estimate")
    assert (await ua.attach_to_approval("01A", note))["attachments_digest"] == "d"
    assert remote.attached == [("01A", (note,))]
    assert note.source is AttachmentSource.APPLICATION
    ua.close()
