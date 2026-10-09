"""SDK approval attachments (approval-attachments.v1 §3): call site, decorator,
registered providers, adapters -- and laziness on every one of them."""

from __future__ import annotations

from typing import Any

import pytest

from unified_enforce import ApprovalKind, ApprovalResponse, Approvals, PolicyEngine
from unified_sdk import Attachment, AttachmentSource, ToolGuard, UnifiedAI
from unified_sdk.adapters.mcp import GuardedSession, mcp_guard

POLICY = """
version: 1
rules:
  - id: lookups-ok
    match: {tool: "mcp://insurance/get_claim", verb: call}
    effect: allow
  - id: claims-need-a-human
    match: {tool: "mcp://insurance/approve_claim", verb: call}
    effect: defer
"""


class Operator:
    def __init__(self) -> None:
        self.asked: list[Any] = []

    async def ask(self, request):
        self.asked.append(request)
        return ApprovalResponse(ApprovalKind.ALLOW, decided_by="csr")


@pytest.fixture
def operator() -> Operator:
    return Operator()


@pytest.fixture
def ua(operator):
    client = UnifiedAI.local(
        PolicyEngine.from_yaml(POLICY), principal="agent:claims-1", approvals=Approvals(operator)
    )
    yield client
    client.close()


def invoice(claim_id: str) -> Attachment:
    return Attachment.bytes(b"%PDF-1.7 " + claim_id.encode(), "application/pdf", "Invoice")


async def test_call_site_callable_receives_the_action_and_providers_follow(ua, operator):
    @ua.attachments_for("mcp://insurance/*")
    def adjuster_report(action):
        return [Attachment.json({"claim": action.params["claim_id"]}, label="Adjuster report")]

    @ua.attachments_for("mcp://bank/*")
    def unrelated(action):  # pragma: no cover - must not run
        raise AssertionError("glob did not match")

    act = await ua.check_async(
        "mcp://insurance/approve_claim",
        verb="call",
        params={"claim_id": "CLM-2001"},
        attachments=lambda action: [invoice(action.params["claim_id"])],
    )
    assert act.allowed
    (request,) = operator.asked
    assert [a.label for a in request.attachments] == ["Invoice", "Adjuster report"]
    assert all(a.source is AttachmentSource.APPLICATION for a in request.attachments)


async def test_nothing_is_loaded_for_an_allowed_action(ua, operator):
    loaded: list[str] = []

    @ua.attachments_for("**")
    def everything(action):
        loaded.append(action.tool)
        return []

    act = await ua.check_async(
        "mcp://insurance/get_claim", verb="call", attachments=lambda a: loaded.append("site")
    )
    assert act.allowed and loaded == [] and operator.asked == []


async def test_the_decorator_passes_bound_arguments(ua, operator):
    @ua.action(
        "mcp://insurance/approve_claim",
        verb="call",
        params=["claim_id"],
        attachments=lambda claim_id, amount: [invoice(f"{claim_id}:{amount}")],
    )
    async def approve_claim(claim_id: str, amount: int = 4200) -> str:
        return "approved"

    assert await approve_claim("CLM-2001") == "approved"
    (request,) = operator.asked
    assert request.attachments[0].data.endswith(b"CLM-2001:4200")


def test_the_decorator_refuses_attachments_on_a_sync_function(ua):
    with pytest.raises(TypeError, match="only async"):

        @ua.action("mcp://insurance/approve_claim", verb="call", attachments=[invoice("x")])
        def approve_claim() -> None: ...


async def test_a_failing_provider_is_shown_and_the_request_still_asked(ua, operator):
    @ua.attachments_for("mcp://insurance/approve_claim")
    def claim_documents(action):
        raise ConnectionError("document store down")

    act = await ua.check_async("mcp://insurance/approve_claim", verb="call")
    assert act.allowed
    (entry,) = operator.asked[0].attachments
    assert (entry.label, entry.unavailable) == (
        "claim_documents",
        "provider_error: ConnectionError",
    )


async def test_toolguard_and_mcp_sessions_carry_attachments(ua, operator):
    @ua.attachments_for("mcp://insurance/approve_claim")
    def claim_documents(action):
        return [invoice(action.params["claim_id"])]

    guard = ToolGuard(ua, origin="test", scheme="mcp")
    act = await guard.check_async(
        "insurance/approve_claim",
        {"claim_id": "CLM-1"},
        attachments=[Attachment.text("call-site", label="Note")],
    )
    assert act.allowed
    assert [a.label for a in operator.asked[0].attachments] == ["Note", "Invoice"]

    class Raw:
        async def call_tool(self, name, arguments):
            return "ok"

    session = GuardedSession(Raw(), mcp_guard(ua), server="insurance")
    assert await session.call_tool("approve_claim", {"claim_id": "CLM-2"}) == "ok"
    assert [a.data for a in operator.asked[1].attachments] == [b"%PDF-1.7 CLM-2"]
