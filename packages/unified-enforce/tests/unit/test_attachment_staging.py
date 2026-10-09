"""Approval attachments P2 (approval-attachments.v1 §4, §5): staging, `from_call`,
late attachment, and the client's check that the answer covers its evidence.

What matters, in order:

1. **Staged evidence never crosses** principals, sessions or calls, and rides
   on exactly one deferred call.
2. **Provenance is set by the surface.** Agent content is `agent`; only a
   result this enforcement point recorded for this caller is `observed`; no
   argument changes that.
3. **The answer covers everything this client attached**, late entries
   included -- a manifest that drops or alters one is refused, and extra
   entries (late ones from the same credential) are signed over, not ignored.
"""

from __future__ import annotations

import asyncio
import base64
import json
from typing import Any

import pytest

from unified_enforce import Action, Approvals, Attachment, AttachmentSource, Principal
from unified_enforce.staging import (
    AttachmentTools,
    RecordedResults,
    StagedAttachments,
    StagingError,
    channel_attach,
)

from test_approval_attachments import INVOICE, PDF, PHOTO, FakeHTTP, deferred, remote
from test_remote_approvals import signer

CLAIM = "mcp://insurance/approve_claim"


def call(principal: str = "agent:a", tool: str = CLAIM, **params: Any) -> Action:
    return Action.build(
        principal=Principal(id=principal),
        tool=tool,
        verb="call",
        resource="*",
        params=params or {"claim_id": "CLM-2001", "amount": 4200.0},
    )


class Clock:
    def __init__(self) -> None:
        self.now = 1_000_000.0

    def __call__(self) -> float:
        return self.now


# --- staging ---------------------------------------------------------------------------


def test_staged_evidence_rides_only_on_the_matching_call_once():
    staging = StagedAttachments()
    staging.stage("agent:a", "s1", CLAIM, {"claim_id": "CLM-2001"}, INVOICE)
    staging.stage("agent:a", "s1", "mcp://insurance/*", None, PHOTO)

    assert staging.take(call(claim_id="CLM-2002"), "s1") == (PHOTO,), "CLM-2001's invoice stays"
    assert staging.take(call(), "s1") == (INVOICE,)
    assert staging.take(call(), "s1") == (), "consumed: one deferred call each"


def test_staged_evidence_never_crosses_principals_or_sessions():
    staging = StagedAttachments()
    staging.stage("agent:a", "s1", CLAIM, None, INVOICE)
    assert staging.take(call("agent:b"), "s1") == ()
    assert staging.take(call("agent:a"), "s2") == ()
    assert staging.list("agent:b", "s1") == []
    (item,) = staging.list("agent:a", "s1")
    assert not staging.discard("agent:b", "s1", item.staged_id), "ids are not an oracle"
    assert staging.take(call("agent:a"), "s1") == (INVOICE,)


def test_match_compares_as_strings_the_sdk_way():
    staging = StagedAttachments()
    staging.stage("agent:a", "s", CLAIM, {"amount": "4200.0"}, INVOICE)
    assert staging.take(call(amount="4200.0"), "s") == (INVOICE,)  # SDK-normalised
    staging.stage("agent:a", "s", CLAIM, {"amount": 4200.0}, INVOICE)
    assert staging.take(call(amount=4200.0), "s") == (INVOICE,)  # hub JSON float
    staging.stage("agent:a", "s", CLAIM, {"amount": "4200"}, INVOICE)
    assert staging.take(call(amount=4200.0), "s") == ()
    staging.stage("agent:a", "s", CLAIM, {"missing": "x"}, PHOTO)
    assert staging.take(call(), "s") == ()


def test_staged_items_expire():
    clock = Clock()
    staging = StagedAttachments(clock=clock)
    item = staging.stage("agent:a", "s", CLAIM, None, INVOICE)
    assert item.expires_at == int((clock.now + 900) * 1000)
    clock.now += 901
    assert staging.list("agent:a", "s") == []
    assert staging.take(call(), "s") == ()


def test_staging_is_bounded_and_refuses_clearly():
    staging = StagedAttachments(max_items=2, max_bytes=len(PDF) * 2 + 1)
    staging.stage("agent:a", "s", CLAIM, None, INVOICE)
    staging.stage("agent:a", "s", CLAIM, None, INVOICE)
    with pytest.raises(StagingError, match="already staged"):
        staging.stage("agent:a", "s", CLAIM, None, PHOTO)
    staging.stage("agent:a", "other", CLAIM, None, INVOICE)  # per (principal, session)

    small = StagedAttachments(max_bytes=len(PDF) + 1)
    small.stage("agent:a", "s", CLAIM, None, INVOICE)
    with pytest.raises(StagingError, match="bytes"):
        small.stage("agent:a", "s", CLAIM, None, INVOICE)


def test_staging_refuses_bad_targets_and_markup():
    staging = StagedAttachments()
    with pytest.raises(StagingError, match="tool URI"):
        staging.stage("agent:a", "s", "approve_claim", None, INVOICE)
    svg = Attachment.bytes(b"<svg onload=alert(1)>", "image/png", "photo")
    with pytest.raises(StagingError, match="HTML and SVG"):
        staging.stage("agent:a", "s", CLAIM, None, svg)


# --- the tool surface: provenance ----------------------------------------------------------


def tools(recorded: RecordedResults | None = None, attach=None) -> AttachmentTools:
    return AttachmentTools(StagedAttachments(), recorded=recorded, attach=attach)


async def test_agent_content_is_agent_whatever_it_claims():
    t = tools()
    out = await t.call(
        "stage_attachment",
        {"for_tool": CLAIM, "label": "Invoice", "content_base64": base64.b64encode(PDF).decode()},
        "agent:a",
        "s",
    )
    assert out["source"] == "agent" and out["media_type"] == "application/pdf"
    for forged in ({"source": "observed"}, {"source": "application"}, {"origin": "x"}):
        with pytest.raises(StagingError, match="unknown argument"):
            await t.call(
                "stage_attachment",
                {"for_tool": CLAIM, "label": "x", "content": "hi", **forged},
                "agent:a",
                "s",
            )
    (taken,) = t.staging.take(call(), "s")
    assert taken.source is AttachmentSource.AGENT


async def test_from_call_is_observed_only_for_a_result_recorded_for_this_caller():
    recorded = RecordedResults()
    recorded.record("agent:a", "s", "d" * 64, {"claim": "CLM-2001", "amount": 4200})
    t = tools(recorded)

    async def stage(principal: str, session: str) -> Attachment:
        await t.call(
            "stage_attachment",
            {"for_tool": CLAIM, "label": "get_claim result", "from_call": "d" * 64},
            principal,
            session,
        )
        (a,) = t.staging.take(call(principal), session)
        return a

    observed = await stage("agent:a", "s")
    assert observed.source is AttachmentSource.OBSERVED and observed.origin_ref == "d" * 64
    assert json.loads(observed.data) == {"amount": 4200, "claim": "CLM-2001"}

    for principal, session in (("agent:b", "s"), ("agent:a", "other")):
        missing = await stage(principal, session)
        assert missing.unavailable == "from_call_not_recorded"
        assert missing.source is AttachmentSource.AGENT and missing.data == b""
        assert missing.origin_ref == "d" * 64

    without_store = tools()
    await without_store.call(
        "stage_attachment",
        {"for_tool": CLAIM, "label": "r", "from_call": "d" * 64},
        "agent:a",
        "s",
    )
    (a,) = without_store.staging.take(call(), "s")
    assert a.unavailable == "from_call_not_recorded"


async def test_exactly_one_content_source_and_list_discard():
    t = tools()
    with pytest.raises(StagingError, match="exactly one"):
        await t.call(
            "stage_attachment",
            {"for_tool": CLAIM, "label": "x", "content": "a", "from_call": "d"},
            "agent:a",
            "s",
        )
    out = await t.call(
        "stage_attachment",
        {"for_tool": CLAIM, "label": "notes", "content": '{"a": 1}', "match": {"claim_id": "X"}},
        "agent:a",
        "s",
    )
    assert out["media_type"] == "application/json" and out["expires_at"].endswith("Z")
    listed = await t.call("list_staged", {}, "agent:a", "s")
    assert [i["staged_id"] for i in listed["staged"]] == [out["staged_id"]]
    assert "content" not in json.dumps(listed["staged"][0]).replace('"content_', "")
    await t.call("discard_staged", {"staged_id": out["staged_id"]}, "agent:a", "s")
    assert (await t.call("list_staged", {}, "agent:a", "s"))["staged"] == []
    with pytest.raises(StagingError, match="no staged"):
        await t.call("discard_staged", {"staged_id": out["staged_id"]}, "agent:a", "s")


async def test_attach_to_approval_needs_console_approvals():
    with pytest.raises(StagingError, match="console approvals"):
        await tools().call(
            "attach_to_approval", {"approval_ref": "01A", "label": "x", "content": "y"}, "a", "s"
        )


# --- late attachment and the manifest check ------------------------------------------------


class HeldHTTP(FakeHTTP):
    """Pending until released, so evidence can be attached while `ask` waits."""

    def __init__(self, s, **kwargs: Any) -> None:
        super().__init__(s, **kwargs)
        self.released = False

    def poll(self, _id: str) -> dict[str, Any]:
        if not self.released:
            return {"status": "pending"}
        return super().poll(_id)


def _queued(channel) -> asyncio.Future[str]:
    """A future resolved with the approval id once `channel` queues."""
    seen: asyncio.Future[str] = asyncio.get_running_loop().create_future()
    channel.on_queued = lambda approval_id, request: seen.done() or seen.set_result(approval_id)
    return seen


async def test_a_late_attachment_is_uploaded_posted_and_covered_by_the_answer():
    s = signer()
    fake = HeldHTTP(s)
    channel = remote(fake)
    queued = _queued(channel)
    task = asyncio.create_task(Approvals(channel).resolve(deferred(INVOICE)))
    ref = await asyncio.wait_for(queued, 2)
    assert channel.waiting_request(ref) is not None

    late = Attachment.bytes(PNG_LATE, "image/png", "Second photo")
    result = await channel.attach(ref, [late])
    assert [e["label"] for e in result["attachments"]] == ["Plumber invoice", "Second photo"]
    assert any(u["sha256"] == late.sha256 for u in fake.uploads), "bytes uploaded first"
    path, body = fake.posts[-1]
    assert path == f"/api/v1/approvals/{ref}/attachments"
    assert body["attachments"][0]["status"] == "stored"

    fake.released = True
    outcome = await asyncio.wait_for(task, 2)
    assert outcome.allowed
    from unified_enforce.attest import attachments_digest

    assert outcome.attachments_digest == attachments_digest(fake.manifest)
    assert channel.waiting_request(ref) is None


PNG_LATE = b"\x89PNG\r\n\x1a\n" + b"\x01" * 40


def _drop_invoice(manifest):
    return [e for e in manifest if e["label"] != "Plumber invoice"]


def _relabel(manifest):
    return [{**e, "label": "Approved by supervisor"} for e in manifest]


@pytest.mark.parametrize(
    "returned",
    [_drop_invoice, _relabel, lambda m: [{**e, "sha256": "0" * 64} for e in m]],
    ids=["dropped", "relabelled", "substituted"],
)
async def test_an_answer_whose_manifest_drops_or_alters_our_evidence_denies(returned):
    """Signed honestly over the manifest it returns -- and still refused,
    because that manifest is not what this client attached."""
    s = signer()
    fake = FakeHTTP(s, returned=returned)
    outcome = await Approvals(remote(fake)).resolve(deferred(INVOICE, PHOTO))
    assert not outcome.allowed
    assert "attachments_mismatch" in (outcome.decision.reason or "")


async def test_an_answer_without_a_manifest_denies_when_evidence_was_attached():
    s = signer()
    fake = FakeHTTP(s)
    channel = remote(fake)
    honest = fake.poll

    def no_manifest(i):
        response = honest(i)
        response.pop("attachments")
        return response

    channel._poll_once = no_manifest  # noqa: SLF001
    outcome = await Approvals(channel).resolve(deferred(INVOICE))
    assert not outcome.allowed and "attachments_mismatch" in (outcome.decision.reason or "")


async def test_late_entries_from_elsewhere_are_signed_over_not_ignored():
    """Another process of this credential attached late: the extra entry is
    part of what the approver saw, so the digest covers it -- and that holds
    for a request this client sent with no evidence at all."""
    s = signer()
    extra = {
        **_manifest_entry(PHOTO),
        "added_at_ms": 2_000_000_000_000,
        "source": "agent",
    }
    for attached in ((INVOICE,), ()):
        fake = FakeHTTP(s, returned=lambda m: [*m, extra])
        outcome = await Approvals(remote(fake)).resolve(deferred(*attached))
        assert outcome.allowed
        from unified_enforce.attest import attachments_digest

        assert outcome.attachments_digest == attachments_digest([*fake.manifest, extra])


def _manifest_entry(a: Attachment) -> dict[str, Any]:
    from unified_enforce.attachments import build_manifest

    (entry,) = build_manifest([a], 1)
    return entry


async def test_attach_to_a_request_not_waiting_here_withholds_content():
    """This instance cannot know the request's rule, so the content stays."""
    s = signer()
    fake = FakeHTTP(s)
    result = await remote(fake).attach("01ELSEWHERE", [INVOICE])
    assert fake.uploads == []
    (sent,) = fake.posts[-1][1]["attachments"]
    assert (sent["status"], sent["detail"]) == ("withheld", "request_not_local")
    assert result["attachments"][-1]["sha256"] == INVOICE.sha256


async def test_a_minimal_rules_late_evidence_is_withheld_too():
    s = signer()
    fake = HeldHTTP(s)
    channel = remote(fake)
    queued = _queued(channel)
    task = asyncio.create_task(Approvals(channel).resolve(deferred(audit_level="minimal")))
    ref = await asyncio.wait_for(queued, 2)
    await channel.attach(ref, [INVOICE])
    assert fake.uploads == []
    assert fake.posts[-1][1]["attachments"][0]["detail"] == "audit_level_minimal"
    fake.released = True
    assert (await asyncio.wait_for(task, 2)).allowed


async def test_on_queued_is_called_and_its_failure_is_not_a_decision():
    s = signer()
    fake = FakeHTTP(s)
    calls: list[tuple[str, Any]] = []

    def boom(approval_id, request):
        calls.append((approval_id, request))
        raise RuntimeError("the app's hook is broken")

    channel = remote(fake, on_queued=boom)
    request = deferred(INVOICE)
    outcome = await Approvals(channel).resolve(request)
    assert outcome.allowed
    assert calls == [("01APPROVAL", request)]


async def test_channel_attach_refuses_another_principals_request():
    s = signer()
    fake = HeldHTTP(s)
    channel = remote(fake)
    queued = _queued(channel)
    task = asyncio.create_task(Approvals(channel).resolve(deferred(INVOICE)))
    ref = await asyncio.wait_for(queued, 2)
    t = tools(attach=channel_attach(lambda: channel))
    args = {"approval_ref": ref, "label": "note", "content": "pre-approved by supervisor"}
    with pytest.raises(StagingError, match="no pending approval"):
        await t.call("attach_to_approval", args, "agent:someone-else", "s")
    with pytest.raises(StagingError, match="no pending approval"):
        await t.call(
            "attach_to_approval", {**args, "approval_ref": "01NOPE"}, "agent:claims-1", "s"
        )
    assert not any(p.endswith(f"{ref}/attachments") for p, _ in fake.posts)

    out = await t.call("attach_to_approval", args, "agent:claims-1", "s")
    assert out["count"] == 2 and out["attachments_digest"]
    assert fake.late[0]["source"] == "agent"
    fake.released = True
    assert (await asyncio.wait_for(task, 2)).allowed
