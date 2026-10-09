"""Approval attachments (approval-attachments.v1, P1): evidence for the approver.

What matters, in order:

1. **Binding.** The resolution is verified against the digest of the manifest
   *this client* sent. A decision signed over other evidence -- or over none,
   when evidence was attached -- is refused, in both directions.
2. **Nothing changes for requests without attachments.** The v2 signed
   payload, the queue body and the chain entry are byte for byte what they
   were, so every control plane and sidecar built before this keeps working.
3. **Missing evidence is not a decision.** A provider that fails becomes an
   `unavailable` entry and the request is still asked.
4. **Laziness.** Loaders run only for a DEFER someone will actually see.
5. **Sniffing.** Markup never passes as an image or as text.
"""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest

from unified_enforce import (
    Action,
    ApprovalKind,
    ApprovalResponse,
    Approvals,
    Attachment,
    AttachmentProvider,
    AttachmentSource,
    AuditChain,
    Enforcer,
    PolicyEngine,
    Principal,
)
from unified_enforce.approval import ApprovalRequest
from unified_enforce.attachments import (
    MAX_ATTACHMENT_BYTES,
    MAX_ATTACHMENTS,
    build_manifest,
    check_media_type,
    resolve_attachments,
    sniff,
)
from unified_enforce.attest import (
    ATTACHMENT_FIELDS,
    Reason,
    accept_resolution,
    attachments_digest,
    canonical,
    resolution_payload,
)
from unified_enforce.policy import Decision, Verdict
from unified_enforce.remote_approvals import (
    ApprovalHTTPError,
    ApprovalTransportError,
    RemoteApprovals,
)

from test_remote_approvals import FLEET, NOW_MS, fresh, keys_for, resolution, signer

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
PDF = b"%PDF-1.7\n" + b"x" * 64

POLICY = """
version: 1
rules:
  - id: reads-ok
    match: {tool: "mcp://files/read", verb: call}
    effect: allow
  - id: no-deletes
    match: {tool: "mcp://files/delete", verb: call}
    effect: deny
  - id: claims-need-a-human
    match: {tool: "mcp://insurance/approve_claim", verb: call}
    effect: defer
"""


def action(tool: str = "mcp://insurance/approve_claim", **params: Any) -> Action:
    return Action.build(
        principal=Principal(id="agent:claims-1"),
        tool=tool,
        verb="call",
        resource="*",
        params=params or {"claim_id": "CLM-2001"},
    )


def entry(**overrides: Any) -> dict[str, Any]:
    base = {
        "sha256": "a" * 64,
        "size": 10,
        "media_type": "application/pdf",
        "label": "Invoice",
        "source": "application",
        "note": "",
        "origin_ref": None,
        "added_at_ms": 1,
        "status": "stored",
        "detail": "",
    }
    return {**base, **overrides}


# --- the digest ---------------------------------------------------------------------


def test_the_digest_ignores_the_order_entries_arrive_in():
    a = entry(sha256="a" * 64, added_at_ms=2)
    b = entry(sha256="b" * 64, added_at_ms=1)
    c = entry(sha256="b" * 64, added_at_ms=1, label="Another")
    assert attachments_digest([a, b, c]) == attachments_digest([c, a, b])


def test_the_digest_normalises_fields_absent_extra_and_reordered():
    full = entry()
    sparse = {k: v for k, v in full.items() if v is not None}  # origin_ref omitted
    noisy = {**full, "expires_at": 123, "viewed": True}  # unknown keys dropped
    assert attachments_digest([full]) == attachments_digest([sparse])
    assert attachments_digest([full]) == attachments_digest([noisy])
    # ...but every listed field is covered.
    for name in ATTACHMENT_FIELDS:
        changed = {**full, name: "changed" if name != "added_at_ms" else 99}
        assert attachments_digest([changed]) != attachments_digest([full]), name


def test_the_manifest_has_every_contract_field_and_hashes_the_bytes():
    (built,) = build_manifest([Attachment.bytes(PDF, "application/pdf", "Invoice")], 1234)
    assert tuple(sorted(built)) == tuple(sorted(ATTACHMENT_FIELDS))
    assert built["status"] == "stored" and built["detail"] == ""
    assert built["size"] == len(PDF)
    assert built["added_at_ms"] == 1234
    assert built["source"] == "application"


def test_json_attachments_are_canonical():
    one = Attachment.json({"b": 1, "a": "é"}, label="Report")
    two = Attachment.json({"a": "é", "b": 1}, label="Report")
    assert one.sha256 == two.sha256
    assert one.data == '{"a":"é","b":1}'.encode()
    assert "data" not in repr(one), "content must never reach a log line"


# --- nothing changes without attachments ------------------------------------------------


def test_the_v2_payload_is_byte_for_byte_unchanged_without_attachments():
    fields = dict(
        action_digest="ab",
        kind="allow",
        approver={"sub": "s"},
        scope=None,
        resolved_at_ms=1,
        expires_at_ms=2,
        nonce="n",
        fleet_id="f",
    )
    assert canonical(resolution_payload(**fields)) == (
        b'{"action_digest":"ab","approver":{"sub":"s"},"expires_at_ms":2,"fleet_id":"f",'
        b'"kind":"allow","nonce":"n","resolved_at_ms":1,"scope":null,"v":2}'
    )
    v3 = resolution_payload(**fields, attachments_digest="d" * 64)
    assert v3["v"] == 3 and v3["attachments_digest"] == "d" * 64


# --- binding: both directions ------------------------------------------------------------


def _signed_with(s, digest: str, shown: str | None) -> dict[str, Any]:
    """A genuine resolution whose signature covers `shown` (or no evidence)."""
    response = resolution(s, digest)
    payload = resolution_payload(
        action_digest=digest,
        kind="allow",
        approver=response["approver"],
        scope=None,
        resolved_at_ms=response["resolved_at_ms"],
        expires_at_ms=response["expires_at_ms"],
        nonce=response["nonce"],
        fleet_id=FLEET,
        attachments_digest=shown,
    )
    from test_remote_approvals import sign

    response["signature"] = sign(s, canonical(payload))
    if shown is not None:
        response["attachments_digest"] = shown
    return response


def _accept(response, s, digest, expected):
    return accept_resolution(
        response,
        keys_for(s),
        fleet_id=FLEET,
        action_digest=digest,
        now_ms=NOW_MS,
        attachments_digest=expected,
    )


def test_a_resolution_covering_the_attached_evidence_is_accepted():
    s, digest = signer(), action().digest(strict=False)
    assert _accept(_signed_with(s, digest, "x" * 64), s, digest, "x" * 64)


def test_a_resolution_naming_no_evidence_is_refused_when_evidence_was_attached():
    s, digest = signer(), action().digest(strict=False)
    verdict = _accept(_signed_with(s, digest, None), s, digest, "x" * 64)
    assert not verdict and verdict.reason is Reason.ATTACHMENTS_MISMATCH


def test_a_resolution_naming_evidence_is_refused_when_none_was_attached():
    s, digest = signer(), action().digest(strict=False)
    verdict = _accept(_signed_with(s, digest, "x" * 64), s, digest, None)
    assert not verdict and verdict.reason is Reason.ATTACHMENTS_MISMATCH


def test_relabelling_the_digest_without_resigning_is_refused():
    s, digest = signer(), action().digest(strict=False)
    response = {**_signed_with(s, digest, "x" * 64), "attachments_digest": "y" * 64}
    assert not _accept(response, s, digest, "y" * 64)


# --- sniffing ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "markup",
    [
        b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>',
        b"\xef\xbb\xbf  \n<!DOCTYPE html><html><script>x</script></html>",
        b'<?xml version="1.0"?><svg/>',
    ],
)
@pytest.mark.parametrize("declared", ["image/png", "text/plain", "text/csv", "application/json"])
def test_markup_is_refused_whatever_it_is_declared_as(markup, declared):
    assert sniff(markup) is None
    assert not check_media_type(declared, markup)
    (built,) = build_manifest([Attachment.bytes(markup, declared, "Photo")], 1)
    assert built["status"] == "unavailable" and built["detail"] == "media_type_refused"


def test_binary_types_must_match_and_text_types_are_a_family():
    assert sniff(PNG) == "image/png" and check_media_type("image/png", PNG)
    assert not check_media_type("image/jpeg", PNG)
    assert not check_media_type("application/pdf", b"just text")
    assert check_media_type("text/csv", b"a,b\n1,2\n")
    assert check_media_type("text/plain", b'{"a": 1}')
    assert not check_media_type("application/json", b"not json")
    assert not check_media_type("application/zip", b"PK\x03\x04")
    assert sniff(b"RIFF\x00\x00\x00\x00WEBPVP8 ") == "image/webp"


def test_file_sniffs_content_not_extension(tmp_path):
    disguised = tmp_path / "invoice.pdf"
    disguised.write_bytes(b"<html><script>x</script></html>")
    attachment = Attachment.file(disguised, label="Invoice")
    (built,) = build_manifest([attachment], 1)
    assert built["status"] == "unavailable" and built["detail"] == "media_type_refused"

    missing = Attachment.file(tmp_path / "nope.pdf", label="Gone")
    (built,) = build_manifest([missing], 1)
    assert built["status"] == "unavailable" and built["sha256"] is None


def test_limits_make_entries_unavailable_never_fail_the_request():
    big = Attachment.bytes(b"a" * (MAX_ATTACHMENT_BYTES + 1), "text/plain", "Huge")
    many = [Attachment.text(f"note {i}", label=f"n{i}") for i in range(MAX_ATTACHMENTS + 2)]
    manifest = build_manifest([big, *many], 1)
    assert manifest[0]["detail"] == "too_large" and manifest[0]["sha256"] == big.sha256
    assert [e["detail"] for e in manifest[MAX_ATTACHMENTS:]] == ["too_many"] * 3
    assert len(manifest) == MAX_ATTACHMENTS + 3


# --- resolving: providers, failure, laziness ---------------------------------------------------


async def test_a_failing_provider_becomes_an_unavailable_entry():
    def claim_documents(_action):
        raise TimeoutError("upstream slow")

    good = AttachmentProvider.build(
        "mcp://insurance/*", lambda a: [Attachment.text("ok", label="Notes")], "notes"
    )
    other = AttachmentProvider.build("mcp://bank/*", lambda a: [Attachment.text("x", "x")])
    resolved = await resolve_attachments(
        None,
        action(),
        providers=[AttachmentProvider.build("mcp://insurance/**", claim_documents), good, other],
    )
    assert [(a.label, a.unavailable) for a in resolved] == [
        ("claim_documents", "provider_error: TimeoutError"),
        ("Notes", None),
    ]


async def test_one_budget_covers_every_source():
    import asyncio

    async def slow(_action):
        await asyncio.sleep(5)

    resolved = await resolve_attachments(slow, action(), timeout=0.05)
    assert resolved[0].unavailable == "provider_error: TimeoutError"


async def test_a_callable_returning_the_wrong_type_is_a_provider_error():
    resolved = await resolve_attachments(lambda a: ["not an attachment"], action())
    assert resolved[0].unavailable == "provider_error: TypeError"


class Recording:
    def __init__(self) -> None:
        self.seen: list[ApprovalRequest] = []

    async def ask(self, request: ApprovalRequest) -> ApprovalResponse:
        self.seen.append(request)
        return ApprovalResponse(ApprovalKind.ALLOW_SESSION, decided_by="alice")


@pytest.mark.parametrize("tool", ["mcp://files/read", "mcp://files/delete"])
async def test_loaders_are_not_invoked_for_allow_or_deny(tool):
    calls: list[str] = []

    def loader(_a):
        calls.append("called")
        return []

    enforcer = Enforcer(PolicyEngine.from_yaml(POLICY), approvals=Approvals(Recording()))
    await enforcer.enforce_with_approval(
        action(tool),
        attachments=loader,
        attachment_providers=[AttachmentProvider.build("**", loader)],
    )
    assert calls == []


async def test_loaders_are_not_invoked_when_a_session_allow_answers():
    calls: list[str] = []

    def loader(_a):
        calls.append("called")
        return [Attachment.bytes(PDF, "application/pdf", "Invoice")]

    channel = Recording()
    enforcer = Enforcer(PolicyEngine.from_yaml(POLICY), approvals=Approvals(channel))
    first = await enforcer.enforce_with_approval(action(), attachments=loader)
    second = await enforcer.enforce_with_approval(action(), attachments=loader)
    assert first.allowed and second.allowed
    assert calls == ["called"], "the session allow answered the second; nobody saw evidence"
    assert channel.seen[0].attachments[0].label == "Invoice"
    assert channel.seen[0].attachments[0].source is AttachmentSource.APPLICATION


async def test_a_provider_error_still_asks_the_human():
    def broken(_a):
        raise RuntimeError("db down")

    channel = Recording()
    enforcer = Enforcer(PolicyEngine.from_yaml(POLICY), approvals=Approvals(channel))
    outcome = await enforcer.enforce_with_approval(action(), attachments=broken)
    assert outcome.allowed
    (request,) = channel.seen
    assert request.attachments[0].unavailable == "provider_error: RuntimeError"


# --- RemoteApprovals: upload, queue, verify ------------------------------------------------------


class FakeHTTP:
    """Stands in for `_post` and `_poll_once`: records what was sent, and
    answers the poll with a resolution signed over the manifest as it now
    stands -- the queued entries plus any late ones, returned beside the
    digest (contract B) -- which is what an honest control plane does.

    `returned` rewrites the manifest the poll returns (a dishonest plane);
    `sign_over` overrides the digest it signs."""

    def __init__(self, s, *, upload=None, sign_over=None, returned=None) -> None:
        self.s = s
        self.posts: list[tuple[str, dict[str, Any]]] = []
        self.late: list[dict[str, Any]] = []
        self.upload = upload or (
            lambda body: {
                "sha256": body["sha256"],
                "size": len(base64.b64decode(body["data_b64"])),
                "media_type": body["media_type"],
                "status": "stored",
            }
        )
        self.sign_over = sign_over  # override what the "control plane" signs
        self.returned = returned

    def post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        self.posts.append((path, body))
        if path == "/api/v1/approvals/attachments":
            result = self.upload(body)
            if isinstance(result, Exception):
                raise result
            return result
        if path.endswith("/attachments"):
            self.late.extend(body["attachments"])
            return {
                "attachments": self.manifest,
                "attachments_digest": attachments_digest(self.manifest),
            }
        return {"id": "01APPROVAL", "status": "pending"}

    @property
    def queued(self) -> dict[str, Any]:
        (body,) = [b for p, b in self.posts if p == "/api/v1/approvals"]
        return body

    @property
    def manifest(self) -> list[dict[str, Any]]:
        bodies = [b for p, b in self.posts if p == "/api/v1/approvals"]
        initial = bodies[0].get("attachments") or [] if bodies else []
        return [*initial, *self.late]

    @property
    def uploads(self) -> list[dict[str, Any]]:
        return [b for p, b in self.posts if p == "/api/v1/approvals/attachments"]

    def poll(self, _id: str) -> dict[str, Any]:
        body = self.queued
        manifest = self.manifest
        if self.returned is not None:
            manifest = self.returned(manifest)
        shown = attachments_digest(manifest) if manifest else None
        if self.sign_over is not None:
            shown = self.sign_over
        response = fresh(self.s, body["action_digest"])
        signed = resolution_payload(
            action_digest=body["action_digest"],
            kind="allow",
            approver=response["approver"],
            scope=None,
            resolved_at_ms=response["resolved_at_ms"],
            expires_at_ms=response["expires_at_ms"],
            nonce=response["nonce"],
            fleet_id=FLEET,
            attachments_digest=shown,
        )
        from test_remote_approvals import sign

        response["signature"] = sign(self.s, canonical(signed))
        if shown is not None:
            response["attachments_digest"] = shown
        if manifest:
            response["attachments"] = manifest
        return response


def remote(fake: FakeHTTP, *, base: str = "https://cp.test", **kwargs: Any) -> RemoteApprovals:
    channel = RemoteApprovals(
        base,
        "uai_sc_test",
        fleet_id=FLEET,
        keys=lambda: keys_for(fake.s),
        poll_seconds=0.001,
        deadline_seconds=1.0,
        **kwargs,
    )
    channel._post = fake.post  # noqa: SLF001 - substituting the transport, not the logic
    channel._poll_once = fake.poll  # noqa: SLF001
    return channel


def deferred(*attachments: Attachment, audit_level: str = "standard", source: str = "rule"):
    return ApprovalRequest(
        action=action(),
        decision=Decision(
            verdict=Verdict.DEFER, rule_id="claims", source=source, audit_level=audit_level
        ),
        summary="approve CLM-2001",
        attachments=attachments,
    )


INVOICE = Attachment.bytes(PDF, "application/pdf", "Plumber invoice")
PHOTO = Attachment.bytes(PNG, "image/png", "Damage photo")


async def test_uploads_then_queues_the_manifest_and_verifies_against_it():
    s = signer()
    fake = FakeHTTP(s)
    request = deferred(INVOICE, PHOTO, INVOICE)  # a duplicate is uploaded once
    outcome = await Approvals(remote(fake)).resolve(request)

    assert outcome.allowed
    assert [p for p, _ in fake.posts][:2] == ["/api/v1/approvals/attachments"] * 2
    assert {u["sha256"] for u in fake.uploads} == {INVOICE.sha256, PHOTO.sha256}
    assert base64.b64decode(fake.uploads[0]["data_b64"]) == PDF
    manifest = fake.queued["attachments"]
    assert [e["status"] for e in manifest] == ["stored"] * 3
    assert "data_b64" not in json.dumps(fake.queued), "bytes never ride in the approval JSON"
    assert outcome.attachments_digest == attachments_digest(manifest)


async def test_a_resolution_over_other_evidence_denies():
    s = signer()
    fake = FakeHTTP(s, sign_over="f" * 64)
    outcome = await Approvals(remote(fake)).resolve(deferred(INVOICE))
    assert not outcome.allowed
    assert "attachments_mismatch" in (outcome.decision.reason or "")


async def test_a_resolution_naming_no_evidence_denies_when_some_was_attached():
    """A control plane that predates attachments: it ignores the manifest and
    signs v2. The approver saw no invoice, so the answer is not about this
    request."""
    s = signer()
    fake = FakeHTTP(s)
    fake.sign_over = None
    channel = remote(fake)

    def poll_v2(_id):
        return fresh(s, fake.queued["action_digest"])

    channel._poll_once = poll_v2  # noqa: SLF001
    outcome = await Approvals(channel).resolve(deferred(INVOICE))
    assert not outcome.allowed


@pytest.mark.parametrize(
    ("kwargs", "level", "source", "reason"),
    [
        ({"share_params": False}, "standard", "rule", "payloads_off"),
        ({}, "minimal", "rule", "audit_level_minimal"),
        ({}, "standard", "distribution", "distribution_state"),
        ({"base": "http://cp.example.com"}, "standard", "rule", "insecure_transport"),
    ],
)
async def test_withheld_requests_upload_nothing_and_send_hashes(kwargs, level, source, reason):
    s = signer()
    fake = FakeHTTP(s)
    request = deferred(INVOICE, audit_level=level, source=source)
    outcome = await Approvals(remote(fake, **kwargs)).resolve(request)

    assert outcome.allowed
    assert fake.uploads == []
    (sent,) = fake.queued["attachments"]
    assert sent["status"] == "withheld" and sent["detail"] == reason
    assert sent["sha256"] == INVOICE.sha256 and sent["label"] == "Plumber invoice"


async def test_not_accepted_and_refused_uploads_become_unavailable():
    s = signer()

    def upload(body):
        if body["sha256"] == INVOICE.sha256:
            return {"status": "not_accepted", "detail": "hosted fleet has not opted in"}
        return ApprovalHTTPError(415, "Unsupported Media Type", "type not allowed")

    fake = FakeHTTP(s, upload=upload)
    outcome = await Approvals(remote(fake)).resolve(deferred(INVOICE, PHOTO))

    assert outcome.allowed
    invoice, photo = fake.queued["attachments"]
    assert (invoice["status"], invoice["detail"]) == ("unavailable", "not_accepted")
    assert invoice["sha256"] == INVOICE.sha256, "the approver still sees which document"
    assert (photo["status"], photo["detail"]) == ("unavailable", "refused: type not allowed")


@pytest.mark.parametrize(
    "failure",
    [
        ApprovalTransportError("cannot reach the control plane"),
        ApprovalHTTPError(404, "Not Found"),
        ApprovalHTTPError(503, "Service Unavailable"),
        {"sha256": "0" * 64, "size": 1, "media_type": "application/pdf", "status": "stored"},
    ],
)
async def test_an_upload_that_cannot_be_trusted_denies_and_queues_nothing(failure):
    s = signer()
    fake = FakeHTTP(s, upload=lambda body: failure)
    outcome = await Approvals(remote(fake)).resolve(deferred(INVOICE))
    assert not outcome.allowed
    assert all(p != "/api/v1/approvals" for p, _ in fake.posts)


async def test_a_request_without_attachments_sends_the_old_body():
    s = signer()
    fake = FakeHTTP(s)
    outcome = await Approvals(remote(fake)).resolve(deferred())
    assert outcome.allowed and outcome.attachments_digest is None
    assert "attachments" not in fake.queued
    assert fake.uploads == []


async def test_a_receipt_claiming_another_manifest_denies_before_anyone_is_asked():
    s = signer()
    fake = FakeHTTP(s)
    original = fake.post

    def post(path, body):
        out = original(path, body)
        return {**out, "attachments_digest": "e" * 64} if path == "/api/v1/approvals" else out

    channel = remote(fake)
    channel._post = post  # noqa: SLF001
    polled: list[str] = []
    channel._poll_once = lambda i: polled.append(i) or {}  # noqa: SLF001
    outcome = await Approvals(channel).resolve(deferred(INVOICE))
    assert not outcome.allowed and polled == []


# --- the chain ---------------------------------------------------------------------------------


async def test_the_chain_records_the_digest_and_omits_it_when_absent(tmp_path):
    from unified_enforce import RecordedApproval

    s = signer()
    fake = FakeHTTP(s)
    with_evidence = deferred(INVOICE)
    outcome = await Approvals(remote(fake)).resolve(with_evidence)
    without = deferred()
    plain = await Approvals(Recording()).resolve(without)

    chain = AuditChain(tmp_path)
    chain.start()
    first = chain.append_approval(RecordedApproval.build(with_evidence, outcome))
    second = chain.append_approval(RecordedApproval.build(without, plain))
    chain.stop()

    assert first["payload"]["attachments_digest"] == outcome.attachments_digest
    assert "attachments_digest" not in second["payload"]
    assert AuditChain.verify(tmp_path).ok


async def test_pack_verification_checks_the_signature_over_the_digest():
    """The recorded approval re-verifies offline only with the digest in the
    signed payload -- and an altered digest fails it."""
    from dataclasses import asdict

    from unified_enforce.pack_verify import _check_one_approval
    from unified_enforce import RecordedApproval

    s = signer()
    fake = FakeHTTP(s)
    request = deferred(INVOICE)
    outcome = await Approvals(remote(fake)).resolve(request)
    record = asdict(RecordedApproval.build(request, outcome))

    ok, detail = _check_one_approval(record, keys_for(s))
    assert ok, detail
    tampered = {**record, "attachments_digest": "0" * 64}
    assert not _check_one_approval(tampered, keys_for(s))[0]
