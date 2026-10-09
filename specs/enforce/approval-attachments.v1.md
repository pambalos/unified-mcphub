# Approval attachments — evidence a person sees before answering a DEFER

Status: **proposed, decisions taken 2026-10-08** (not built). Decisions: the
attachments digest is signed from P1 (A1). Reviewers (CSR role) see every
attachment inline by default (entity-rbac.v1 Q3).
Extends: `approval.v1` (the DEFER contract), `payload-evidence.v1` (content
doctrine), and control-plane `evidence-retention.v1`.
Consumers: SDK (`unified-sdk`), hub (`unified-mcphub`), control plane and console
(`unified-control-plane`). Companion spec: control-plane `entity-rbac.v1` decides
*who* may open what this spec stores.

## Naming

In code and on the wire these are **attachments**. The console labels them
**Evidence**, because that is what a claims reviewer calls a plumber's invoice.
The code name avoids a collision. "Evidence" already means decision evidence
(`EvidenceShipper`, `/api/v1/evidence`, `evidence.v1`), payload evidence
(`payload-evidence.v1`), and evidence packs (`evidence_pack.py`). A fourth
meaning inside the same modules is how two of them get confused in a retention
rule.

## §1 Why

A DEFER asks a person to decide. Today the person sees the tool, the rule, a
120-character summary and, unless withheld, the params. For "approve claim
CLM-2001 for $4,200", that is the amount without the reason for it. A reviewer
with no invoice, no photos and no adjuster report either rubber-stamps the claim
or leaves the queue to look things up in another system. Both defeat the point of
asking a person.

So an approval request should be able to carry the material the decision depends
on, from either of two sources:

- **Programmatically:** the application knows which documents belong to a claim and loads them when, and only when, the action defers.
- **From the agent, by MCP tool:** the agent gathered something during its work (a photo the customer uploaded, a policy lookup) and attaches it for the reviewer.

Three properties make this more than an upload feature:

1. **What the approver saw is bound to what they answered** (§5). "Approved having seen the invoice" must be provable afterwards. A document swapped after the decision must be detectable.
2. **Attachments are claims, and the console says whose** (§6). An invoice the hub fetched from an upstream tool, an invoice the application loaded, and an "invoice" the agent wrote are three different strengths of evidence.
3. **Attachments are content** (§7). They follow the payload doctrine — encrypted at rest, governed by the fleet's capture setting, every read attributed. They must not follow the approval-params precedent, which (as built) bypasses both. That gap is named in §7 so this feature does not copy it.

## §2 The model

```python
@dataclass(frozen=True)
class Attachment:
    label: str                       # "Plumber invoice", shown to the approver (≤ 120 chars)
    media_type: str                  # allowlisted, §6.3
    data: bytes                      # the content; never logged
    source: AttachmentSource         # who produced it, §6.1 — set by the surface, not the caller
    note: str = ""                   # why it is attached (≤ 500 chars)
    origin_ref: str | None = None    # e.g. the action digest of the tool call it came from

    @property
    def sha256(self) -> str: ...

class AttachmentSource(StrEnum):
    OBSERVED    = "observed"     # the enforcement point captured it from an upstream response
    APPLICATION = "application"  # application code supplied it (SDK, programmatic)
    AGENT       = "agent"        # the agent supplied it (MCP attach/stage tools)
```

Constructors: `Attachment.file(path, label=...)` (media type sniffed and checked
against the allowlist, not taken from the extension), `Attachment.bytes(data,
media_type, label)`, `Attachment.json(obj, label)` (canonical JSON, so the same
object always hashes the same), and `Attachment.text(str, label)`.

`ApprovalRequest` (approval.py) gains one field:

```python
attachments: tuple[Attachment, ...] = ()
```

It defaults to empty, so every existing channel and test is unaffected. The
request is still frozen, which means attachments are fixed once a request is
built. Additions after queueing go through §4.3, never by mutating the request.

**The manifest** is what travels with the request in place of the bytes, and what
gets signed (§5):

```json
{"attachments": [
  {"sha256": "…", "size": 48213, "media_type": "application/pdf",
   "label": "Plumber invoice", "source": "application", "note": "", "origin_ref": null,
   "added_at_ms": 1791600000000}
]}
```

`attachments_digest` = sha256 over the canonical JSON of the manifest, with
entries sorted by (`added_at_ms`, `sha256`). It is computed identically by the
engine (`attest.py`) and the control plane's vendored verifier, and both are
pinned to a shared vector file.

**Attachments never change `action_digest`.** The digest identifies the action,
and policy decided it. Attachments are about the *request* for a decision. If
they were folded in, adding a document would make the action a different action,
and nothing that keys on the digest (the approval queue's idempotency, the audit
chain, payload evidence) would still line up.

## §3 Programmatic attachment (SDK)

### §3.1 At the call site

```python
from unified_sdk import Attachment

act = await ua.check_async(
    "mcp://insurance/approve_claim", verb="call",
    params={"claim_id": "CLM-2001", "amount": 4200.0},
    attachments=lambda action: [
        Attachment.file(docs / "CLM-2001" / "invoice.pdf", label="Plumber invoice"),
        Attachment.json(adjuster_report("CLM-2001"), label="Adjuster report"),
    ],
)
```

`attachments=` takes either a sequence or a **callable that receives the built
`Action`**. The callable runs **only if the decision is DEFER**, after policy and
before the request is queued. Loading three PDFs for an action policy allows
outright would be wasted I/O. It would also be a privacy cost: content would be
read, and possibly logged by a careless loader, for an action nobody was going to
review.

The same parameter is threaded through `UnifiedAI.check_async`, the `action()`
decorator (`attachments=` takes a callable over the function's arguments), and
`ToolGuard.check_async(name, args, *, summary, attachments)`.
`Enforcer.enforce_with_approval` passes it to `ApprovalRequest`. Synchronous
`check()` and `acting()` never wait for approval (client.py), so they do not take
it.

### §3.2 Registered providers — attaching without touching call sites

```python
@ua.attachments_for("mcp://insurance/approve_claim")
def claim_documents(action):
    return load_claim_documents(action.params["claim_id"])
```

A provider is keyed by tool glob, using the same segment-aware matching as policy.
Providers run, in registration order, for every DEFER on a matching tool, and
their results are appended after any call-site attachments. This is the
integration point for a framework adapter or an MCP server built on `mcp_guard`:
the tools keep their signatures, and the application declares once where each
tool's supporting documents come from.

**Provider failure is not a decision.** A provider that raises, or exceeds its
time budget (default 5 s total for all providers), is logged, and the request is
queued **without** that provider's attachments and with a manifest entry:

```json
{"label": "claim_documents", "status": "unavailable", "detail": "TimeoutError"}
```

The approver therefore sees that something was meant to be attached and is
missing. Missing evidence is a reason for a person to deny. It is not a reason for
the engine to deny on their behalf, and it must never be silently absent.

### §3.3 Limits (enforced in the SDK, re-enforced by the control plane)

| limit | default | ceiling |
|---|---|---|
| per attachment | 10 MiB | 25 MiB |
| per request (total) | 25 MiB | 100 MiB |
| count per request | 20 | 50 |

Over a limit, the attachment is replaced by an `unavailable` manifest entry
(`detail: "too_large"`) rather than failing the request (same reasoning as above).
The control plane advertises its own limits in the approval receipt, as
`PayloadShipper` learns `max_payload_bytes`. The SDK uses the smaller of the two.

## §4 Attachment over MCP

### §4.1 The constraint

`Hub._handle_call` holds a `tools/call` in-line until it is resolved
(`await self.approval.resolve(...)`). The hub has no progress-notification or
task mechanism. While its sensitive call is held, the agent's session cannot make
another call. So "the agent calls `approve_claim`, then attaches the invoice"
cannot happen inside one blocked call. The design must work with that constraint:

### §4.2 Staging — the primary agent path

The hub (and any MCP server built on `mcp_guard`, via a helper) exposes reserved
tools in the `unified` namespace. They are policy-evaluated like any tool, and an
allow rule is shipped in the default workspace policy:

```
unified.stage_attachment(for_tool, match, label, content | content_base64 | from_call, media_type?, note?)
    -> {"staged_id", "sha256", "expires_at"}
unified.list_staged() / unified.discard_staged(staged_id)
```

- `for_tool` is the tool URI the attachment is for (`mcp://insurance/approve_claim`). `match` is an optional subset of params that must equal the deferred call's params (`{"claim_id": "CLM-2001"}`). An attachment staged for CLM-2001 can therefore never ride along on CLM-2002.
- On the next DEFER of a matching call **from the same principal and session**, staged items are attached in staging order and consumed. They expire unused after 15 minutes. Staged items are held in the enforcement point's memory and spool, and are never sent anywhere until a DEFER consumes them.
- `from_call` names the action digest of an earlier tool call in this session. The hub attaches that call's **recorded result** as the content, with `source: observed` (§6.1). This is the highest-strength evidence an agent can offer: "the get_claim result I based this on", as captured by the hub rather than retyped by the agent. It requires the hub to have recorded the result (`record_payloads`), and gives `unavailable` otherwise.
- Agent-supplied content (`content` / `content_base64`) is `source: agent`.

The agent's instructions are therefore to stage first and then call: "stage the
photos and the invoice for approve_claim CLM-2001, then call approve_claim". The
tool descriptions say exactly that, because the descriptions are what an agent
reads.

### §4.3 Attaching to a pending request — late evidence

```
unified.attach_to_approval(approval_ref, label, content | content_base64 | from_call, ...)
```

- `approval_ref` is the id the control plane returned when the request was queued. The enforcement point surfaces it in the DEFER's tool result or error (`{"approval_ref": "01M4…", "status": "awaiting_approval"}`) for surfaces that do not block. The sample claims desk returns it with its 202, for example. Another session or process of the *same principal* can attach while a blocking call waits.
- Only while the request is **pending**, and only through the **credential that queued it**. A different sidecar, or another fleet's, gets a 404.
- The console marks late attachments: "added 14:02, after the request was raised at 13:58". Evidence that turns up after someone has started reading is worth noticing.

Programmatic late attachment is the same call in the SDK:
`await ua.attach_to_approval(ref, Attachment...)`.

## §5 Binding what was seen to what was answered

The decision signature today covers `action_digest, kind, approver, scope,
resolved_at, expires_at, nonce, fleet_id` (control plane `signing.sign_decision`).
It does not cover what the approver was shown. This spec adds
**`attachments_digest`** to the signed resolution:

1. When resolving, the console sends the `attachments_digest` of the manifest it rendered. The resolve body gains the field, and `ApprovalResolutionIn` stays `extra="forbid"`.
2. The control plane compares it with the request's current manifest. If they differ, the response is **409** ("new evidence was attached since you opened this request; review it"). The approver is never recorded as having seen something they did not. This is the policy page's `based_on`, applied to evidence.
3. The digest is part of the signed decision. A **resolution format version bump** (attest `RESOLUTION_VERSION`) is required. The sidecar verifies with `accept_resolution(..., attachments_digest=<what it uploaded + what it attached late>)` and refuses a resolution whose digest names any other manifest (`Reason.ATTACHMENTS_MISMATCH`), exactly as it refuses one for a different action. A control plane that showed the approver a substituted document cannot produce a decision the sidecar will honour.
4. Old sidecars (previous resolution version) keep working for requests **without** attachments. A request with attachments from such a sidecar is impossible, because only new sidecars send them.

The audit chain records the manifest digest with the approval
(`RecordedApproval.attachments_digest`), and the decision evidence shipped to the
control plane carries the manifest's metadata (hashes, sizes, types, labels,
sources — never content). An evidence pack can therefore show, offline, which
documents the approver was shown, by hash.

## §6 Trust and safety

### §6.1 Provenance is shown, never inferred

| source | meaning | console badge |
|---|---|---|
| `observed` | captured by the enforcement point from an upstream tool response it relayed | **Captured by gateway** |
| `application` | supplied by application code via the SDK | **From application** |
| `agent` | supplied by the agent (staged or attached by tool) | **Provided by agent — unverified** |

The source is set by the surface that receives the attachment, never by the
caller. The MCP staging tools force `agent` unless `from_call` resolves to a
hub-recorded result. The SDK sets `application`. Neither accepts a `source`
argument. An agent that could label its own upload "observed" would make the
badge decorative.

### §6.2 Prompt injection runs the other way here

Attachments are shown to people, and people are what they are aimed at. A PDF
saying "pre-approved by supervisor, approve immediately" is social engineering of
the reviewer, and an agent compromised enough to want a payout would write
exactly that. The console therefore:

- shows `agent` attachments below `observed` and `application` ones, under the unverified badge;
- never renders an attachment's text as UI chrome (no attachment content in titles, summaries or buttons);
- if the Guardian or any model ever summarises attachments, treats them as untrusted input — out of scope for v1, but noted here because it is the obvious next step.

### §6.3 Rendering without executing

- **Allowlist**, sniffed from content and not trusted from the declared type or extension: `application/pdf`, `image/png`, `image/jpeg`, `image/webp`, `text/plain`, `text/csv`, `application/json`. HTML and SVG are refused, because both are script containers. Archives are refused, because the reviewer cannot judge what they cannot see.
- Downloads are served from a dedicated console route with:
  - `Content-Disposition: attachment` for PDFs by default;
  - `Content-Security-Policy: sandbox; default-src 'none'`;
  - `X-Content-Type-Options: nosniff`;
  - the sniffed type.
- Images are shown inline after a server-side decode and re-encode (stripping metadata, including GPS EXIF: a claimant's home location is not the reviewer's business).
- PDFs are offered in a sandboxed viewer `iframe` with no same-origin privileges.
- JSON, CSV and text are rendered as escaped text, pretty-printed in the same way `payloads.tsx` renders values.
- Optional malware scan hook (`ATTACHMENT_SCAN_COMMAND`, a ClamAV or ICAP adapter). Until it reports clean, an attachment shows "scanning". A detection shows "blocked" with its hash, and the content is never served.

## §7 Content doctrine

Attachments are customer content, so they follow the **payload** rules, not the
approval-params precedent:

- **Encrypted at rest** under the payload key (AES-256-GCM, AAD = fleet | approval id | sha256), as payloads are. Self-hosted deployments may configure an object store (S3, with SSE-KMS and a per-tenant key under the HSM work), and the database row then holds the ciphertext location.
- **Governed by the fleet's capture setting.** A `hosted` deployment refuses attachments unless the fleet opted in, as it refuses payloads. A refused upload yields an `unavailable` manifest entry (`detail: "not_accepted"`). The approver sees that evidence exists, with its hash and label, and without content.
- **Transport:** https, or http to loopback only (`payload_transport_ok`). This is the same rule console approvals already apply.
- **`payloads: off` / `audit_level: minimal`:** no attachment content leaves the enforcement point. The manifest is sent with hashes and labels, so the approver can see that the evidence exists and what it is called. This mirrors `params_withheld`. Note that `params_withheld` itself is currently **dropped by the control plane** (not stored or shown). That is fixed as part of this work, because "withheld" and "there was nothing" must look different to a reviewer.
- **Reads are attributed:**
  - Opening an attachment requires `read_attachments` (until `entity-rbac.v1` lands: `read_payloads`).
  - Every open writes an admin event (`read_attachment`, target = sha256).
  - The resolution records which attachments the approver opened before answering. The console shows "viewed 2 of 3" on the decision, which is what a reviewer of the reviewer wants to know.
- **Retention:** attachments live as long as their approval row (pruned with it, `retention.py`) and never longer than the fleet's payload retention. Unconsumed uploads (§8) are deleted after 24 h.

**The params gap.** As built, approval params are stored in plaintext JSON and
returned to any fleet caller, which bypasses the hosted refusal and
`read_payloads`. That is the "named exception" of `evidence-retention.v1`.
Attachments make the exception larger by orders of magnitude if they inherit it.
This spec does not fix params, but the control-plane work should open that ticket
alongside it.

## §8 Wire contract (control plane)

Attachments are uploaded before the request references them. Bytes stay out of
the approval JSON, whose route has no body limit today.

```
POST /api/v1/approvals/attachments            (sidecar credential, channel proof)
     multipart: file + {label, media_type, source, note, origin_ref}
  -> 201 {"sha256", "size", "media_type", "status": "stored" | "not_accepted", "expires_at"}
     content-addressed per (fleet, sha256): re-uploading the same bytes is a no-op

POST /api/v1/approvals                         (existing; one new field)
     {..., "attachments": [manifest entries]}
  -> each `stored` entry must exist for this fleet with a matching sha256, size and type, or 422
  -> receipt adds {"attachments_digest", "limits": {...}}

POST /api/v1/approvals/{id}/attachments        (§4.3; the queuing credential only; pending only)
     {"attachments": [manifest entries]}          (stored entries uploaded first, as above)
  -> 200 {"attachments": [full manifest], "attachments_digest"}; 404 other credential; 409 not pending
GET  /api/v1/approvals/{id}/decision           (resolved with attachments: + "attachments": [full manifest])
GET  /api/v1/approvals/{id}                    (detail gains "attachments" manifest + per-viewer "viewed")
GET  /api/v1/approvals/{id}/attachments/{sha256}   (operator; read_attachments; admin event; 404 across fleets/entities)
POST /api/v1/approvals/{id}/resolve            (body gains "attachments_digest", §5)
```

Server-side checks:

- The sha256 of the received bytes must equal the declared hash.
- Type sniffing, against the allowlist in §6.3.
- The limits in §3.3.
- Per-fleet attachment storage counts toward `payload_fleet_max_bytes`.
- `ApprovalRequestIn` gains `attachments` and a body limit (8 MiB, which a manifest never approaches). The route currently has neither.

`RemoteApprovals.ask` becomes:

1. upload each attachment, skipping any the control plane already holds by hash;
2. queue with the manifest;
3. poll as today;
4. verify the resolution: every entry this client attached (initially, or late through `attach`) must be in the returned manifest unaltered, or the answer is refused (`ATTACHMENTS_MISMATCH`); the digest is then recomputed over the returned manifest -- which may include late entries another process of the same credential added -- and must equal the signed one.

## §9 Console

- **Queue card:** a "📎 3" badge, with the source badges summarised. "1 unverified" is shown when any attachment is `agent`-sourced.
- **Detail page:**
  - An **Evidence** panel listing each attachment's label, source badge, type, size, added time (late attachments are flagged), sha256 (short, with copy), and note.
  - Inline preview per §6.3, plus open and download actions.
  - `unavailable` entries are shown with their reason.
  - The Decide form carries the rendered `attachments_digest` as a hidden field and handles the 409 (§5) by reloading the panel with a banner: "new evidence was attached; review before answering".
- **History:** a resolved decision shows its manifest and "viewed N of M by <approver>".
- **Entity scoping and the CSR role:** see `entity-rbac.v1` §3 and §5.

## §10 Hub configuration

```yaml
control_plane:
  attachments: auto        # auto | off   (off: manifests only, no content leaves)
approvals:
  attachments:
    staging_ttl_seconds: 900
    max_bytes: 10485760
    providers_timeout_seconds: 5
```

The terminal approval channel lists attachments as label, source, size and hash,
and writes them to a temp directory so a person at the terminal can open them.
The terminal is a development surface, and that is stated in the output.

## §11 Phasing

| phase | delivers |
|---|---|
| **P1** | `Attachment` + `ApprovalRequest.attachments`; SDK `attachments=` (sequence or callable) on `check_async`, the `action()` decorator and `ToolGuard`; registered providers; control-plane upload, manifest, encrypted storage, read route with admin event; console Evidence panel (PDF/image/JSON/text); §5 binding and resolution version bump. **Demo:** the sample claims desk attaches the invoice PDF and damage photos for CLM-2001, and the CSR sees them before approving. |
| **P2** | MCP staging tools in the hub and the `mcp_guard` helper; `from_call` observed attachments; late attachment by `approval_ref`; "viewed N of M". |
| **P3** | object-store backend; scan hook; EXIF stripping with re-encode for every image type; entity scoping (with `entity-rbac.v1`). |

## §12 Test plan (the properties that matter)

- **Binding:**
  - A resolution whose `attachments_digest` differs from the client's manifest is refused by the sidecar (`ATTACHMENTS_MISMATCH`).
  - The control plane returns 409 when evidence changed between render and resolve.
- **Provenance:**
  - An agent cannot obtain `observed` or `application` by any argument.
  - `from_call` with an unrecorded call yields `unavailable`, not agent content labelled `observed`.
- **Matching:** an attachment staged for CLM-2001 is never attached to CLM-2002. One staged by principal A is never attached to principal B's call.
- **Callable laziness:** a callable passed as `attachments=` (or a registered provider) is not invoked for ALLOW or DENY.
- **Provider failure:** it is surfaced as an `unavailable` entry, and the request is still queued.
- **Content doctrine:**
  - In hosted mode without opt-in, no bytes are stored.
  - `payloads: off` sends manifests only.
  - Every read writes an admin event.
  - A cross-fleet read returns 404.
- **Rendering:**
  - An SVG or HTML upload is refused even when declared as `image/png` (sniffing).
  - Served responses carry the sandbox CSP.
- **Digest:** the engine and the control plane agree on `attachments_digest` over a shared vector file.

## Open decisions

- **A1 — Is `attachments_digest` in the signed resolution required in P1? → Decided: yes, P1.** The resolution format version bump ships with the first release of attachments.
- **Display → decided: everything inline.** Every attachment is previewed on the detail page without an extra click, for anyone holding `read_attachments`. Each render still writes the read admin event, so "viewed N of M" becomes "rendered to N people". The per-item open tracking in §7 is kept for downloads.
- **A2 — Do the MCP staging tools live in the hub only, or also in `mcp_guard`-based servers** (like the sample claims desk)? Recommendation: both, sharing one implementation in `unified_sdk.adapters`.
- **A3 — Default for `agent`-sourced attachments in hosted deployments.** Accept (badged unverified), or refuse unless the fleet opts in? Recommendation: accept, badged. Refusing pushes agents to paste the same content into `note`, where it has no badge at all.
