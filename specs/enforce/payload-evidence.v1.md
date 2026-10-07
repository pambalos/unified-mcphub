# Payload evidence — v1

Arguments and results, copied to the control plane where the deployment allows
it, verifiably equal to what the customer's signed chain recorded.

## Why

Decision evidence (`evidence.v1`) is metadata and digests only. That keeps a
**hosted** control plane out of every customer's agent traffic, which is the
point of hosting it that way. A **self-hosted** control plane runs inside the
customer's perimeter; there, refusing the content protects nothing and leaves
the console, History and exports unable to show what an agent actually sent.

So:

| Deployment | Default | Change it |
|---|---|---|
| self-hosted (`UNIFIED_CP_DEPLOYMENT=self_hosted`, the default) | **accept** payloads | per fleet: `capture off` |
| hosted (`UNIFIED_CP_DEPLOYMENT=hosted`) | **refuse** payloads | per fleet: `capture on` (opt-in) |

The reporter can always decline locally (`control_plane.payloads: off`). It
never sends unless the control plane has said it accepts.

The customer's signed chain stays the record. A payload in the control plane
is a copy whose equality to that record is checkable, never a replacement.

## Wire

`POST /api/v1/evidence/payloads` with `{"payloads": [record, ...]}`, same
credential and request proof as `POST /api/v1/evidence`.

A record:

| field | signed | meaning |
|---|---|---|
| `action_digest` | yes | the action this payload belongs to |
| `chain_seq`, `chain_hash` | yes | the chain entry the value was detached from (a hub's `received` entry for `args`, its `completed` entry for `result`) |
| `path` | yes | the detached path: `args`, `result`, `payload.action.params`, … |
| `digest` | yes | the salted digest the chain entry commits to (`detached[path]`) |
| `size_bytes` | yes | length of the canonical JSON of `value` |
| `salt` | no | standard base64 of exactly 16 bytes, from the entry's `salts[path]` |
| `value` | no | the value as the chain hashed it: `canonical(value)` parsed back as JSON |
| `sig`, `key_id` | — | reporter signature (base64url) over the signed fields |

Signed form and checks: `attest.payload_evidence_payload`,
`attest.sign_payload_evidence`, `attest.accept_payload_evidence` (version
`PAYLOAD_EVIDENCE_VERSION = 1`). The content is not inside the signature; the
digest is, and `sha256(salt ‖ canonical(value)) == digest` binds the content
to it (`attest.payload_content_digest`, identical to `detach.digest`).

A record that fails either check is **refused**, not stored as unattested:
content that does not match its digest is not the recorded content. The
decision row and the customer's chain are unaffected.

Further checks, each refusing the record (never raising):

- **The salt is exactly 16 bytes** of strict base64 (`validate=True`). The
  digest has no framing between salt and content, so only the salt's length
  fixes the boundary; accept any length and leading bytes of a value can be
  moved into the salt with the digest still matching (`123` as salt‖`1` and
  `23`). detach.py has only ever written 16-byte salts, so no existing chain
  is affected; `detach.check` (and so the evidence-pack verifier) applies the
  same rule.
- **`size_bytes` equals the length of `canonical(value)`**, checked after the
  digest, with its own message (`payload size_bytes does not match its
  value`).
- `chain_seq` and `size_bytes` are integers (not booleans); the record is an
  object.

`canonical` is detach.py's: sorted keys, no whitespace, UTF-8, and anything
JSON cannot carry stringified. The reporter ships `value` as those bytes
parsed back, so a date or a Decimal travels as the string that was hashed. A
value whose dict keys are not all strings does not survive that round trip
byte for byte (`{10: …, 9: …}` sorts differently once the keys are strings)
and fails the digest check: refused, safely, and still in the chain.

Response: `{"accepted": n, "refused": [{"index": i, "reason": "..."}],
"payloads": "accept"|"refuse", "max_payload_bytes": N}`.

## Discovery

The receipt of `POST /api/v1/evidence` gains `payloads` (`"accept"` or
`"refuse"`) and `max_payload_bytes`; every payload response carries both too.

- **Pending.** Until the first receipt the reporter sends nothing. It *holds*
  values offered meanwhile (none larger than 1 MiB, there being no receiver
  limit to apply yet), so the calls made just after a restart are not lost to
  the race with the first decision batch.
- **Accept** (`"payloads": "accept"` with a positive integer
  `max_payload_bytes`): held values ship. A value larger than
  `max_payload_bytes` is not sent; the console says it is held only in the
  customer's chain.
- **Refuse** -- any other receipt, including one that says nothing about
  payloads, and `accept` without a usable limit: held values are discarded
  and nothing more is queued. Three decision batches shipped with no receipt
  at all also settle to refuse.
- The gate is re-read **before every batch**: a refusal or a lower limit that
  arrives mid-flush (on a payload response, or on a decision receipt) applies
  to the next batch.

## Reporter obligations

- **https only.** Payloads are sent only to an `https://` control plane, or to
  plain `http://` on loopback (`localhost`, `127.0.0.1`, `::1`). Otherwise the
  reporter builds no payload stream and logs once why.
- **`audit_level: minimal`.** A call whose deciding rule is `minimal` ships no
  payloads, neither arguments nor result. The chain still records the content
  (detach.py); `minimal` is the default view and export, and this copy is an
  export.
- **Approvals are a separate copy.** A console approval request shows the
  approver the action's arguments, governed by approval.v1 §5 rather than by
  this stream's gate: never `context.extra`; no arguments for a `minimal` rule
  or a hub with `control_plane.payloads: off`; and only over https (loopback
  http excepted). The decision binding is unaffected — the control plane keys
  and signs on `action_digest`, which the reporter computed over the full
  action.
- **Only portable JSON.** A value whose canonical bytes are not strict JSON
  — a `NaN`/`Infinity` (Python writes them as bare tokens, which a strict
  parser, proxy or WAF rejects along with the rest of the batch) — or that
  does not survive a parse and re-serialise byte for byte (non-string keys:
  `{10: …, 9: …}` sorts numerically when digested and as strings when parsed
  back; keys of mixed type cannot be sorted at all) is not sent, and is
  counted as `unportable` in the hub's `fleet.payloads` status. It cannot be
  repaired: the digest is over those exact bytes, so any substitute would
  fail verification. The chain still commits to it.
- **Only beside a row.** Payloads are offered only for a decision row that was
  actually queued, under the same `action_digest` (a hub: the lenient digest
  its `received` entry records). Findings (`count=False` records) ship none.
- **Bounded batches.** At most 20 records and 8 MiB of `size_bytes` per
  request, UTF-8 without `\u` escaping. On HTTP 413 the reporter splits the
  batch and resends the halves; a single record refused for size on its own is
  discarded and counted. A batch that cannot be serialised is discarded, never
  retried.

## Control plane storage and access

- Stored encrypted (AES-256-GCM, key `UNIFIED_CP_PAYLOAD_KEY`; AAD binds fleet,
  reporter, chain hash and path), separate from decision metadata. Unique on
  (fleet, reporter, chain_hash, path).
- Reading content needs the `read_payloads` capability (approver, policy_admin,
  owner — not viewer). Every read is recorded as an admin event.
- Retention per fleet (`payload_retention_days`; default 90 self-hosted, 30
  hosted), pruned by the refresher service.
- History shows a row's arguments and result, marked "matches signed digest";
  Export has an opt-in `include_payloads` (CSV columns `args_json`,
  `result_json`), gated by the same capability.
