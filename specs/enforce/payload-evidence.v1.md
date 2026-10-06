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
| `salt` | no | base64, from the entry's `salts[path]` |
| `value` | no | the raw value |
| `sig`, `key_id` | — | reporter signature (base64url) over the signed fields |

Signed form and checks: `attest.payload_evidence_payload`,
`attest.sign_payload_evidence`, `attest.accept_payload_evidence` (version
`PAYLOAD_EVIDENCE_VERSION = 1`). The content is not inside the signature; the
digest is, and `sha256(salt ‖ canonical(value)) == digest` binds the content
to it (`attest.payload_content_digest`, identical to `detach.digest`).

A record that fails either check is **refused**, not stored as unattested:
content that does not match its digest is not the recorded content. The
decision row and the customer's chain are unaffected.

Response: `{"accepted": n, "refused": [{"index": i, "reason": "..."}],
"payloads": "accept"|"refuse", "max_payload_bytes": N}`.

## Discovery

The receipt of `POST /api/v1/evidence` gains `payloads` (`"accept"` or
`"refuse"`) and `max_payload_bytes`. A reporter starts in `refuse` and ships
payloads only after a receipt says `accept`. A value larger than
`max_payload_bytes` is not sent; the console says it is held only in the
customer's chain.

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
