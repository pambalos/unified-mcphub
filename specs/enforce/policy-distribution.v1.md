# Signed policy distribution — v1

**Status:** accepted, unimplemented. Written before the code deliberately.
**Date:** 2026-08-12
**Tracking:** UAI-176. Related: UAI-175 (signed decisions), UAI-165 (kill switch), UAI-179 (key custody), UAI-182 (failure modes).

## Why this is specified before it is built

An attacker who can push policy does not need to defeat the enforcement plane.
They push allow-all and walk through it, and the audit chain will faithfully
record that nothing was violated. It is the highest-value attack on the whole
architecture — cheaper than compromising a sidecar, quieter than tampering with
the chain, and it leaves evidence that actively argues in the attacker's favour.

Policy distribution is not built yet, which is the only reason this document can
be written cheaply. Every property below is expensive to retrofit and nearly
free to specify now.

## Summary of decisions

| | Decision |
|---|---|
| Signed unit | A manifest of content hashes, not the files themselves |
| Encoding | Detached-style JWS over exact bytes — no canonicalisation |
| Freshness | Monotonic version **and** short expiry; both are required |
| Keys | Offline root signs a key set; online key signs manifests |
| Trust anchor | Root public key pinned at enrolment |
| Distribution | Pull-only, transport-agnostic |
| On expiry | Keep enforcing last-known, alarm loudly |
| With no bundle at all | Deny everything |
| Customer-held keys | Designed for, not shipped in v1 |

---

## 1. Sign the bytes, not the object

Decision signing (UAI-175) canonicalises, because a decision's fields travel as
separate JSON keys and the verifier reassembles them. That design produced a
real bug: `isoformat()` timestamps signed differently on SQLite and Postgres,
so a signature verified only where it was made.

Bundles have no such constraint. The manifest is transmitted **verbatim** and
the signature covers those exact bytes. There is no canonical form to agree on,
no float rule, no timestamp formatting, and no opportunity for producer and
consumer to drift. Every class of bug the decision signer has to defend against
is simply absent here.

This is the single most important choice in the document and it is free.

### Envelope

RFC 7515 JWS, General JSON Serialization, so a reviewer recognises it and the
signing input is defined by an existing standard rather than by us:

```json
{
  "payload": "<base64url(manifest bytes)>",
  "signatures": [
    {
      "protected": "<base64url({\"alg\":\"EdDSA\",\"kid\":\"0522f7d844e19e34\"})>",
      "signature": "<base64url(sig)>"
    }
  ]
}
```

Signing input is `ASCII(BASE64URL(protected) || '.' || BASE64URL(payload))`, per
the RFC. Because `payload` carries the manifest's literal bytes, this preserves
the sign-the-bytes property.

`signatures` is a list, and that is deliberate: it is what allows a bundle to
carry both our signature and the customer's later (§6) without a format change.

### Manifest

```json
{
  "schema": "unified.policy-bundle/v1",
  "fleet_id": "acme",
  "version": 47,
  "issued_at_ms": 1786000000000,
  "expires_at_ms": 1786086400000,
  "mode": "enforce",
  "files": [
    {"path": "policies/owasp-llm-top10.yaml", "sha256": "…", "size": 4211},
    {"path": "policies/payments.yaml",        "sha256": "…", "size": 812}
  ]
}
```

One signature regardless of bundle size; partial or resumed fetches stay
verifiable; each file is checked against its hash before it is parsed. Same
shape as an OCI manifest, for the same reasons.

Policy files travel alongside the manifest by any means (§4). They are not
signed individually and do not need to be — a file whose hash is not in a
verified manifest is not policy.

---

## 2. Rollback, freeze, and why a version number is not enough

**Rollback.** Last month's policy, from before a floor was added, is validly
signed forever. The obvious defence is a monotonic version, and it is necessary
but not sufficient.

**The fresh-client hole.** A sidecar that has just started has no previous
version, so it has no floor to compare against. An attacker serves it a genuine
old bundle and it accepts happily. This is the failure people skip, because a
long-running sidecar is protected and the hole only opens on restart —
i.e. during a deploy, an autoscale event, or an incident.

**Freeze.** An attacker who can drop traffic does not need to forge anything.
They stop serving updates. The sidecar keeps enforcing v41 indefinitely, and
*nothing looks wrong* — the fleet is up, decisions are being made, the console
is green.

A short `expires_at` inside the signature closes both. An old bundle presented
to a fresh sidecar is expired. A frozen feed becomes a visibly stale one.

### Acceptance rule

A sidecar accepts a manifest when **all** hold:

1. The JWS verifies against a key valid for the `policy` role (§3).
2. `schema` is recognised.
3. `fleet_id` equals the sidecar's own fleet.
4. `expires_at_ms > now`, allowing bounded clock skew (§7).
5. `version > current`, **or** `version == current` and `expires_at_ms` is
   strictly greater than the current one.

Rule 5's second branch is what lets the control plane refresh freshness without
inventing versions. Manifests are re-signed on a schedule (suggested: expiry of
24h, re-signed every 6h) with the same version and a later expiry. Policy
changes increment the version; time passing does not.

> *Alternative considered:* TUF's separate `timestamp` role — a tiny frequently
> re-signed document pointing at the current manifest hash, leaving manifests
> immutable. Cleaner, and the right answer if manifests ever get large or if
> re-signing cost matters. Rejected for v1 only because it adds a third artifact
> for no benefit at current sizes. The upgrade path is additive.

---

## 3. Key hierarchy

Two roles. Not TUF's five, and not one.

- **Root** — offline, in an HSM or on a hardware token, used a handful of times
  a year. Signs only a *key set*. Long expiry (suggested: 1 year).
- **Policy** — online, in the control plane, signs manifests. Short-lived
  (suggested: 90 days).

The key set is itself a JWS signed by root:

```json
{
  "schema": "unified.keyset/v1",
  "issued_at_ms": …,
  "expires_at_ms": …,
  "keys": [
    {"kid": "0522f7…", "alg": "EdDSA", "role": "policy", "public_key": "…", "expires_at_ms": …},
    {"kid": "9a17bb…", "alg": "EdDSA", "role": "decision", "public_key": "…", "expires_at_ms": …}
  ]
}
```

**The sidecar pins the root public key at enrolment** and nothing else. Every
other key reaches it inside a root-signed key set.

This is what makes rotation possible. With a single online key, rotating means
re-enrolling every sidecar in the fleet — which means it will not be done, and a
key that is never rotated is the real outcome. With a root, rotation is a signed
message. It also contains blast radius: compromise of the online key lets an
attacker sign policy until the key set is reissued; it does not let them mint
new keys or forge a key set.

It further lets the decision-signing key (UAI-175) be distributed the same way,
which closes the rotation gap left open there — decision keys currently arrive
only at enrolment.

Overlapping validity is required in both directions: a key set may list two
`policy` keys during a rotation, and verifiers accept any listed, unexpired key.
Rotation that requires simultaneous restarts does not happen.

---

## 4. Distribution is transport-agnostic, and that is the point

Once a bundle is self-authenticating, the channel it arrives on does not need to
be trusted. Verification is byte-identical whether it came from:

- an HTTP poll against the control plane (the default; mirrors the approval
  poll already built),
- an object store the customer controls,
- a Kubernetes ConfigMap or a mounted volume,
- a git checkout,
- a file carried into an air-gapped facility on removable media.

Air-gapped deployments are therefore not a special case with weaker guarantees —
they get exactly the same verification as a SaaS tenant, which is unusual and
worth saying out loud in the C3 materials.

**Pull, never push.** Push would require inbound connectivity into the
customer's network, inverting the egress-lock arrangement that E3 exists to
provide. The sidecar has one outbound path and uses it.

### Revocations are a separate artifact

Kill-switch revocations (UAI-165) need lower latency than policy. Same envelope,
same keys, separate document with a much shorter expiry (suggested: 5 minutes)
and a correspondingly higher poll frequency.

Reusing the envelope means one verification implementation and one set of
adversarial tests. Separating the artifact means a revocation does not wait for
a policy poll, and a stale revocation list is visible as such.

Note the asymmetry, which is intentional: an expired *policy* bundle keeps
enforcing (§5), but an expired *revocation list* means the sidecar cannot know
whether an agent has been contained. That should escalate, not silently lapse.

---

## 5. Failure modes

Feeds UAI-182. The rule: **a distribution failure may cost freshness; it may
never grant permission.**

| Situation | Behaviour |
|---|---|
| Cannot reach the source | Keep enforcing last verified bundle. Not an error state until expiry. |
| Signature does not verify | Reject, keep last verified bundle, alarm. Never fall back to unsigned. |
| Bundle is for another fleet | Reject, alarm. Staging is always the weakest environment; its policy must not become production's. |
| Version older than current | Reject, alarm. This is an attack, not a mistake. |
| A file's hash does not match | Reject the whole bundle. Partial application is worse than none. |
| Bundle expired | **Keep enforcing**, alarm loudly, surface the fleet as stale in the console. Optionally escalate to DEFER (§5.1). |
| **No valid bundle at all** (fresh sidecar, cannot fetch) | **Deny everything.** |
| Revocation list expired | Escalate per configuration; do not silently assume nothing is revoked. |

The last two matter most.

A **fresh sidecar with no policy must deny**, not allow. Default-deny is already
the engine's posture and this is the one place someone might reasonably reach
for a permissive default to avoid a startup outage. It would mean an attacker
who can block one fetch gets an unprotected agent. If denying at startup is
operationally unacceptable for a customer, the answer is a bundle baked into the
deployment image — not a permissive default.

"Cannot reach the source" is deliberately **not** an alarm on its own. Brief
unreachability is normal, and alerting on it trains operators to ignore the
alert that matters. Expiry is the signal.

### 5.1 Expiry behaviour is configurable

Same axis as the kill switch's containment modes (UAI-165), and it should be the
same knob rather than a second one:

- `keep` *(default)* — continue enforcing the stale bundle, alarm.
- `defer` — escalate every action to a human while policy is unverifiable. For
  high-assurance deployments. Needs the same queue-flood protection as the kill
  switch, or a busy fleet drowns its operators.
- `deny` — refuse everything. Available, never the default; a network partition
  should not take down a customer's agents.

---

## 6. Customer-held keys

v1 signs with the control plane's key. The design must not preclude the
customer's, and two things reserve the space:

1. `signatures` is a list, so a bundle can carry ours and theirs.
2. The trust anchor is configuration, not a constant. A sidecar can be told to
   require a signature from a specific `kid` or root.

The end state worth building toward: a customer authors policy, signs it with
their own key, and we distribute it without being able to alter it. We become an
untrusted CDN for the most security-critical artifact in their deployment.

That is a claim very few vendors in this space can make, and it converts an
objection ("you could change our rules") into a differentiator. It is also
mandatory for the strongest air-gapped and BYOC positions, so the shape should
be right from the start even though the key management is deferred.

---

## 7. Clock

Expiry makes correctness depend on time.

- Verifiers allow bounded skew (suggested: 60s) when checking `expires_at_ms`.
- A sidecar whose clock is badly wrong refuses to verify and says so plainly.
  Refusing is safer than accepting, but it must be diagnosable — an
  authentication failure that presents as a mystery outage gets "fixed" by
  disabling the check.
- Timestamps are integer milliseconds, for the reason UAI-175 learned the hard
  way.

---

## 8. Shadow mode

`mode: "shadow"` in the manifest means: evaluate this bundle alongside the
active one, report where the verdicts differ, and enforce **neither** of the new
bundle's decisions.

E2's `replay()` already computes divergences against a candidate policy, so most
of this exists. It gives a safe path for the change most likely to cause an
incident — a policy edit that is either too permissive to notice or too strict
to survive.

Divergence reports ride the evidence ingest seam (UAI-150) and surface as a
diff in the console before an operator promotes the bundle to `enforce`.

---

## 9. What this does not defend against

Stated because the gaps are defensible named and indefensible discovered.

- **A compromised sidecar.** It can ignore the policy it verified. Signing
  proves the bundle is authentic, not that anyone honoured it. Detecting that is
  UAI-183 (verifying ingested evidence) and, ultimately, UAI-134.
- **A compromised online policy key.** Until the key set is reissued, an
  attacker can sign valid policy. The root limits how far that goes and how long
  it lasts; it does not prevent it. This is what makes the compromise runbook in
  UAI-179 load-bearing.
- **A malicious insider with control-plane access**, in the v1 default where we
  hold the signing key. §6 is the answer, and until it ships this limit belongs
  in the threat model (UAI-80) rather than in a footnote.
- **A policy that is simply wrong.** Signing says who wrote it, not whether it
  is any good. Shadow mode and the corpus tests are the defence there.

---

## 10. Test plan

Everything below joins the UAI-181 spoofing suite, and every case must be shown
to fail against an implementation without the corresponding check — a security
test that has never failed is decoration.

- Genuine bundle verifies; **and a vacuity test** proving the verifier rejects a
  corrupted signature, so the negative cases are not all passing trivially.
- Unsigned bundle; wrong key; key valid for the `decision` role used to sign
  policy; key expired; key absent from the key set.
- Key set not signed by root; key set expired; key set for another fleet.
- Rollback: older version rejected. Fresh sidecar offered an expired old bundle:
  rejected. Same version with an earlier expiry: rejected.
- Freeze: a feed that stops updating is stale and alarms within one expiry.
- Fleet binding: a `staging` bundle rejected by a `production` sidecar.
- File tampering: a policy file altered after manifest signing is rejected, and
  the whole bundle is rejected rather than partially applied.
- Failure matrix: every row of §5 asserted, especially **fresh sidecar with no
  bundle denies everything**.
- Clock: skew inside tolerance accepted, outside rejected with a clear reason.
- Rotation: a fleet mid-rotation, with two valid `policy` keys, accepts bundles
  signed by either and requires no restart.
- Round-trip against both SQLite and Postgres, per the UAI-175 lesson.
