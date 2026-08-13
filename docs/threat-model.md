# Threat model

**Ticket:** UAI-80. Companion to [SECURITY.md](../SECURITY.md).

The claim this project makes is narrow on purpose:

> A rogue agent cannot exceed its policy, and here is its full action history.

Not "we detect rogue agents". Detection is a classifier that degrades as attacks
evolve; containment is architectural and stays true. Everything below is written
to that standard — each boundary states its attacker, the control, and **what is
still true after the control**, because a residual risk stated plainly is
defensible and the same risk discovered by a reader is not.

---

## 1. Identity boundaries

Seven places where one party has to prove who it is to another. Each is
adversarially tested: `tests/test_spoofing.py` in the control plane registers an
attack per boundary and **fails the build if a new route or artifact appears
without one**, so this table cannot quietly fall behind the code.

### sidecar → control plane

**Attacker:** a machine claiming to be a sidecar of some fleet, to read another
tenant's policy or queue approvals into their console.

**Control:** enrolment issues a bearer credential bound to a fleet; the fleet is
read off that credential and a `fleet_id` in the request body is a 422 rather
than something ignored. Join tokens are single-use, enforced by conditional
UPDATE and tested under concurrency.

**Residual:** a leaked credential is that sidecar until revoked. Revocation takes
effect on the next request — there is no cache to wait out.

### a stolen credential, without the key it is bound to

**Attacker:** someone who has the bearer token — from a log, a heap dump, a
misconfigured proxy — and not the private key.

**Control:** a client registers a public key at enrolment and signs each request
over the method, path and a digest of the body, with a 60-second life. A proof
cannot be moved to a different request, a different route, or a rewritten body.
Once a credential carries a key, an unproven request is refused and logged as
`CHANNEL DOWNGRADE`.

**Not mTLS, deliberately.** The control plane sits behind a TLS terminator and
never sees a client certificate, so mTLS would mean trusting a header the proxy
is supposed to have stripped — a check whose correctness depends on topology and
is invisible by inspection. mTLS at the edge remains worth having; it is not what
the binding rests on.

**Residual:** a client that leaks its private key leaks its identity.

### operator → control plane

**Attacker:** anyone who can reach the console, trying to answer approvals as
somebody else.

**Control:** authentication is an IdP (any OIDC provider) or a local password
account; **authentication is not authorisation**. A grant table decides whether a
subject may act on a fleet and is consulted on every request, so a grant
withdrawn while somebody is looking at a queue stops working on their next click
rather than when a cookie expires. Roles are viewer / approver / policy\_admin /
owner.

**Residual:** an operator's IdP account is as strong as their IdP. Local password
accounts are weaker than a Workspace identity with 2FA, which is why their
subjects are namespaced `local:` — an audit record shows which kind of
authentication produced a decision without a join.

### console acting on behalf of an operator

**Attacker:** a compromised console, or anyone who can reach the API holding the
console's credential, claiming to act for a human.

**Control:** the console's bearer credential says "this is the console"; a
separate short-lived assertion, signed with a key bound to that credential, says
"and it is acting for this person, on this operation, right now". Assertions live
two minutes and a resolve is bound to the approval id it answers, so a captured
one can at most re-answer a settled question — which is a 409.

**Residual:** a console holding both its credential and its assertion key can
speak for any operator granted on its fleet. The response to a compromised
console is revoking its credential, not rotating a key quietly.

### control plane → sidecar: approval decisions

**Attacker:** anything serving plain JSON that says "approved", to release an
action a policy floor deliberately held.

**Control:** decisions are signed; an unverifiable allow is a denial. The
verifier is the same code in both places — vendored verbatim and pinned by hash,
because two implementations of verification that drift are a vulnerability rather
than a bug.

**Residual:** the signing key is online by necessity. Compromising the control
plane's decision key forges decisions until the key set is republished, which is
what the offline root exists for.

### control plane → sidecar: policy and revocations

**Attacker:** whoever can serve a sidecar a document — including a
TLS-terminating proxy somebody added for observability.

**Control:** bundles are signed and carry a monotonic version plus a short
expiry. A rollback to an older-but-validly-signed bundle is refused and alarmed;
a file whose hash does not match rejects the *whole* bundle. **No valid bundle
means deny everything.** A revocation list that cannot be verified escalates
rather than assuming nobody is contained — the asymmetry is deliberate: old rules
are still rules, but "I do not know whether this agent was stopped" is not a
reason to let it run.

**Residual:** an air-gapped fleet running on an expired key set eventually
refuses to verify anything. That is the intended failure and the reason expiry
*is* the revocation mechanism where there is no network.

### agent → gateway

**Attacker:** an agent claiming a principal id it was not issued, to inherit
another agent's authority.

**Control:** identity is established at the gateway rather than taken from a
header the agent controls. Principals carry how their identity was established —
`assigned` (deployment position), `derived` (an authenticated channel) or
`attested` (a workload attestation) — because a policy decision means different
things depending on which.

**Residual:** with `assigned`, per-agent policy is exactly as strong as the
customer's pod topology. That was the whole of it before attestation existed, and
it remains the level a deployment gets if it does not attest. This boundary is
tested against real Envoy rather than a paraphrase, because the failure that
motivated it — route-level header removal running *after* `ext_authz` — was
invisible by inspection and only real Envoy caught it.

---

## 2. Evidence: three tiers, and what defeats each

| tier | proves | defeated by |
|---|---|---|
| hash chain | internal consistency | an attacker who owns the writer: they rewrite the history, every hash recomputes, and `verify()` reports it pristine |
| Ed25519 signature | attributable authorship | a compromised *live* writer, which holds the key by definition |
| Merkle checkpoint, anchored | this log looked like this at time T | nothing the writer alone can do |

The first tier's limit is not a flaw in hash chains — it is what a hash chain is,
and there is a test that performs the attack and confirms it succeeds. The third
tier closes it: a sidecar publishes a signed Merkle root over a range of its log,
the anchor records and countersigns it, and a second root for the same range is
arithmetic rather than opinion.

**Inclusion proofs** are why it is a tree and not just the chain head: one action
can be proven to have been in the log at time T with that entry and about twenty
hashes, without disclosing the rest of a customer's operational history.

**Residual, and it is the important one:** an anchor is only as good as the
independence of whoever holds it. The control-plane anchor is independent of the
sidecar and its host — the attacker the first two tiers fail against — and **not**
independent of the vendor. A deployment needing that anchors somewhere the vendor
does not run; the anchor interface is a protocol for exactly that reason. Entries
written since the last checkpoint are chained and signed but not yet pinned, so
that tail remains rewritable — a bounded, reported gap, shortened by
checkpointing more often.

---

## 3. Attacks on the agent, and what enforcement does about them

**Prompt injection.** No claim to detect it. The claim is narrower and holds
under pressure: **a successful injection still cannot call a forbidden tool.**
The policy corpus asserts that the *action an injection would produce* is
stopped, not that the injection was noticed. The sharpest case is an agent
persuaded to edit infrastructure and remove its own egress lock — that operation
floors to a human.

**SSRF.** Browser and fetch tooling seeds a deny list covering loopback,
IPv6-loopback and cloud metadata endpoints across all ports, so a browser cannot
be turned into a pivot onto the instance's credentials, while the open internet
stays reachable.

**Unbounded consumption.** Per-action caps and cumulative budgets. Counting
happens outside the decision path — totals are computed by the enforcer and
handed to a still-pure engine as data — so no lookup was added to a path whose
fail-closed story depends on not having one. Totals are per sidecar: N sidecars
can permit N times a budget until the control plane's fleet view catches up and
contains the principal. That is a bounded window, declared as a passing test in
the corpus rather than as prose.

**Excessive agency.** The category this project exists for: tool allowlists,
value-level authority, destructive-action floors, human approval. Anything not
named by policy is denied, and **that default is not configurable.**

---

## 4. Supply chain

The verifier the control plane uses is vendored from the engine verbatim, pinned
by hash, with a test that fails on a local edit and a second that fails when the
copy falls behind the source. That second test exists because the first does not
catch staleness — both values are regenerated together — and the copy really did
go stale exactly that way once.

Envoy protos are vendored on the same discipline.

The policy packs are a security claim, so they are run against an adversarial
corpus: attacks paired with the legitimate calls they most resemble, because a
pack that denied everything would pass every attack case and be useless. Known
gaps are encoded as **passing tests** marked `known_gap: true` rather than
described in prose, so the day one closes, a test fails and somebody has to
change it deliberately.

---

## 5. Deliberate limits

Stated here so nobody has to discover them.

1. **The hub ships unsandboxed.** MCP servers are child processes with the
   privileges of the user that started them. Enforcement governs what an agent
   may ask a server to do; it is not a sandbox for the server. Tracked in *M0.5 ·
   Security Hardening*.
2. **`assigned` principal identity is only as strong as the deployment
   topology.** Attestation exists; a deployment that does not use it gets the
   weaker level, and the evidence records which.
3. **The vendor-operated anchor is not independent of the vendor.** See §2.
4. **Detection reports; it never contains.** Only explicit policy and explicit
   human action stop an agent. Reasoning in
   [rogue-agents.md](https://github.com/pambalos/unified-control-plane) (control
   plane, `docs/rogue-agents.md`).
5. **Rate limiting at the edges is in-process.** Per-instance and forgotten on
   restart; real limiting belongs in front of every instance.
6. **Nothing downstream of a compromised writer can fix a writer that lied.**
   Evidence continuity detects gaps and forks; it cannot detect an action that
   was never recorded. Anchoring bounds this, it does not remove it.

---

## 6. How to check any of this

Most claims here correspond to a test, and the interesting ones correspond to a
*negative control* — a script that breaks the defence on purpose and fails if the
test suite stays green. There are 36. A claim in this document that is not
enforced by something executable should be reported as a documentation bug, which
is the standard the rest of the project is held to.
