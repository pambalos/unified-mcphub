# Unified AI — Product & Repository Map

> The enforcement plane for AI agents — self-hosted, cross-platform, and able to say no.

This file exists in every active product repo. It states **what this repo owns** and gives
**short descriptions of the others**, so anyone can see at a glance which repo owns which part
of the product. Keep it current when scope moves between repos.

Fuller company positioning lives at [unified-ai.app](https://unified-ai.app) and in
`unified-ai-docs`. Technology choices for this repo are locked in
[technologies.md](technologies.md); architecture decisions continue as ADRs under `specs/`.

---

## This repo owns — `unified-mcphub` (open-core, MIT)

The **engine and open data plane** — the half of the open-core split that ships MIT and must
always build and run clean with no commercial component.

- **`packages/unified-enforce` — the engine.** Action canonicalization
  (`{principal, tool, verb, resource, params, context}`), policy-as-code evaluation
  (`ALLOW` / `DENY` / `DEFER`-to-human) with a constitutional > exact > floor > wildcard
  precedence model, the hash-chained tamper-evident audit log with offline `verify`/`replay`,
  the approval contract, OTel decision spans, and the Envoy **ext_authz gateway** (gRPC + HTTP)
  with mTLS and egress-lockdown templates (the no-bypass guarantee). Measured p99 3.6–8.4 ms
  in-process.
- **`packages/unified-mcphub` — the MCP hub.** The first integration of the engine: one
  audited, policy-gated MCP server that every AI harness connects to instead of wiring up its
  own tool servers. Default-deny authz, an approval TUI, an append-only audit log, the
  **deployment security profile** (`policy_protection: open|locked`, reload-gating, constitutional
  config-dir protection, operator `reload`), and per-agent identity ingestion (mTLS SAN / OIDC /
  SPIFFE).
- **`packages/unified-sdk` — the optional SDK.** Client library that annotates actions with
  business semantics (a refund vs. a lookup) for finer-grained policy. "The proxy is the lock;
  the SDK is the label."
- **`packages/unified-mcp-servers`** — first-party light/safe MCP servers (filesystem, shell,
  fetch, python, documents). **`packages/unified-mcp-client`** — the async MCP client the hub
  uses upstream. **`packages/unified-paths`** — shared path canonicalization the decider and the
  actor both import. **`packages/unified-mcp-graphify`** — optional code-knowledge-graph server.
- **`deploy/terraform`** — data-plane IaC (agent/sidecar security groups, egress allowlists;
  BYOC / self-hosted / hybrid). *There is no control plane in this repo.*

The engine never depends on the control plane. Policies flow down, evidence flows up, over a
versioned API.

---

## Repository map

**The product (enforcement plane):**

| Repo | Owns | License |
|---|---|---|
| **`unified-mcphub`** ← *this repo* | Engine (`unified-enforce`), MCP hub, SDK, Envoy gateway/egress, first-party MCP servers, shared libs, data-plane IaC | **MIT (open-core)** |
| **`unified-control-plane`** | The commercial control plane: fleet policy distribution (signed bundles), evidence ingestion + court-grade audit checkpoints, the human approval/DEFER queue, containment/kill-switch + signed revocation lists, the **Guardian** (detect→propose→confirm, enterprise-gated), operator identity/RBAC/sessions, and the Next.js **console** (`web/`). Multi-tenant-safe data layer. | Proprietary |
| **`unified-ai-docs`** | Single source of truth: ADRs, specs, roadmap, plans, reviews (referenced by ADR number); GTM/outreach materials; Guardian capstone design. | — |
| **`unified-web`** | Marketing site (`unified-ai.app`), `/investors` page, one-pager PDF. Vercel git-integration deploy. | — |

**Legacy (pre-pivot, superseded — not part of the current product):**

- **`unified-be`** — old "LLM chat platform" backend (BYOB storage, agentic cloud).
- **`unified-fe`** — old multi-mode AI chat frontend (was `chat.unified-ai.app`, now delinked).
- **`unified-orchestrator`** — the original monorepo the current repos were extracted from.

**Unrelated (not the product):**

- **`toon`** — Token-Oriented Object Notation, a separate open-source format project.
- **`unified-tracking`** — a personal LLM-cost tracking tool (DuckDB over JSONL).

---

## Open-core & tiering

- **Open-core split:** the engine/hub/SDK/gateway are **MIT** (this repo); the control plane is
  **proprietary** (`unified-control-plane`).
- **Tiers (enforced by a signed, offline-verifiable license — no phone-home):**
  - *Free / self-hosted* fully **enforces** — allow/deny/defer, hash-chained signed audit, kill
    switch, single-fleet console.
  - *Paid — self-hostable or cloud* adds the **operate/aggregate/report** layer: the Guardian
    (Detect), multi-fleet management, SSO/SCIM/RBAC, SIEM/SOAR export, compliance evidence reports,
    HSM/per-tenant keys. Paid features run air-gapped too; the moat is "you pay," not "we hold your
    data."
- **Cloud multi-tenant** (vendor-run, shared-DB default + dedicated-instance premium) is in design
  — see the Linear **"Cloud & Enterprise Offering"** project.

## Wedge and expansion

1. **Enforce** — action authorization (the moat) ← this repo + the control plane
2. **Detect** — compromised agents & anomalies, contained via the plane (the Guardian, enterprise)
3. **Test** — pre-release replay of recorded actions against candidate policies/models; red-teaming
4. **Align** — policy packs & evaluation datasets (BYO or co-built)

---

*Keep this accurate: when a component moves repos, or a new repo joins the product, update the
"This repo owns" and "Repository map" sections here and in the sibling `product.md` files.*
