# Unified AI — Product Definition

> The enforcement plane for AI agents — self-hosted, cross-platform, and able to say no.

Locked 2026-08-11 alongside [technologies.md](technologies.md). Linear project:
[Unified AI — Enforcement Plane](https://linear.app/personal-work-bj/project/unified-ai-enforcement-plane-d92891715251).
Source positioning: the Aug 2026 concept brief (one-pager) and https://unified-ai.app.

## The problem

Enterprises deploy AI agents faster than they can control them. Agents read email, query
databases, move money, and merge code — yet most governance tooling only *observes*
(traces, scores, alerts). Almost none of it can stop an agent mid-action, and the vendors
that do enforce are cloud-tethered SaaS — unusable for banks, health systems, and defense
programs that need governance inside their own perimeter.

## The product

Unified AI is a **runtime authorization layer** between every agent and everything it
touches. Each tool call, API request, and data operation is:

1. **Canonicalized** into a signed, replayable `Action`
   `{principal, tool, verb, resource, params, context}`
2. **Decided** deterministically against policy-as-code in **<10 ms** —
   `ALLOW` / `DENY` / `DEFER` (to a human)
3. **Recorded** in an append-only, hash-chained audit log with full reasoning context —
   replayable offline for auditors and incident response

Framework-agnostic (LangChain, CrewAI, MCP, homegrown) and platform-agnostic
(Bedrock, Vertex, Azure, on-prem). BYO compute / policies / storage / datasets.

**The proxy is the lock; the SDK is the label.** Network-layer interposition plus egress
policy means agents have no route to tools except through the plane — enforcement is
mandatory, not best-effort. The optional SDK adds business semantics (a refund vs. a
lookup) for finer-grained policy.

## Components

| Component | What it is | Where it lives | License |
|---|---|---|---|
| **Engine** | Action canonicalization, policy evaluation (ALLOW/DENY/DEFER), hash-chained audit, approval contract | this repo, `packages/unified-enforce` (new) | MIT (public at Public Release milestone) |
| **MCP hub** | First integration of the engine: aggregates MCP servers behind one governed endpoint | this repo, `packages/unified-mcphub` | MIT |
| **Gateway** | Envoy-based data plane; engine answers over ext_authz. Egress policy = the no-bypass guarantee | this repo (Envoy configs + ext_authz server in `unified-enforce`) | MIT |
| **SDK** | Optional client lib annotating actions with intent/amounts/data classes | this repo, `packages/unified-sdk` (new); TypeScript SDK later | MIT |
| **Control plane** | Fleet policy mgmt + versioning, dashboards, web approval queue, SSO/RBAC, evidence reports, SIEM/SOAR export | **separate private repo** (`unified-control-plane`) | Proprietary |
| **Marketing site** | unified-ai.app | `unified-web` repo | — |
| **Chat app** | chat.unified-ai.app (pre-pivot product, kept running) | `unified-fe` / `unified-be` repos | — |

The engine never depends on the control plane. Policies flow down, evidence flows up,
over a versioned API. The OSS repo must always build and run clean without any
commercial component.

## Wedge and expansion

1. **Enforce** — action authorization (the moat) ← everything above
2. **Observe** — traces, evals, continuous monitoring (seeded by the Observability Stack milestone)
3. **Test** — pre-release sandbox: replay recorded actions against candidate policies/models; red-teaming (seeded by audit replay)
4. **Align** — safety datasets for open-weight models from action corpora + verdicts

## Deployment modes

- **Managed SaaS** — fastest start
- **Customer VPC** — data never leaves
- **Fully air-gapped** — zero egress; defense / critical infrastructure

## Roadmap (Linear milestones)

- **Phase 0 — outreach**: W1 website (done 2026-08-11: marketing site at unified-ai.app,
  chat app at chat.unified-ai.app) · G1 design-partner outreach (3–5 security/platform
  teams in regulated industries; 45-min calls; lifetime preferred pricing)
- **Phase 1 — engine**: M0.75 supply chain · M0.8 remote approvals · E1 Action model +
  policy engine v0.1 (the doc partners critique) · E2 court-grade audit ·
  E3 gateway/egress · E4 SDK v0 · M0.5 security hardening · M0.5 observability ·
  Public Release (MIT)
- **Phase 2 — commercial**: C1 control plane MVP · C2 compliance evidence + SIEM ·
  C3 deployment modes
- **Phase 3 — land**: G2 first design-partner deployment · X1–X3 expansion pillars

## Decisions

Technology choices and their rationale are locked in [technologies.md](technologies.md).
Architecture decisions continue as ADRs under `specs/`.
