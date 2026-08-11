# Unified AI — Technology Decisions

Locked 2026-08-11 with [product.md](product.md). These are commitments, not
suggestions; revisit only via an ADR in `specs/` that supersedes the entry here.

## Guiding constraints

- **Python-first.** One product language wherever possible; matches the existing
  codebase and the "pip-installable in minutes" promise. Other languages only where a
  component's job demands it — and so far none does, because we don't build a proxy.
- **Deterministic <10 ms decisions.** Every policy-path dependency must be
  synchronous, local, and allocation-cheap. No network hops inside evaluation.
- **Self-hosted first.** Everything ships into a customer VPC or air-gapped network.
  No component may require egress to function.
- **OSS/commercial split.** MIT engine in this repo; proprietary control plane in a
  separate private repo. The engine never imports from the control plane.

## Locked decisions

### 1. Policy language: YAML rules + embedded CEL conditions

The v0.1 policy model evolves the hub's shipped three-state (allow/deny/prompt),
default-deny YAML rules. Structured matching (principal, tool, verb, resource) stays
declarative YAML; conditions (spend limits, data boundaries, param constraints) are
[CEL](https://cel.dev) expressions evaluated with `cel-python`.

*Why:* incremental from production code; we own the schema design partners critique
(E1/G1); pure-Python install; CEL is deterministic, non-Turing-complete, and
industry-legible (Kubernetes, Envoy RBAC use it). *Rejected:* Cedar (strong pedigree
but adopts someone else's schema + native wheels), OPA/Rego (heaviest embedding,
murkier <10 ms determinism story).

### 2. Data plane: Envoy + ext_authz — we do not build a proxy

The E3 gateway is **Envoy** (gateway or per-agent sidecar). The engine exposes an
**ext_authz gRPC** server; Envoy consults it on every request and enforces the
verdict. Egress policy (NetworkPolicy / iptables / security groups templates, shipped
per deployment mode) guarantees agents have no route around it. The engine also keeps
its in-process enforcement path (as in the MCP hub today) for framework-level
integration.

*Why:* platform teams already run and trust Envoy; TLS/H2/egress handled; ext_authz is
purpose-built for sub-10 ms external checks; the whole decision path stays in one
Python codebase. *Rejected:* own Go/Rust proxy (a year rebuilding Envoy, second
language), mitmproxy MVP (throwaway work).

### 3. Control plane: FastAPI + Next.js + Postgres, separate private repo

Backend FastAPI (same idioms as the engine), frontend Next.js/React, Postgres for
state, delivered as docker-compose first and Helm later. SSO: generic OIDC at MVP,
SAML + SCIM when a customer requires it. Talks to engines over a versioned HTTP API —
policies down, evidence up.

*Why:* matches existing skills and repos (React chat app, Next.js MyProgram, FastAPI
hub); boring, self-contained, VPC-shippable. *Rejected:* Go backend (language
divergence), serving a SPA from the hub process (couples OSS engine to commercial UI).

### 4. Repo topology

- **This repo (public at Public Release, MIT):** uv workspace grows
  `packages/unified-enforce` (Action model, policy engine, audit, approval contract,
  ext_authz server) and `packages/unified-sdk`. `unified-mcphub` becomes the first
  integration of `unified-enforce` rather than the owner of authz/audit logic.
- **`unified-control-plane` (new, private):** C1–C3.
- **`unified-web`**, **`unified-ai-docs`**: unchanged.
- TypeScript SDK: later, separate `unified-sdk-ts` repo when demand exists.

## Cross-cutting stack (locked)

| Concern | Choice | Notes |
|---|---|---|
| Language / runtime | Python ≥3.12 | ruff (line 100), mypy, pytest(-asyncio/-cov) — as today |
| Packaging / env | uv workspace; PyPI wheels | `pip install unified-enforce` is the OSS front door |
| Data models | pydantic v2 | Action + policy schemas also published as JSON Schema (versioned) |
| Action signing | Ed25519 via `cryptography` | already a dependency; key in OS keyring locally, KMS/HSM in enterprise |
| Audit log | append-only JSONL + SHA-256 hash chain; SQLite read index | evolves `audit.py`; Merkle checkpoints later if needed |
| Engine-local state | SQLite | zero-dependency self-hosting |
| Control-plane state | Postgres | |
| API surfaces | FastAPI + uvicorn (HTTP), grpcio (ext_authz only) | Unix socket + TCP, as today |
| Approvals | one approval contract (control API) | TUI, web queue, Discord/OpenClaw bridge, OS notifications are all thin clients — per M0.8 |
| Telemetry | OpenTelemetry → embedded Tempo | per M0.5 Observability; `otel.enabled` off by default. Backend is pluggable via standard OTLP endpoint config — Tempo is only the embedded default; Langfuse (self-hosted or cloud, `/api/public/otel`) and any OTLP collector work unchanged |
| Secrets | OS keyring + `secrets.enc`; OAuth (Auth Code + PKCE) hub-side | as today |
| CI | GitHub Actions | lint + type + test + clean-clone/no-secrets gate (Public Release milestone) |
| Containers | Docker images pinned by digest, Sigstore-signed | per M0.5 Security Hardening supply-chain work |
| MCP | official `mcp` SDK | the hub remains a first-class MCP citizen |

## Non-goals (for now)

- No Rust/Go rewrite of the decision path before profiling proves Python can't hold
  the p99 budget behind Envoy.
- No multi-tenant SaaS control plane before C1 self-hosted ships (M1+ groundwork only).
- No custom policy DSL beyond YAML+CEL; resist inventing a language.
