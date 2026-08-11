# ADR — Policy v0.2: absorb the hub's authz semantics into the engine

Status: accepted 2026-08-11 (supersedes the "policy language" scope of
[e1.v1.md](e1.v1.md) §4; technologies.md decision 1 — YAML + CEL — stands, this
extends the YAML side). Implements the migration flagged in e2.v1.md §5.

## Decision

The hub's battle-tested authorization constructs (ADR-0006) become first-class
engine policy instead of being emulated in generated CEL. The hub's resolver
then becomes a thin adapter doing *mechanical* translation — semantics move
with their code and tests, they are not re-implemented.

Rejected: compiling `args_filter` to CEL (missing-arg and string-coercion
emulation in a second language; the floor tier still doesn't fit precedence).
Rejected: keeping two policy brains permanently (C1 fleet policy must target
one model; design partners must see one semantics).

## v0.2 additions

1. **`match.principal` accepts a list** — OR of globs. Generalizes the hub's
   `callers` exact-membership list.
2. **`match.args`** — per-argument operator map, ported verbatim:
   `{arg: {equals|starts_with|matches: [values]}}`. Arg names AND; operators
   per arg AND; value lists OR. The compared value is Python `str()` of the
   argument (`True` → `"True"`); a **missing argument compares as `""`** (the
   rule quietly doesn't match — never an error). `equals` is case-insensitive;
   `starts_with` case-sensitive; `matches` is `re.search` (Python flavor,
   `(?i)` for case-insensitivity). Structured matchers are for shape; CEL
   (`when`) remains for value logic — a rule may use both (args AND when).
3. **`floors:`** — a precedence tier between exact and wildcard that forces
   DEFER. Generalizes dangerous-commands: a wildcard `allow` can never override
   a floor; only an explicit exact rule can. `{id, match, reason?, audit_level?,
   when?}`; `source: "floor"` in the Decision.

Precedence (v0.2): ① exact rules (no wildcard in `tool`), file order →
② floors → ③ wildcard rules, first match → ④ default-deny (not configurable).

## Intentional divergences from the hub (all stricter / fail-closed)

- **Unknown operator** — hub: operator evaluates False at runtime (rule can
  never match, silently dead). Engine: **load error**. The adapter preserves
  hub behavior by dropping such rules at translation (identical outcome:
  never matched).
- **Invalid `matches` regex** — hub: raises at evaluation time (first call that
  reaches the rule). Engine: **load error** (regexes are precompiled). Broken
  config fails fast instead of failing mid-call.
- **Bare `*` tool pattern** — hub glob never crosses `/`, so `tool: "*"` never
  matched any URI (dead rule). Engine treats a bare `*` axis as unconstrained.
  The adapter drops these dead rules rather than letting them go live.

## Adapter translation (hub → engine), mechanical

| Hub (workspace / dangerous-commands) | Engine |
|---|---|
| `tool` pattern (`*` never crosses `/`) | `match.tool`, with `**`-runs collapsed to `*` (hub semantics; engine `**` crosses `/`) |
| `callers: [c…]` / absent | `match.principal: ["agent:<c>", …]` / `"*"` |
| `args_filter` | `match.args` verbatim (unknown-op rules dropped — see above) |
| `effect: prompt` | `effect: defer` (mapped back to `Effect.PROMPT`) |
| danger pattern `mcp://s/t` | floor `match.tool` |
| danger pattern `mcp://s/t:<prefix>*` | floor `match.tool` + `args: {command: {starts_with: ["<prefix>"]}}` |
| danger non-scheme pattern | floor `match.tool` = whole pattern as glob |
| Decision `source: danger_floor` | engine `floor`, mapped back at the adapter |
| Decision `rule` (= tool pattern) | engine `rule_id` → pattern via adapter map (ids are synthesized; hub rules have none) |

Caller ids are treated as literal principals; a caller id containing `*` would
glob (documented; token-registry names make this unrealistic).

Learned-rule persistence, workspace YAML format, and dangerous-commands.yaml
are untouched — translation happens at load, and on every config reload.

## Verification contract

A differential parity harness runs the frozen legacy resolver and the adapter
side by side over the hub's existing corpus plus seeded-random configs × calls
(all operators, case variants, missing args, non-string args, floors with and
without command prefixes), requiring bit-identical
`(effect, rule, audit_level, source)`. The hub's 17 authz unit tests run
unchanged against the adapter. The legacy implementation is deleted after the
harness and the e2e matrix are green; the harness keeps the frozen copy as the
reference semantics.
