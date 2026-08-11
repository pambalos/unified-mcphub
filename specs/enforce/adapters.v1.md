# Framework adapters & telemetry backends

Status: **implemented** — `unified_sdk.adapters` (MCP, LangChain, raw
tool-loop) with a shared conformance suite; Langfuse verified against a real
self-hosted instance. Linear UAI-132.

Two different kinds of integration get lumped together and shouldn't be.
**Adapters** intercept an agent's tool call so it becomes an Action.
**Telemetry backends** receive decision spans, and need no adapter at all —
OTLP is the abstraction.

## §1 The abstraction

Agent frameworks look different and converge on the same thing: **a named
callable invoked with a dict of arguments**. That is the whole surface, so
`ToolGuard` holds all the logic and each framework binding is a shape
translation of a few dozen lines. If an adapter grows past that, it is doing
something it shouldn't.

Two rules every adapter follows:

**Wrap, never hook.** Several frameworks expose callbacks around tool
execution (LangChain's `on_tool_start`). They are *observational*. Raising from
one happens to abort in some versions, which is the trap: a callback-based
adapter passes its own tests, ships, and then silently stops enforcing after a
minor upgrade — with no error, because nothing was ever contractually
blocking. The enforcement point is always the callable itself.

**Identity is framework-agnostic by default.** `tool://send_email`, not
`langchain://send_email`, with the framework in `context.origin` and
`context.extra.framework`. The product promise is framework-agnostic policy; a
security team should not rewrite rules because a squad migrated CrewAI →
LangChain. Ecosystems with a genuine namespace keep it — MCP stays
`mcp://server/tool`, because the server is part of what the tool *is* and two
servers can both expose `read_file`. That also means a policy written for the
hub applies unchanged to a direct MCP client.

## §2 The adapters

| Adapter | Entry point | Notes |
| --- | --- | --- |
| **MCP** | `GuardedSession(session, guard, server=…)` | Duck-typed proxy; forwards everything but `call_tool`. The hub already proves the shape server-side — this is the client-side counterpart. |
| **LangChain** | `guard_tools(tools, guard)` | Returns *replacement* `StructuredTool`s with the same name, description and schema. The agent's prompt is unchanged. |
| **Raw tool loop** | `Toolbox(guard)` + `denial_result()` | No framework at all — a team dispatching `tool_use` blocks on the Anthropic/OpenAI SDK directly, which is common in exactly the regulated environments this product targets. |

LangChain gets replacement tools rather than a patched original because
`BaseTool` is a Pydantic model: assigning over `_run` is fragile across
Pydantic and LangChain versions, and mutating a caller's object is rude
besides. Building a `StructuredTool` around `invoke`/`ainvoke` uses only stable
public surface.

`denial_result()` matters more than it looks. A bare error invites the model to
retry the identical call, burning tokens and filling the audit log with
identical denials; the returned result says the refusal is a *policy decision*
and names the rule, so the agent can pick another route or tell the user.

## §3 Capture — the one real tension

The `@action` decorator makes param capture explicit (`params=["amount"]`) so
API keys never reach the evidence chain. An adapter cannot ask the developer
per tool — it sees whatever the model passed — so it captures everything by
default, which reintroduces exactly what explicit capture solved.

Two mitigations, in order of strength: the audit capture level scrubs
secret-shaped values before anything is written, and `ToolGuard(capture=[...])`
drops arguments before they enter the Action at all. The second is stronger and
is the right answer for a tool that takes a credential — do not rely on the
scrubber to recognise a token format it has never seen.

## §4 Argument binding

Policy matches on argument *names*, so the same call must produce the same
params whether written positionally or by keyword. `_as_args` binds against the
signature to normalise that.

`**kwargs` is **flattened** rather than left nested. `bind_partial` collects it
under the parameter's own name, so a tool declared `def tool(**kwargs)` — how a
great many wrapped tools are written — would otherwise produce
`params={"kwargs": {"amount": 9000}}`, and no `params.amount` rule would ever
match. Silently unmatchable is the worst failure mode a policy engine has. This
was a real bug, caught by the conformance suite before the adapters shipped.

`*args` keep their parameter name as a list: unlike keywords they have no names
to match on, but dropping them would hide real arguments from the audit record.

## §5 Conformance — one contract, every adapter

`tests/unit/test_adapter_conformance.py` is one parametrized suite each adapter
must satisfy, in the spirit of the differential parity harness that pinned the
authz migration. An adapter supplies only a driver — how to invoke a tool
through it — and inherits the policy, the scenarios and the assertions, so it
cannot quietly diverge.

The load-bearing test is `test_the_same_policy_decides_the_same_way`: one
policy, every adapter, identical verdicts. That is what converts
"framework-agnostic" from a slogan into something CI enforces. The rest cover
the properties that matter per adapter — an allowed tool's result is unaltered,
**a denied tool never runs**, a value inside the arguments decides, async is
guarded before it awaits, a deferral can be released by a human, and every
adapter's decision lands in the audit chain.

## §6 Telemetry backends: what testing Langfuse actually found

The Langfuse integration had never sent a byte. Its only test monkeypatched the
exporter and asserted a URL string; every other telemetry test used
`InMemorySpanExporter`, which skips protobuf encoding and HTTP entirely. Three
tiers now exist, and each found something the tier below could not:

**Tier 1 — `tests/unit/test_enforce_otlp.py`.** A real `OTLPSpanExporter`
against a local server, decoding the actual protobuf. No containers. Covers
encoding, the auth header, path derivation, and that `shutdown()` flushes
rather than dropping the last decisions a process made.

**Tier 2 — a real OTel Collector.** Removes the circularity of tier 1, where
the same library encodes and decodes. A span the collector accepts is
wire-compatible by something else's judgement.

**Tier 3 — a real self-hosted Langfuse** (six containers, headless-seeded API
keys). Two findings that only a real instance could produce:

1. **Langfuse v4 runs in `events_only` mode**, where `/api/public/traces` and
   `/api/public/observations` return a deprecation notice with **200 and no
   data**. A test querying them sees an empty list and concludes "nothing was
   ingested" while ingestion is working perfectly — which is exactly how the
   first version of this test failed. Reads must use
   `/api/public/v2/observations`. A test now pins this so a regression to the
   v1 paths fails loudly instead of turning the suite into a no-op.
2. **v4 projects observations to a fixed field set and returns no custom
   attributes or metadata.** Every `unified.*` attribute is invisible to
   anyone querying the API — an operator could see that a decision happened and
   how severe it was, but not *what was decided*. `status_message` is one of
   the few fields that round-trips, so the verdict and its rule now ride there
   (`"defer (payouts-need-a-human)"`). Verified against the live instance.

Also worth knowing: a batch exporter swallows HTTP failures. A wrong endpoint
produces silence, not an error, which is why tier 1 asserts on a captured POST
rather than on the absence of an exception.

## §7 Open

- **CrewAI, LlamaIndex, Pydantic AI, AutoGen** — mechanical now that the
  contract exists; add a driver and the suite covers it. Deferred until a
  design partner asks for a specific one.
- **Version drift.** Adapters break when frameworks move. `langchain-core` is
  pinned in the dev group and the driver skips when absent, but nothing yet
  installs the latest on a schedule to report breakage early.
- **Langfuse metadata.** Whether `langfuse.observation.metadata.*` reaches the
  UI could not be determined from the API, since the v4 projection omits
  metadata entirely. If richer detail than `status_message` is wanted, that
  needs checking against the UI or a newer API.
