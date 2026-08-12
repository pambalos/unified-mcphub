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
| **LlamaIndex** | `guard_tools(tools, guard)` | The friendliest to wrap: `FunctionTool.from_defaults` takes both `fn` and `async_fn`, so the replacement is built from public constructor arguments alone. Both `call` and `acall` are guarded — an agent picks between them itself, and guarding one would leave a route through which nothing is enforced. |
| **CrewAI** | `guard_tools(tools, guard)` | A Pydantic subclass built at call time, since `BaseTool` is a model. ⚠️ Structurally verified only — see §5. |
| **Raw tool loop** | `Toolbox(guard)` + `denial_result()` | No framework at all — a team dispatching tool calls on a provider SDK directly, which is common in exactly the regulated environments this product targets. |

### Providers are not frameworks

OpenAI, OpenRouter, Bedrock and Anthropic are inference APIs: the model emits a
tool call and *your* loop dispatches it. There is nothing to adapt, so
`adapters/providers.py` supplies the smaller missing piece — the same tool call
is spelled four ways, and a denial has to be spelled back in the matching
dialect.

`from_openai` / `from_anthropic` / `from_bedrock` (plus `tool_calls(response,
provider=…)`) normalize to one `ProviderToolCall`; `denial_message(...,
provider=…)` renders a refusal in that provider's tool-result shape. No
provider SDK is required — the payloads are read structurally, so the SDK stays
the application's choice.

Three details that would otherwise bite quietly:

- **OpenAI ships arguments as a JSON string**, the others as a dict. A loop
  written against Anthropic and pointed at OpenAI hands policy `params={}`,
  and every value-based rule silently stops matching. OpenRouter, Azure
  OpenAI, Together and Groq are all this shape.
- **A model can emit invalid JSON.** That is a model failure, not a policy
  question, so it is flagged (`malformed`) rather than raised — but it must be
  visible, because empty params mean params-based rules do not apply. Treat
  `malformed` as a refusal unless the tool genuinely takes no arguments.
- **The three denial dialects genuinely differ.** Anthropic wants a
  `tool_result` block with `is_error`; OpenAI wants a `role: "tool"` message
  with no error flag at all, so the text has to carry it; Bedrock wants a
  `toolResult` with `status: "error"`.

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
2. **`fields` selects exclusive groups, and an unrecognised value silently
   falls back to the default.** The default projection omits metadata, and
   `fields=all` — which is not a real group — returns that default rather than
   erroring. This produced a wrong conclusion the second time round: that v4
   drops custom attributes entirely. **It does not.** Every `unified.*`
   attribute is retrievable under `metadata`, keyed `attributes.<name>`, with
   `fields=basic,metadata`. `basic` carries name/level/statusMessage.

   The full enforcement record — verdict, rule, principal, tool, source, audit
   level, and the action digest that joins back to the audit chain — is
   queryable from Langfuse. An operator can reconstruct who did what and which
   rule fired. `status_message` remains useful as a convenience, not a
   workaround: it puts the verdict in the *default* projection, so it shows in
   observation lists and alerts without anyone needing to know about field
   groups.

Also worth knowing: a batch exporter swallows HTTP failures. A wrong endpoint
produces silence, not an error, which is why tier 1 asserts on a captured POST
rather than on the absence of an exception. The same reflex applies to reads —
an API that answers 200 with a projection you did not expect looks identical to
an API with no data in it.

## §7 Langfuse version matrix

Self-hosters lag, so a partner is as likely to be on v3 as v4. The suite runs
the full Langfuse tier against **both**, parametrized on one compose file.

That immediately proved worth the container time, because **the read API is
inverted between majors, and each failure is silent in its own way**:

| | v3 | v4 |
| --- | --- | --- |
| OTLP ingest | `/api/public/otel/v1/traces` | same |
| Read endpoint | `/api/public/observations` | `/api/public/v2/observations` |
| The other's endpoint | v2 path → **404** | v1 path → **200, no data** |
| Metadata by default | included | omitted unless `fields=metadata` |
| Attribute shape | nested `metadata.attributes.<k>` | flat `metadata["attributes.<k>"]` |

A single-version suite would have shipped an integration that silently returned
nothing on the other major. `_attributes()` normalizes the two shapes so
callers never have to care which is running.

**v2 is the support floor, and it is a hard one:** `/api/public/otel/v1/traces`
returns **404, not 405**, so OTel ingestion does not exist there at all and no
configuration makes it work. A test pins that, because "Langfuse is supported"
otherwise reads as covering every version a self-hoster might still run.

## §8 Open

- **Pydantic AI, AutoGen, smolagents** — mechanical now that the contract
  exists; add a driver and the suite covers it. Deferred until asked for.
- **CrewAI is structurally verified only.** `crewai` depends on `lancedb`,
  which publishes no wheel for macOS x86_64, so it cannot be installed on the
  current dev machine. The conformance driver runs against a stub mirroring
  `BaseTool`'s contract — that covers the part we own (the subclass builds,
  identity is preserved, `_run` is blocked before it delegates) but not
  CrewAI's real runtime. Run the suite on Linux or an arm64 Mac to close it.
- **Version drift.** Adapters break when frameworks move. The extras are
  declared and drivers skip when absent, but nothing yet installs the latest
  on a schedule to report breakage early.
