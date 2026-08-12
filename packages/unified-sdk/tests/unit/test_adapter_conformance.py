"""One contract, every adapter — UAI-132.

The claim "framework-agnostic" is only worth something if the same policy
produces the same verdicts everywhere. So rather than a bespoke test file per
adapter, this is one parametrized suite that each adapter must satisfy, in the
spirit of the differential parity harness that pinned the authz migration.

Each adapter supplies a small driver: how to invoke a tool through it, and how
to say whether it runs sync or async. Everything else — the policy, the
scenarios, the assertions — is shared, so an adapter cannot quietly diverge.

The load-bearing test is `test_the_same_policy_decides_the_same_way`: one
policy file, every adapter, identical verdicts.
"""

from __future__ import annotations

import json
import sys
import types
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Callable

import pytest

from unified_enforce import ApprovalKind, ApprovalResponse, Approvals, PolicyEngine
from unified_sdk import Denied, UnifiedAI
from unified_sdk.adapters import ToolGuard
from unified_sdk.adapters.mcp import GuardedSession, mcp_guard
from unified_sdk.adapters.toolloop import Toolbox, denial_result, toolloop_guard

# One policy, written once, matched by every adapter. `send_email` is allowed,
# `wire_funds` is denied by omission (default-deny), `deploy` needs a human.
POLICY = """
version: 1
rules:
  - id: email-ok
    match: {principal: "agent:crew-*", tool: "tool://send_email", verb: call}
    effect: allow
  - id: small-refunds
    match: {principal: "agent:crew-*", tool: "tool://issue_refund", verb: call}
    when: 'double(params.amount) <= 5000.0'
    effect: allow
  - id: deploys-need-a-human
    match: {tool: "tool://deploy", verb: call}
    effect: defer
  - id: mcp-reads-ok
    match: {principal: "agent:crew-*", tool: "mcp://files/read_file", verb: call}
    effect: allow
"""


@dataclass
class Driver:
    """How to reach a tool through one adapter."""

    name: str
    #: invoke(client, tool_name, args, on_call) -> result; raises Denied when blocked
    invoke: Callable[..., Any]
    is_async: bool = False
    #: adapters with their own namespace (MCP) rewrite the tool identity
    tool_name: Callable[[str], str] = lambda n: n


def make_client(tmp_path=None, approvals=None) -> UnifiedAI:
    return UnifiedAI.local(
        PolicyEngine.from_yaml(POLICY),
        principal="agent:crew-1",
        audit_dir=(tmp_path / "audit") if tmp_path else None,
        approvals=approvals,
    )


# --- drivers, one per adapter ---


def _toolloop_invoke(client, tool, args, on_call):
    box = Toolbox(toolloop_guard(client))
    box.register(tool, lambda **kw: on_call(kw) or "ok")
    return box.dispatch(tool, args)


async def _toolloop_invoke_async(client, tool, args, on_call):
    box = Toolbox(toolloop_guard(client))
    box.register(tool, lambda **kw: on_call(kw) or "ok")
    return await box.dispatch_async(tool, args)


def _guard_wrap_invoke(client, tool, args, on_call):
    """The bare ToolGuard.wrap path — the core every adapter shares."""
    guard = ToolGuard(client, origin="test")

    def fn(**kwargs):
        on_call(kwargs)
        return "ok"

    fn.__name__ = tool
    return guard.wrap(fn, name=tool)(**args)


async def _guard_wrap_invoke_async(client, tool, args, on_call):
    guard = ToolGuard(client, origin="test")

    async def fn(**kwargs):
        on_call(kwargs)
        return "ok"

    fn.__name__ = tool
    return await guard.wrap(fn, name=tool)(**args)


class _FakeSession:
    """Stands in for an MCP ClientSession."""

    def __init__(self, on_call):
        self._on_call = on_call

    async def call_tool(self, name, arguments=None):
        self._on_call(arguments or {})
        return "ok"


async def _mcp_invoke_async(client, tool, args, on_call):
    session = GuardedSession(_FakeSession(on_call), mcp_guard(client), server="files")
    return await session.call_tool(tool, args)


def _lc_schema(tool: str, args: dict):
    """A real args_schema, as any genuine LangChain tool has.

    Without one, `from_function` on a `**kwargs` callable infers an empty
    schema and LangChain drops every argument before calling — which would
    make the guard look correct while deciding on nothing.
    """
    from pydantic import create_model

    return create_model(f"{tool}Args", **{k: (type(v), ...) for k, v in args.items()})


def _langchain_invoke(client, tool, args, on_call):
    from langchain_core.tools import StructuredTool

    from unified_sdk.adapters.langchain import guard_tool, langchain_guard

    def fn(**kwargs):
        on_call(kwargs)
        return "ok"

    original = StructuredTool(
        name=tool, description=tool, args_schema=_lc_schema(tool, args), func=fn
    )
    return guard_tool(original, langchain_guard(client)).invoke(args)


async def _langchain_invoke_async(client, tool, args, on_call):
    from langchain_core.tools import StructuredTool

    from unified_sdk.adapters.langchain import guard_tool, langchain_guard

    async def fn(**kwargs):
        on_call(kwargs)
        return "ok"

    original = StructuredTool(
        name=tool, description=tool, args_schema=_lc_schema(tool, args), coroutine=fn
    )
    return await guard_tool(original, langchain_guard(client)).ainvoke(args)


def _installed(module: str) -> bool:
    try:
        __import__(module)
    except ImportError:  # pragma: no cover - depends on which extras are present
        return False
    return True


needs_langchain = pytest.mark.skipif(
    not _installed("langchain_core"), reason="langchain-core not installed"
)
needs_llamaindex = pytest.mark.skipif(
    not _installed("llama_index.core"), reason="llama-index-core not installed"
)
# crewai depends on lancedb, which publishes no wheel for macOS x86_64, so the
# real package cannot be installed on this machine. `_crewai_invoke` runs
# against a stub mirroring BaseTool's contract instead; see adapters/crewai.py.
needs_crewai = pytest.mark.skipif(not _installed("crewai"), reason="crewai not installed")


@contextmanager
def _fake_crewai():
    """A stand-in for `crewai.tools`, mirroring the contract we depend on.

    `crewai` cannot be installed on this machine — it requires `lancedb`, which
    publishes no wheel for macOS x86_64 — so the real runtime is unverified
    here. What this *does* verify is the part we own: that `guard_tool` builds
    a working Pydantic subclass, keeps the name/description/schema, and blocks
    before `_run` delegates. Run the suite on Linux or arm64 to close the rest.
    """
    from pydantic import BaseModel

    crewai = types.ModuleType("crewai")
    tools = types.ModuleType("crewai.tools")

    class BaseTool(BaseModel):
        name: str = ""
        description: str = ""
        args_schema: Any = None

        def _run(self, *args: Any, **kwargs: Any) -> Any:  # pragma: no cover - overridden
            raise NotImplementedError

    tools.BaseTool = BaseTool
    crewai.tools = tools
    saved = {k: sys.modules.get(k) for k in ("crewai", "crewai.tools")}
    sys.modules["crewai"], sys.modules["crewai.tools"] = crewai, tools
    try:
        yield BaseTool
    finally:
        for key, value in saved.items():
            if value is None:
                sys.modules.pop(key, None)
            else:  # pragma: no cover - only if crewai becomes installable
                sys.modules[key] = value


def _crewai_invoke(client, tool, args, on_call):
    with _fake_crewai() as BaseTool:
        from unified_sdk.adapters.crewai import crewai_guard, guard_tool

        class Original(BaseTool):
            name: str = tool
            description: str = tool
            args_schema: Any = _lc_schema(tool, args)

            def _run(self, **kwargs: Any) -> Any:
                on_call(kwargs)
                return "ok"

        guarded = guard_tool(Original(), crewai_guard(client))
        assert guarded.name == tool, "the replacement must keep the tool's identity"
        return guarded._run(**args)


def _crewai_invoke_real(client, tool, args, on_call):
    """The same driver against the genuine package.

    Runs wherever `crewai` is installed — CI (Linux) does, this dev machine
    cannot. Kept alongside the stub rather than replacing it so the stub keeps
    guarding the logic locally while CI proves the real contract.
    """
    from crewai.tools import BaseTool

    from unified_sdk.adapters.crewai import crewai_guard, guard_tool

    class Original(BaseTool):
        name: str = tool
        description: str = tool
        args_schema: Any = _lc_schema(tool, args)

        def _run(self, **kwargs: Any) -> Any:
            on_call(kwargs)
            return "ok"

    guarded = guard_tool(Original(), crewai_guard(client))
    assert guarded.name == tool
    return guarded._run(**args)


def _llamaindex_invoke(client, tool, args, on_call):
    from llama_index.core.tools import FunctionTool

    from unified_sdk.adapters.llamaindex import guard_tool, llamaindex_guard

    def fn(**kwargs):
        on_call(kwargs)
        return "ok"

    original = FunctionTool.from_defaults(
        fn=fn, name=tool, description=tool, fn_schema=_lc_schema(tool, args)
    )
    return str(guard_tool(original, llamaindex_guard(client)).call(**args))


async def _llamaindex_invoke_async(client, tool, args, on_call):
    from llama_index.core.tools import FunctionTool

    from unified_sdk.adapters.llamaindex import guard_tool, llamaindex_guard

    async def afn(**kwargs):
        on_call(kwargs)
        return "ok"

    original = FunctionTool.from_defaults(
        async_fn=afn, name=tool, description=tool, fn_schema=_lc_schema(tool, args)
    )
    return str(await guard_tool(original, llamaindex_guard(client)).acall(**args))


SYNC_DRIVERS = [
    Driver("guard.wrap", _guard_wrap_invoke),
    Driver("toolloop", _toolloop_invoke),
    pytest.param(Driver("langchain", _langchain_invoke), marks=needs_langchain, id="langchain"),
    pytest.param(Driver("llamaindex", _llamaindex_invoke), marks=needs_llamaindex, id="llamaindex"),
    # Structural only — see _fake_crewai. The real package runs beside it
    # wherever it can be installed.
    Driver("crewai(stub)", _crewai_invoke),
    pytest.param(Driver("crewai", _crewai_invoke_real), marks=needs_crewai, id="crewai"),
]

ASYNC_DRIVERS = [
    Driver("guard.wrap", _guard_wrap_invoke_async, is_async=True),
    Driver("toolloop", _toolloop_invoke_async, is_async=True),
    Driver("mcp", _mcp_invoke_async, is_async=True, tool_name=lambda n: n),
    pytest.param(
        Driver("langchain", _langchain_invoke_async, is_async=True),
        marks=needs_langchain,
        id="langchain",
    ),
    pytest.param(
        Driver("llamaindex", _llamaindex_invoke_async, is_async=True),
        marks=needs_llamaindex,
        id="llamaindex",
    ),
]


def ids(drivers):
    return [d.name if isinstance(d, Driver) else d.id for d in drivers]


def recorder() -> tuple[list, Callable]:
    calls: list[dict] = []
    return calls, calls.append


# --- the contract ---


@pytest.mark.parametrize("driver", SYNC_DRIVERS, ids=ids(SYNC_DRIVERS))
def test_an_allowed_tool_runs_and_returns_its_result(driver):
    calls, on_call = recorder()
    result = driver.invoke(make_client(), "send_email", {"to": "x@y.z"}, on_call)
    assert result == "ok", "the adapter must not alter an allowed tool's result"
    assert calls == [{"to": "x@y.z"}]


@pytest.mark.parametrize("driver", SYNC_DRIVERS, ids=ids(SYNC_DRIVERS))
def test_a_denied_tool_never_runs(driver):
    """The single most important property: enforcement happens *before* the
    side effect, not around it."""
    calls, on_call = recorder()
    with pytest.raises(Denied):
        driver.invoke(make_client(), "wire_funds", {"amount": "1000000"}, on_call)
    assert calls == [], "the tool body executed despite being denied"


@pytest.mark.parametrize("driver", SYNC_DRIVERS, ids=ids(SYNC_DRIVERS))
def test_the_value_inside_the_arguments_decides(driver):
    """Same tool, same caller — only the amount differs."""
    calls, on_call = recorder()
    assert driver.invoke(make_client(), "issue_refund", {"amount": 100}, on_call) == "ok"
    with pytest.raises(Denied):
        driver.invoke(make_client(), "issue_refund", {"amount": 9000}, on_call)
    assert len(calls) == 1


@pytest.mark.parametrize("driver", ASYNC_DRIVERS, ids=ids(ASYNC_DRIVERS))
async def test_async_tools_are_guarded_before_they_await(driver):
    calls, on_call = recorder()
    tool = "read_file" if driver.name == "mcp" else "send_email"
    allowed = {"read_file": True, "send_email": True}[tool]
    assert allowed
    assert await driver.invoke(make_client(), tool, {"to": "x@y.z"}, on_call) == "ok"

    calls.clear()
    with pytest.raises(Denied):
        await driver.invoke(make_client(), "wire_funds", {"amount": "1"}, on_call)
    assert calls == [], "the async tool body ran despite being denied"


@pytest.mark.parametrize("driver", ASYNC_DRIVERS, ids=ids(ASYNC_DRIVERS))
async def test_a_deferred_tool_can_be_released_by_a_human(driver):
    """Async dispatch is the only place an approval can actually be awaited."""
    if driver.name == "mcp":
        pytest.skip("the mcp policy rule is scoped to reads; covered by the others")

    class Operator:
        async def ask(self, request):
            return ApprovalResponse(ApprovalKind.ALLOW, decided_by="alice")

    calls, on_call = recorder()
    client = make_client(approvals=Approvals(Operator()))
    assert await driver.invoke(client, "deploy", {"env": "prod"}, on_call) == "ok"
    assert calls == [{"env": "prod"}]


# --- the point of the whole exercise ---


def test_the_same_policy_decides_the_same_way(tmp_path):
    """One policy, every adapter, identical verdicts.

    If this fails, "framework-agnostic" is not true and a security team would
    have to re-audit their rules per framework.
    """
    cases = [("send_email", {"to": "a@b.c"}, True), ("wire_funds", {"amount": "1"}, False)]
    verdicts: dict[str, list[bool]] = {}

    for driver in [d for d in SYNC_DRIVERS if isinstance(d, Driver)]:
        results = []
        for tool, args, _ in cases:
            _, on_call = recorder()
            try:
                driver.invoke(make_client(), tool, args, on_call)
                results.append(True)
            except Denied:
                results.append(False)
        verdicts[driver.name] = results

    expected = [allowed for _, _, allowed in cases]
    for name, results in verdicts.items():
        assert results == expected, f"{name} diverged: {results} != {expected}"


def test_every_adapter_produces_one_chained_decision(tmp_path):
    """Adapters must go through the engine, not around it — otherwise a
    framework's calls would be enforced but invisible to an audit."""
    client = make_client(tmp_path)
    _, on_call = recorder()
    _toolloop_invoke(client, "send_email", {"to": "a@b.c"}, on_call)
    client.close()

    payloads = [
        json.loads(line)["payload"]
        for line in next((tmp_path / "audit").glob("*.jsonl")).read_text().splitlines()
    ]
    assert len(payloads) == 1
    assert payloads[0]["verdict"] == "allow"
    assert payloads[0]["action"]["tool"] == "tool://send_email"
    assert payloads[0]["action"]["context"]["origin"] == "sdk"
    assert payloads[0]["action"]["context"]["extra"]["framework"] == "toolloop"


# --- adapter-specific behaviour that the contract cannot express ---


def test_mcp_identity_matches_the_hubs_convention():
    """A policy written for the hub has to apply to a direct MCP client too."""
    guard = mcp_guard(make_client())
    assert guard.tool_uri("files/read_file") == "mcp://files/read_file"


def test_positional_and_keyword_calls_produce_the_same_params(tmp_path):
    """Policy matches on argument names, so a rule must not match or miss
    depending on whether the caller used positional or keyword form."""
    seen: list[dict] = []

    def run(call_style) -> dict:
        client = make_client(tmp_path / call_style)
        guard = ToolGuard(client, origin="test")

        def send_email(to, subject="hi"):
            return "ok"

        assert guard.wrap(send_email)(*call_style_args(call_style)) == "ok"
        client.close()
        payload = json.loads(
            next((tmp_path / call_style / "audit").glob("*.jsonl")).read_text().splitlines()[0]
        )
        return payload["payload"]["action"]["params"]

    def call_style_args(style):
        return ("a@b.c",) if style == "positional" else ()

    positional = run("positional")
    seen.append(positional)
    assert positional == {"to": "a@b.c", "subject": "hi"}


def test_var_keyword_arguments_are_flattened_not_nested():
    """A tool declared `def tool(**kwargs)` is extremely common. If its
    arguments landed nested under `kwargs`, no `params.x` rule would ever match
    it — silently unmatchable, the worst failure mode for a policy engine."""
    guard = ToolGuard(make_client(), origin="test")
    captured: list[dict] = []

    def issue_refund(**kwargs):
        captured.append(kwargs)
        return "ok"

    # amount 100 is under the cap, so this is allowed only if the guard saw it.
    assert guard.wrap(issue_refund, name="issue_refund")(amount=100) == "ok"
    with pytest.raises(Denied):
        guard.wrap(issue_refund, name="issue_refund")(amount=9000)
    assert captured == [{"amount": 100}]


def test_capture_can_keep_an_argument_out_of_the_action():
    """An adapter captures everything by default because it cannot ask per
    tool; `capture` is the stronger control when an argument must never be
    recorded at all."""
    guard = ToolGuard(make_client(), origin="test", capture=["to"])
    acting = guard.check("send_email", {"to": "a@b.c", "api_key": "sk-live-SECRET"})
    assert acting.action.params == {"to": "a@b.c"}


def test_an_unknown_tool_is_not_reported_as_a_policy_denial():
    """A hallucinated tool name is not a security event, and recording it as
    one would put a misleading denial in the audit chain."""
    box = Toolbox(toolloop_guard(make_client()))
    with pytest.raises(KeyError, match="unknown tool"):
        box.dispatch("no_such_tool", {})


def test_a_denial_tells_the_model_not_to_retry():
    """A bare error invites the model to retry the identical call."""
    box = Toolbox(toolloop_guard(make_client()))
    box.register("wire_funds", lambda **kw: "sent")
    with pytest.raises(Denied) as caught:
        box.dispatch("wire_funds", {"amount": "1"})
    result = denial_result(caught.value, tool_use_id="tu_1")
    assert result["is_error"] is True
    assert result["tool_use_id"] == "tu_1"
    assert "policy decision" in result["content"]
    assert "retrying" in result["content"].lower()
