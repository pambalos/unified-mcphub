"""The SDK client — E4. Spec: specs/enforce/e4.v1.md.

*The proxy is the lock; the SDK is the label.*

The gateway (E3) sees `POST https://api.stripe.com/v1/refunds` and nothing more,
so network-level policy can say "no POST to /v1/refunds" but never "no refund
over $5,000". This module lets application code declare what an operation
*means* — intent, amounts, data classes — and get a verdict on that.

It produces ordinary canonical Actions (`origin: sdk`), so SDK-declared and
gateway-observed operations share one policy language, one audit chain, and one
digest scheme. Nothing here is a second enforcement mechanism.

Two properties this module must never break:

1. **Optional.** An application that does not call the SDK is still enforced at
   the network layer. The SDK raises the *resolution* of policy; it is never
   what makes enforcement happen. If skipping it granted more freedom, every
   agent would skip it.
2. **Claims, not facts.** Annotations come from inside the trust boundary the
   gateway is protecting — the application can lie. Policy authors can tell
   them apart via `context.origin`, and the rule that follows from it is in the
   spec: never grant *more* on an SDK claim than the network layer would grant.
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any, Literal

from unified_enforce import (
    Action,
    ActionContext,
    Approvals,
    AttachmentProvider,
    AuditChain,
    Decision,
    Enforcer,
    PolicyEngine,
    Principal,
    Telemetry,
    Verdict,
)
from unified_enforce.attachments import AttachmentsSpec

from .errors import ApprovalRequired, Denied

#: Carries the SDK action's digest across the HTTP hop so the gateway can link
#: the two observations of one operation. See spec §4 — the sidecar strips it
#: before the request leaves, and it is recorded as a *claim*, never trusted.
CORRELATION_HEADER = "x-unified-action"


def _normalize(value: Any) -> Any:
    """Make a param value canonicalizable.

    Floats are rejected by strict canonicalization because their repr is not
    portable, and a signed action must verify on a non-Python verifier. Both
    float and Decimal therefore become strings, which is exactly what the
    gateway's body parser does — so the same refund annotated by the SDK and
    observed by the sidecar canonicalizes identically instead of one of them
    failing to sign. `repr` on a float is the shortest round-tripping form.
    """
    if isinstance(value, bool):  # bool is an int subclass; keep it a bool
        return value
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, dict):
        return {k: _normalize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize(v) for v in value]
    return value


def _current_trace() -> tuple[str | None, str | None]:
    """Trace/span ids from an ambient OTel span, when one exists.

    Read lazily and defensively: opentelemetry is not a dependency of this
    package, and an application that has not configured tracing must not pay
    for it or crash on it.
    """
    try:
        from opentelemetry import trace
    except ImportError:
        return None, None
    ctx = trace.get_current_span().get_span_context()
    if not getattr(ctx, "is_valid", False):
        return None, None
    return format(ctx.trace_id, "032x"), format(ctx.span_id, "016x")


@dataclass
class Acting:
    """One decided action, and the correlation material for its outbound call."""

    action: Action
    decision: Decision

    @property
    def allowed(self) -> bool:
        return self.decision.verdict is Verdict.ALLOW

    @property
    def digest(self) -> str:
        return self.action.digest()

    @property
    def headers(self) -> dict[str, str]:
        """Headers to attach to the outbound request this action describes.

        Attaching them lets the sidecar record that its network-level
        observation and this semantic action are the same operation. Omitting
        them costs nothing but the link — the gateway still enforces.
        """
        headers = {CORRELATION_HEADER: self.digest}
        trace_id, span_id = self.action.context.trace_id, self.action.context.span_id
        if trace_id and span_id:
            headers["traceparent"] = f"00-{trace_id}-{span_id}-01"
        return headers

    def raise_for_verdict(self) -> "Acting":
        if self.decision.verdict is Verdict.DENY:
            raise Denied(self.action, self.decision)
        if self.decision.verdict is Verdict.DEFER:
            raise ApprovalRequired(self.action, self.decision)
        return self


class UnifiedAI:
    """Enforcement for semantically-annotated actions.

        ua = UnifiedAI.local("policy.yaml", principal="agent:crew-1")

        @ua.action("stripe://refunds", verb="create",
                   resource="customer:{customer_id}", params=["amount"])
        def issue_refund(customer_id: str, amount: Decimal): ...

    Wrap an existing `Enforcer` to share one policy engine, audit chain, and
    telemetry pipeline with the rest of a process (a hub or gateway already
    running in-process); use `local()` to build the whole stack from a policy
    file.
    """

    def __init__(
        self,
        enforcer: Enforcer,
        *,
        principal: str,
        workspace: str | None = None,
        principal_kind: Literal["agent", "user", "service"] = "agent",
    ) -> None:
        self._enforcer = enforcer
        self._principal = Principal(id=principal, kind=principal_kind)
        self._workspace = workspace
        self._chain: AuditChain | None = None  # set by local(), for close()
        #: `attachments_for` registrations, in order (approval-attachments.v1
        #: §3.2). Applied to every `check_async` on a matching tool, which is
        #: every async path in this package: the `action()` decorator,
        #: `ToolGuard`, wrapped tools and `GuardedSession` all route through it.
        self._attachment_providers: list[AttachmentProvider] = []

    @classmethod
    def local(
        cls,
        policy: PolicyEngine | str | Path,
        *,
        principal: str,
        audit_dir: str | Path | None = None,
        telemetry: Telemetry | None = None,
        workspace: str | None = None,
        approvals: "Approvals | None" = None,
    ) -> "UnifiedAI":
        """Build the full stack in-process: policy engine, audit chain, telemetry.

        Decisions stay local and synchronous — no network hop to a control
        plane on the decision path, which is what keeps them inside the latency
        budget and keeps an outage from becoming an outage of every agent.
        """
        engine = policy if isinstance(policy, PolicyEngine) else PolicyEngine.from_file(policy)
        chain = None
        if audit_dir is not None:
            chain = AuditChain(audit_dir)
            chain.start()
        client = cls(
            Enforcer(engine, chain=chain, telemetry=telemetry, approvals=approvals),
            principal=principal,
            workspace=workspace,
        )
        client._chain = chain
        return client

    # --- lifecycle ---

    def close(self) -> None:
        if self._chain is not None:
            self._chain.stop()
            self._chain = None

    def __enter__(self) -> "UnifiedAI":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # --- deciding ---

    def check(
        self,
        tool: str,
        *,
        verb: str,
        resource: str = "*",
        params: dict[str, Any] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> Acting:
        """Decide, record, and return — without raising.

        Use when the caller wants to branch on the verdict (offer the user an
        approval path, fall back to a cheaper operation) rather than abort.
        """
        action = self._build(tool, verb, resource, params, extra)
        return Acting(action, self._enforcer.enforce(action))

    def _build(
        self,
        tool: str,
        verb: str,
        resource: str,
        params: dict[str, Any] | None,
        extra: dict[str, Any] | None,
    ) -> Action:
        trace_id, span_id = _current_trace()
        return Action.build(
            principal=self._principal,
            tool=tool,
            verb=verb,
            resource=resource,
            params=_normalize(params or {}),
            context=ActionContext(
                origin="sdk",
                workspace=self._workspace,
                trace_id=trace_id,
                span_id=span_id,
                extra=_normalize(extra or {}),
            ),
        )

    async def check_async(
        self,
        tool: str,
        *,
        verb: str,
        resource: str = "*",
        params: dict[str, Any] | None = None,
        extra: dict[str, Any] | None = None,
        summary: str = "",
        attachments: AttachmentsSpec = None,
    ) -> Acting:
        """Decide, and take a DEFER to a human if approvals are configured.

        The async twin of `check()`. It exists separately because asking a
        person is a fundamentally different operation from evaluating policy:
        `check()` returns in microseconds and never blocks, this one may wait
        as long as an operator takes. Code that cannot wait — anything on a
        request path with a timeout — should keep using `check()` and treat
        DEFER as a refusal, which is what the gateway does.

        Without approvals configured this is `check()` with an await: DEFER
        comes back as DEFER rather than a synthesized deny, so a missing
        approval channel is visible instead of silently strict.

        `attachments` is evidence for the approver: a sequence of
        `Attachment`s, or a callable receiving the built `Action` (sync or
        async) that returns them. The callable runs **only** if the action is
        actually going to a person -- never for ALLOW or DENY -- so loading a
        claim's documents costs nothing on the actions policy settles alone.
        Providers registered with `attachments_for` are appended after it.
        A loader that fails is shown to the approver as an unavailable entry;
        the request is still asked.
        """
        action = self._build(tool, verb, resource, params, extra)
        outcome = await self._enforcer.enforce_with_approval(
            action,
            summary=summary,
            attachments=attachments,
            attachment_providers=tuple(self._attachment_providers),
        )
        return Acting(action, outcome.decision)

    def attachments_for(self, tool_glob: str) -> Callable[[Callable], Callable]:
        """Register a provider of approval evidence for tools matching `tool_glob`.

            @ua.attachments_for("mcp://insurance/approve_claim")
            def claim_documents(action):
                return load_claim_documents(action.params["claim_id"])

        The glob is the policy engine's (segment-aware: `*` stops at `/`),
        compiled now so a malformed one fails at import rather than on the
        first deferral in production. Providers run in registration order,
        only for a DEFER that will be put to a person, after any call-site
        `attachments=`; together they share one time budget. The decorated
        function is returned unchanged.
        """

        def register(fn: Callable) -> Callable:
            self._attachment_providers.append(AttachmentProvider.build(tool_glob, fn))
            return fn

        return register

    @contextmanager
    def acting(
        self,
        tool: str,
        *,
        verb: str,
        resource: str = "*",
        params: dict[str, Any] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> Iterator[Acting]:
        """Guard a block: decide first, raise unless allowed, then run it.

            with ua.acting("stripe://refunds", verb="create",
                           resource="customer:42",
                           params={"amount": "8000.00"}) as act:
                httpx.post(url, json=payload, headers=act.headers)

        The decision happens before the block, so a denied operation never
        starts. Nothing is re-checked on exit — an action that was allowed and
        then failed is the application's business, and the audit chain already
        records what was authorized.
        """
        yield self.check(
            tool, verb=verb, resource=resource, params=params, extra=extra
        ).raise_for_verdict()

    def action(
        self,
        tool: str,
        *,
        verb: str,
        resource: str = "*",
        params: Sequence[str] = (),
        extra: dict[str, Any] | None = None,
        summary: str = "",
        attachments: Callable[..., Any] | Sequence[Any] | None = None,
    ) -> Callable[[Callable], Callable]:
        """Decorate a function so calling it is an enforced action.

        `tool` and `resource` are format templates over the function's bound
        arguments (`"customer:{customer_id}"`). `params` names the arguments to
        capture into the action.

        Capture is **explicit by design**. Sweeping every argument in would put
        API keys, tokens, and personal data into the audit chain by default,
        and an evidence log is the worst possible place to discover that. Name
        what policy needs; the rest stays out.

        Unknown names in `params`, `tool`, or `resource` raise at decoration
        time rather than on the first call in production.

        `attachments` is approval evidence: a sequence of `Attachment`s, or a
        callable receiving the decorated function's bound arguments as
        keywords (`lambda claim_id, **_: [...]`), run only when the call is
        put to a person. Async functions only: a sync call never waits for
        approval, so evidence for it would never be seen -- passing it is a
        mistake, and raises at decoration time.
        """
        signature_error = "unknown argument {name!r} in @action(...) for {fn}"

        def decorate(fn: Callable) -> Callable:
            sig = inspect.signature(fn)
            for name in params:
                if name not in sig.parameters:
                    raise TypeError(signature_error.format(name=name, fn=fn.__qualname__))
            if attachments is not None and not inspect.iscoroutinefunction(fn):
                raise TypeError(
                    f"@action(attachments=...) on {fn.__qualname__}: only async functions "
                    "wait for approval, so attachments for a sync one would never be shown"
                )

            def resolve_call(args: tuple, kwargs: dict) -> dict[str, Any]:
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()
                values = bound.arguments
                try:
                    resolved_tool = tool.format(**values)
                    resolved_resource = resource.format(**values)
                except KeyError as exc:
                    raise TypeError(
                        signature_error.format(name=exc.args[0], fn=fn.__qualname__)
                    ) from exc
                return {
                    "attachments": _over_arguments(attachments, values),
                    "tool": resolved_tool,
                    "verb": verb,
                    "resource": resolved_resource,
                    "params": {name: values[name] for name in params},
                    "extra": extra,
                }

            if inspect.iscoroutinefunction(fn):
                # A sync wrapper around an async function would decide, then
                # return a coroutine that runs the real work after the guard
                # has already exited — authorized, but at a misleading moment.
                #
                # This path also routes through approvals: an async agent action
                # is exactly where waiting for a human is affordable, and it is
                # the only call style that can await one at all.
                @functools.wraps(fn)
                async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                    call = resolve_call(args, kwargs)
                    acting = await self.check_async(call.pop("tool"), summary=summary, **call)
                    acting.raise_for_verdict()
                    return await fn(*args, **kwargs)

                return async_wrapper

            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                call = resolve_call(args, kwargs)
                call.pop("attachments")
                self.check(call.pop("tool"), **call).raise_for_verdict()
                return fn(*args, **kwargs)

            return wrapper

        return decorate


def _over_arguments(attachments: Any, values: dict[str, Any]) -> AttachmentsSpec:
    """`@action(attachments=...)` as an engine `attachments=` spec.

    The decorator's callable takes the function's bound arguments, not the
    Action: the Action holds only the captured `params`, and the document a
    reviewer needs is usually keyed by an argument policy has no reason to
    see. Its name is kept, so a failure is labelled with it for the approver.
    """
    if not callable(attachments):
        return attachments

    def over_arguments(_action: Action) -> Any:
        return attachments(**values)

    over_arguments.__name__ = getattr(attachments, "__name__", "attachments")
    return over_arguments
