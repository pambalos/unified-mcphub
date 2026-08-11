"""E3 gateway scaffold — Envoy ext_authz seam. Spec: specs/enforce/e3.v1.md.

Envoy is the data plane (technologies.md: we do not build a proxy). This module
is the engine side of that split, layered so the transport is swappable:

- `ExtAuthzCore.check()` — transport-agnostic: HTTP request attributes → canonical
  Action (origin "gateway") → Enforcer (decide + chain + span) → CheckResult.
- `create_http_service()` — Envoy `http_service` ext_authz transport (a plain
  HTTP authorization server). Working today; needs the [gateway] extra.
- gRPC `envoy.service.auth.v3.Authorization` transport — the locked target for
  the sub-10 ms path — lands next on the same core (proto vendoring tracked in
  the spec). Nothing above the transport changes.

Verdict mapping at the network layer: ALLOW → 200; DENY → 403; DEFER → 403 with
`x-unified-verdict: defer` (fail closed — a gateway has no interactive approval
channel until the approval contract is wired in; M0.8). Every response carries
`x-unified-*` headers so callers and Envoy access logs see why.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .action import Action, ActionContext, Principal
from .enforcer import Enforcer
from .policy import Decision, Verdict

PRINCIPAL_HEADER = "x-unified-principal"
_TRACEPARENT = re.compile(r"^[0-9a-f]{2}-([0-9a-f]{32})-([0-9a-f]{16})-[0-9a-f]{2}$")


@dataclass
class CheckInput:
    """The attributes of one intercepted request, however the transport got them."""

    principal_id: str  # from mTLS SAN, sidecar identity, or PRINCIPAL_HEADER
    method: str
    host: str
    path: str  # includes query string if any
    scheme: str = "https"
    headers: dict[str, str] = field(default_factory=dict)  # lowercase keys


@dataclass
class CheckResult:
    allowed: bool
    status_code: int  # 200 | 403
    headers: dict[str, str]  # x-unified-* response headers
    body: str
    decision: Decision
    action: Action


def _trace_ids(headers: dict[str, str]) -> tuple[str | None, str | None]:
    m = _TRACEPARENT.match(headers.get("traceparent", ""))
    return (m.group(1), m.group(2)) if m else (None, None)


class ExtAuthzCore:
    """Transport-agnostic ext_authz decision path.

    Principal trust (spec §5) is a deployment property, so it is configured
    here rather than assumed by a transport:

    - `default_principal` — per-agent **sidecar** mode: identity comes from
      *which* sidecar received the request, so set it at startup
      (`agent:crew-1`) and leave the header untrusted.
    - `trust_principal_header` — **gateway** (multi-tenant) mode: identity
      arrives in `x-unified-principal`, which is only as trustworthy as the
      infrastructure that sets it. The header MUST be stripped from
      client-supplied traffic at the trust boundary (the shipped Envoy
      templates do this); otherwise an agent can impersonate any principal.
    - mTLS SAN, when the mesh provides it, outranks both and is unspoofable.
    """

    def __init__(
        self,
        enforcer: Enforcer,
        *,
        default_principal: str = "agent:unknown",
        trust_principal_header: bool = True,
    ) -> None:
        self._enforcer = enforcer
        self._default_principal = default_principal
        self._trust_principal_header = trust_principal_header

    def principal_for(self, *, mtls: str | None = None, header: str | None = None) -> str:
        """Resolve the acting principal: mTLS identity > header > default.

        An mTLS SAN (e.g. `spiffe://cluster.local/ns/prod/sa/crew-1`) is passed
        through verbatim — policy globs match SPIFFE paths directly, and any
        rewrite here would be lossy guesswork.
        """
        if mtls:
            return mtls
        if header and self._trust_principal_header:
            return header
        return self._default_principal

    def check(self, req: CheckInput) -> CheckResult:
        trace_id, span_id = _trace_ids(req.headers)
        action = Action.build(
            principal=Principal(id=req.principal_id),
            tool=f"{req.scheme}://{req.host}{req.path}",
            verb=req.method.lower(),
            resource="*",  # network layer can't see business semantics — that's the SDK's job (E4)
            params={},  # bodies are not inspected at the gateway (scaffold; see spec §4)
            context=ActionContext(origin="gateway", trace_id=trace_id, span_id=span_id),
        )
        decision = self._enforcer.enforce(action)
        allowed = decision.verdict is Verdict.ALLOW
        headers = {
            "x-unified-verdict": decision.verdict.value,
            "x-unified-source": decision.source,
            "x-unified-action-digest": action.digest(),
        }
        if decision.rule_id is not None:
            headers["x-unified-rule"] = decision.rule_id
        body = "" if allowed else f"unified-enforce: {decision.verdict.value}"
        return CheckResult(
            allowed=allowed,
            status_code=200 if allowed else 403,
            headers=headers,
            body=body,
            decision=decision,
            action=action,
        )


def create_http_service(core: ExtAuthzCore) -> Any:
    """Envoy `http_service` ext_authz server: 200 = allow, 403 = deny.

    Envoy forwards the original method and path (plus `path_prefix` if
    configured — any prefix is accepted here) and the allowlisted headers;
    see deploy/envoy/ext_authz-http.yaml. Requires the [gateway] extra.
    """
    try:
        from fastapi import FastAPI, Request, Response
    except ImportError as exc:
        raise RuntimeError(
            "FastAPI is not installed — pip install 'unified-enforce[gateway]'"
        ) from exc

    app = FastAPI(title="unified-enforce ext_authz", docs_url=None, redoc_url=None)

    async def check(path, request):
        headers = {k.lower(): v for k, v in request.headers.items()}
        full_path = "/" + path
        if request.url.query:
            full_path += "?" + request.url.query
        result = core.check(
            CheckInput(
                principal_id=core.principal_for(header=headers.get(PRINCIPAL_HEADER)),
                method=request.method,
                host=headers.get("x-forwarded-host") or headers.get("host", ""),
                path=full_path,
                scheme=headers.get("x-forwarded-proto", "https"),
                headers=headers,
            )
        )
        return Response(content=result.body, status_code=result.status_code, headers=result.headers)

    # PEP 563 stringifies annotations module-wide, and FastAPI can't resolve names
    # imported inside this function from the module globals — hand it real objects.
    check.__annotations__ = {"path": str, "request": Request, "return": Response}
    app.api_route(
        "/{path:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
    )(check)

    return app
