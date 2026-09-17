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

import json
import re
from dataclasses import dataclass, field
from typing import Any, Literal

from .action import Action, ActionContext, Attestation, Principal
from . import agent_protocol, flows
from .enforcer import Enforcer
from .identity import OIDCValidator
from .policy import Decision, Verdict

PRINCIPAL_HEADER = "x-unified-principal"
#: Set by the E4 SDK to the digest of the semantic Action it already decided,
#: so both observations of one operation can be joined in the audit chain.
CORRELATION_HEADER = "x-unified-action"
_TRACEPARENT = re.compile(r"^[0-9a-f]{2}-([0-9a-f]{32})-([0-9a-f]{16})-[0-9a-f]{2}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class BodyInspection:
    """Opt-in request-body parsing — spec §8, E3 completion.

    Off by default. Without it the gateway sees only method/host/path, so
    policy can say "no POST to /v1/payouts" but never "no refund over $5,000".
    It stays opt-in because it changes the latency profile, requires Envoy to
    buffer request bodies, and pulls payloads into the audit chain (where the
    capture level then governs what is retained).

    **Numbers are parsed as strings.** `json.loads(..., parse_float=str)` keeps
    `8000.50` as `"8000.50"` rather than a float. Floats are rejected by strict
    canonicalization precisely because their repr is not portable, so parsing
    them would make the action digest unstable across verifiers. Keeping the
    literal text is exact, deterministic, and matches the args matchers, which
    str()-coerce anyway. In CEL, compare with `double(params.amount) > 5000`.

    `on_unreadable` governs a body we cannot turn into params — oversize,
    truncated, malformed, a content type outside `content_types`, or a JSON
    document that isn't an object. Enabling body inspection is a statement that
    bodies carry meaning for policy, so the default is **deny**: a body we
    cannot read is a body we cannot clear. Set `"ignore"` to fall through to
    the header-level rules instead, which is the right choice when body rules
    only ever *narrow* an already-restrictive policy.
    """

    max_bytes: int = 64 * 1024
    content_types: tuple[str, ...] = ("application/json",)
    on_unreadable: Literal["deny", "ignore"] = "deny"


@dataclass
class CheckInput:
    """The attributes of one intercepted request, however the transport got them."""

    principal_id: str  # from mTLS SAN, OIDC subject, sidecar identity, or PRINCIPAL_HEADER
    method: str
    host: str
    path: str  # includes query string if any
    scheme: str = "https"
    headers: dict[str, str] = field(default_factory=dict)  # lowercase keys
    body: bytes | None = None  # only when the filter sets with_request_body
    # Envoy's declared full request size. None when the transport cannot know
    # it; a value larger than len(body) means Envoy truncated the body.
    body_size: int | None = None
    # How principal_id was established — resolve_principal() fills both. A
    # non-None identity_problem means a credential was PRESENTED and failed
    # verification, which is a structural deny, not a fall-through.
    attestation: Attestation = "assigned"
    identity_problem: str | None = None


@dataclass
class ConnInput:
    """One intercepted TCP connection — the network (L4) filter's view. E3.5.

    No method, no path, no headers: at L4 the observable facts are who is
    connecting and where to. The destination is always the literal ip:port the
    kernel saw; SNI, when a TLS inspector captured one, is the client's *claim*
    of a hostname and rides in params where rules can match it — it never
    replaces the address in the tool URI, because a client controls its own
    ClientHello and a policy keyed on it alone would be keyed on attacker input.
    """

    principal_id: str
    destination_address: str  # IP as Envoy saw it
    destination_port: int
    source_address: str | None = None
    sni: str | None = None
    attestation: Attestation = "assigned"  # "attested" when the id is an mTLS SAN


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


def bearer_of(headers: dict[str, str]) -> str | None:
    """The bearer token from an `authorization` header, if one is present."""
    value = headers.get("authorization", "")
    scheme, _, token = value.partition(" ")
    return token.strip() or None if scheme.lower() == "bearer" else None


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
        body_inspection: BodyInspection | None = None,
        oidc: OIDCValidator | None = None,
        flows: Any = None,
    ) -> None:
        self._enforcer = enforcer
        self._default_principal = default_principal
        self._trust_principal_header = trust_principal_header
        self._body = body_inspection
        self._oidc = oidc
        #: A shipper for `flow.v1` records (`flows.flow_shipper`), or None.
        #: The gateway sees every connection and request it decides on, which
        #: makes it the control plane's cheapest egress-log exporter (build-14
        #: S-2). Emission never touches the verdict: `submit` cannot raise.
        self._flows = flows

    def _unenrolled(self, req: CheckInput) -> bool:
        """Did this peer establish an identity? The deployment default and a
        credential that failed are "no"; a stamped header the deployment
        chose to trust, an OIDC subject or an mTLS SAN are "yes"."""
        return req.identity_problem is not None or req.principal_id == self._default_principal

    def _record_unenrolled_protocol(
        self, action: Action, protocol: str, decision: Decision
    ) -> None:
        """S-5: an agent protocol spoken by a peer nobody enrolled. A finding
        beside the verdict, never instead of it: the request was allowed or
        denied by policy as usual; this records that the fleet's servers are
        being addressed as agents by something outside the inventory."""
        try:
            finding = Action.build(
                principal=action.principal,
                tool=action.tool,
                verb="ingress",
                resource=protocol,
                params={},
                context=ActionContext(
                    origin="gateway",
                    extra={"agent_protocol": protocol, "verdict": decision.verdict.value},
                ),
            )
            self._enforcer.record(
                finding,
                Decision(
                    verdict=decision.verdict,
                    rule_id=None,
                    source="agent_protocol_unenrolled",
                    reason=f"{protocol} spoken by a peer that established no identity",
                ),
                count=False,  # beside the verdict, which was already counted
            )
        except Exception:  # noqa: BLE001 - a finding must never change a verdict
            pass

    def _emit_flow(self, record: dict[str, Any]) -> None:
        if self._flows is None:
            return
        try:
            self._flows.submit(record)
        except Exception:  # noqa: BLE001 - telemetry must never change a verdict
            pass

    def principal_for(self, *, mtls: str | None = None, header: str | None = None) -> str:
        """Back-compat shim over resolve_principal — id only, provenance dropped."""
        return self.resolve_principal(mtls=mtls, header=header)[0]

    def resolve_principal(
        self,
        *,
        mtls: str | None = None,
        bearer: str | None = None,
        header: str | None = None,
    ) -> tuple[str, Attestation, str | None]:
        """Resolve the acting principal and how it was established.

        Returns (id, attestation, problem). Precedence is by strength of
        proof, not by configuration order:

        - mTLS SAN → `attested`. Possession of a channel; a SPIFFE ID (e.g.
          `spiffe://cluster.local/ns/prod/sa/crew-1`) passes through verbatim —
          policy globs match SPIFFE paths directly, and any rewrite here would
          be lossy guesswork.
        - OIDC bearer, verified → `derived`. Proven to the strength of a
          bearer secret — real proof, weaker than a channel, which is why the
          SAN outranks it even when both are present.
        - PRINCIPAL_HEADER / default → `assigned`. Deployment position.

        `problem` is non-None when a bearer was PRESENTED and failed
        verification (or was presented with no validator configured). That is
        not a fall-through to the weaker identities: a caller waving a bad
        credential must not end up quietly enforced as `agent:unknown` — the
        caller records a structural deny with the problem string instead.
        """
        if mtls:
            return mtls, "attested", None
        if bearer:
            if self._oidc is None:
                return (
                    self._default_principal,
                    "assigned",
                    "bearer presented but no oidc configured",
                )
            identity, problem = self._oidc.verify(bearer)
            if identity is None:
                return self._default_principal, "assigned", problem or "token invalid"
            return identity.principal_id, "derived", None
        if header and self._trust_principal_header:
            return header, "assigned", None
        return self._default_principal, "assigned", None

    def _read_body(self, req: CheckInput) -> tuple[dict[str, Any], str | None]:
        """Parse the request body into params. Returns (params, problem).

        `problem` is None when there is nothing wrong — including the common
        case of a request that simply has no body (GET, DELETE). An absent body
        is not a failure to read one: a params-dependent rule just won't match.
        """
        cfg = self._body
        if cfg is None or not req.body:
            return {}, None
        ctype = req.headers.get("content-type", "").split(";")[0].strip().lower()
        if ctype not in cfg.content_types:
            return {}, "unsupported_content_type"
        if len(req.body) > cfg.max_bytes:
            return {}, "oversize"
        # Envoy truncates rather than rejects when allow_partial_message is on.
        # A prefix of a JSON document usually fails to parse anyway, but it can
        # parse cleanly by luck, so check the declared size rather than trust it.
        if req.body_size is not None and req.body_size > len(req.body):
            return {}, "truncated"
        try:
            parsed = json.loads(req.body, parse_float=str)
        except (ValueError, UnicodeDecodeError):
            return {}, "unparseable"
        if not isinstance(parsed, dict):
            return {}, "not_an_object"  # params is a mapping; a bare list/scalar isn't one
        return parsed, None

    def check(self, req: CheckInput) -> CheckResult:
        trace_id, span_id = _trace_ids(req.headers)
        params, problem = self._read_body(req)
        extra: dict[str, Any] = {}
        if problem is not None:
            # Recorded even when ignored, so the audit log shows that params
            # were unavailable rather than merely absent — an auditor can tell
            # "no rule matched" from "we never saw what this request carried".
            extra["body"] = problem
        # SDK correlation (E4). Recorded as a CLAIM and deliberately not
        # trusted: anything inside the trust boundary can set this header, so a
        # hostile agent could point it at an unrelated action's digest. It never
        # affects the verdict — the gateway decides on what it observed either
        # way — and only the SDK's own chained entry is authoritative. Its value
        # is that an honest client makes the two records joinable.
        claimed = req.headers.get(CORRELATION_HEADER)
        if claimed and _DIGEST.match(claimed):
            extra["sdk_action_claimed"] = claimed
        if req.identity_problem is not None:
            extra["identity"] = req.identity_problem
        # S-5 (build-14): what protocol is this, and did the peer establish an
        # identity? Recorded on the action for the audit; a finding below when
        # the answer is "an agent protocol" and "no".
        protocol = agent_protocol.fingerprint(
            method=req.method, path=req.path, headers=req.headers, body=req.body, params=params
        )
        if protocol is not None:
            extra["agent_protocol"] = protocol
        action = Action.build(
            principal=Principal(
                id=req.principal_id,
                # From resolve_principal(): "attested" for an mTLS SAN,
                # "derived" for a verified OIDC bearer, "assigned" for a
                # stamped header or deployment default. UAI-137 stops an agent
                # *asserting* an identity, which is not the same as
                # establishing one — this field records which happened.
                attestation=req.attestation,
            ),
            tool=f"{req.scheme}://{req.host}{req.path}",
            verb=req.method.lower(),
            resource="*",  # network layer can't see business semantics — that's the SDK's job (E4)
            params=params,  # empty unless body inspection is enabled (see BodyInspection)
            context=ActionContext(
                origin="gateway", trace_id=trace_id, span_id=span_id, extra=extra
            ),
        )
        if req.identity_problem is not None:
            # A presented credential that fails verification must not fall
            # through to be enforced as the weaker identity it fell back to —
            # that would let an expired token quietly become agent:unknown's
            # rules. Recorded through the enforcer like every other verdict.
            decision = self._enforcer.record(
                action,
                Decision(
                    verdict=Verdict.DENY,
                    rule_id=None,
                    source="identity_invalid",
                    reason=req.identity_problem,
                ),
            )
        elif problem is not None and self._body is not None and self._body.on_unreadable == "deny":
            # Short-circuit: params-dependent rules cannot be evaluated, so no
            # ALLOW here would be trustworthy. Recorded through the enforcer so
            # it is chained and traced exactly like a policy verdict.
            decision = self._enforcer.record(
                action,
                Decision(
                    verdict=Verdict.DENY,
                    rule_id=None,
                    source="body_unreadable",
                    reason=f"request body {problem}",
                ),
            )
        else:
            decision = self._enforcer.enforce(action)
        allowed = decision.verdict is Verdict.ALLOW
        if protocol is not None and self._unenrolled(req):
            self._record_unenrolled_protocol(action, protocol, decision)
        headers = {
            "x-unified-verdict": decision.verdict.value,
            "x-unified-source": decision.source,
            "x-unified-action-digest": action.digest(),
        }
        if decision.rule_id is not None:
            headers["x-unified-rule"] = decision.rule_id
        body = "" if allowed else f"unified-enforce: {decision.verdict.value}"
        self._emit_flow(flows.from_request(req, decision))
        return CheckResult(
            allowed=allowed,
            status_code=200 if allowed else 403,
            headers=headers,
            body=body,
            decision=decision,
            action=action,
        )

    def check_connection(self, conn: ConnInput) -> CheckResult:
        """Connection-level enforcement for traffic that is not HTTP. E3.5.

        Agents talk to databases, caches and queues on their own wire
        protocols, and an HTTP-only gateway leaves that whole class to the
        network layer's blunt CIDR rules. This is the connection-granularity
        answer: policy decides whether this principal may open a TCP
        connection to this destination at all, and the verdict lands in the
        chain like any other. What it deliberately does not see is what flows
        afterwards — statement-level inspection is a protocol-aware proxy's
        job, and pretending otherwise here would be an ALLOW dressed as
        understanding.

        The action shape keeps L4 rules unmistakably distinct from L7 ones:
        tool `tcp://ip:port`, verb `connect`. A rule matching `https://*` can
        never accidentally clear a raw socket to the same host.
        """
        extra: dict[str, Any] = {"transport": "tcp"}
        if conn.source_address:
            extra["source"] = conn.source_address
        params: dict[str, Any] = {}
        if conn.sni:
            params["sni"] = conn.sni
        action = Action.build(
            principal=Principal(id=conn.principal_id, attestation=conn.attestation),
            tool=f"tcp://{conn.destination_address}:{conn.destination_port}",
            verb="connect",
            resource="*",
            params=params,
            context=ActionContext(origin="gateway", extra=extra),
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
        self._emit_flow(flows.from_connection(conn, decision))
        return CheckResult(
            allowed=allowed,
            status_code=200 if allowed else 403,
            headers=headers,
            body="" if allowed else f"unified-enforce: {decision.verdict.value}",
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
        body = await request.body()
        principal_id, attestation, identity_problem = core.resolve_principal(
            bearer=bearer_of(headers), header=headers.get(PRINCIPAL_HEADER)
        )
        result = core.check(
            CheckInput(
                principal_id=principal_id,
                attestation=attestation,
                identity_problem=identity_problem,
                method=request.method,
                host=headers.get("x-forwarded-host") or headers.get("host", ""),
                path=full_path,
                scheme=headers.get("x-forwarded-proto", "https"),
                headers=headers,
                body=body or None,
                # Unlike the gRPC transport, this one has no trustworthy view of
                # the original request size — Envoy rewrites content-length when
                # it truncates — so truncation cannot be detected here. Configure
                # `allow_partial_message: false` with this transport so Envoy
                # rejects oversized bodies itself rather than silently shortening
                # one into something that might still parse.
                body_size=None,
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
