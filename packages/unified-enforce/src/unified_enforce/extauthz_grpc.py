"""Envoy ext_authz gRPC transport — `envoy.service.auth.v3.Authorization`.

The locked data-plane target (technologies.md decision 2): Envoy consults this
servicer on every request and enforces the verdict. Enforcement logic lives in
`ExtAuthzCore`; this module only translates protobuf ⇄ CheckInput/CheckResult,
so the HTTP and gRPC transports can never disagree about a decision.

Messages come from a **vendored minimal subset** of the Envoy v3 protos
(`protos/ext_authz.proto`), declared under our own package name. Two reasons:
the `xds-protos` distribution ships a stale `opentelemetry/proto/**` that
overwrites the real `opentelemetry-proto` package (breaking [otel] whenever
[gateway] is installed), and a distinct symbol namespace lets this coexist with
real Envoy protos in one process. Protobuf matches on field numbers and
tolerates unknown fields, so Envoy's full messages parse against our subset.

The wire service name Envoy dials — `envoy.service.auth.v3.Authorization` —
is set on the gRPC handler below, independent of the message namespace.

Identity: Envoy populates `attributes.source.principal` with the client's mTLS
SAN when `include_peer_certificate: true`. That is unspoofable and outranks the
`x-unified-principal` header (see ExtAuthzCore for the trust rules).

Decisions are pure CPU work, so a small thread pool saturates fine; the engine
holds no I/O in the decision path.
"""

from __future__ import annotations

from concurrent import futures
from typing import Any

from .extauthz import PRINCIPAL_HEADER, CheckInput, CheckResult, ExtAuthzCore
from .protos import ext_authz_pb2 as pb

SERVICE_NAME = "envoy.service.auth.v3.Authorization"
_OK = 0  # google.rpc.Code.OK
_PERMISSION_DENIED = 7  # google.rpc.Code.PERMISSION_DENIED

_INSTALL_HINT = "gRPC ext_authz needs the gateway extra — pip install 'unified-enforce[gateway]'"


def _to_check_input(request: Any, core: ExtAuthzCore) -> CheckInput:
    http = request.attributes.request.http
    headers = {k.lower(): v for k, v in http.headers.items()}
    return CheckInput(
        principal_id=core.principal_for(
            mtls=request.attributes.source.principal or None,
            header=headers.get(PRINCIPAL_HEADER),
        ),
        method=http.method,
        host=http.host,
        path=http.path,
        scheme=http.scheme or "https",
        headers=headers,
    )


def _header_options(result: CheckResult) -> list[Any]:
    return [
        pb.HeaderValueOption(header=pb.HeaderValue(key=k, value=v))
        for k, v in result.headers.items()
    ]


def check(core: ExtAuthzCore, request: Any) -> Any:
    """One ext_authz decision: CheckRequest → CheckResponse."""
    result = core.check(_to_check_input(request, core))
    if result.allowed:
        return pb.CheckResponse(
            status=pb.Status(code=_OK),
            ok_response=pb.OkHttpResponse(headers=_header_options(result)),
        )
    return pb.CheckResponse(
        status=pb.Status(code=_PERMISSION_DENIED),
        denied_response=pb.DeniedHttpResponse(
            status=pb.HttpStatus(code=result.status_code),
            headers=_header_options(result),
            body=result.body,
        ),
    )


def create_generic_handler(core: ExtAuthzCore) -> Any:
    """gRPC handler registered under Envoy's service name.

    A generic handler (rather than a generated servicer base class) is what
    decouples the wire service name from our message package.
    """
    try:
        import grpc
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise RuntimeError(_INSTALL_HINT) from exc

    return grpc.method_handlers_generic_handler(
        SERVICE_NAME,
        {
            "Check": grpc.unary_unary_rpc_method_handler(
                lambda request, context: check(core, request),
                request_deserializer=pb.CheckRequest.FromString,
                response_serializer=pb.CheckResponse.SerializeToString,
            )
        },
    )


def create_grpc_server(
    core: ExtAuthzCore, address: str = "127.0.0.1:9001", *, max_workers: int = 8
) -> Any:
    """Build (but do not start) a gRPC server serving the Authorization service.

    Bind to loopback or a Unix socket: the engine is a sidecar-local decision
    point, not a network service. Call `.start()` / `.wait_for_termination()`.
    The bound port is exposed as `server.bound_port` (useful with port 0).
    """
    try:
        import grpc
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(_INSTALL_HINT) from exc

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=max_workers))
    server.add_generic_rpc_handlers((create_generic_handler(core),))
    server.bound_port = server.add_insecure_port(address)
    return server
