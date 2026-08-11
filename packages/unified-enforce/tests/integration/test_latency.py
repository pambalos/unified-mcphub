"""E3 §8: p99 latency of the ext_authz decision path.

`technologies.md` makes this measurement the precondition for any argument that
the data plane needs a Rust/Go rewrite: measure first, then decide. Until this
number exists, "Python is too slow here" is an assumption.

What is measured is the **engine's serving latency** — a full gRPC Check round
trip, client to servicer and back, under sustained concurrency. That is the
quantity a rewrite would change. Envoy's own filter overhead is deliberately
excluded: it is the same whatever language the servicer is written in, and
Envoy already reports it (`ext_authz.*` stats).

Both policy paths are exercised, because they cost very different amounts:
  - `glob`, a structural match only;
  - `cel`, which parses a JSON body into params and evaluates a CEL condition
    over it — the expensive branch, and the one E4's SDK will lean on.

Run it for real numbers (not just the regression guard):

    uv run python packages/unified-enforce/tests/integration/test_latency.py
"""

from __future__ import annotations

import json
import statistics
import subprocess
import sys
import time
from concurrent import futures

import grpc
import pytest

from unified_enforce import BodyInspection, Enforcer, ExtAuthzCore, PolicyEngine
from unified_enforce.extauthz_grpc import SERVICE_NAME, create_grpc_server
from unified_enforce.protos import ext_authz_pb2 as pb

pytestmark = pytest.mark.integration

# The budget the product claims for a decision.
BUDGET_MS = 10.0

POLICY = """
version: 1
rules:
  - id: api-reads-ok
    match: {principal: "agent:crew-*", tool: "https://api.internal/v1/users**", verb: get}
    effect: allow
  - id: small-refunds
    match: {principal: "agent:crew-*", tool: "https://payments.internal/v1/refunds", verb: post}
    when: 'double(params.amount) <= 5000.0'
    effect: allow
"""


def _request(kind: str) -> pb.CheckRequest:
    req = pb.CheckRequest()
    http = req.attributes.request.http
    http.scheme = "https"
    http.headers["x-unified-principal"] = "agent:crew-1"
    if kind == "glob":
        http.method, http.host, http.path = "GET", "api.internal", "/v1/users"
    else:
        http.method, http.host, http.path = "POST", "payments.internal", "/v1/refunds"
        http.headers["content-type"] = "application/json"
        http.raw_body = json.dumps({"amount": 100, "currency": "USD"}).encode()
        http.size = len(http.raw_body)
    return req


def _percentiles(samples_ms: list[float]) -> dict[str, float]:
    ordered = sorted(samples_ms)
    return {
        "n": len(ordered),
        "p50": statistics.median(ordered),
        "p95": ordered[int(len(ordered) * 0.95) - 1],
        "p99": ordered[int(len(ordered) * 0.99) - 1],
        "max": ordered[-1],
    }


def generate_load(port: int, kind: str, workers: int, per_worker: int) -> list[float]:
    """Hammer the servicer and return per-RPC latencies in ms.

    A single shared channel with several threads mirrors how Envoy actually
    calls the engine: one HTTP/2 connection, many concurrent streams. Separate
    channels per thread would measure a topology nothing runs.
    """
    with grpc.insecure_channel(f"127.0.0.1:{port}") as channel:
        rpc = channel.unary_unary(
            f"/{SERVICE_NAME}/Check",
            request_serializer=pb.CheckRequest.SerializeToString,
            response_deserializer=pb.CheckResponse.FromString,
        )
        req = _request(kind)
        # Warm up: the first calls pay channel setup and any lazy CEL work, and
        # would otherwise land in the tail and misreport it as a p99.
        for _ in range(20):
            rpc(req, timeout=10)

        def run() -> list[float]:
            out = []
            for _ in range(per_worker):
                start = time.perf_counter()
                rpc(req, timeout=10)
                out.append((time.perf_counter() - start) * 1000)
            return out

        with futures.ThreadPoolExecutor(max_workers=workers) as pool:
            batches = [f.result() for f in [pool.submit(run) for _ in range(workers)]]
    return [s for batch in batches for s in batch]


def measure(kind: str, *, workers: int = 8, per_worker: int = 250) -> dict[str, float]:
    """Serve in this process, generate load from a separate one.

    The load generator MUST NOT share an interpreter with the servicer. An
    in-process client puts the load threads and the serving threads on the same
    GIL, so they measure each other: the first version of this harness reported
    a CEL p99 of ~15ms that way, roughly double what the engine actually takes.
    Envoy is a separate C++ process, so co-locating the client would inflate
    the very number the rewrite decision hangs on.
    """
    core = ExtAuthzCore(
        Enforcer(PolicyEngine.from_yaml(POLICY)),
        body_inspection=BodyInspection(max_bytes=4096),
    )
    server = create_grpc_server(core, "127.0.0.1:0", max_workers=workers)
    server.start()
    try:
        proc = subprocess.run(
            [sys.executable, __file__, "--load", str(server.bound_port), kind,
             str(workers), str(per_worker)],
            capture_output=True, text=True, timeout=600,
        )  # fmt: skip
        if proc.returncode != 0:
            raise RuntimeError(f"load generator failed:\n{proc.stderr}")
        return _percentiles(json.loads(proc.stdout.strip().splitlines()[-1]))
    finally:
        server.stop(None)


@pytest.mark.parametrize("kind", ["glob", "cel"])
def test_decision_latency_stays_within_budget(kind, capsys):
    stats = measure(kind)
    with capsys.disabled():
        print(
            f"\n  ext_authz Check [{kind}]  n={stats['n']}  "
            f"p50={stats['p50']:.2f}ms  p95={stats['p95']:.2f}ms  "
            f"p99={stats['p99']:.2f}ms  max={stats['max']:.2f}ms"
        )
    # A regression guard, not the published figure — CI runners and laptops
    # differ enough that a tight bound would flake. The number that belongs in
    # the spec comes from running this file directly on representative hardware.
    assert stats["p99"] < BUDGET_MS * 5, (
        f"p99 {stats['p99']:.2f}ms is far outside the {BUDGET_MS}ms budget — "
        "this is a regression, not machine noise"
    )


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--load":
        # Re-entry as the load generator, in its own interpreter (see measure()).
        _port, _kind, _workers, _per = sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
        print(json.dumps(generate_load(int(_port), _kind, int(_workers), int(_per))))
        sys.exit(0)

    print(f"unified-enforce ext_authz decision latency (budget {BUDGET_MS}ms)\n")
    for kind in ("glob", "cel"):
        s = measure(kind, per_worker=1000)
        print(
            f"{kind:5}  n={s['n']:<6.0f} p50={s['p50']:6.2f}ms  p95={s['p95']:6.2f}ms  "
            f"p99={s['p99']:6.2f}ms  max={s['max']:6.2f}ms"
        )
