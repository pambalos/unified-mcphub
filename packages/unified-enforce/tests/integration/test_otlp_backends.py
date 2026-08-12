"""Decision spans against real OTLP backends: an OTel Collector, and Langfuse.

Tier 1 (tests/unit/test_enforce_otlp.py) proves we emit well-formed OTLP by
decoding it ourselves. That is circular in one respect: the same library that
encodes also decodes. These tests remove the circularity.

  - The **collector** applies the validation any production OTLP pipeline
    would, so a span it accepts is genuinely wire-compatible.
  - **Langfuse** is the claim we actually make to design partners, and until
    now nothing had ever sent it a byte. It also checks the half we cannot
    test alone: that `for_langfuse` derives a path Langfuse really routes, and
    that `langfuse.observation.level` lands where their UI reads it.

Both are marked `integration` and skipped without Docker. Langfuse is a six
container stack; expect minutes on a cold image cache.

    uv run pytest packages/unified-enforce/tests/integration/test_otlp_backends.py \
        -m integration -s
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from unified_enforce import Action, ActionContext, PolicyEngine, Principal, Telemetry

pytestmark = pytest.mark.integration

HERE = Path(__file__).resolve().parent
COLLECTOR_IMAGE = "otel/opentelemetry-collector-contrib:latest"
COMPOSE_PROJECT = "unified-langfuse-test"

PUBLIC_KEY = "pk-lf-unified-test"
SECRET_KEY = "sk-lf-unified-test"

POLICY = """
version: 1
rules:
  - {id: reads-ok, match: {tool: "mcp://github/list_prs", verb: read}, effect: allow}
  - {id: payouts-need-a-human, match: {tool: "mcp://bank/payout"}, effect: defer}
"""


def _docker_ok() -> bool:
    if shutil.which("docker") is None:
        return False
    return subprocess.run(["docker", "info"], capture_output=True, timeout=60).returncode == 0


requires_docker = pytest.mark.skipif(not _docker_ok(), reason="docker daemon not available")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def emit(telemetry: Telemetry, tool: str, verb: str = "read") -> Action:
    """Record one decision through the real exporter and flush it."""
    engine = PolicyEngine.from_yaml(POLICY)
    action = Action.build(
        principal=Principal(id="agent:crew-1"),
        tool=tool,
        verb=verb,
        resource="*",
        params={"threshold": 0.75},
        context=ActionContext(origin="mcp"),
    )
    telemetry.record_decision(action, engine.decide(action))
    telemetry.shutdown()
    return action


# --- Tier 2: a real OTel Collector ---


@pytest.fixture
def collector(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    out.chmod(0o777)  # the collector runs unprivileged inside the container
    port = _free_port()
    name = f"unified-otelcol-{port}"
    proc = subprocess.run(
        ["docker", "run", "-d", "--rm", "--name", name,
         "-p", f"127.0.0.1:{port}:4318",
         "-v", f"{HERE / 'otel-collector.yaml'}:/etc/otelcol-contrib/config.yaml:ro",
         "-v", f"{out}:/out",
         COLLECTOR_IMAGE],
        capture_output=True, text=True, timeout=600,
    )  # fmt: skip
    if proc.returncode != 0:
        pytest.fail(f"collector failed to start: {proc.stderr}")
    try:
        _wait_until(lambda: _port_open(port), 60, "collector never opened 4318")
        yield port, out / "traces.json"
    finally:
        logs = subprocess.run(["docker", "logs", name], capture_output=True, text=True)
        print(logs.stderr[-2000:])
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


def _port_open(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(1)
        return s.connect_ex(("127.0.0.1", port)) == 0


def _wait_until(predicate, timeout_s: float, message: str, interval: float = 1.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            result = predicate()
        except Exception:
            result = None
        if result:
            return result
        time.sleep(interval)
    raise TimeoutError(message)


@requires_docker
def test_a_real_collector_accepts_our_spans(collector):
    """Wire compatibility judged by something that is not our own decoder."""
    port, traces_file = collector
    emit(Telemetry(endpoint=f"http://127.0.0.1:{port}/v1/traces"), "mcp://github/list_prs")

    _wait_until(
        lambda: traces_file.exists() and traces_file.stat().st_size > 0,
        30,
        "the collector never wrote a trace — it rejected the export",
    )
    payload = json.loads(traces_file.read_text().splitlines()[0])
    spans = [s for rs in payload["resourceSpans"] for ss in rs["scopeSpans"] for s in ss["spans"]]
    (span,) = spans
    assert span["name"] == "enforce.decide mcp://github/list_prs"

    attrs = {a["key"]: list(a["value"].values())[0] for a in span["attributes"]}
    assert attrs["unified.verdict"] == "allow"
    assert attrs["unified.rule_id"] == "reads-ok"
    assert attrs["langfuse.observation.level"] == "DEFAULT"


# --- Tier 3: a real self-hosted Langfuse ---


@dataclass(frozen=True)
class LangfuseVersion:
    """What differs between Langfuse majors, from our side of the wire.

    Self-hosters lag, so a partner is as likely to be on v3 as v4. The read API
    is *inverted* between them — each version 404s or blanks the other's
    endpoint — which is precisely the kind of thing a single-version suite
    would miss until someone reported that observability "doesn't work".
    """

    tag: str
    observations_path: str
    #: v4 requires an explicit time window and field groups; v3 requires neither
    needs_query_params: bool

    @property
    def project(self) -> str:
        return f"{COMPOSE_PROJECT}-v{self.tag}"


# v2 is absent on purpose: it has no OTLP endpoint at all (see the support-floor
# test below), so there is nothing for this integration to talk to.
LANGFUSE_VERSIONS = [
    LangfuseVersion(
        tag="3", observations_path="/api/public/observations", needs_query_params=False
    ),
    LangfuseVersion(
        tag="4", observations_path="/api/public/v2/observations", needs_query_params=True
    ),
]


def _compose(
    version: LangfuseVersion, *args: str, timeout: int = 900
) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", "-p", version.project,
         "-f", str(HERE / "langfuse-compose.yaml"), *args],
        capture_output=True, text=True, timeout=timeout,
    )  # fmt: skip


def _langfuse_get(port: int, path: str) -> dict:
    auth = base64.b64encode(f"{PUBLIC_KEY}:{SECRET_KEY}".encode()).decode()
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", headers={"Authorization": f"Basic {auth}"}
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.loads(response.read())


def _observations(port: int, version: LangfuseVersion) -> list[dict]:
    """Read back what Langfuse ingested, on whichever major is running.

    Three details, each of which produced a wrong conclusion before it was
    understood — and all three are silent, which is what makes them dangerous:

    1. **The read endpoint is inverted between majors.** v4 disables the v1
       paths (200 with a deprecation notice and no data — indistinguishable
       from "nothing was ingested"), and v3 404s the v2 path. The first version
       of this test queried v1 against v4 and reported an ingestion failure
       while the export was working perfectly.
    2. **`fields` selects exclusive groups, and an unrecognised value falls
       back to the default rather than erroring.** The default omits metadata,
       so `fields=all` — not a real group — made the second version of this
       test conclude that v4 drops custom attributes. It does not.
    3. **Timestamps need a literal `Z`.** An offset written `+00:00` arrives as
       a space, because `+` means space in a query string.
    """
    query = ""
    if version.needs_query_params:
        now = datetime.now(UTC)
        window = timedelta(hours=1)
        fmt = "%Y-%m-%dT%H:%M:%SZ"
        query = (
            f"?fromStartTime={(now - window).strftime(fmt)}"
            f"&toStartTime={(now + window).strftime(fmt)}&limit=50&fields=basic,metadata"
        )
    else:
        query = "?limit=50"
    return _langfuse_get(port, version.observations_path + query).get("data", [])


def _find(port: int, version: LangfuseVersion, name: str):
    """The most recent observation with this name.

    Newest-first because a name is not unique: each test emits its own span,
    and picking an arbitrary match would let one test assert against another's
    observation.
    """
    matches = [o for o in _observations(port, version) if o.get("name") == name]
    return max(matches, key=lambda o: o["startTime"]) if matches else None


def _attributes(observation: dict) -> dict[str, str]:
    """The span's attributes, however this major happens to shape them.

    v3 nests them (`metadata.attributes.<name>`); v4 flattens them into dotted
    keys on metadata itself (`metadata["attributes.<name>"]`). Same data, and
    callers should not have to care which is running.
    """
    metadata = observation.get("metadata") or {}
    nested = metadata.get("attributes")
    if isinstance(nested, dict):
        return dict(nested)
    return {
        key.removeprefix("attributes."): value
        for key, value in metadata.items()
        if key.startswith("attributes.")
    }


@pytest.fixture(scope="module", params=LANGFUSE_VERSIONS, ids=lambda v: f"langfuse-v{v.tag}")
def langfuse(request):
    """A running Langfuse of each supported major.

    Module-scoped and parametrized: the stack costs minutes to start, so every
    test for a version runs against one instance rather than one each.
    """
    version: LangfuseVersion = request.param
    port = _free_port()
    (HERE / f".env.v{version.tag}").write_text(
        f"LANGFUSE_PORT={port}\nLANGFUSE_VERSION={version.tag}\n"
    )
    env_file = ["--env-file", str(HERE / f".env.v{version.tag}")]
    up = _compose(version, *env_file, "up", "-d", "--wait")
    if up.returncode != 0:
        _compose(version, *env_file, "down", "-v")
        (HERE / f".env.v{version.tag}").unlink(missing_ok=True)
        pytest.fail(f"langfuse v{version.tag} failed to start:\n{up.stderr[-3000:]}")
    try:
        # Health first, then the seeded key: headless init runs after the web
        # process is already answering, so a 200 on /health is not enough.
        _wait_until(
            lambda: _langfuse_get(port, "/api/public/health") is not None,
            300,
            f"langfuse v{version.tag} never became healthy",
            interval=3,
        )
        _wait_until(
            lambda: _langfuse_get(port, "/api/public/projects") is not None,
            180,
            "the seeded API key never became valid (headless init did not complete)",
            interval=3,
        )
        yield port, version
    finally:
        logs = _compose(version, *env_file, "logs", "--tail", "40", "langfuse-web", timeout=120)
        print(logs.stdout[-3000:])
        _compose(version, *env_file, "down", "-v", timeout=300)
        (HERE / f".env.v{version.tag}").unlink(missing_ok=True)


@requires_docker
def test_langfuse_ingests_a_deferred_decision_as_a_warning(langfuse):
    """The claim in technologies.md, actually exercised: point the engine at a
    real Langfuse and have the decision arrive, readable, through its API."""
    port, version = langfuse
    emit(
        Telemetry.for_langfuse(f"http://127.0.0.1:{port}", PUBLIC_KEY, SECRET_KEY),
        "mcp://bank/payout",
        verb="call",
    )
    name = "enforce.decide mcp://bank/payout"
    observation = _wait_until(
        lambda: _find(port, version, name), 180, "the decision never appeared", interval=3
    )

    # Only a real Langfuse can confirm the attribute mapping: a deferred action
    # has to read as a warning rather than routine traffic.
    assert observation["level"] == "WARNING"
    # ...and the verdict has to be legible at a glance, without asking for
    # metadata (see telemetry.py).
    assert observation["statusMessage"] == "defer (payouts-need-a-human)"


@requires_docker
def test_every_decision_attribute_is_retrievable_from_langfuse(langfuse):
    """The whole enforcement record survives into Langfuse and can be queried.

    This is the test that answers "is any of this actually observable?" — an
    operator must be able to reconstruct who did what and which rule fired,
    not merely see that something happened.
    """
    port, version = langfuse
    emit(
        Telemetry.for_langfuse(f"http://127.0.0.1:{port}", PUBLIC_KEY, SECRET_KEY),
        "mcp://bank/payout",
        verb="call",
    )
    name = "enforce.decide mcp://bank/payout"
    observation = _wait_until(lambda: _find(port, version, name), 180, "never appeared", interval=3)
    attributes = _attributes(observation)
    assert attributes["unified.verdict"] == "defer"
    assert attributes["unified.rule_id"] == "payouts-need-a-human"
    assert attributes["unified.principal.id"] == "agent:crew-1"
    assert attributes["unified.tool"] == "mcp://bank/payout"
    assert attributes["unified.decision.source"] == "exact"
    assert attributes["unified.policy.audit_level"] == "standard"
    # The digest is the join back to the audit chain entry for this action.
    assert len(attributes["unified.action.digest"]) == 64


@requires_docker
def test_an_allow_is_not_flagged_as_a_warning(langfuse):
    """The counterpart: routine traffic must not drown the signal."""
    port, version = langfuse
    emit(
        Telemetry.for_langfuse(f"http://127.0.0.1:{port}", PUBLIC_KEY, SECRET_KEY),
        "mcp://github/list_prs",
    )
    name = "enforce.decide mcp://github/list_prs"
    observation = _wait_until(
        lambda: _find(port, version, name), 180, "the allow never appeared", interval=3
    )
    assert observation["level"] == "DEFAULT"
    assert observation["statusMessage"] == "allow (reads-ok)"


@requires_docker
def test_each_major_refuses_the_other_majors_read_path(langfuse):
    """Guards the mistake this suite already made once.

    The read API is inverted between majors, and each failure is *silent* in
    its own way: v4 answers the v1 path with 200, a deprecation notice and no
    data — indistinguishable from "nothing was ingested" — while v3 simply 404s
    the v2 path. Pinning both directions means a future single-endpoint
    simplification fails loudly here instead of quietly asserting nothing.
    """
    port, version = langfuse
    wrong_path = (
        "/api/public/observations?limit=10"
        if version.tag == "4"
        else "/api/public/v2/observations?limit=10"
    )
    try:
        body = _langfuse_get(port, wrong_path)
    except urllib.error.HTTPError as exc:
        body = {"status": exc.code}

    assert not body.get("data"), (
        f"v{version.tag} returned data from {wrong_path} — the read path may have changed, "
        "and this suite's endpoint selection needs revisiting"
    )


@requires_docker
def test_langfuse_v2_has_no_otlp_endpoint_at_all():
    """The support floor, verified rather than assumed.

    v2 predates OTel ingestion entirely: `/api/public/otel/v1/traces` is a
    **404, not a 405**, so there is nothing for this integration to talk to and
    no configuration that would make it work. Worth pinning, because "Langfuse
    is supported" otherwise reads as covering every version a self-hoster might
    still be running.

    A route that exists but rejects GET answers 405; one that does not exist
    answers 404. That distinction is the whole assertion, and it needs a real
    database underneath — v2 runs migrations before it serves, so a stub
    connection string never gets far enough to answer anything.
    """
    port = _free_port()
    project = f"{COMPOSE_PROJECT}-v2"
    compose = ["docker", "compose", "-p", project,
               "-f", str(HERE / "langfuse-v2-compose.yaml")]  # fmt: skip
    env = {**os.environ, "LANGFUSE_V2_PORT": str(port)}
    up = subprocess.run([*compose, "up", "-d"], capture_output=True, text=True,
                        timeout=900, env=env)  # fmt: skip
    if up.returncode != 0:
        pytest.fail(f"langfuse v2 failed to start:\n{up.stderr[-2000:]}")
    try:

        def status_of(path: str):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5)
            except urllib.error.HTTPError as exc:
                return exc.code
            except Exception:
                return None
            return 200

        _wait_until(
            lambda: status_of("/api/public/health") == 200,
            300,
            "langfuse v2 never started serving",
            interval=3,
        )
        otlp = status_of("/api/public/otel/v1/traces")
        assert otlp == 404, (
            f"expected no OTLP route on v2, got {otlp} — if this is now 405 the route "
            "exists and v2 belongs in LANGFUSE_VERSIONS"
        )
        # Sanity: a route that *does* exist answers something other than 404,
        # so the assertion above is about this path and not a dead server.
        assert status_of("/api/public/observations") != 404
    finally:
        subprocess.run([*compose, "down", "-v"], capture_output=True, timeout=300, env=env)
