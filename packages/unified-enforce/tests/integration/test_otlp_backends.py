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
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
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


def _compose(*args: str, timeout: int = 900) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", "-p", COMPOSE_PROJECT, "-f", str(HERE / "langfuse-compose.yaml"), *args],
        capture_output=True, text=True, timeout=timeout,
    )  # fmt: skip


def _langfuse_get(port: int, path: str) -> dict:
    auth = base64.b64encode(f"{PUBLIC_KEY}:{SECRET_KEY}".encode()).decode()
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", headers={"Authorization": f"Basic {auth}"}
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.loads(response.read())


def _observations(port: int) -> list[dict]:
    """Read back what Langfuse ingested.

    Must be the **v2** endpoint. Langfuse v4 runs in `events_only` mode, where
    `/api/public/traces` and `/api/public/observations` return a deprecation
    notice with no data instead of an error — a query against them looks like
    "nothing was ingested", which is how the first version of this test failed
    while the export was working perfectly.

    Timestamps are formatted with a literal `Z`: an offset written `+00:00`
    reaches the server as a space, because `+` means space in a query string.
    """
    now = datetime.now(UTC)
    window = timedelta(hours=1)
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    query = (
        f"?fromStartTime={(now - window).strftime(fmt)}"
        f"&toStartTime={(now + window).strftime(fmt)}&limit=50"
    )
    return _langfuse_get(port, "/api/public/v2/observations" + query).get("data", [])


def _find(port: int, name: str):
    """The most recent observation with this name.

    Newest-first because a name is not unique: each test emits its own span,
    and picking an arbitrary match would let one test assert against another's
    observation.
    """
    matches = [o for o in _observations(port) if o.get("name") == name]
    return max(matches, key=lambda o: o["startTime"]) if matches else None


@pytest.fixture(scope="module")
def langfuse():
    port = _free_port()
    env_line = f"LANGFUSE_PORT={port}"
    (HERE / ".env").write_text(env_line + "\n")
    up = _compose("up", "-d", "--wait")
    if up.returncode != 0:
        _compose("down", "-v")
        (HERE / ".env").unlink(missing_ok=True)
        pytest.fail(f"langfuse stack failed to start:\n{up.stderr[-3000:]}")
    try:
        # Health first, then the seeded key: headless init runs after the web
        # process is already answering, so a 200 on /health is not enough.
        _wait_until(
            lambda: _langfuse_get(port, "/api/public/health") is not None,
            300,
            "langfuse never became healthy",
            interval=3,
        )
        _wait_until(
            lambda: _langfuse_get(port, "/api/public/projects") is not None,
            180,
            "the seeded API key never became valid (headless init did not complete)",
            interval=3,
        )
        yield port
    finally:
        logs = _compose("logs", "--tail", "40", "langfuse-web", timeout=120)
        print(logs.stdout[-3000:])
        _compose("down", "-v", timeout=300)
        (HERE / ".env").unlink(missing_ok=True)


@requires_docker
def test_langfuse_ingests_a_deferred_decision_as_a_warning(langfuse):
    """The claim in technologies.md, actually exercised: point the engine at a
    real Langfuse and have the decision arrive, readable, through its API."""
    emit(
        Telemetry.for_langfuse(f"http://127.0.0.1:{langfuse}", PUBLIC_KEY, SECRET_KEY),
        "mcp://bank/payout",
        verb="call",
    )
    name = "enforce.decide mcp://bank/payout"
    observation = _wait_until(
        lambda: _find(langfuse, name), 180, "the decision never appeared in Langfuse", interval=3
    )

    assert observation["type"] == "SPAN"
    # Only a real Langfuse can confirm the attribute mapping: a deferred action
    # has to read as a warning rather than routine traffic.
    assert observation["level"] == "WARNING"
    # ...and the verdict itself has to be legible. Langfuse v4 projects
    # observations to a fixed field set and returns no custom attributes, so
    # status_message is the channel that survives (see telemetry.py).
    assert observation["statusMessage"] == "defer (payouts-need-a-human)"


@requires_docker
def test_an_allow_is_not_flagged_as_a_warning(langfuse):
    """The counterpart: routine traffic must not drown the signal."""
    emit(
        Telemetry.for_langfuse(f"http://127.0.0.1:{langfuse}", PUBLIC_KEY, SECRET_KEY),
        "mcp://github/list_prs",
    )
    name = "enforce.decide mcp://github/list_prs"
    observation = _wait_until(
        lambda: _find(langfuse, name), 180, "the allow never appeared", interval=3
    )
    assert observation["level"] == "DEFAULT"
    assert observation["statusMessage"] == "allow (reads-ok)"


@requires_docker
def test_the_v1_endpoints_are_gone_so_the_test_cannot_silently_pass(langfuse):
    """Guards the mistake this suite already made once.

    In v4 `events_only` mode the v1 read endpoints answer 200 with a
    deprecation notice and no data. A test querying them sees an empty list and
    reports "nothing ingested" while ingestion is in fact working. Pinning the
    behaviour means a future move back to v1 paths fails loudly here rather
    than turning the whole suite into a no-op.
    """
    try:
        body = _langfuse_get(langfuse, "/api/public/observations?limit=10")
    except urllib.error.HTTPError as exc:
        body = json.loads(exc.read())

    # Whether it answers 200-with-a-notice or an error status, the property
    # that matters is the same: no usable data comes back, so a suite pointed
    # here would be asserting against nothing.
    assert not body.get("data"), "v1 returned data — the read path may have changed back"
    assert "not available" in body.get("message", "").lower()
