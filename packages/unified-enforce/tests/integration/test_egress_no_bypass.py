"""The no-bypass guarantee, executed rather than read. E3 §6, UAI-140.

`deploy/egress/` carries the load-bearing claim of the whole product —
*enforcement is mandatory, not best-effort; the agent has no route to tools
except through the plane* — and until this file existed, not one line of those
artifacts had ever run. Everything else E3 hardened sits behind a lock nobody
had tried the door on.

This runs **the shipped script**, unmodified, mounted read-only from
`deploy/egress/`. A test that reimplemented the rules would only prove the test
author understood iptables.

The topology mirrors what the script assumes: one host, an agent uid and a
proxy uid, a sidecar on the redirect port, and a separate "upstream" container
standing in for a third-party tool. The signal throughout is *where the packet
ended up* — the upstream answers `UPSTREAM`, the sidecar answers `SIDECAR`, so
a bypass is not an error code to interpret but a different string.

The first test is a **negative control**, and it is the most important one
here: it proves the harness can see a bypass at all. A no-bypass suite that
cannot fail is worth nothing, and this one has a real way to be vacuous — if
the container simply had no route to the upstream, every later assertion would
pass for the wrong reason.

    uv run pytest packages/unified-enforce/tests/integration/test_egress_no_bypass.py \
        -m integration
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

HERE = Path(__file__).resolve().parent
EGRESS_DIR = HERE.parent.parent / "deploy" / "egress"
IMAGE = "unified-egress-lab:test"

AGENT_UID = 1001
PROXY_UID = 1337
PROXY_PORT = 10000
UPSTREAM_TCP = 8080


def _docker_ok() -> bool:
    if shutil.which("docker") is None:
        return False
    return subprocess.run(["docker", "info"], capture_output=True, timeout=60).returncode == 0


requires_docker = pytest.mark.skipif(not _docker_ok(), reason="docker daemon not available")


def _run(args: list[str], timeout: int = 120) -> subprocess.CompletedProcess:
    # BuildKit wants to write state under ~/.docker/buildx, which is not always
    # writable (a sandboxed runner, a locked-down CI image). The lab image is a
    # handful of apk installs, so the legacy builder costs nothing and removes
    # a dependency on the developer's Docker configuration.
    env = {**os.environ, "DOCKER_BUILDKIT": "0"}
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=env)


@dataclass
class Lab:
    """The agent host, with a way to run commands as either identity."""

    container: str
    upstream_ip: str

    def exec(self, command: str, *, user: str | None = None, timeout: int = 60):
        args = ["docker", "exec"]
        if user:
            args += ["-u", user]
        args += [self.container, "sh", "-c", command]
        return _run(args, timeout=timeout)

    def fetch(self, *, user: str, port: int = UPSTREAM_TCP) -> str:
        """What answers when this identity dials the upstream directly?

        `--max-time` keeps a DROP from hanging the suite, and stdout is
        whichever server actually received the connection.
        """
        result = self.exec(
            f"curl -sS --max-time 5 http://{self.upstream_ip}:{port}/ || echo NO_CONNECTION",
            user=user,
        )
        return result.stdout.strip()

    def udp(self, *, user: str, port: int) -> str:
        result = self.exec(
            f"python3 /opt/udp_probe.py {self.upstream_ip} {port}", user=user, timeout=30
        )
        return result.stdout.strip()


@pytest.fixture(scope="module")
def lab():
    build = _run(["docker", "build", "-q", "-t", IMAGE, str(HERE / "egress")], timeout=900)
    if build.returncode != 0:
        pytest.fail(f"could not build the egress lab image:\n{build.stderr[-2000:]}")

    network = "unified-egress-net"
    upstream_name, agent_name = "unified-egress-upstream", "unified-egress-agent"
    for name in (upstream_name, agent_name):
        _run(["docker", "rm", "-f", name])
    _run(["docker", "network", "rm", network])
    _run(["docker", "network", "create", network])

    try:
        up = _run(
            ["docker", "run", "-d", "--rm", "--name", upstream_name, "--network", network,
             "-v", f"{HERE / 'egress' / 'upstream.py'}:/opt/upstream.py:ro",
             IMAGE, "python3", "/opt/upstream.py", str(UPSTREAM_TCP)],
        )  # fmt: skip
        if up.returncode != 0:
            pytest.fail(f"upstream failed to start: {up.stderr}")

        inspect = _run(
            ["docker", "inspect", upstream_name, "--format",
             "{{json .NetworkSettings.Networks}}"],
        )  # fmt: skip
        upstream_ip = next(iter(json.loads(inspect.stdout).values()))["IPAddress"]

        # NET_ADMIN is what lets the shipped script install its chains. The
        # egress directory is mounted read-only: the test runs the artifact,
        # it does not get to edit it.
        agent = _run(
            ["docker", "run", "-d", "--rm", "--name", agent_name, "--network", network,
             "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW",
             "-v", f"{EGRESS_DIR}:/egress:ro",
             IMAGE, "sleep", "infinity"],
        )  # fmt: skip
        if agent.returncode != 0:
            pytest.fail(f"agent host failed to start: {agent.stderr}")

        lab = Lab(container=agent_name, upstream_ip=upstream_ip)
        _wait_for_upstream(lab)
        yield lab
    finally:
        for name in (agent_name, upstream_name):
            _run(["docker", "rm", "-f", name])
        _run(["docker", "network", "rm", network])


def _wait_for_upstream(lab: Lab) -> None:
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if lab.fetch(user="root") == "UPSTREAM":
            return
        time.sleep(1)
    pytest.fail("the upstream never became reachable — the lab itself is broken")


@pytest.fixture(scope="module")
def locked(lab: Lab):
    """Install the real egress lock, once, after the control has run."""
    installed = lab.exec(
        f"AGENT_UID={AGENT_UID} PROXY_UID={PROXY_UID} PROXY_PORT={PROXY_PORT} "
        "bash /egress/iptables-sidecar.sh"
    )
    if installed.returncode != 0:
        pytest.fail(f"the shipped egress script failed to run:\n{installed.stderr}")

    started = lab.exec(
        f"su-exec proxy python3 /opt/sidecar.py {PROXY_PORT} >/tmp/sidecar.log 2>&1 &"
    )
    assert started.returncode == 0
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if lab.exec(f"curl -sS --max-time 2 http://127.0.0.1:{PROXY_PORT}/").stdout == "SIDECAR":
            break
        time.sleep(1)
    else:
        pytest.fail("the sidecar never came up; nothing below would mean anything")
    return lab


# --- the control: can this harness see a bypass at all? ---


@requires_docker
def test_without_the_lock_the_agent_reaches_the_upstream_directly(lab):
    """The negative control, and the most important test in this file.

    Before the lock is installed the agent *must* be able to reach the upstream.
    If it cannot — a missing route, a firewall in the lab, a broken upstream —
    then every assertion below would pass for the wrong reason and this suite
    would be proving nothing while looking green.
    """
    assert lab.fetch(user="agent") == "UPSTREAM", (
        "the agent could not reach the upstream even before the lock was installed, "
        "so this suite cannot distinguish enforcement from a broken lab"
    )


# --- the guarantee itself ---


@requires_docker
def test_the_agents_traffic_is_forced_through_the_sidecar(locked):
    """No bypass: the agent dials the upstream and reaches the sidecar instead.

    Same command as the control, opposite answer. The agent is not asked to
    cooperate, is not using a proxy setting, and does not know the sidecar
    exists — the kernel redirects it.
    """
    assert locked.fetch(user="agent") == "SIDECAR"


@requires_docker
def test_redirected_traffic_is_not_caught_by_the_catch_all_drop(locked):
    """Regression guard for the bug this suite was written to find.

    `REDIRECT` rewrites the destination to 127.0.0.1, but the packet reaches
    the filter chain still carrying its **original** output interface — so the
    `-o lo` RETURN never matches redirected traffic and the catch-all DROP eats
    every connection. The lock failed closed, which is the safe direction, but
    the agent could then reach neither the upstream *nor its own sidecar*: a
    documented deployment that does not work at all.

    Asserting on the DROP counter rather than only on reachability pins the
    mechanism. A behavioural test alone would go green again if someone
    "fixed" it by loosening the DROP.
    """
    before = _drop_packets(locked)
    assert locked.fetch(user="agent") == "SIDECAR"
    assert _drop_packets(locked) == before, (
        "redirected traffic hit the catch-all DROP — the loopback-destination "
        "RETURN is missing or ordered after it"
    )


def _drop_packets(lab: Lab) -> int:
    """Packet count on the UNIFIED_EGRESS catch-all DROP rule."""
    output = lab.exec("iptables -L UNIFIED_EGRESS -v -n -x").stdout
    for line in output.splitlines():
        if "DROP" in line:
            return int(line.split()[0])
    raise AssertionError(f"no DROP rule found in UNIFIED_EGRESS:\n{output}")


@requires_docker
def test_the_upstream_is_unreachable_by_address(locked):
    """Naming the upstream by IP on a different port changes nothing.

    Worth its own test because a policy that only catches port 80/443 would
    pass the test above and still leak everything else.
    """
    assert locked.fetch(user="agent", port=9090) == "SIDECAR"


@requires_docker
def test_quic_is_rejected_rather_than_quietly_escaping(locked):
    """The trap the script exists to close.

    `REDIRECT` only covers TCP, so a client that upgrades to HTTP/3 would leave
    the plane behind entirely — enforced traffic silently becoming unenforced.
    """
    assert locked.udp(user="agent", port=443) == "BLOCKED"


@requires_docker
def test_other_udp_is_dropped(locked):
    """Anything not TCP and not DNS has no business leaving."""
    assert locked.udp(user="agent", port=9999) == "BLOCKED"


@requires_docker
def test_dns_still_works(locked):
    """A lock that breaks name resolution gets removed by whoever is on call,
    so the carve-out is part of the guarantee rather than a weakening of it."""
    assert locked.udp(user="agent", port=53) == "REACHED"


@requires_docker
def test_the_sidecar_itself_is_exempt(locked):
    """The owner match has to let the proxy out, or nothing reaches any tool
    and the plane is a very thorough way of turning the agent off."""
    assert locked.fetch(user="proxy") == "UPSTREAM"


@requires_docker
def test_a_dead_sidecar_fails_closed_rather_than_falling_back(locked):
    """With the sidecar stopped the agent must fail, not slip out directly.

    This is the property that makes the guarantee *mandatory*: enforcement
    unavailable has to mean no traffic, never unenforced traffic.
    """
    locked.exec("pkill -f sidecar.py")
    time.sleep(1)
    try:
        assert locked.fetch(user="agent") == "NO_CONNECTION"
    finally:
        locked.exec(f"su-exec proxy python3 /opt/sidecar.py {PROXY_PORT} >/dev/null 2>&1 &")
        time.sleep(2)
