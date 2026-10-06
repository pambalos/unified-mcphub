"""The host runtime sensor — build-14 S-3, `host.v1`.

Runs on a customer's host, asks osquery three questions, reduces the answers
to *names* — process names and their parents, listening ports and the
process behind them, package names and versions — and posts them to the
control plane's `/api/v1/evidence/hosts`. Standard library only, so it runs
wherever Python does, with no dependency a reviewer has to trust.

What never leaves the host: command lines, environments, file contents,
arguments of any kind. The reduction drops them by construction (it copies
named columns, never rows), the control plane refuses them by name, and the
`--dry-run` flag prints exactly what would be sent so an operator can check
before enrolling a single machine.

    python -m unified_enforce.host_sensor --control-plane https://cp.example \\
        --credential-env UNIFIED_CREDENTIAL --interval 300

The credential is a sidecar credential enrolled for this fleet; the control
plane attributes every report to it.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
from datetime import UTC, datetime
from typing import Any

VERSION = "0.1"
HOSTS_PATH = "/api/v1/evidence/hosts"
MAX_FACTS = 2000
NAME_LIMIT = 256

#: The questions. Named columns only: `processes.cmdline` is deliberately
#: not selected, and nothing here reads `process_envs` or any file table.
QUERIES: dict[str, str] = {
    "processes": (
        "SELECT p.name AS name, pp.name AS parent, u.username AS user "
        "FROM processes p "
        "LEFT JOIN processes pp ON pp.pid = p.parent "
        "LEFT JOIN users u ON u.uid = p.uid "
        "WHERE p.name != '';"
    ),
    "listening_ports": (
        "SELECT lp.port AS port, lp.protocol AS protocol, p.name AS process "
        "FROM listening_ports lp LEFT JOIN processes p ON p.pid = lp.pid "
        "WHERE lp.port > 0;"
    ),
    "python_packages": "SELECT name, version FROM python_packages;",
}

_PROTOCOLS = {"6": "tcp", "17": "udp", "tcp": "tcp", "udp": "udp"}


def _clip(value: Any, limit: int = NAME_LIMIT) -> str:
    return str(value or "")[:limit]


def reduce(rows_by_query: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """osquery rows → `host.v1` facts. Copies named columns; drops everything
    else, so a row that happened to carry a command line does not carry it
    here. Deduplicated and bounded."""
    facts: list[dict[str, Any]] = []
    seen: set[tuple] = set()

    def add(fact: dict[str, Any]) -> None:
        key = (
            fact["kind"],
            fact["name"],
            fact.get("detail", ""),
            fact.get("user", ""),
            fact.get("port"),
        )
        if key in seen or len(facts) >= MAX_FACTS:
            return
        seen.add(key)
        facts.append(fact)

    for row in rows_by_query.get("processes", []):
        name = _clip(row.get("name"))
        if not name:
            continue
        add(
            {
                "kind": "process",
                "name": name,
                "detail": f"parent={_clip(row.get('parent'), 120)}",
                "user": _clip(row.get("user"), 128),
            }
        )
    for row in rows_by_query.get("listening_ports", []):
        try:
            port = int(row.get("port") or 0)
        except (TypeError, ValueError):
            continue
        if port <= 0:
            continue
        protocol = _PROTOCOLS.get(str(row.get("protocol") or "").lower(), "tcp")
        add(
            {
                "kind": "socket",
                "name": protocol,
                "port": port,
                "detail": _clip(row.get("process"), 120),
            }
        )
    for row in rows_by_query.get("python_packages", []):
        name = _clip(row.get("name"))
        if not name:
            continue
        add({"kind": "package", "name": name, "detail": _clip(row.get("version"), 64)})
    return facts


def build_report(host: str, facts: list[dict[str, Any]], *, now: datetime | None = None) -> dict:
    return {
        "host": host[:128],
        "sensor_version": VERSION,
        "observed_at": (now or datetime.now(UTC)).isoformat(),
        "facts": facts,
    }


def run_osquery(sql: str, *, osqueryi: str = "osqueryi", timeout: float = 30.0) -> list[dict]:
    """One query through `osqueryi --json`. Failure is an empty answer, and
    is logged: a sensor that cannot ask is still a heartbeat."""
    try:
        out = subprocess.run(
            [osqueryi, "--json", sql], capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"host-sensor: osquery failed: {exc}", file=sys.stderr)
        return []
    if out.returncode != 0:
        print(
            f"host-sensor: osquery exit {out.returncode}: {out.stderr.strip()[:200]}",
            file=sys.stderr,
        )
        return []
    try:
        rows = json.loads(out.stdout or "[]")
    except ValueError:
        return []
    return rows if isinstance(rows, list) else []


def collect(*, osqueryi: str = "osqueryi") -> dict[str, list[dict]]:
    return {name: run_osquery(sql, osqueryi=osqueryi) for name, sql in QUERIES.items()}


def post(base_url: str, credential: str, report: dict, *, timeout: float = 15.0) -> dict:
    """POST the report. Raises on refusal, so a loop can log and keep going."""
    import urllib.request

    body = json.dumps(report).encode()
    request = urllib.request.Request(
        base_url.rstrip("/") + HOSTS_PATH,
        data=body,
        headers={"content-type": "application/json", "authorization": f"Bearer {credential}"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read()
    try:
        return json.loads(raw) if raw else {}
    except ValueError:
        return {}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="unified-host-sensor", description=__doc__.split("\n\n")[0]
    )
    parser.add_argument("--control-plane", help="base URL of the control plane")
    parser.add_argument(
        "--credential-env",
        default="UNIFIED_CREDENTIAL",
        help="environment variable holding the sidecar credential",
    )
    parser.add_argument("--host", default=socket.gethostname(), help="this host's name as declared")
    parser.add_argument("--interval", type=float, default=300.0, help="seconds between reports")
    parser.add_argument("--once", action="store_true", help="report once and exit")
    parser.add_argument("--dry-run", action="store_true", help="print the report; send nothing")
    parser.add_argument("--osqueryi", default="osqueryi")
    args = parser.parse_args(argv)

    credential = os.environ.get(args.credential_env, "")
    if not args.dry_run and (not args.control_plane or not credential):
        parser.error(
            "--control-plane and a credential in the environment are required unless --dry-run"
        )

    while True:
        report = build_report(args.host, reduce(collect(osqueryi=args.osqueryi)))
        if args.dry_run:
            print(json.dumps(report, indent=2))
        else:
            try:
                receipt = post(args.control_plane, credential, report)
                print(
                    f"host-sensor: {len(report['facts'])} fact(s) sent; "
                    f"accepted={receipt.get('accepted')} raised={receipt.get('raised')}",
                    file=sys.stderr,
                )
            except Exception as exc:  # noqa: BLE001 - keep reporting; the plane records the gap
                print(f"host-sensor: report failed: {exc}", file=sys.stderr)
        if args.once or args.dry_run:
            return 0
        time.sleep(max(args.interval, 30.0))


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
