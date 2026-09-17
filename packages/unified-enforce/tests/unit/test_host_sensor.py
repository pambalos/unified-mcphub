"""The host sensor reduces osquery rows to names — build-14 S-3."""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer

from unified_enforce import host_sensor

ROWS = {
    "processes": [
        {
            "name": "ollama",
            "parent": "systemd",
            "user": "svc",
            "cmdline": "ollama serve --key=SECRET",
        },
        {"name": "python3", "parent": "bash", "user": "dev", "cmdline": "python3 agent.py"},
        {"name": "python3", "parent": "bash", "user": "dev"},
        {"name": "", "parent": "x", "user": "y"},
    ],
    "listening_ports": [
        {"port": "11434", "protocol": "6", "process": "ollama"},
        {"port": "0", "protocol": "6", "process": "x"},
        {"port": "bad", "protocol": "6", "process": "x"},
    ],
    "python_packages": [
        {"name": "anthropic", "version": "0.60.0"},
        {"name": "requests", "version": "2.32.0"},
    ],
}


def test_reduce_copies_names_and_drops_everything_else():
    facts = host_sensor.reduce(ROWS)
    assert facts == [
        {"kind": "process", "name": "ollama", "detail": "parent=systemd", "user": "svc"},
        {"kind": "process", "name": "python3", "detail": "parent=bash", "user": "dev"},
        {"kind": "socket", "name": "tcp", "port": 11434, "detail": "ollama"},
        {"kind": "package", "name": "anthropic", "detail": "0.60.0"},
        {"kind": "package", "name": "requests", "detail": "2.32.0"},
    ]
    assert "SECRET" not in json.dumps(facts) and "cmdline" not in json.dumps(facts)


def test_reduce_is_bounded_and_deduplicated(monkeypatch):
    monkeypatch.setattr(host_sensor, "MAX_FACTS", 3)
    rows = {"processes": [{"name": f"p{i}", "parent": "x", "user": "u"} for i in range(10)]}
    assert len(host_sensor.reduce(rows)) == 3
    dup = {"processes": [{"name": "a", "parent": "b", "user": "c"}] * 5}
    assert len(host_sensor.reduce(dup)) == 1


def test_the_queries_never_select_content():
    for sql in host_sensor.QUERIES.values():
        lowered = sql.lower()
        assert "cmdline" not in lowered and "process_envs" not in lowered
        assert "file" not in lowered and "hash" not in lowered


def test_build_report_shape():
    now = datetime(2026, 9, 17, 12, 0, tzinfo=UTC)
    report = host_sensor.build_report("build-7", [{"kind": "process", "name": "x"}], now=now)
    assert report == {
        "host": "build-7",
        "sensor_version": host_sensor.VERSION,
        "observed_at": "2026-09-17T12:00:00+00:00",
        "facts": [{"kind": "process", "name": "x"}],
    }


def test_post_sends_the_report_with_the_credential():
    received: dict = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("content-length", 0))
            received["path"] = self.path
            received["auth"] = self.headers.get("authorization")
            received["body"] = json.loads(self.rfile.read(length))
            self.send_response(202)
            self.send_header("content-type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"accepted": 1, "duplicates": 0, "raised": 0}')

        def log_message(self, *a):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}"
        report = host_sensor.build_report("build-7", [])
        receipt = host_sensor.post(url, "uai_sc_test", report)
    finally:
        server.shutdown()
    assert receipt["accepted"] == 1
    assert received["path"] == "/api/v1/evidence/hosts"
    assert received["auth"] == "Bearer uai_sc_test"
    assert received["body"]["host"] == "build-7"


def test_run_osquery_failure_is_an_empty_answer(tmp_path):
    assert host_sensor.run_osquery("SELECT 1;", osqueryi=str(tmp_path / "missing")) == []


def test_dry_run_prints_and_sends_nothing(monkeypatch, capsys):
    monkeypatch.setattr(host_sensor, "collect", lambda **kw: ROWS)
    assert host_sensor.main(["--dry-run", "--host", "build-7"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["host"] == "build-7" and len(out["facts"]) == 5
    assert "SECRET" not in json.dumps(out)


def test_sending_requires_a_control_plane_and_a_credential(monkeypatch):
    monkeypatch.delenv("UNIFIED_CREDENTIAL", raising=False)
    try:
        host_sensor.main(["--once", "--control-plane", "https://cp"])
    except SystemExit as exc:
        assert exc.code == 2
    else:  # pragma: no cover
        raise AssertionError("argparse should have refused")
