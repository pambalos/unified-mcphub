"""``build_graph`` — subprocess wrapper over ``graphify extract``.

We shell out to graphify's CLI (its stable, public build contract) rather than
re-implementing the extraction pipeline, so this wrapper never drifts against
graphify's internals across releases. Output lands at the native
``<path>/graphify-out/graph.json``.

backend defaults to ``claude-cli`` — keyless (uses the local Claude Code
subscription). Code-only repos skip the LLM pass entirely, so the backend is
*named but never invoked* there; doc/PDF/image corpora use it for semantic
extraction.

Extraction can run for many minutes on doc-heavy repos — longer than the MCP
client's per-call timeout (the harness default is 120s). So ``build_graph`` is
the synchronous *worker*; the MCP tool drives it through ``start_build``, which
runs it on a background thread and returns immediately, and ``build_state``,
which the ``build_status`` tool polls. The registry is in-process: a job lives
only as long as the resident server, but graphify's SHA256 cache makes a
restart-and-rebuild incremental.
"""

from __future__ import annotations

import re
import subprocess
import sys
import threading
import time
from pathlib import Path

# matches: "wrote /abs/.../graph.json: 14071 nodes, 29670 edges, 423 communities"
_SUMMARY_RE = re.compile(
    r"wrote\s+\S*graph\.json:\s+"
    r"(?P<nodes>\d+)\s+nodes,\s+(?P<edges>\d+)\s+edges,\s+(?P<communities>\d+)\s+communities"
)

# resolved repo path -> job record. Guarded by ``_jobs_lock``.
_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()


def build_graph(
    path: str,
    *,
    backend: str = "claude-cli",
    deep: bool = False,
    timeout: float = 600.0,
) -> dict:
    """Build (or incrementally rebuild) the graph for ``path``. Synchronous.

    Returns a result dict with ``ok`` plus, on success, node/edge/community
    counts and the graph path. graphify's SHA256 cache makes re-builds
    incremental automatically.
    """
    target = Path(path).expanduser().resolve()
    if not target.is_dir():
        return {"ok": False, "error": f"not a directory: {target}"}

    cmd = [
        sys.executable,
        "-m",
        "graphify",
        "extract",
        str(target),
        "--backend",
        backend,
        # claude-cli spawns one `claude -p` per chunk; serialize for stability
        # unless GRAPHIFY_CLAUDE_CLI_PARALLEL=1 (see graphify llm.py).
        "--max-concurrency",
        "1",
    ]
    if deep:
        cmd += ["--mode", "deep"]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "error": f"build timed out after {timeout:.0f}s",
            "hint": "large/doc-heavy repo — raise the client timeout or build out-of-band",
        }

    combined = f"{proc.stdout or ''}\n{proc.stderr or ''}"
    if proc.returncode != 0:
        return {
            "ok": False,
            "error": f"graphify extract failed (exit {proc.returncode})",
            "detail": combined.strip()[-1500:],
        }

    result: dict = {
        "ok": True,
        "path": str(target),
        "graph_json": str(target / "graphify-out" / "graph.json"),
        "backend": backend,
    }
    match = _SUMMARY_RE.search(combined)
    if match:
        result["nodes"] = int(match["nodes"])
        result["edges"] = int(match["edges"])
        result["communities"] = int(match["communities"])
    return result


def _run_build(key: str, backend: str, deep: bool, timeout: float) -> None:
    """Background worker: run the synchronous build, then record the outcome."""
    try:
        result = build_graph(key, backend=backend, deep=deep, timeout=timeout)
    except Exception as exc:  # noqa: BLE001 — never let a thread die silently
        result = {"ok": False, "error": f"build crashed: {exc}"}
    with _jobs_lock:
        job = _jobs.get(key)
        if job is not None:
            job["state"] = "done" if result.get("ok") else "failed"
            job["finished_at"] = time.time()
            job["result"] = result


def start_build(
    path: str,
    *,
    backend: str = "claude-cli",
    deep: bool = False,
    timeout: float = 600.0,
) -> dict:
    """Start a build on a background thread and return immediately.

    Returns ``{ok, state: "running", ...}`` while extraction runs; poll
    :func:`build_state` (the ``build_status`` tool) for completion. A build
    already running for the same resolved ``path`` is not duplicated — the
    in-flight job is returned instead.
    """
    target = Path(path).expanduser().resolve()
    if not target.is_dir():
        return {"ok": False, "error": f"not a directory: {target}"}
    key = str(target)

    with _jobs_lock:
        existing = _jobs.get(key)
        if existing is not None and existing["state"] == "running":
            return {
                "ok": True,
                "state": "running",
                "path": key,
                "started_at": existing["started_at"],
                "note": "build already in progress for this path",
            }
        _jobs[key] = {
            "state": "running",
            "started_at": time.time(),
            "finished_at": None,
            "result": None,
            "backend": backend,
            "deep": deep,
        }

    thread = threading.Thread(
        target=_run_build,
        args=(key, backend, deep, timeout),
        name=f"graphify-build:{key}",
        daemon=True,
    )
    thread.start()

    return {
        "ok": True,
        "state": "running",
        "path": key,
        "backend": backend,
        "hint": "poll build_status(path) until state is 'done' or 'failed'",
    }


def build_state(path: str) -> dict | None:
    """Snapshot of the in-process job for ``path``, or ``None`` if none ran.

    Returns a copy so callers never mutate the live record.
    """
    key = str(Path(path).expanduser().resolve())
    with _jobs_lock:
        job = _jobs.get(key)
        return dict(job) if job is not None else None
