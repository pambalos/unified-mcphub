"""``build_graph`` — subprocess wrapper over ``graphify extract``.

We shell out to graphify's CLI (its stable, public build contract) rather than
re-implementing the extraction pipeline, so this wrapper never drifts against
graphify's internals across releases. Output lands at the native
``<path>/graphify-out/graph.json``.

backend defaults to ``claude-cli`` — keyless (uses the local Claude Code
subscription). Code-only repos skip the LLM pass entirely, so the backend is
*named but never invoked* there; doc/PDF/image corpora use it for semantic
extraction.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

# matches: "wrote /abs/.../graph.json: 14071 nodes, 29670 edges, 423 communities"
_SUMMARY_RE = re.compile(
    r"wrote\s+\S*graph\.json:\s+"
    r"(?P<nodes>\d+)\s+nodes,\s+(?P<edges>\d+)\s+edges,\s+(?P<communities>\d+)\s+communities"
)


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
