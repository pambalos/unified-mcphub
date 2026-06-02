"""``graph_status`` — does a graph exist for a repo, when was it built, and is it
stale relative to the repo's git HEAD / working tree.

graphify itself doesn't expose this, so it's our own code: file mtime for "built
at", and a git comparison for staleness.
"""

from __future__ import annotations

import subprocess
from datetime import datetime, timezone
from pathlib import Path

from ._graph import graph_json_path


def _git(target: Path, *args: str) -> str | None:
    try:
        proc = subprocess.run(
            ["git", "-C", str(target), *args],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return proc.stdout.strip() if proc.returncode == 0 else None


def graph_status(path: str) -> dict:
    """Report graph existence, build time, and staleness vs git HEAD for ``path``."""
    target = Path(path).expanduser().resolve()
    gp = graph_json_path(path)
    out: dict = {"path": str(target), "graph_json": str(gp), "graph_exists": gp.exists()}

    built: datetime | None = None
    if gp.exists():
        st = gp.stat()
        built = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc)
        out["built_at"] = built.isoformat()
        out["size_bytes"] = st.st_size
    else:
        out["hint"] = "run build_graph to create the graph"

    head = _git(target, "rev-parse", "HEAD")
    if head:
        out["git_head"] = head[:12]
        dirty = bool(_git(target, "status", "--porcelain"))
        out["working_tree_dirty"] = dirty
        head_iso = _git(target, "show", "-s", "--format=%cI", "HEAD")
        if built is not None and head_iso:
            try:
                head_dt = datetime.fromisoformat(head_iso)
            except ValueError:
                head_dt = None
            if head_dt is not None:
                if dirty:
                    out["stale"], out["reason"] = True, "working tree has uncommitted changes"
                elif head_dt > built:
                    out["stale"], out["reason"] = True, "HEAD is newer than the graph"
                else:
                    out["stale"], out["reason"] = False, "up to date"
    return out
