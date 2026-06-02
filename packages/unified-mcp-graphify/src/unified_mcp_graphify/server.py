"""unified-mcp-graphify MCP server.

Tools (all take a per-call ``path`` = repo root → ``<path>/graphify-out/graph.json``):
  - build_graph   -> subprocess `graphify extract`  (write/compute → gate `prompt`)
  - graph_status  -> own code (git-HEAD staleness)   (read → `allow`)
  - query_graph / get_node / get_neighbors / get_community / god_nodes /
    graph_stats / shortest_path  -> library-import from graphify.serve  (read → `allow`)
  - list_prs / get_pr_impact / triage_prs  -> library-import from graphify.prs;
    run `gh`/`git` with cwd = ``path`` (graph impact uses that repo's graph).
"""

from __future__ import annotations

import contextlib
import os
import threading
from pathlib import Path

import networkx as nx
from mcp.server.fastmcp import FastMCP

from graphify.analyze import god_nodes as _god_nodes
from graphify.build import edge_data
from graphify.security import sanitize_label
from graphify.serve import _find_node, _query_graph_text, _score_nodes

from ._graph import GraphNotBuiltError, load
from .build import build_graph as _build_graph
from .status import graph_status as _graph_status

mcp = FastMCP("graphify")

_NO_GRAPH = "No graph for {path!r}. Run build_graph(path) first."


# --------------------------------------------------------------------------
# build / status
# --------------------------------------------------------------------------


@mcp.tool()
def build_graph(path: str, backend: str = "claude-cli", deep: bool = False) -> dict:
    """Build (or incrementally rebuild) the graphify knowledge graph for a repo.

    Runs graphify extraction over ``path``; the graph lands at
    ``<path>/graphify-out/graph.json``. ``backend`` defaults to ``claude-cli``
    (uses the local Claude Code subscription — no API key). Code-only repos never
    invoke the backend. Synchronous; may take minutes on large/doc-heavy repos.
    """
    return _build_graph(path, backend=backend, deep=deep)


@mcp.tool()
def graph_status(path: str) -> dict:
    """Whether a graph exists for ``path``, when it was built, and whether it is
    stale vs the repo's git HEAD / working tree."""
    return _graph_status(path)


# --------------------------------------------------------------------------
# graph queries (per-call path; logic mirrors graphify.serve's tool handlers)
# --------------------------------------------------------------------------


@mcp.tool()
def query_graph(
    path: str,
    question: str,
    mode: str = "bfs",
    depth: int = 3,
    token_budget: int = 2000,
    context_filter: list[str] | None = None,
) -> str:
    """Search the knowledge graph (BFS/DFS) for ``question``; returns a scoped
    subgraph as text. ``mode``: bfs=broad context, dfs=trace a path."""
    try:
        graph, _ = load(path)
    except GraphNotBuiltError:
        return _NO_GRAPH.format(path=path)
    return _query_graph_text(
        graph,
        question,
        mode=mode,
        depth=depth,
        token_budget=token_budget,
        context_filters=context_filter,
    )


@mcp.tool()
def get_node(path: str, label: str) -> str:
    """Full details for a node by label or ID."""
    try:
        graph, _ = load(path)
    except GraphNotBuiltError:
        return _NO_GRAPH.format(path=path)
    term = label.lower()
    matches = [
        (nid, d)
        for nid, d in graph.nodes(data=True)
        if term in (d.get("label") or "").lower() or term == nid.lower()
    ]
    if not matches:
        return f"No node matching '{label}' found."
    nid, d = matches[0]
    return "\n".join(
        [
            f"Node: {sanitize_label(d.get('label', nid))}",
            f"  ID: {sanitize_label(nid)}",
            f"  Source: {sanitize_label(str(d.get('source_file', '')))} "
            f"{sanitize_label(str(d.get('source_location', '')))}",
            f"  Type: {sanitize_label(str(d.get('file_type', '')))}",
            f"  Community: {sanitize_label(str(d.get('community', '')))}",
            f"  Degree: {graph.degree(nid)}",
        ]
    )


@mcp.tool()
def get_neighbors(path: str, label: str, relation_filter: str = "") -> str:
    """Direct neighbors of a node with edge details (optionally filtered by relation)."""
    try:
        graph, _ = load(path)
    except GraphNotBuiltError:
        return _NO_GRAPH.format(path=path)
    matches = _find_node(graph, label)
    if not matches:
        return f"No node matching '{label}' found."
    nid = matches[0]
    rel_filter = relation_filter.lower()
    lines = [f"Neighbors of {sanitize_label(graph.nodes[nid].get('label', nid))}:"]
    for nb in graph.successors(nid):
        d = edge_data(graph, nid, nb)
        rel = d.get("relation", "")
        if rel_filter and rel_filter not in rel.lower():
            continue
        lines.append(
            f"  --> {sanitize_label(graph.nodes[nb].get('label', nb))} "
            f"[{sanitize_label(str(rel))}] [{sanitize_label(str(d.get('confidence', '')))}]"
        )
    for nb in graph.predecessors(nid):
        d = edge_data(graph, nb, nid)
        rel = d.get("relation", "")
        if rel_filter and rel_filter not in rel.lower():
            continue
        lines.append(
            f"  <-- {sanitize_label(graph.nodes[nb].get('label', nb))} "
            f"[{sanitize_label(str(rel))}] [{sanitize_label(str(d.get('confidence', '')))}]"
        )
    return "\n".join(lines)


@mcp.tool()
def get_community(path: str, community_id: int) -> str:
    """All nodes in a community by ID (0-indexed by size)."""
    try:
        graph, communities = load(path)
    except GraphNotBuiltError:
        return _NO_GRAPH.format(path=path)
    cid = int(community_id)
    nodes = communities.get(cid, [])
    if not nodes:
        return f"Community {cid} not found."
    lines = [f"Community {cid} ({len(nodes)} nodes):"]
    for n in nodes:
        d = graph.nodes[n]
        lines.append(
            f"  {sanitize_label(d.get('label', n))} "
            f"[{sanitize_label(str(d.get('source_file', '')))}]"
        )
    return "\n".join(lines)


@mcp.tool()
def god_nodes(path: str, top_n: int = 10) -> str:
    """The most-connected nodes — the core abstractions of the graph."""
    try:
        graph, _ = load(path)
    except GraphNotBuiltError:
        return _NO_GRAPH.format(path=path)
    nodes = _god_nodes(graph, top_n=int(top_n))
    lines = ["God nodes (most connected):"]
    lines += [f"  {i}. {n['label']} - {n['degree']} edges" for i, n in enumerate(nodes, 1)]
    return "\n".join(lines)


@mcp.tool()
def graph_stats(path: str) -> str:
    """Summary stats: node count, edge count, communities, confidence breakdown."""
    try:
        graph, communities = load(path)
    except GraphNotBuiltError:
        return _NO_GRAPH.format(path=path)
    confs = [d.get("confidence", "EXTRACTED") for _, _, d in graph.edges(data=True)]
    total = len(confs) or 1
    return (
        f"Nodes: {graph.number_of_nodes()}\n"
        f"Edges: {graph.number_of_edges()}\n"
        f"Communities: {len(communities)}\n"
        f"EXTRACTED: {round(confs.count('EXTRACTED') / total * 100)}%\n"
        f"INFERRED: {round(confs.count('INFERRED') / total * 100)}%\n"
        f"AMBIGUOUS: {round(confs.count('AMBIGUOUS') / total * 100)}%\n"
    )


@mcp.tool()
def shortest_path(path: str, source: str, target: str, max_hops: int = 8) -> str:
    """Shortest path between two concepts in the knowledge graph."""
    try:
        graph, _ = load(path)
    except GraphNotBuiltError:
        return _NO_GRAPH.format(path=path)
    src_scored = _score_nodes(graph, [t.lower() for t in source.split()])
    tgt_scored = _score_nodes(graph, [t.lower() for t in target.split()])
    if not src_scored:
        return f"No node matching source '{source}' found."
    if not tgt_scored:
        return f"No node matching target '{target}' found."
    src_nid, tgt_nid = src_scored[0][1], tgt_scored[0][1]
    if src_nid == tgt_nid:
        return (
            f"'{source}' and '{target}' both resolved to the same node "
            f"'{src_nid}'. Use a more specific label or the exact node ID."
        )
    try:
        path_nodes = nx.shortest_path(graph.to_undirected(as_view=True), src_nid, tgt_nid)
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return (
            f"No path found between '{graph.nodes[src_nid].get('label', src_nid)}' "
            f"and '{graph.nodes[tgt_nid].get('label', tgt_nid)}'."
        )
    hops = len(path_nodes) - 1
    if hops > max_hops:
        return f"Path exceeds max_hops={max_hops} ({hops} hops found)."
    segments: list[str] = []
    for i in range(len(path_nodes) - 1):
        u, v = path_nodes[i], path_nodes[i + 1]
        if graph.has_edge(u, v):
            edata, forward = edge_data(graph, u, v), True
        else:
            edata, forward = edge_data(graph, v, u), False
        rel = edata.get("relation", "")
        conf = edata.get("confidence", "")
        conf_str = f" {conf}" if conf else ""
        label_v = graph.nodes[v].get("label", v)
        if i == 0:
            segments.append(str(graph.nodes[u].get("label", u)))
        segments.append(
            f"--{rel}{conf_str}--> {label_v}" if forward else f"<--{rel}{conf_str}-- {label_v}"
        )
    return f"Shortest path ({hops} hops):\n  " + " ".join(segments)


# --------------------------------------------------------------------------
# GitHub PR tools (library-import from graphify.prs)
#
# graphify.prs runs gh/git in the PROCESS cwd (with an optional --repo for gh),
# so to honor the per-call `path` we chdir into the repo for the duration. chdir
# is process-global; these calls are network-bound and infrequent, so we
# serialize them under a lock to avoid a cwd race with concurrent tool calls.
# --------------------------------------------------------------------------

_cwd_lock = threading.Lock()


@contextlib.contextmanager
def _in_repo(path: str):
    target = Path(path).expanduser().resolve()
    with _cwd_lock:
        prev = os.getcwd()
        os.chdir(target)
        try:
            yield target
        finally:
            os.chdir(prev)


@mcp.tool()
def list_prs(path: str, base: str = "", repo: str = "") -> str:
    """List open GitHub PRs for the repo at ``path`` with CI/review status and
    local worktree paths. ``base`` auto-detected if omitted; ``repo`` (owner/repo)
    defaults to the repo at ``path``."""
    from graphify.prs import (
        _detect_default_branch,
        fetch_prs,
        fetch_worktrees,
        format_prs_text,
    )

    repo_arg = repo or None
    with _in_repo(path):
        resolved_base = base or _detect_default_branch(repo_arg)
        try:
            prs = fetch_prs(repo=repo_arg, base=resolved_base)
        except RuntimeError as exc:
            return f"Error: {exc}"
        worktrees = fetch_worktrees()
        for pr in prs:
            pr.worktree_path = worktrees.get(pr.branch)
        return format_prs_text(prs, resolved_base)


@mcp.tool()
def get_pr_impact(path: str, pr_number: int, repo: str = "") -> str:
    """Graph impact for a specific PR: changed files, knowledge-graph communities
    affected, and node count — for the repo at ``path``."""
    from graphify.prs import _gh, _parse_ci, compute_pr_impact, fetch_pr_files

    try:
        graph, _ = load(path)
    except GraphNotBuiltError:
        return _NO_GRAPH.format(path=path)
    repo_arg = repo or None
    number = int(pr_number)
    with _in_repo(path):
        view_args = [
            "pr",
            "view",
            str(number),
            "--json",
            "title,headRefName,baseRefName,author,isDraft,reviewDecision,statusCheckRollup,updatedAt",
        ]
        if repo_arg:
            view_args += ["--repo", repo_arg]
        pr_data = _gh(*view_args)
        if pr_data is None:
            return f"PR #{number} not found or gh not authenticated."
        files = fetch_pr_files(number, repo_arg)
    if not files:
        return f"PR #{number}: no changed files found (may require gh auth)."
    comms, nodes = compute_pr_impact(files, graph)
    ci = _parse_ci(pr_data.get("statusCheckRollup") or [])
    lines = [
        f"PR #{number}: {pr_data['title']}",
        f"CI: {ci}  Review: {pr_data.get('reviewDecision') or 'none'}",
        f"Base: {pr_data['baseRefName']}  Author: {(pr_data.get('author') or {}).get('login', '?')}",
        f"\nGraph impact: {nodes} nodes across {len(comms)} communities",
        f"Communities touched: {comms}",
        f"Files changed ({len(files)}):",
    ]
    lines += [f"  {f}" for f in files[:20]]
    if len(files) > 20:
        lines.append(f"  … and {len(files) - 20} more")
    return "\n".join(lines)


@mcp.tool()
def triage_prs(path: str, base: str = "", repo: str = "") -> str:
    """Return actionable open PRs (correct base, not stale) with graph-impact data
    so you can reason about review priority and merge risk — for the repo at ``path``."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    from graphify.prs import (
        _STATUS_ORDER,
        _detect_default_branch,
        compute_pr_impact,
        fetch_pr_files,
        fetch_prs,
        fetch_worktrees,
    )

    try:
        graph, _ = load(path)
    except GraphNotBuiltError:
        return _NO_GRAPH.format(path=path)
    repo_arg = repo or None
    with _in_repo(path):
        resolved_base = base or _detect_default_branch(repo_arg)
        try:
            prs = fetch_prs(repo=repo_arg, base=resolved_base)
        except RuntimeError as exc:
            return f"Error: {exc}"
        worktrees = fetch_worktrees()
        for pr in prs:
            pr.worktree_path = worktrees.get(pr.branch)
        actionable = [
            p
            for p in prs
            if p.base_branch == resolved_base and p.status not in ("WRONG-BASE", "STALE")
        ]
        if not actionable:
            return f"No actionable PRs targeting {resolved_base}."
        workers = min(8, len(actionable))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            future_to_pr = {
                pool.submit(fetch_pr_files, pr.number, repo_arg): pr for pr in actionable
            }
            for fut in as_completed(future_to_pr):
                pr = future_to_pr[fut]
                try:
                    files = fut.result()
                except Exception:
                    files = []
                if files:
                    pr.files_changed = files
                    pr.communities_touched, pr.nodes_affected = compute_pr_impact(files, graph)
    header = (
        f"Actionable PRs targeting {resolved_base}: {len(actionable)}\n"
        "Rank by review priority. Higher blast_radius = more communities affected "
        "= higher merge risk.\n"
    )
    lines = [header]
    for p in sorted(
        actionable,
        key=lambda x: _STATUS_ORDER.index(x.status) if x.status in _STATUS_ORDER else 99,
    ):
        impact = f"  blast_radius={p.blast_radius}" if p.blast_radius else ""
        wt = f"  worktree={p.worktree_path}" if p.worktree_path else ""
        lines.append(
            f"PR #{p.number} [{p.status}] CI={p.ci_status} review={p.review_decision or 'none'} "
            f"age={p.days_old}d author={p.author}{impact}{wt}\n  title: {p.title}"
        )
    return "\n\n".join(lines)


def main() -> None:
    """Console entry point — run the stdio MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
