"""Content search — real ripgrep when present, stdlib fallback otherwise.

Option A from the spec review: use the actual ``rg`` binary (fast,
gitignore-aware, faithful to the orchestrator) when it is on PATH; degrade to a
pure-stdlib ``os.walk`` + ``re`` scan when it is not, so the package stays
``mcp``-only with no install-time binary requirement.
"""

from __future__ import annotations

import fnmatch
import os
import re
import shutil
import subprocess

# Directories never worth descending into. ripgrep already skips these via its
# own ignore rules; the stdlib fallback honours the same set.
IGNORE_DIRS = {
    "__pycache__",
    ".git",
    ".svn",
    ".hg",
    "node_modules",
    ".npm",
    ".yarn",
    ".venv",
    "venv",
    ".tox",
    ".nox",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    ".idea",
    ".vscode",
    "dist",
    "build",
    ".cache",
}

MAX_RESULTS = 50


def _rg_path() -> str | None:
    return shutil.which("rg")


def search_text(
    query: str,
    directory: str,
    file_pattern: str = "*",
    *,
    case_sensitive: bool = False,
    max_results: int = MAX_RESULTS,
) -> dict:
    """Grep-like search. Returns {results: [{file, line, content}], engine, ...}."""
    rg = _rg_path()
    if rg:
        results, truncated = _rg_search(
            rg, query, directory, file_pattern, case_sensitive, max_results
        )
        engine = "ripgrep"
    else:
        results, truncated = _stdlib_search(
            query, directory, file_pattern, case_sensitive, max_results
        )
        engine = "stdlib"
    return {
        "success": True,
        "found_matches": bool(results),
        "engine": engine,
        "search_directory": os.path.abspath(directory),
        "query": query,
        "file_pattern": file_pattern,
        "result_count": len(results),
        "results": results,
        "truncated": truncated,
    }


def _rg_search(rg, query, directory, file_pattern, case_sensitive, max_results):
    # --with-filename forces the `path:` prefix even for a single-file argument
    # (rg omits it otherwise), so the path:line:content split stays aligned.
    cmd = [
        rg,
        "--with-filename",
        "--line-number",
        "--no-heading",
        "--color=never",
        "--max-count",
        str(max_results),
    ]
    if not case_sensitive:
        cmd.append("--ignore-case")
    if file_pattern and file_pattern != "*":
        cmd += ["--glob", file_pattern]
    cmd += ["--regexp", query, directory]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except (subprocess.TimeoutExpired, OSError):
        return [], False
    results = []
    for raw in proc.stdout.splitlines():
        # path:line:content — content may itself contain ':', so split at most twice.
        parts = raw.split(":", 2)
        if len(parts) < 3 or not parts[1].isdigit():
            continue  # defensive: skip any line that doesn't parse as path:line:content
        path, lineno, content = parts
        results.append({"file": path, "line": int(lineno), "content": content})
        if len(results) >= max_results:
            return results, True
    return results, False


def _stdlib_search(query, directory, file_pattern, case_sensitive, max_results):
    flags = 0 if case_sensitive else re.IGNORECASE
    try:
        pattern = re.compile(query, flags)
    except re.error:
        pattern = re.compile(re.escape(query), flags)
    results = []

    # `directory` may be a single file (find_files hybrid passes file paths, and
    # ripgrep accepts file args too) — scan it directly rather than walking.
    if os.path.isfile(directory):
        _scan_file(directory, pattern, results, max_results)
        return results, len(results) >= max_results

    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        for name in files:
            if file_pattern and file_pattern != "*" and not fnmatch.fnmatch(name, file_pattern):
                continue
            if _scan_file(os.path.join(root, name), pattern, results, max_results):
                return results, True
    return results, False


def _scan_file(fpath, pattern, results, max_results) -> bool:
    """Append matches from one file. Returns True if max_results was reached."""
    try:
        with open(fpath, encoding="utf-8", errors="ignore") as fh:
            for lineno, line in enumerate(fh, start=1):
                if pattern.search(line):
                    results.append({"file": fpath, "line": lineno, "content": line.rstrip("\n")})
                    if len(results) >= max_results:
                        return True
    except (OSError, UnicodeError):
        return False
    return False
