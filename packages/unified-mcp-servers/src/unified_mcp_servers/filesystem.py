"""filesystem MCP server — mcp://filesystem/*

Faithful rebuild of the orchestrator filesystem tools, stdlib-only, with the
agent-loop ergonomics dropped (silent param aliases, fuzzy resolution,
read-before-edit tracking — see spec §"Safeties dropped"). Kept: is_path_safe.

Flags:
  --delete-mode soft|hard   soft (default) → move to trash; hard → unlink
  --trash-dir PATH          where soft-deletes go (default ~/.unified-ai/mcphub/trash)
"""

from __future__ import annotations

import argparse
import glob as globlib
import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from . import _search
from ._safety import format_bytes, format_numbered, is_path_safe, path_error, resolve

mcp = FastMCP("filesystem")

BINARY_EXTS = {".pyc", ".pyo", ".so", ".dylib", ".dll", ".exe", ".bin", ".o", ".a"}
IGNORE_NAMES = {"__pycache__", ".git", ".DS_Store", "node_modules", ".venv"}


def _default_trash() -> Path:
    home = os.environ.get("UNIFIED_HOME")
    base = Path(home) if home else Path.home() / ".unified-ai"
    return base / "mcphub" / "trash"


@dataclass
class Config:
    delete_mode: str = "soft"
    trash_dir: Path = field(default_factory=_default_trash)


CONFIG = Config()


@mcp.tool()
def file_info(path: str) -> dict:
    """Size, line count, type and mtime for a file."""
    if not is_path_safe(path):
        return path_error(path)
    full = resolve(path)
    if not os.path.exists(full):
        return {"success": False, "error": f"not found: {path}", "path": path}
    st = os.stat(full)
    ext = os.path.splitext(full)[1].lower()
    is_binary = ext in BINARY_EXTS
    out = {
        "success": True,
        "path": path,
        "absolute_path": full,
        "size_bytes": st.st_size,
        "size_human": format_bytes(st.st_size),
        "extension": ext,
        "type": "directory" if os.path.isdir(full) else "file",
        "modified": datetime.fromtimestamp(st.st_mtime).isoformat(),
        "is_binary": is_binary,
    }
    if not is_binary and os.path.isfile(full) and st.st_size < 100_000_000:
        try:
            with open(full, encoding="utf-8", errors="ignore") as fh:
                out["line_count"] = sum(1 for _ in fh)
        except OSError:
            pass
    return out


@mcp.tool()
def read_file(
    path: str,
    start_line: int | None = None,
    end_line: int | None = None,
    offset: int | None = None,
    limit: int | None = None,
) -> dict:
    """Read a file. Line mode (start_line/end_line) or byte mode (offset/limit)."""
    if not is_path_safe(path):
        return path_error(path)
    full = resolve(path)
    if not os.path.isfile(full):
        return {"success": False, "error": f"not a file: {path}", "path": path}

    if offset is not None or limit is not None:
        try:
            with open(full, "rb") as fh:
                fh.seek(offset or 0)
                data = fh.read(limit if limit is not None else -1)
        except OSError as exc:
            return {"success": False, "error": str(exc), "path": path}
        try:
            text, is_text = data.decode("utf-8"), True
        except UnicodeDecodeError:
            text, is_text = data.decode("latin-1"), False
        return {
            "success": True,
            "path": path,
            "mode": "byte",
            "content": text,
            "offset": offset or 0,
            "bytes_read": len(data),
            "size_bytes": os.path.getsize(full),
            "is_text": is_text,
        }

    try:
        with open(full, encoding="utf-8", errors="ignore") as fh:
            lines = fh.read().split("\n")
    except OSError as exc:
        return {"success": False, "error": str(exc), "path": path}
    total = len(lines)
    s = (start_line or 1) - 1
    e = end_line if end_line is not None else total
    selected = lines[max(0, s):e]
    return {
        "success": True,
        "path": path,
        "mode": "line",
        "content": format_numbered("\n".join(selected), start_line or 1),
        "lines": len(selected),
        "total_lines": total,
        "size_bytes": os.path.getsize(full),
        "line_format_note": "Leading 'N→' are display-only line numbers, not file content.",
    }


@mcp.tool()
def create_file(path: str, content: str) -> dict:
    """Create a new file. Fails if it already exists (no silent overwrite)."""
    if not is_path_safe(path):
        return path_error(path)
    full = resolve(path)
    if os.path.exists(full):
        return {
            "success": False,
            "error": f"file already exists: {path}",
            "path": path,
            "hint": "use edit_file to modify an existing file",
        }
    os.makedirs(os.path.dirname(full) or ".", exist_ok=True)
    with open(full, "w", encoding="utf-8") as fh:
        fh.write(content)
    return {"success": True, "path": path, "size_bytes": len(content.encode("utf-8"))}


@mcp.tool()
def edit_file(path: str, old_string: str, new_string: str, replace_all: bool = False) -> dict:
    """Replace old_string with new_string. Errors if old_string is absent or ambiguous."""
    if not is_path_safe(path):
        return path_error(path)
    full = resolve(path)
    if not os.path.isfile(full):
        return {"success": False, "error": f"not a file: {path}", "path": path}
    with open(full, encoding="utf-8", errors="ignore") as fh:
        text = fh.read()
    count = text.count(old_string)
    if count == 0:
        return {"success": False, "error": "old_string not found", "path": path, "searched_for": old_string}
    if count > 1 and not replace_all:
        return {
            "success": False,
            "error": f"old_string is not unique ({count} occurrences); pass replace_all=true or add context",
            "path": path,
            "occurrences": count,
        }
    updated = text.replace(old_string, new_string) if replace_all else text.replace(old_string, new_string, 1)
    with open(full, "w", encoding="utf-8") as fh:
        fh.write(updated)
    return {"success": True, "path": path, "replacements": count if replace_all else 1}


@mcp.tool()
def list_files(
    path: str = ".",
    file_pattern: str = "*",
    recursive: bool = False,
    show_hidden: bool = False,
) -> dict:
    """List files and directories under path."""
    if not is_path_safe(path):
        return path_error(path)
    base = resolve(path)
    if not os.path.isdir(base):
        return {"success": False, "error": f"not a directory: {path}", "path": path}
    pattern = os.path.join(base, "**", file_pattern) if recursive else os.path.join(base, file_pattern)
    files, dirs = [], []
    for match in globlib.glob(pattern, recursive=recursive):
        name = os.path.basename(match)
        if not show_hidden and (name.startswith(".") or name in IGNORE_NAMES):
            continue
        try:
            st = os.stat(match)
        except OSError:
            continue
        entry = {
            "name": name,
            "path": os.path.relpath(match, base),
            "size_bytes": st.st_size,
            "modified": datetime.fromtimestamp(st.st_mtime).isoformat(),
        }
        (dirs if os.path.isdir(match) else files).append(entry)
    return {
        "success": True,
        "path": path,
        "file_pattern": file_pattern,
        "recursive": recursive,
        "file_count": len(files),
        "directory_count": len(dirs),
        "files": files,
        "directories": dirs,
    }


@mcp.tool()
def delete_file(path: str) -> dict:
    """Delete a file. Soft (move to trash) by default; hard (unlink) per --delete-mode."""
    if not is_path_safe(path):
        return path_error(path)
    full = resolve(path)
    if not os.path.exists(full):
        return {"success": False, "error": f"not found: {path}", "path": path}
    if os.path.isdir(full):
        return {"success": False, "error": "refusing to delete a directory", "path": path}
    if CONFIG.delete_mode == "hard":
        os.unlink(full)
        return {"success": True, "path": path, "deleted": True, "mode": "hard"}
    CONFIG.trash_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    dest = CONFIG.trash_dir / f"{ts}-{os.path.basename(full)}"
    shutil.move(full, str(dest))
    return {"success": True, "path": path, "trashed_to": str(dest), "mode": "soft"}


@mcp.tool()
def search_files(query: str, path: str | None = None, file_pattern: str = "*") -> dict:
    """Grep-like content search (ripgrep when available, stdlib otherwise)."""
    directory = path or "."
    if not is_path_safe(directory):
        return path_error(directory)
    return _search.search_text(query, directory, file_pattern)


@mcp.tool()
def glob_files(pattern: str, directory: str | None = None, case_sensitive: bool = False) -> dict:
    """Find paths matching a glob pattern. (case_sensitive follows the OS: POSIX globs are case-sensitive.)"""
    base = resolve(directory or ".")
    if not is_path_safe(base):
        return path_error(base)
    matches = []
    for p in Path(base).glob(pattern):
        rel = os.path.relpath(str(p), base)
        try:
            st = p.stat()
        except OSError:
            continue
        matches.append({
            "path": rel,
            "absolute_path": str(p),
            "is_file": p.is_file(),
            "is_dir": p.is_dir(),
            "size_bytes": st.st_size,
        })
        if len(matches) >= 1000:
            break
    return {
        "success": True,
        "directory": base,
        "pattern": pattern,
        "match_count": len(matches),
        "matches": matches,
    }


@mcp.tool()
def find_files(
    pattern: str | None = None,
    content: str | None = None,
    directory: str = ".",
    case_sensitive: bool = False,
) -> dict:
    """Find files by name glob and/or by content. Hybrid narrows by glob first."""
    if not is_path_safe(directory):
        return path_error(directory)
    if not pattern and not content:
        return {"success": False, "error": "provide pattern, content, or both"}

    if pattern and not content:
        res = glob_files(pattern, directory, case_sensitive)
        res["strategy"] = "glob_only"
        return res
    if content and not pattern:
        res = _search.search_text(content, directory, "*")
        res["strategy"] = "content_only"
        return res

    base = resolve(directory)
    candidates = [p for p in Path(base).glob(pattern) if p.is_file()]
    matches = []
    for p in candidates:
        sub = _search.search_text(content, str(p), "*")
        if sub["results"]:
            matches.append({
                "path": os.path.relpath(str(p), base),
                "content_matches": sub["results"],
                "match_count": len(sub["results"]),
            })
    return {
        "success": True,
        "directory": base,
        "pattern": pattern,
        "content": content,
        "strategy": "hybrid_glob_then_content",
        "files_scanned": len(candidates),
        "match_count": len(matches),
        "matches": matches,
    }


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="unified_mcp_servers.filesystem")
    parser.add_argument("--delete-mode", choices=["soft", "hard"], default="soft")
    parser.add_argument("--trash-dir", default=None)
    args = parser.parse_args(argv)
    CONFIG.delete_mode = args.delete_mode
    if args.trash_dir:
        CONFIG.trash_dir = Path(args.trash_dir).expanduser()
    mcp.run()


if __name__ == "__main__":
    main()
