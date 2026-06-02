"""python MCP server — mcp://python/*

Static analysis only. No code execution: ``check_syntax`` parses with ``ast``,
``find_function`` walks the AST of *.py files. Both read-only.
"""

from __future__ import annotations

import ast
import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from ._safety import is_path_safe, path_error, resolve

mcp = FastMCP("python")

_IGNORE_DIRS = {"__pycache__", ".git", ".venv", "venv", "node_modules", "build", "dist"}


@mcp.tool()
def check_syntax(path: str) -> dict:
    """Parse a Python file with ast and report syntax validity."""
    if not is_path_safe(path):
        return path_error(path)
    full = resolve(path)
    if not full.endswith(".py"):
        return {"success": False, "error": "not a .py file", "path": path}
    if not os.path.isfile(full):
        return {"success": False, "error": f"not found: {path}", "path": path}
    source = Path(full).read_text(encoding="utf-8", errors="ignore")
    try:
        ast.parse(source)
    except SyntaxError as exc:
        return {
            "success": True,
            "valid": False,
            "path": path,
            "error_type": "SyntaxError",
            "error_message": exc.msg,
            "line": exc.lineno,
            "offset": exc.offset,
            "text": (exc.text or "").rstrip("\n"),
        }
    return {"success": True, "valid": True, "path": path, "lines": source.count("\n") + 1}


@mcp.tool()
def find_function(
    name: str, directory: str = ".", type: str = "any", exact_match: bool = False
) -> dict:
    """Find function/class/method definitions by name across *.py files."""
    if not is_path_safe(directory):
        return path_error(directory)
    base = resolve(directory)
    want_func = type in ("any", "function", "method")
    want_class = type in ("any", "class")

    def matches(candidate: str) -> bool:
        return candidate == name if exact_match else name.lower() in candidate.lower()

    results: list[dict] = []
    files_searched = 0
    for root, dirs, files in os.walk(base):
        dirs[:] = [d for d in dirs if d not in _IGNORE_DIRS]
        for fname in files:
            if not fname.endswith(".py"):
                continue
            fpath = os.path.join(root, fname)
            files_searched += 1
            try:
                tree = ast.parse(Path(fpath).read_text(encoding="utf-8", errors="ignore"))
            except (SyntaxError, OSError):
                continue
            for node in ast.walk(tree):
                if (
                    isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and want_func
                    and matches(node.name)
                ):
                    args = [a.arg for a in node.args.args]
                    is_method = _enclosed(tree, node)
                    if type == "method" and not is_method:
                        continue
                    if type == "function" and is_method:
                        continue
                    results.append(
                        {
                            "file": os.path.relpath(fpath, base),
                            "line": node.lineno,
                            "type": "method" if is_method else "function",
                            "name": node.name,
                            "signature": f"{node.name}({', '.join(args)})",
                        }
                    )
                elif isinstance(node, ast.ClassDef) and want_class and matches(node.name):
                    methods = [
                        n.name
                        for n in node.body
                        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                    ]
                    results.append(
                        {
                            "file": os.path.relpath(fpath, base),
                            "line": node.lineno,
                            "type": "class",
                            "name": node.name,
                            "methods": methods[:10],
                            "method_count": len(methods),
                        }
                    )
                if len(results) >= 50:
                    break
    return {
        "success": True,
        "found_matches": bool(results),
        "query": name,
        "type_filter": type,
        "exact_match": exact_match,
        "files_searched": files_searched,
        "found_count": len(results),
        "results": results,
    }


def _enclosed(tree: ast.AST, target: ast.AST) -> bool:
    """True if target is a direct child of a ClassDef body (i.e. a method)."""
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and target in node.body:
            return True
    return False


def main(argv: list[str] | None = None) -> None:
    mcp.run()


if __name__ == "__main__":
    main()
