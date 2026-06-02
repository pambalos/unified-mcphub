"""documents MCP server — mcp://documents/*

Read text from documents. Plain-text formats use the stdlib; PDF/DOCX are
lazy-imported (``pypdf`` / ``python-docx``) so the server stays light — if the
optional dep is absent it returns a clear "pip install …" error rather than
failing to import.
"""

from __future__ import annotations

import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from ._safety import is_path_safe, path_error, resolve

mcp = FastMCP("documents")

_TEXT_EXTS = {".txt", ".md", ".rst", ".csv", ".log", ".json", ".yaml", ".yml", ".toml"}


@mcp.tool()
def read_document(path: str) -> dict:
    """Extract text from a document (txt/md/csv natively; pdf/docx via optional deps)."""
    if not is_path_safe(path):
        return path_error(path)
    full = resolve(path)
    if not os.path.isfile(full):
        return {"success": False, "error": f"not found: {path}", "path": path}
    ext = Path(full).suffix.lower()

    if ext == ".pdf":
        return _read_pdf(full, path)
    if ext in (".docx", ".doc"):
        return _read_docx(full, path)
    if ext in _TEXT_EXTS or ext == "":
        text = Path(full).read_text(encoding="utf-8", errors="ignore")
        return {
            "success": True,
            "path": path,
            "format": ext.lstrip(".") or "text",
            "content": text,
            "content_length": len(text),
        }
    return {"success": False, "error": f"unsupported format: {ext}", "path": path}


def _read_pdf(full: str, path: str) -> dict:
    try:
        import pypdf
    except ImportError:
        return {
            "success": False,
            "path": path,
            "error": "PDF support needs pypdf — install with: pip install 'unified-mcp-servers[documents]'",
        }
    reader = pypdf.PdfReader(full)
    pages = [page.extract_text() or "" for page in reader.pages]
    content = "\n\n".join(pages)
    return {
        "success": True,
        "path": path,
        "format": "pdf",
        "content": content,
        "content_length": len(content),
        "page_count": len(pages),
    }


def _read_docx(full: str, path: str) -> dict:
    try:
        import docx
    except ImportError:
        return {
            "success": False,
            "path": path,
            "error": "DOCX support needs python-docx — install with: pip install 'unified-mcp-servers[documents]'",
        }
    document = docx.Document(full)
    paras = [p.text for p in document.paragraphs]
    content = "\n\n".join(paras)
    return {
        "success": True,
        "path": path,
        "format": "docx",
        "content": content,
        "content_length": len(content),
        "paragraph_count": len(paras),
    }


def main(argv: list[str] | None = None) -> None:
    mcp.run()


if __name__ == "__main__":
    main()
