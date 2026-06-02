"""Unit tests for shell, python and documents servers."""

from __future__ import annotations

import unified_mcp_servers.documents as docs
import unified_mcp_servers.python as py
import unified_mcp_servers.shell as sh


def test_shell_runs_and_reports_exit_code():
    ok = sh.execute_command("echo hi")
    assert ok["success"] and ok["exit_code"] == 0 and "hi" in ok["stdout"]
    bad = sh.execute_command("exit 3")
    assert bad["success"] is False and bad["exit_code"] == 3


def test_shell_timeout():
    res = sh.execute_command("sleep 5", timeout=1)
    assert res["timed_out"] is True and res["success"] is False


def test_check_syntax(tmp_path):
    good = tmp_path / "g.py"
    good.write_text("def f():\n    return 1\n")
    assert py.check_syntax(str(good))["valid"] is True

    bad = tmp_path / "b.py"
    bad.write_text("def f(:\n")
    r = py.check_syntax(str(bad))
    assert r["valid"] is False and r["error_type"] == "SyntaxError"


def test_find_function_classes_and_methods(tmp_path):
    (tmp_path / "m.py").write_text(
        "def top():\n    pass\n\nclass C:\n    def meth(self):\n        pass\n"
    )
    res = py.find_function("top", str(tmp_path), exact_match=True)
    assert res["found_count"] == 1 and res["results"][0]["type"] == "function"

    methods = py.find_function("meth", str(tmp_path), type="method")
    assert methods["found_count"] == 1 and methods["results"][0]["type"] == "method"

    classes = py.find_function("C", str(tmp_path), type="class", exact_match=True)
    assert classes["results"][0]["type"] == "class" and "meth" in classes["results"][0]["methods"]


def test_read_document_text(tmp_path):
    p = tmp_path / "n.md"
    p.write_text("# Title\n\nbody\n")
    r = docs.read_document(str(p))
    assert r["success"] and "Title" in r["content"] and r["format"] == "md"


def test_read_document_pdf_missing_dep_is_graceful(tmp_path, monkeypatch):
    # Simulate pypdf absent: the lazy import should yield a clear install hint.
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "pypdf":
            raise ImportError("no pypdf")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    p = tmp_path / "d.pdf"
    p.write_bytes(b"%PDF-1.4 fake")
    r = docs.read_document(str(p))
    assert r["success"] is False and "pypdf" in r["error"]
