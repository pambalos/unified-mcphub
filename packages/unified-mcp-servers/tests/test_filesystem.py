"""Unit tests for the filesystem server (tool functions called directly)."""

from __future__ import annotations

import os
from pathlib import Path

import unified_mcp_servers.filesystem as fs


def test_create_read_edit_roundtrip(tmp_path):
    p = tmp_path / "a.txt"
    assert fs.create_file(str(p), "hello\nworld\n")["success"]
    # create refuses to overwrite
    assert fs.create_file(str(p), "x")["success"] is False

    r = fs.read_file(str(p), start_line=1, end_line=2)
    assert r["success"] and "1→hello" in r["content"]

    e = fs.edit_file(str(p), "world", "there")
    assert e["success"] and e["replacements"] == 1
    assert "there" in Path(p).read_text()


def test_edit_ambiguous_requires_replace_all(tmp_path):
    p = tmp_path / "b.txt"
    p.write_text("x\nx\n")
    amb = fs.edit_file(str(p), "x", "y")
    assert amb["success"] is False and amb["occurrences"] == 2
    ok = fs.edit_file(str(p), "x", "y", replace_all=True)
    assert ok["success"] and ok["replacements"] == 2


def test_delete_soft_then_hard(tmp_path, monkeypatch):
    trash = tmp_path / "trash"
    monkeypatch.setattr(fs.CONFIG, "trash_dir", trash)
    monkeypatch.setattr(fs.CONFIG, "delete_mode", "soft")
    p = tmp_path / "gone.txt"
    p.write_text("bye")
    res = fs.delete_file(str(p))
    assert res["success"] and res["mode"] == "soft"
    assert not p.exists()
    assert list(trash.iterdir())  # moved to trash

    monkeypatch.setattr(fs.CONFIG, "delete_mode", "hard")
    p2 = tmp_path / "gone2.txt"
    p2.write_text("bye")
    res2 = fs.delete_file(str(p2))
    assert res2["success"] and res2["mode"] == "hard" and not p2.exists()


def test_path_safety_blocks_restricted():
    assert fs.read_file("/etc/shadow")["success"] is False
    assert fs.file_info("~/.ssh/id_rsa")["success"] is False


def test_search_and_glob(tmp_path):
    (tmp_path / "x.py").write_text("def foo():\n    return 1\n")
    (tmp_path / "y.txt").write_text("nothing here\n")
    s = fs.search_files("def foo", str(tmp_path))
    assert s["success"] and s["result_count"] == 1
    g = fs.glob_files("*.py", str(tmp_path))
    assert g["match_count"] == 1 and g["matches"][0]["path"] == "x.py"


def test_find_files_hybrid_matches_content(tmp_path):
    # Regression: hybrid (pattern + content) passes file paths to the search
    # engine; the stdlib engine must scan a file path, not os.walk it.
    # a.md's match contains a ':' — exercises the path:line:content split for both
    # the ripgrep engine (single-file output) and the stdlib engine.
    (tmp_path / "a.md").write_text("intro\n2. **SSRF:** guard default-off\n")
    (tmp_path / "b.md").write_text("no keyword\n")
    (tmp_path / "c.txt").write_text("SSRF but wrong extension\n")
    r = fs.find_files(pattern="**/*.md", content="SSRF", directory=str(tmp_path))
    assert r["success"] and r["strategy"] == "hybrid_glob_then_content"
    hit_files = {m["path"] for m in r["matches"]}
    assert hit_files == {"a.md"}  # b.md lacks it; c.txt excluded by glob
    assert r["matches"][0]["match_count"] == 1


def test_find_files_content_only(tmp_path):
    (tmp_path / "f.txt").write_text("alpha\nSSRF\n")
    r = fs.find_files(content="SSRF", directory=str(tmp_path))
    assert r["strategy"] == "content_only" and r["result_count"] == 1


# --- the blocklist is canonical containment, not a string prefix -------------


def test_restricted_paths_are_not_reachable_through_a_symlink(tmp_path):
    """`~/.ssh/id_rsa` was refused while a symlink to the same file went
    straight through, because the comparison never resolved the link. The
    blocklist is only worth something if it names files, not strings."""
    from unified_mcp_servers._safety import is_path_safe

    secret = os.path.expanduser("~/.ssh/id_rsa")
    assert not is_path_safe(secret)

    link = tmp_path / "ssh"
    link.symlink_to(os.path.expanduser("~/.ssh"))
    assert not is_path_safe(str(link / "id_rsa"))


def test_ordinary_paths_are_still_allowed(tmp_path):
    from unified_mcp_servers._safety import is_path_safe

    assert is_path_safe(str(tmp_path / "notes.txt"))
    assert is_path_safe("notes.txt")  # relative, resolved against the cwd


def test_an_unparseable_path_is_refused_rather_than_guessed_at():
    from unified_mcp_servers._safety import is_path_safe

    assert not is_path_safe("\0")
