"""Unit tests for built-in tool discovery + schema generation — spec §10, §10.1."""

from __future__ import annotations

import textwrap

from unified_mcphub.tools import BuiltinRegistry, _schema_from_signature


def test_schema_from_signature():
    def fn(name: str, count: int = 5, ratio: float = 1.0, on: bool = False):
        return None

    schema = _schema_from_signature(fn)
    assert schema["type"] == "object"
    assert schema["properties"]["name"]["type"] == "string"
    assert schema["properties"]["count"]["type"] == "integer"
    assert schema["properties"]["ratio"]["type"] == "number"
    assert schema["properties"]["on"]["type"] == "boolean"
    assert schema["required"] == ["name"]  # only the param without a default


def test_builtin_ping_registered():
    reg = BuiltinRegistry()
    assert reg.has("ping")
    assert reg.call("ping", {}) == "pong"
    assert "ping" in [t.name for t in reg.list_tools()]


def test_load_user_tools(tmp_path):
    (tmp_path / "greet.py").write_text(
        textwrap.dedent(
            """
            from unified_mcphub.tools import tool

            @tool(name="greet", description="Greet someone")
            def greet(who: str) -> str:
                return "hi " + who
            """
        ).strip()
        + "\n"
    )
    reg = BuiltinRegistry()
    reg.load_user_tools(tmp_path)
    assert reg.has("greet")
    assert reg.call("greet", {"who": "bradley"}) == "hi bradley"
    tool = next(t for t in reg.list_tools() if t.name == "greet")
    assert tool.description == "Greet someone"
    assert tool.inputSchema["required"] == ["who"]


def test_load_user_tools_ignores_missing_dir(tmp_path):
    reg = BuiltinRegistry()
    reg.load_user_tools(tmp_path / "nope")  # no raise
    assert reg.has("ping")
