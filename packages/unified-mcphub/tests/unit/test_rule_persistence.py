"""Persisting an *_always rule must NOT destroy the hand-edited workspace file.

Regression for the comment-stripping bug: PyYAML's safe_dump round-trip wiped
comments/ordering; the persist path uses ruamel round-trip instead (ADR-0006
tier-1 exact rule; spec §5.3).
"""

from __future__ import annotations

import yaml

from unified_mcphub.config import load_config, workspace_path
from unified_mcphub.hub import Hub

WORKSPACE = """\
# Default workspace — hand-edited, comments must survive.
servers: {}

authz:
  rules:
    # Reads are safe:
    - tool: "mcp://*/read_*"   # wildcard read allow
      effect: allow
"""


def test_persist_preserves_comments_and_adds_rule(hub_home):
    path = workspace_path("default")
    path.write_text(WORKSPACE)

    hub = Hub(load_config())
    hub._persist_exact_rule("mcp://shell/execute_command", "claude-code", allowed=True)

    text = path.read_text()
    # Comments preserved (this is the whole point):
    assert "# Default workspace — hand-edited, comments must survive." in text
    assert "# Reads are safe:" in text
    assert "# wildcard read allow" in text

    # New tier-1 rule was prepended and is loadable + correct:
    data = yaml.safe_load(text)
    rules = data["authz"]["rules"]
    assert rules[0] == {
        "tool": "mcp://shell/execute_command",
        "callers": ["claude-code"],
        "effect": "allow",
    }
    assert rules[1]["tool"] == "mcp://*/read_*"  # original rule kept, after the new one


def test_persist_into_empty_workspace(hub_home):
    # No existing authz section — must still write a valid file.
    path = workspace_path("default")
    path.write_text("servers: {}\n")
    hub = Hub(load_config())
    hub._persist_exact_rule("mcp://filesystem/delete_file", "opencode", allowed=False)
    data = yaml.safe_load(path.read_text())
    assert data["authz"]["rules"][0]["effect"] == "deny"
