"""Persisting an *_always rule writes to the machine-managed .local.yaml.

ADR-0024: learned rules persist to `workspaces/<name>.local.yaml`, never into the
hand-curated `workspaces/<name>.yaml`. At load they merge as tier-1 exact rules
ordered ahead of the curated rules (ADR-0006; first-match-wins → they win).
"""

from __future__ import annotations

import yaml

from unified_mcphub.authz import Effect
from unified_mcphub.config import load_config, workspace_local_path, workspace_path
from unified_mcphub.hub import Hub

# Hand-edited curated workspace — comments/ordering must never be touched by the hub.
WORKSPACE = """\
# Default workspace — hand-edited, comments must survive.
servers: {}

authz:
  rules:
    # Reads are safe:
    - tool: "mcp://*/read_*"   # wildcard read allow
      effect: allow
"""


def test_allow_always_writes_local_file_and_leaves_curated_untouched(hub_home):
    curated = workspace_path("default")
    curated.write_text(WORKSPACE)
    before = curated.read_bytes()

    hub = Hub(load_config())
    hub._persist_exact_rule("mcp://shell/execute_command", "claude-code", allowed=True)

    # The curated file is byte-for-byte unchanged.
    assert curated.read_bytes() == before

    # The learned rule landed in the separate .local.yaml as a flat list.
    local = workspace_local_path("default")
    learned = yaml.safe_load(local.read_text())
    assert learned == [
        {"tool": "mcp://shell/execute_command", "callers": ["claude-code"], "effect": "allow"}
    ]

    # A fresh load merges it as a tier-1 exact rule the resolver returns.
    cfg = load_config()
    assert cfg.workspace.authz.rules[0].tool == "mcp://shell/execute_command"
    assert cfg.workspace.authz.rules[1].tool == "mcp://*/read_*"  # curated rule still after it
    resolver = Hub(cfg).authz
    assert resolver.resolve("mcp://shell/execute_command", {}, "claude-code").effect is Effect.ALLOW


def test_deny_always_writes_local_file_and_leaves_curated_untouched(hub_home):
    curated = workspace_path("default")
    curated.write_text(WORKSPACE)
    before = curated.read_bytes()

    hub = Hub(load_config())
    hub._persist_exact_rule("mcp://filesystem/delete_file", "opencode", allowed=False)

    assert curated.read_bytes() == before

    local = workspace_local_path("default")
    learned = yaml.safe_load(local.read_text())
    assert learned == [
        {"tool": "mcp://filesystem/delete_file", "callers": ["opencode"], "effect": "deny"}
    ]

    cfg = load_config()
    resolver = Hub(cfg).authz
    assert resolver.resolve("mcp://filesystem/delete_file", {}, "opencode").effect is Effect.DENY


def test_learned_rules_accrete_newest_first(hub_home):
    workspace_path("default").write_text(WORKSPACE)
    hub = Hub(load_config())
    hub._persist_exact_rule("mcp://shell/execute_command", "claude-code", allowed=True)
    hub._persist_exact_rule("mcp://filesystem/delete_file", "claude-code", allowed=False)

    learned = yaml.safe_load(workspace_local_path("default").read_text())
    assert [r["tool"] for r in learned] == [
        "mcp://filesystem/delete_file",  # most recent first
        "mcp://shell/execute_command",
    ]


def test_persist_exact_command_scopes_via_args_filter(hub_home):
    workspace_path("default").write_text(WORKSPACE)
    hub = Hub(load_config())
    af = {"command": {"equals": ["git status"]}}
    hub._persist_exact_rule(
        "mcp://shell/execute_command", "claude-code", allowed=True, args_filter=af
    )

    # The args_filter is persisted alongside the rule.
    learned = yaml.safe_load(workspace_local_path("default").read_text())
    assert learned[0]["args_filter"] == af

    resolver = Hub(load_config()).authz
    # Only the exact command is allowed; any other command falls through to deny.
    assert (
        resolver.resolve(
            "mcp://shell/execute_command", {"command": "git status"}, "claude-code"
        ).effect
        is Effect.ALLOW
    )
    assert (
        resolver.resolve(
            "mcp://shell/execute_command", {"command": "rm -rf /"}, "claude-code"
        ).effect
        is Effect.DENY
    )


def test_persist_prefix_scopes_via_args_filter(hub_home):
    workspace_path("default").write_text(WORKSPACE)
    hub = Hub(load_config())
    af = {"command": {"starts_with": ["git "]}}
    hub._persist_exact_rule(
        "mcp://shell/execute_command", "claude-code", allowed=True, args_filter=af
    )

    resolver = Hub(load_config()).authz
    assert (
        resolver.resolve(
            "mcp://shell/execute_command", {"command": "git log --oneline"}, "claude-code"
        ).effect
        is Effect.ALLOW
    )
    assert (
        resolver.resolve(
            "mcp://shell/execute_command", {"command": "npm test"}, "claude-code"
        ).effect
        is Effect.DENY
    )


def test_learned_deny_overrides_curated_allow(hub_home):
    # Curated file allows everything via a wildcard; a learned exact deny must win.
    workspace_path("default").write_text(
        'servers: {}\nauthz:\n  rules:\n    - tool: "mcp://*/*"\n      effect: allow\n'
    )
    hub = Hub(load_config())
    hub._persist_exact_rule("mcp://filesystem/delete_file", "claude-code", allowed=False)

    resolver = Hub(load_config()).authz
    # The learned tier-1 exact deny beats the curated wildcard allow.
    assert resolver.resolve("mcp://filesystem/delete_file", {}, "claude-code").effect is Effect.DENY
    # An unrelated tool still rides the curated wildcard allow.
    assert resolver.resolve("mcp://filesystem/read_file", {}, "claude-code").effect is Effect.ALLOW
