"""Deployment security profile — policy_protection open|locked (UAI-216).

Covers the config layer, the constitutional-tier injection, and the guarantee
that a constitutional deny cannot be overridden by a workspace rule.
"""

from __future__ import annotations

import pytest

from unified_enforce import Action, Principal
from unified_enforce.policy import PolicyDoc, PolicyEngine, Verdict
from unified_enforce.policy import Match as EngineMatch
from unified_enforce.policy import Rule as EngineRule
from unified_mcphub.authz import AuthzResolver, _constitutional_rules
from unified_mcphub.config import (
    Authz,
    DangerousCommands,
    DeploymentConfig,
    HubConfig,
    Rule,
    Workspace,
    mcphub_home,
)


# --- config layer -----------------------------------------------------------


def test_defaults_preserve_open_hot():
    d = DeploymentConfig()
    assert d.policy_protection == "open"
    assert not d.is_locked
    assert d.effective_reload_mode() == "hot"


def test_locked_derives_approval_reload():
    d = DeploymentConfig(policy_protection="locked")
    assert d.is_locked
    assert d.effective_reload_mode() == "approval"


def test_explicit_reload_mode_wins_over_derivation():
    assert (
        DeploymentConfig(policy_protection="locked", reload_mode="manual").effective_reload_mode()
        == "manual"
    )
    assert (
        DeploymentConfig(policy_protection="open", reload_mode="approval").effective_reload_mode()
        == "approval"
    )


@pytest.mark.parametrize("bad", ["prod", "on", "", "OPEN"])
def test_invalid_protection_rejected(bad):
    with pytest.raises(ValueError):
        DeploymentConfig(policy_protection=bad)


def test_invalid_reload_mode_rejected():
    with pytest.raises(ValueError):
        DeploymentConfig(reload_mode="sometimes")


def test_hubconfig_carries_deployment_default():
    assert HubConfig().deployment.policy_protection == "open"


# --- constitutional injection -----------------------------------------------


def test_open_injects_nothing():
    assert _constitutional_rules(DeploymentConfig()) == []
    assert _constitutional_rules(None) == []


def test_locked_injects_config_dir_write_denies():
    rules = _constitutional_rules(DeploymentConfig(policy_protection="locked"))
    assert {r.id for r in rules} == {
        "const-fs-create_file",
        "const-fs-edit_file",
        "const-fs-delete_file",
    }
    assert all(r.effect == "deny" for r in rules)
    home = str(mcphub_home())
    for r in rules:
        assert r.match.args["path"]["starts_with"] == [home]


# --- end-to-end: constitutional deny is un-overridable ----------------------


def _write_action(path: str):
    return Action.build(
        principal=Principal(id="agent:claude-code"),
        tool="mcp://filesystem/edit_file",
        verb="call",
        resource="*",
        params={"path": path, "old_string": "x", "new_string": "y"},
    )


def test_locked_denies_policy_dir_write_even_with_allow_rule():
    """A workspace rule that ALLOWs the write must not defeat the constitutional
    deny — that is the whole point of the tier."""
    policy_file = str(mcphub_home() / "workspaces" / "default.local.yaml")
    # Workspace explicitly allows filesystem edits (the permissive local setup).
    ws = Workspace(authz=Authz(rules=[Rule(tool="mcp://filesystem/edit_file", effect="allow")]))
    resolver = AuthzResolver(
        ws, DangerousCommands(), deployment=DeploymentConfig(policy_protection="locked")
    )
    d = resolver.resolve(
        "mcp://filesystem/edit_file",
        {"path": policy_file, "old_string": "x", "new_string": "y"},
        "claude-code",
        action=_write_action(policy_file),
    )
    assert d.effect.value == "deny"
    assert d.source == "constitutional"


def test_locked_allows_writes_outside_config_dir():
    ws = Workspace(authz=Authz(rules=[Rule(tool="mcp://filesystem/edit_file", effect="allow")]))
    resolver = AuthzResolver(
        ws, DangerousCommands(), deployment=DeploymentConfig(policy_protection="locked")
    )
    d = resolver.resolve(
        "mcp://filesystem/edit_file",
        {"path": "/tmp/some_project/main.py", "old_string": "x", "new_string": "y"},
        "claude-code",
        action=_write_action("/tmp/some_project/main.py"),
    )
    assert d.effect.value == "allow"


def test_open_allows_policy_dir_write():
    """Open mode is the desired local behavior — policy is freely editable."""
    policy_file = str(mcphub_home() / "workspaces" / "default.local.yaml")
    ws = Workspace(authz=Authz(rules=[Rule(tool="mcp://filesystem/edit_file", effect="allow")]))
    resolver = AuthzResolver(ws, DangerousCommands(), deployment=DeploymentConfig())
    d = resolver.resolve(
        "mcp://filesystem/edit_file",
        {"path": policy_file, "old_string": "x", "new_string": "y"},
        "claude-code",
        action=_write_action(policy_file),
    )
    assert d.effect.value == "allow"


# --- engine tier directly ---------------------------------------------------


def test_constitutional_tier_outranks_exact_rule():
    doc = PolicyDoc(
        version=1,
        constitutional=[EngineRule(id="c", match=EngineMatch(tool="mcp://x/y"), effect="deny")],
        rules=[EngineRule(id="r", match=EngineMatch(tool="mcp://x/y"), effect="allow")],
    )
    eng = PolicyEngine(doc)
    action = Action.build(
        principal=Principal(id="agent:a"), tool="mcp://x/y", verb="call", resource="*", params={}
    )
    d = eng.decide(action)
    assert d.verdict == Verdict.DENY
    assert d.source == "constitutional"


def test_empty_constitutional_is_noop():
    """Absent constitutional rules, the exact allow wins exactly as before."""
    doc = PolicyDoc(
        version=1,
        rules=[EngineRule(id="r", match=EngineMatch(tool="mcp://x/y"), effect="allow")],
    )
    eng = PolicyEngine(doc)
    action = Action.build(
        principal=Principal(id="agent:a"), tool="mcp://x/y", verb="call", resource="*", params={}
    )
    assert eng.decide(action).verdict == Verdict.ALLOW
