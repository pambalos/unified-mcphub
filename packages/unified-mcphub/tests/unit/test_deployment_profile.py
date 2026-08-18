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
        # `path_under`, not `starts_with`: the protected dir is matched by real
        # containment so traversal and symlinks cannot walk around it.
        assert r.match.args["path"]["path_under"] == [home]


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


# --- path containment, not string prefix ------------------------------------


def _resolver(protection: str = "locked"):
    """Permissive workspace (filesystem edits allowed) + the given profile, so
    any deny below can only have come from the constitutional tier."""
    ws = Workspace(authz=Authz(rules=[Rule(tool="mcp://filesystem/edit_file", effect="allow")]))
    return AuthzResolver(
        ws, DangerousCommands(), deployment=DeploymentConfig(policy_protection=protection)
    )


def _effect(resolver, path: str) -> str:
    d = resolver.resolve(
        "mcp://filesystem/edit_file",
        {"path": path, "old_string": "x", "new_string": "y"},
        "claude-code",
        action=_write_action(path),
    )
    return d.effect.value


def test_traversal_into_the_protected_dir_is_denied():
    """The bypass a lexical prefix misses: the string does not start with the
    protected dir, but the path resolves inside it."""
    home = mcphub_home()
    sneaky = str(home.parent / "elsewhere" / ".." / home.name / "config.yaml")
    assert not sneaky.startswith(str(home)), "the string prefix must genuinely not match"
    assert _effect(_resolver(), sneaky) == "deny"


def test_the_protected_dir_itself_is_denied():
    assert _effect(_resolver(), str(mcphub_home())) == "deny"


def test_a_sibling_directory_sharing_the_prefix_is_not_swept_up():
    """`<home>-backup` is a different directory. A bare `starts_with` prefix
    denied writes to it; a containment test does not."""
    sibling = f"{mcphub_home()}-backup/notes.txt"
    assert _effect(_resolver(), sibling) == "allow"


def test_constitutional_rule_is_named_by_its_tool_pattern_in_the_audit_map():
    """`authz_rule` carries the same shape for a constitutional deny as for any
    other rule — a tool pattern, not a prose reason."""
    assert _resolver()._names["const-fs-edit_file"] == "mcp://filesystem/edit_file"


# --- locked + hot is refused ------------------------------------------------


def test_locked_with_hot_reload_is_refused():
    """The combination reads as protected and is not, so it is a load error
    rather than something quietly honoured."""
    with pytest.raises(ValueError, match="cancels reload-gating"):
        DeploymentConfig(policy_protection="locked", reload_mode="hot")


def test_locked_defaults_to_approval():
    assert DeploymentConfig(policy_protection="locked").effective_reload_mode() == "approval"


def test_locked_may_still_be_manual_or_approval():
    for mode in ("manual", "approval"):
        assert DeploymentConfig(policy_protection="locked", reload_mode=mode).reload_mode == mode


def test_open_with_hot_is_fine():
    cfg = DeploymentConfig(policy_protection="open", reload_mode="hot")
    assert cfg.effective_reload_mode() == "hot"


# --- indeterminate paths fail closed, per rule direction ---------------------


def _engine(effect: str):
    doc = PolicyDoc(
        version=1,
        constitutional=[
            EngineRule(
                id="c",
                match=EngineMatch(
                    tool="mcp://filesystem/edit_file",
                    args={"path": {"path_under": ["/protected"]}},
                ),
                effect=effect,
            )
        ]
        if effect == "deny"
        else [],
        rules=[
            EngineRule(
                id="r",
                match=EngineMatch(
                    tool="mcp://filesystem/edit_file",
                    args={"path": {"path_under": ["/protected"]}},
                ),
                effect=effect,
            )
        ]
        if effect != "deny"
        else [],
    )
    return PolicyEngine(doc)


def _decide(engine, path: str):
    """The full decision: the engine defaults to deny when nothing matches, so
    the verdict alone cannot tell "the rule fired" from "nothing did"."""
    return engine.decide(
        Action.build(
            principal=Principal(id="agent:a"),
            tool="mcp://filesystem/edit_file",
            verb="call",
            resource="*",
            params={"path": path},
        )
    )


def test_a_deny_rule_matches_an_unresolvable_path():
    """A relative path names no single location. A deny rule cannot let that
    through, or the protection is bypassed by dropping the leading slash."""
    for path in ("../protected/config.yaml", ""):
        d = _decide(_engine("deny"), path)
        assert d.verdict == Verdict.DENY and d.rule_id == "c", path


def test_a_deny_rule_still_ignores_a_resolvable_path_elsewhere():
    """It falls through to the engine's default rather than being caught by the
    rule — the fail-closed arm must not swallow every path."""
    d = _decide(_engine("deny"), "/somewhere/else.txt")
    assert d.rule_id != "c"


def test_an_allow_rule_withholds_on_an_unresolvable_path():
    """The safe direction for an allow rule is the opposite one: no grant."""
    assert _decide(_engine("allow"), "relative/path.txt").verdict != Verdict.ALLOW
    assert _decide(_engine("allow"), "/protected/x.txt").verdict == Verdict.ALLOW


def test_a_rule_naming_a_relative_directory_is_a_load_error():
    """It could never match anything meaningful, so it fails at load rather
    than sitting in the policy looking like a protection."""
    with pytest.raises(Exception, match="absolute directory"):
        PolicyEngine(
            PolicyDoc(
                version=1,
                rules=[
                    EngineRule(
                        id="r",
                        match=EngineMatch(tool="x", args={"path": {"path_under": ["rel/dir"]}}),
                        effect="deny",
                    )
                ],
            )
        )


def test_a_symlink_into_the_protected_dir_is_denied(tmp_path):
    """Resolution happens on the real path, so a link is not a way around it."""
    link = tmp_path / "shortcut"
    link.symlink_to(str(mcphub_home()))
    assert _effect(_resolver(), str(link / "config.yaml")) == "deny"
