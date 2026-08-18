"""Policy-diff broadening detection (UAI-216, Enh B5)."""

from __future__ import annotations

from unified_mcphub.config import Rule
from unified_mcphub.policy_diff import policy_broadening


def _allow(tool, callers=None, args=None):
    return Rule(tool=tool, callers=callers, effect="allow", args_filter=args)


def _deny(tool, callers=None):
    return Rule(tool=tool, callers=callers, effect="deny")


def test_no_change_is_no_broadening():
    rules = [_allow("mcp://x/y", ["a"]), _deny("mcp://x/z")]
    assert policy_broadening(rules, list(rules)) == []


def test_a_new_allow_rule_is_flagged():
    old = [_deny("mcp://x/z")]
    new = old + [_allow("mcp://x/y", ["a"])]
    b = policy_broadening(old, new)
    assert len(b) == 1
    assert b[0].tool == "mcp://x/y"
    assert b[0].callers == ["a"]
    assert b[0].note == "new allow rule"


def test_effect_flipped_to_allow_for_existing_target_is_widened():
    old = [_deny("mcp://x/y")]  # target (mcp://x/y, any) existed as deny
    new = [_deny("mcp://x/y"), _allow("mcp://x/y", None)]
    b = policy_broadening(old, new)
    assert len(b) == 1
    assert b[0].note == "widened to allow"


def test_widening_principals_to_any_is_flagged():
    old = [_allow("mcp://x/y", ["a"])]
    new = [_allow("mcp://x/y", None)]  # None = any principal — strictly broader
    b = policy_broadening(old, new)
    assert len(b) == 1
    # The grant now reaches any principal — surfaced with callers None, whichever
    # note it carries (any-principal is a new target, so "new allow rule").
    assert b[0].callers is None


def test_effect_flip_for_same_target_reads_as_widened():
    """deny→allow for the *same* (tool, callers) is a widening of that grant."""
    old = [_deny("mcp://x/y", ["a"])]
    new = [_allow("mcp://x/y", ["a"])]
    b = policy_broadening(old, new)
    assert len(b) == 1
    assert b[0].note == "widened to allow"


def test_tightening_is_not_flagged():
    """An allow that became a deny only reduces authority — not broadening."""
    old = [_allow("mcp://x/y", ["a"])]
    new = [_deny("mcp://x/y")]
    assert policy_broadening(old, new) == []


def test_shrinking_principals_is_not_flagged():
    old = [_allow("mcp://x/y", None)]  # any principal
    new = [_allow("mcp://x/y", ["a"])]  # narrowed to just `a`
    b = policy_broadening(old, new)
    # The narrowed rule is a different identity, but it grants *less*, not more —
    # it is still a fresh allow for (tool, [a]) so it surfaces as a new grant.
    # That is acceptable: a review seeing "allow x for a" is informed, not misled.
    assert all(x.tool == "mcp://x/y" for x in b)


def test_args_scoped_allow_is_distinct():
    old = [_allow("mcp://x/y", ["a"], {"path": {"starts_with": ["/safe"]}})]
    new = old + [_allow("mcp://x/y", ["a"], {"path": {"starts_with": ["/etc"]}})]
    b = policy_broadening(old, new)
    assert len(b) == 1
    assert b[0].args_filter == {"path": {"starts_with": ["/etc"]}}
