"""The external-benchmark harness, gated per PR. UAI-148.

The benchmark *run* is nightly and needs the network. The harness's scoring does
not, and it is the part that can be quietly wrong — so it is tested here, on
synthetic attempts, against a tiny pack whose verdicts are obvious by
inspection.

The test to read first is `test_a_default_deny_is_not_counted_as_a_defence`.
That distinction is the whole reason this harness is more than a wrapper: the
packs use their own example tool URIs, so an unmapped benchmark tool falls
through to default-deny and is refused. Reporting that as a win produces a
triumphant number describing a pack that recognised nothing, which is the most
plausible way this ends up lying.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

BENCHMARKS = Path(__file__).resolve().parents[2] / "benchmarks"
sys.path.insert(0, str(BENCHMARKS))

external = pytest.importorskip("external", reason="benchmark harness not on the path")

#: Small enough to reason about: one rule that allows, one that denies, one
#: floor that defers, and everything else falling to default-deny.
PACK = {
    "version": 1,
    "rules": [
        {"id": "reads-are-fine", "match": {"tool": "sdk://files/read"}, "effect": "allow"},
        {"id": "no-shell", "match": {"tool": "mcp://shell/**"}, "effect": "deny"},
    ],
    "floors": [{"id": "payments-need-a-human", "match": {"tool": "sdk://payments/**"}}],
}

MAPPING = {
    "BenignRead": {"tool": "sdk://files/read", "verb": "read"},
    "RunShell": {"tool": "mcp://shell/exec", "verb": "execute"},
    "MoveMoney": {"tool": "sdk://payments/transfer", "verb": "create"},
    "SomethingNobodyNamed": {"tool": "sdk://unheard/of", "verb": "create"},
}


def attempt(tool: str) -> object:
    return external.Attempt(
        case_id=f"synthetic/{tool}",
        suite="synthetic",
        attack_type="test",
        benchmark_tool=tool,
        instruction="an attacker instruction",
    )


def report_for(tools: list[str]):
    import tempfile

    import yaml

    with tempfile.TemporaryDirectory() as tmp:
        pack_path = Path(tmp) / "tiny.yaml"
        pack_path.write_text(yaml.safe_dump(PACK))
        # `run` resolves packs by name from the shipped directory, so point it
        # at a temporary one by monkeypatching the constant rather than by
        # writing into the package.
        original = external.PACKS
        external.PACKS = Path(tmp)
        try:
            return external.run([attempt(t) for t in tools], pack="tiny", mapping=MAPPING)
        finally:
            external.PACKS = original


# --- the distinction the whole harness exists for -------------------------------------


def test_a_default_deny_is_not_counted_as_a_defence():
    """The most plausible way this harness ends up lying.

    An unmapped or unknown tool is refused by default-deny, which is true and is
    not evidence the pack defends against the attack. Counting it as a win would
    produce a triumphant score describing a pack that recognised nothing.
    """
    report = report_for(["SomethingNobodyNamed"])

    assert report.counts() == {"denied_by_default": 1}
    assert report.as_dict()["stopped_by_policy"] == 0.0, (
        "a default-deny was counted towards the headline"
    )


def test_a_named_rule_denying_is_the_score():
    report = report_for(["RunShell"])

    assert report.counts() == {"denied_by_rule": 1}
    assert report.as_dict()["stopped_by_policy"] == 1.0


def test_a_floor_counts_as_stopped():
    """Deferring to a human is a win: the action did not proceed unattended."""
    report = report_for(["MoveMoney"])

    assert report.counts() == {"deferred": 1}
    assert report.as_dict()["stopped_by_policy"] == 1.0


def test_an_allowed_attack_is_a_finding():
    """The bucket that must work, or a run reporting zero findings is
    indistinguishable from a run that could not report one at all."""
    report = report_for(["BenignRead"])

    assert report.counts() == {"allowed": 1}
    assert report.as_dict()["stopped_by_policy"] == 0.0
    assert report.allowed()[0].attempt.benchmark_tool == "BenignRead"


def test_every_bucket_is_reachable():
    """Together, so a change that collapsed two buckets into one is visible."""
    report = report_for(["BenignRead", "RunShell", "MoveMoney", "SomethingNobodyNamed"])

    assert report.counts() == {
        "allowed": 1,
        "denied_by_rule": 1,
        "deferred": 1,
        "denied_by_default": 1,
    }
    assert report.as_dict()["stopped_by_policy"] == 0.5


# --- the mapping ----------------------------------------------------------------------


def test_an_unmapped_tool_is_not_scored_at_all():
    """Not counted as denied, and not counted as allowed. A benchmark tool with
    no entry is a gap in the mapping, and folding it into either bucket would
    make the mapping's completeness invisible."""
    report = report_for(["NotInTheMappingAtAll"])

    assert report.counts() == {"unmapped": 1}
    assert report.as_dict()["scored"] == 0
    assert report.as_dict()["stopped_by_policy"] is None, (
        "a run that scored nothing must not report a percentage"
    )


def test_the_shipped_mapping_loads_and_covers_the_suite_it_claims_to():
    """The real mapping file, checked for shape rather than content.

    Content is a judgement call reviewed in the diff; what can be checked
    mechanically is that it parses, that every entry names a canonical tool URI,
    and that nobody has left a bare tool name in it.
    """
    mapping = external.load_mapping()

    assert len(mapping) >= 30
    for name, entry in mapping.items():
        assert "://" in entry["tool"], f"{name} maps to {entry['tool']!r}, not a tool URI"
        assert entry.get("verb"), f"{name} has no verb; the packs distinguish read from create"


def test_the_unimplemented_suites_are_declared():
    """A report covering one suite reads exactly like one covering two."""
    assert "agentdojo" in external.NOT_IMPLEMENTED
    assert len(external.NOT_IMPLEMENTED["agentdojo"]) > 40, (
        "a declared gap needs a reason, not a placeholder"
    )
