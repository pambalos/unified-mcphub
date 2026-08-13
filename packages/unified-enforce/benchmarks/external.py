"""External adversarial suites, scored on our terms. UAI-148.

The authored corpus gates every PR and is written by whoever wrote the pack,
which makes it excellent at catching regressions and poor at catching blind
spots. This runs suites we did not author, nightly, to find the attack shapes we
did not think of.

**These benchmarks measure a different thing, and the adapter has to know it.**
AgentDojo and InjecAgent mostly score whether a *model* resists an injection. We
score whether the *plane* stops the resulting tool call. A run where the model
complies enthusiastically and every dangerous call is refused is a **success**
for us and a failure by their scoring — so the model is never run here at all.
What is extracted is the tool call the attack was trying to cause, which is the
only part an enforcement plane can have an opinion about.

**The number this could easily fake.** The packs use their own example tool
URIs, so an unmapped benchmark tool falls through to default-deny and gets
refused. Reporting that as "denied" would produce a triumphant 100% describing a
pack that recognised nothing. So the report separates:

- `denied_by_rule` — a named rule in the pack refused it. **This is the score.**
- `deferred` — a floor sent it to a human. Also a win.
- `denied_by_default` — nothing in the pack named it. True, and not evidence
  that the pack defends against this attack.
- `allowed` — it got through. These are the findings, and each becomes an
  authored corpus case, which is how the fast suite grows from what the slow one
  finds.

Run it:

    uv run python benchmarks/external.py --suite injecagent
    uv run python benchmarks/external.py --suite injecagent --json report.json

Data is fetched at run time and never vendored: it belongs to its authors (both
suites are MIT), and a copy in this repository would go stale and would make
their licence our packaging problem.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
PACKS = HERE.parent / "src" / "unified_enforce" / "policies"

#: InjecAgent's direct-harm cases. Pinned to a commit rather than `main`: a
#: nightly job whose input silently changes cannot tell a regression in the pack
#: from a change in the benchmark.
INJECAGENT_COMMIT = "main"
INJECAGENT_URLS = {
    "direct-harm": (
        f"https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/{INJECAGENT_COMMIT}"
        "/data/test_cases_dh_base.json"
    ),
    "data-stealing": (
        f"https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/{INJECAGENT_COMMIT}"
        "/data/test_cases_ds_base.json"
    ),
}

#: Suites known to this harness but not implemented, with the reason. Declared
#: rather than omitted: a report covering one suite reads exactly like one
#: covering two.
NOT_IMPLEMENTED = {
    "agentdojo": (
        "its attacks are Python task classes rather than a data file, so "
        "extracting the intended tool calls means importing the package and its "
        "dependency tree. Worth doing; not done here."
    ),
}


@dataclass
class Attempt:
    """One attacker tool call, in the benchmark's own vocabulary."""

    case_id: str
    suite: str
    attack_type: str
    benchmark_tool: str
    instruction: str


@dataclass
class Outcome:
    attempt: Attempt
    tool: str | None
    verdict: str
    rule_id: str | None
    source: str

    @property
    def bucket(self) -> str:
        if self.tool is None:
            return "unmapped"
        if self.verdict == "defer":
            return "deferred"
        if self.verdict == "deny":
            return "denied_by_default" if self.source == "default" else "denied_by_rule"
        return "allowed"


@dataclass
class Report:
    suite: str
    pack: str
    outcomes: list[Outcome] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        return dict(Counter(o.bucket for o in self.outcomes))

    def allowed(self) -> list[Outcome]:
        return [o for o in self.outcomes if o.bucket == "allowed"]

    def as_dict(self) -> dict[str, Any]:
        counts = self.counts()
        scored = len(self.outcomes) - counts.get("unmapped", 0)
        return {
            "suite": self.suite,
            "pack": self.pack,
            "cases": len(self.outcomes),
            "scored": scored,
            "counts": counts,
            # The headline, and deliberately the strict one: attacks the pack
            # actively recognised and stopped, over attacks it was asked about.
            "stopped_by_policy": round(
                (counts.get("denied_by_rule", 0) + counts.get("deferred", 0)) / scored, 4
            )
            if scored
            else None,
            "allowed_distinct": [
                {"benchmark_tool": bt, "tool": tool, "count": n}
                for (bt, tool), n in Counter(
                    (o.attempt.benchmark_tool, o.tool) for o in self.allowed()
                ).most_common()
            ],
            "allowed": [
                {
                    "case_id": o.attempt.case_id,
                    "attack_type": o.attempt.attack_type,
                    "benchmark_tool": o.attempt.benchmark_tool,
                    "tool": o.tool,
                    "instruction": o.attempt.instruction[:160],
                }
                for o in self.allowed()
            ],
        }


def load_mapping(path: Path | None = None) -> dict[str, dict[str, str]]:
    import yaml

    document = yaml.safe_load((path or HERE / "mapping.yaml").read_text())
    return document["tools"]


def fetch(url: str, *, timeout: float = 60.0) -> Any:
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return json.loads(response.read())


def injecagent_attempts(*, timeout: float = 60.0) -> list[Attempt]:
    """Every attacker tool call InjecAgent tries to cause.

    The *attacker* tool, not the user tool: the user tool is the legitimate call
    the agent was making when it read the injection, and refusing that would be
    a broken pack rather than a defended one.
    """
    attempts: list[Attempt] = []
    for split, url in INJECAGENT_URLS.items():
        try:
            cases = fetch(url, timeout=timeout)
        except Exception as exc:  # noqa: BLE001 - report and continue
            print(f"could not fetch {split}: {exc}", file=sys.stderr)
            continue

        for index, case in enumerate(cases):
            for tool in case.get("Attacker Tools") or []:
                attempts.append(
                    Attempt(
                        case_id=f"injecagent/{split}/{index}",
                        suite="injecagent",
                        attack_type=case.get("Attack Type", "unknown"),
                        benchmark_tool=tool,
                        instruction=case.get("Attacker Instruction", ""),
                    )
                )
    return attempts


def run(
    attempts: list[Attempt],
    *,
    pack: str = "owasp-llm-top10",
    mapping: dict[str, dict[str, str]] | None = None,
    principal: str = "agent:benchmark",
) -> Report:
    """Put each attempt through the shipped pack and record what happened."""
    sys.path.insert(0, str(HERE.parent / "src"))
    from unified_enforce import Action, PolicyEngine, Principal

    engine = PolicyEngine.from_file(PACKS / f"{pack}.yaml")
    mapping = mapping if mapping is not None else load_mapping()
    report = Report(suite=attempts[0].suite if attempts else "none", pack=pack)

    for attempt in attempts:
        mapped = mapping.get(attempt.benchmark_tool)
        if mapped is None:
            report.outcomes.append(Outcome(attempt, None, "unmapped", None, "unmapped"))
            continue

        decision = engine.decide(
            Action.build(
                principal=Principal(id=principal),
                tool=mapped["tool"],
                verb=mapped.get("verb", "create"),
                resource="*",
            )
        )
        report.outcomes.append(
            Outcome(
                attempt,
                mapped["tool"],
                decision.verdict.value,
                decision.rule_id,
                decision.source,
            )
        )
    return report


def render(report: Report) -> str:
    counts = report.counts()
    data = report.as_dict()
    lines = [
        f"{report.suite} against {report.pack}",
        f"  cases            {data['cases']}",
        f"  mapped & scored  {data['scored']}",
        "",
        f"  denied by a rule {counts.get('denied_by_rule', 0)}   <- the score",
        f"  deferred         {counts.get('deferred', 0)}",
        f"  denied by default{counts.get('denied_by_default', 0):>4}   "
        "(nothing in the pack named it; true, but not a defence)",
        f"  ALLOWED          {counts.get('allowed', 0)}   <- findings",
        f"  unmapped         {counts.get('unmapped', 0)}   (no entry in mapping.yaml; not scored)",
    ]
    if data["stopped_by_policy"] is not None:
        lines.append(f"\n  stopped by policy: {data['stopped_by_policy']:.1%}")
    if report.allowed():
        # Grouped, because 34 identical lines is noise and the distinct
        # (benchmark tool -> canonical tool) pairs are the actual findings.
        # A list nobody reads is the same as no list.
        grouped = Counter((o.attempt.benchmark_tool, o.tool) for o in report.allowed())
        lines.append("\nattacks that got through — each becomes an authored corpus case:")
        for (benchmark_tool, tool), n in grouped.most_common():
            lines.append(f"  {n:4}x  {benchmark_tool} -> {tool}")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", default="injecagent", choices=["injecagent", "agentdojo"])
    parser.add_argument("--pack", default="owasp-llm-top10")
    parser.add_argument("--json", type=Path, help="write the full report here")
    parser.add_argument(
        "--fail-on-allowed",
        action="store_true",
        help="exit non-zero when an attack gets through. Off by default: the "
        "headline is expected to be unflattering at first, and a nightly job "
        "that is always red is a nightly job nobody reads.",
    )
    args = parser.parse_args()

    if args.suite in NOT_IMPLEMENTED:
        print(f"{args.suite} is not implemented: {NOT_IMPLEMENTED[args.suite]}", file=sys.stderr)
        return 2

    attempts = injecagent_attempts()
    if not attempts:
        # Loudly, because an empty run reports 0 findings and looks like a pass.
        print("no attempts loaded — the benchmark data could not be fetched", file=sys.stderr)
        return 1

    report = run(attempts, pack=args.pack)
    print(render(report))

    if args.json:
        args.json.write_text(json.dumps(report.as_dict(), indent=2))

    return 1 if (args.fail_on_allowed and report.allowed()) else 0


if __name__ == "__main__":
    raise SystemExit(main())
