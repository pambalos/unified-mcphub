"""Offline replay — spec §4 (specs/enforce/e2.v1.md).

Re-decide recorded actions against a (candidate) policy and report where the
verdicts diverge. This is the technical seed of the Test expansion pillar (X2):
"what would this policy change have done to last month's traffic?"

Entries recorded at `minimal` capture have no params, so conditions can't be
re-evaluated faithfully — they are counted as skipped, never silently replayed.
Entries whose stored copy was scrubbed (`redacted: true`) are replayed but
flagged: a condition that read a scrubbed value may diverge for that reason
alone.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .action import Action
from .policy import PolicyEngine


@dataclass
class Divergence:
    seq: int
    action_digest: str
    tool: str
    recorded_verdict: str
    replayed_verdict: str
    recorded_rule: str | None
    replayed_rule: str | None
    redacted: bool  # stored params were scrubbed — divergence may be an artifact


@dataclass
class ReplayReport:
    total: int = 0  # decision entries seen
    replayed: int = 0
    skipped: int = 0  # minimal capture or unparseable stored action
    divergences: list[Divergence] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not self.divergences


def replay(audit_dir: str | Path, engine: PolicyEngine) -> ReplayReport:
    report = ReplayReport()
    for path in sorted(Path(audit_dir).glob("*.jsonl")):
        with path.open("rb") as fh:
            for raw in fh:
                if not raw.strip():
                    continue
                entry = json.loads(raw)
                if entry.get("kind") != "decision":
                    continue
                report.total += 1
                payload = entry["payload"]
                if payload.get("audit_level") == "minimal":
                    report.skipped += 1
                    continue
                try:
                    action = Action.model_validate(payload["action"])
                except Exception:
                    report.skipped += 1
                    continue
                decision = engine.decide(action)
                report.replayed += 1
                if (
                    decision.verdict.value != payload["verdict"]
                    or decision.rule_id != payload["rule_id"]
                ):
                    report.divergences.append(
                        Divergence(
                            seq=entry["seq"],
                            action_digest=payload["action_digest"],
                            tool=action.tool,
                            recorded_verdict=payload["verdict"],
                            replayed_verdict=decision.verdict.value,
                            recorded_rule=payload["rule_id"],
                            replayed_rule=decision.rule_id,
                            redacted=bool(payload.get("redacted")),
                        )
                    )
    return report
