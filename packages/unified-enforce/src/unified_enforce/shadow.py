"""Evaluating a candidate policy against live traffic without enforcing it.

Spec §8. A bundle marked `shadow` is a proposal: the sidecar runs it beside the
policy actually in force, records where the two would disagree, and enforces
**neither** of the candidate's decisions.

This exists because the change most likely to cause an incident is a policy
edit — either too permissive to notice or too strict to survive contact with
real traffic. A divergence report turns "we think this rule is right" into a
list of the actions it would have changed, before anyone is affected by it.

Two invariants, and both are tested rather than trusted:

**A candidate can never alter a verdict.** The real decision is made and
returned first; the candidate is evaluated afterwards, and its result is only
ever written to a report. If shadow evaluation raises, throws, hangs on a
malformed rule or takes an unreasonable amount of time, the enforced decision
is already made and unaffected.

**A candidate can never become policy by accident.** It is compiled into its
own engine, held in its own fields, and never consulted by `gate()`. The
promotion path is a human publishing the same content with `mode: enforce`,
which produces a new signed bundle — not a flag flipping somewhere.

Divergences carry no action content, for the same reason evidence does not:
they travel to a control plane, and the digest is how an investigator reaches
the detail in the customer's own chain.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .action import Action
from .policy import Decision, PolicyEngine

log = logging.getLogger("unified_enforce.shadow")


@dataclass(frozen=True)
class Divergence:
    """One action the candidate policy would have decided differently."""

    action_digest: str
    principal_id: str
    tool: str
    verb: str
    enforced: str
    proposed: str
    enforced_rule: str | None
    proposed_rule: str | None
    shadow_version: int

    def as_record(self) -> dict[str, Any]:
        """The wire form. Metadata only, by allowlist — same rule as evidence."""
        return {
            "action_digest": self.action_digest,
            "principal_id": self.principal_id,
            "tool": self.tool,
            "verb": self.verb,
            "enforced": self.enforced,
            "proposed": self.proposed,
            "enforced_rule": self.enforced_rule,
            "proposed_rule": self.proposed_rule,
            "shadow_version": self.shadow_version,
        }


class ShadowEvaluator:
    """Holds the compiled candidate and compares it against real decisions.

    Compilation happens on `load()`, not per action: a policy that fails to
    compile must be a visible refusal at load time rather than an exception on
    every request, and re-parsing YAML in the decision path would be a way for
    a proposal to cost latency.
    """

    def __init__(self, on_divergence: Callable[[Divergence], None] | None = None) -> None:
        #: Where a divergence goes the moment it is found. Without one, findings
        #: accumulate in memory and die with the process -- which is how a
        #: feature ends up built, correct, and useless to the person it was
        #: built for.
        #:
        #: Called inline but guarded: a shipper that raises must not turn a
        #: proposal into a failed enforcement, which is the invariant this whole
        #: module rests on.
        self._on_divergence = on_divergence
        self._engine: PolicyEngine | None = None
        self._version: int | None = None
        self.divergences: list[Divergence] = []
        #: Actions compared, so a report of "no divergences" can be told apart
        #: from a candidate that never ran. The first means the proposal is
        #: equivalent on observed traffic; the second means nothing was learned.
        self.compared = 0
        self.errors = 0

    @property
    def version(self) -> int | None:
        return self._version

    def load(self, files: dict[str, bytes], version: int) -> bool:
        """Compile a candidate. Returns whether it is usable.

        A candidate that will not compile is a real finding — it is what would
        have happened had someone promoted it — so it is refused loudly here
        rather than discovered later.
        """
        if version == self._version:
            return self._engine is not None

        try:
            self._engine = _compile(files)
        except Exception as exc:
            log.error("candidate policy v%s does not compile: %s", version, exc)
            self._engine = None
            self._version = version
            return False

        self._version = version
        self.divergences.clear()
        self.compared = 0
        self.errors = 0
        log.info("evaluating candidate policy v%s in shadow", version)
        return True

    def clear(self) -> None:
        self._engine = None
        self._version = None
        self.divergences.clear()
        self.compared = 0

    def compare(self, action: Action, enforced: Decision) -> Divergence | None:
        """Evaluate the candidate and record a disagreement.

        Never raises. The enforced decision has already been made and returned
        by the time this runs; a defect in a proposal must not become a failed
        enforcement, which would make shadow mode more dangerous than the
        change it exists to de-risk.
        """
        if self._engine is None or self._version is None:
            return None

        try:
            proposed = self._engine.decide(action)
        except Exception:
            self.errors += 1
            log.exception("candidate policy raised; the enforced decision is unaffected")
            return None

        self.compared += 1
        enforced_verdict = _verdict(enforced)
        proposed_verdict = _verdict(proposed)
        if enforced_verdict == proposed_verdict:
            return None

        divergence = Divergence(
            action_digest=action.digest(),
            principal_id=action.principal.id,
            tool=action.tool,
            verb=action.verb,
            enforced=enforced_verdict,
            proposed=proposed_verdict,
            enforced_rule=enforced.rule_id,
            proposed_rule=proposed.rule_id,
            shadow_version=self._version,
        )
        self.divergences.append(divergence)
        if self._on_divergence is not None:
            try:
                self._on_divergence(divergence)
            except Exception:
                log.exception("could not report a divergence; enforcement is unaffected")
        return divergence

    def summary(self) -> dict[str, Any]:
        """What an operator needs before promoting a candidate.

        Counts by direction, because the two are not equally interesting: a
        proposal that would newly *allow* something currently denied is the one
        that needs justifying, and burying it in a total would hide it.
        """
        loosened = [d for d in self.divergences if d.enforced == "deny" and d.proposed != "deny"]
        tightened = [d for d in self.divergences if d.enforced != "deny" and d.proposed == "deny"]
        return {
            "shadow_version": self._version,
            "compared": self.compared,
            "divergences": len(self.divergences),
            "would_newly_allow": len(loosened),
            "would_newly_deny": len(tightened),
            "errors": self.errors,
        }


def _verdict(decision: Decision) -> str:
    value = decision.verdict
    return value.value if hasattr(value, "value") else str(value)


def _compile(files: dict[str, bytes]) -> PolicyEngine:
    """Build an engine from a bundle's files.

    Single-file bundles are the common case. Multi-file support belongs with
    whatever the loader does for the enforcing bundle, and duplicating a
    different merge order here would mean the candidate and the promoted
    version behaved differently — which would make the divergence report a
    report about this function rather than about the policy.
    """
    policies = sorted(p for p in files if p.endswith((".yaml", ".yml")))
    if not policies:
        raise ValueError("candidate bundle contains no policy files")
    if len(policies) > 1:
        raise NotImplementedError(
            "multi-file candidates need the enforcing loader's merge order; "
            "evaluating them with a different one would report on the merge, "
            "not the policy"
        )
    return PolicyEngine.from_yaml(files[policies[0]].decode("utf-8"))
