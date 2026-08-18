"""Policy-diff broadening detection — the reviewable half of reload (UAI-216).

When an operator applies a policy change (`unified-mcphub reload`), the one
question worth answering before it takes effect is *what did this grant that was
not granted before* — a new `allow`, or a rule whose principals widened. This
module answers exactly that, from the old and new rule lists, so the reload
result can name the broadening and an operator sees it rather than trusting a
diff they may not have read.

What this is not: attribution. "No principal may grant *itself* allow" needs to
know who authored the change, which the file-based model does not record — that
belongs with the control plane's operator identity. Here the signal is the
broadening itself, which is the part that matters whoever wrote it. A tightening
(an allow that became deny/prompt, a principal list that shrank) is deliberately
not flagged: it can only reduce authority, and drowning the real signal in
harmless changes is how a review stops happening.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from .config import Rule


def _args_key(rule: Rule) -> str | None:
    return json.dumps(rule.args_filter, sort_keys=True) if rule.args_filter else None


def _identity(rule: Rule) -> tuple:
    """Everything that makes two rules the same grant. `callers=None` (any
    principal) is distinct from a named list, so widening to `None` is caught."""
    callers = None if rule.callers is None else tuple(rule.callers)
    return (rule.tool, callers, rule.effect, _args_key(rule))


@dataclass
class Broadening:
    tool: str
    callers: list[str] | None  # None = any principal
    args_filter: dict | None
    note: str

    def as_dict(self) -> dict:
        return {
            "tool": self.tool,
            "callers": self.callers,
            "args_filter": self.args_filter,
            "note": self.note,
        }


def policy_broadening(old: list[Rule], new: list[Rule]) -> list[Broadening]:
    """`allow`-granting changes present in `new` and not in `old`.

    Two kinds, both broadening: an allow rule with no equivalent before (a fresh
    grant), and an allow for a (tool, callers) that previously decided otherwise
    (an effect widened to allow). Order-independent; identity is the grant, not
    the position in the list.
    """
    old_identities = {_identity(r) for r in old}
    # (tool, callers) seen in old under *any* effect. A new allow for one of
    # these is an effect that flipped to allow (a widening of an existing grant);
    # one for a target not seen before is a fresh grant.
    old_targets = {(r.tool, None if r.callers is None else tuple(r.callers)) for r in old}
    out: list[Broadening] = []
    for rule in new:
        if rule.effect != "allow" or _identity(rule) in old_identities:
            continue
        target = (rule.tool, None if rule.callers is None else tuple(rule.callers))
        note = "widened to allow" if target in old_targets else "new allow rule"
        out.append(Broadening(rule.tool, rule.callers, rule.args_filter, note))
    return out
