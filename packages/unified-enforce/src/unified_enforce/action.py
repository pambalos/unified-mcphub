"""Canonical Action model — spec §1 (specs/enforce/e1.v1.md).

An Action is the unit of enforcement: one tool call / API request / data
operation, normalized to {principal, tool, verb, resource, params, context}.
Its identity is content-derived (`digest` over canonical bytes), so the same
operation observed by two interceptors produces the same digest — and a signed
Action is replayable offline byte-for-byte.

Timestamps are ISO-8601 UTC strings (not datetime) because canonical bytes must
round-trip exactly through JSON.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, model_serializer
from ulid import ULID

from .canonical import canonical_bytes, sha256_hex

SCHEMA_VERSION: Final = "unified.action/v1"


def _utcnow_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


#: How an identity was established. Every rule the plane enforces keys on
#: `principal.id`, so the strength of a floor, a budget or a kill switch is the
#: strength of that identifier — and until now nothing recorded which of these
#: it was, which let "we enforce per agent" mean three different things.
#:
#: `assigned`  — deployment position. A header a gateway stamped, a value in a
#:               config file, a process boundary. UAI-137 stops an agent
#:               *asserting* its own identity, which is not the same as
#:               establishing one: the claim is exactly as good as the
#:               customer's topology, and several agents behind one sidecar
#:               necessarily share it.
#: `derived`   — from an authenticated channel. The hub resolving a caller from
#:               a bearer token it issued, or a sidecar's own enrolment
#:               credential. Proven to the strength of that secret.
#: `attested`  — from a workload attestation: a SPIFFE SVID, an mTLS client
#:               certificate, a cloud instance identity document. Produced by
#:               the gateway when the principal came from an mTLS SAN
#:               (ExtAuthzCore.resolve_principal); a verified OIDC bearer is
#:               `derived` — a JWT is a bearer secret, not a channel.
Attestation = Literal["assigned", "derived", "attested"]

#: Grades are ordered, and the order is the whole point of build-01 §4: a chain
#: is only as strong as its weakest link, so comparing grades has to mean
#: something. Kept as a module constant rather than an Enum because the wire
#: type is a string literal and the audit log records it verbatim.
_GRADE_RANK: Final[dict[str, int]] = {"assigned": 0, "derived": 1, "attested": 2}


def grade_at_least(grade: Attestation, floor: Attestation) -> bool:
    """Is `grade` at or above `floor`? `assigned < derived < attested`."""
    return _GRADE_RANK[grade] >= _GRADE_RANK[floor]


class Hop(BaseModel):
    """One established link in a delegation chain — build-01 §2.

    Each hop carries its **own** attestation grade: how *that* delegation was
    established, not how the leaf authenticated. A hop is only ever written by
    the parent's own credentialed context (§3) — never from a value in the
    child's request, because an agent asserting its own parent is worth exactly
    as much as an agent asserting its own identity, which UAI-137 already
    established is nothing.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    kind: Literal["agent", "user", "service"] = "agent"
    attestation: Attestation = "assigned"


class Principal(BaseModel):
    """Who is acting. `id` is namespaced: agent:<name>, user:<name>, service:<name>."""

    model_config = ConfigDict(extra="forbid")

    id: str
    kind: Literal["agent", "user", "service"] = "agent"
    session_id: str | None = None
    labels: dict[str, str] = Field(default_factory=dict)

    #: How `id` was established. Defaults to the weakest answer on purpose: a
    #: caller that has not thought about it should not be recorded as having
    #: proven anything.
    attestation: Attestation = "assigned"

    #: The principal that spawned this one, if any.
    #:
    #: An agent that spawns agents is the common case in the frameworks this
    #: supports, and a child inheriting its parent's `id` makes the audit trail
    #: wrong in a way that only surfaces during an incident — every action looks
    #: like the parent's, so "what did the researcher do" has no answer and
    #: revoking the child revokes the parent.
    #:
    #: Lineage is exactly as trustworthy as the principal it descends from,
    #: which is the honest position: a child of an `assigned` parent is not
    #: better attested than its parent, and `attestation` above says so
    #: independently.
    parent_id: str | None = None

    #: The delegation chain, ordered **root-first**: the human or system at
    #: index 0, the immediate parent last. build-01 §2.
    #:
    #: Omitted entirely when there is no delegation — `None` and `[]` are the
    #: same statement and canonicalize identically, so adding this field leaves
    #: every existing action's digest byte-for-byte unchanged (§2, and
    #: `test_chain_is_canonical`).
    #:
    #: Authoritative over `parent_id`, which predates it and survives only as a
    #: one-level input. Where both are present the chain wins; where only
    #: `parent_id` is set, accessors read it as a single hop of **`assigned`**
    #: grade, because a parent recorded without a grade is a parent whose
    #: delegation was never established — and §4 says the honest reading of an
    #: unknown grade is the weakest one.
    on_behalf_of: list[Hop] | None = None

    @model_serializer(mode="wrap")
    def _omit_empty_chain(self, handler: Any) -> dict[str, Any]:
        """Drop `on_behalf_of` from the payload when there is no chain.

        This is what makes the field digest-compatible: a principal with no
        delegation serializes to exactly the bytes it did before build-01. The
        other optional fields keep emitting `null`, because they were part of
        the canonical bytes already and dropping them now *would* change
        existing digests.
        """
        data = handler(self)
        if not data.get("on_behalf_of"):
            data.pop("on_behalf_of", None)
        return data

    def chain(self) -> list[Hop]:
        """The delegation chain, root-first. `[]` for an undelegated principal.

        One reader for two representations: the `on_behalf_of` list when it is
        set, otherwise the legacy `parent_id` read as a single `assigned` hop.
        Callers never branch on which one a producer happened to write, which
        is the point — two sources of truth for lineage is the drift this
        method exists to prevent.
        """
        if self.on_behalf_of:
            return list(self.on_behalf_of)
        if self.parent_id is not None:
            # Widened explicitly rather than with an `in` test, which does not
            # narrow `str` to the literal union: the namespace prefix is
            # attacker-influenced in the general case, so anything unrecognized
            # falls to `agent` — the kind with no special standing in §6's
            # human-rootedness check.
            prefix = self.parent_id.split(":", 1)[0]
            kind: Literal["agent", "user", "service"] = "agent"
            if prefix == "user":
                kind = "user"
            elif prefix == "service":
                kind = "service"
            return [Hop(id=self.parent_id, kind=kind, attestation="assigned")]
        return []

    def lineage(self) -> list[str]:
        """This principal and its ancestors, **nearest first**.

        Walks the full chain since build-01; the pre-chain contract (leaf, then
        parent) is the depth-1 case of the same list, so callers written against
        it keep working — which is what the original one-level docstring
        promised would happen when a chain arrived.
        """
        return [self.id] + [hop.id for hop in reversed(self.chain())]

    def chain_grade(self) -> Attestation:
        """Effective attestation: the **minimum** across the leaf and every hop.

        build-01 §4, the load-bearing invariant. A well-attested leaf behind one
        `assigned` hop is an `assigned` chain. Taking the maximum — or the
        leaf's own grade — would let delegation *launder* a weak identity into a
        strong-looking one, which is strictly worse than having no chain at all:
        it manufactures unearned confidence, and unearned confidence is what the
        join engine (build-10) would go on to act on.
        """
        weakest = self.attestation
        for hop in self.chain():
            if _GRADE_RANK[hop.attestation] < _GRADE_RANK[weakest]:
                weakest = hop.attestation
        return weakest

    def weakest_link(self) -> Hop | None:
        """The hop that set `chain_grade()`, or None when the leaf itself is weakest.

        Exists so a denial can name which link failed rather than reporting only
        that the chain was too weak — a `why` that does not identify the bad hop
        sends an operator to read the whole topology.
        """
        worst: Hop | None = None
        rank = _GRADE_RANK[self.attestation]
        for hop in self.chain():
            if _GRADE_RANK[hop.attestation] < rank:
                worst, rank = hop, _GRADE_RANK[hop.attestation]
        return worst

    def human_rooted(self) -> bool:
        """Does the chain terminate in a `user:` or `service:` principal?

        build-01 §6. A chain that does not is **flagged, not denied** — a fully
        autonomous agent with no human root is legitimate (a cron, a scheduled
        job) but is a distinct security class, and the evidence has to show it
        as one rather than blend it in.
        """
        chain = self.chain()
        root = chain[0] if chain else self
        return root.kind in ("user", "service")

    def delegate(
        self,
        *,
        id: str,
        kind: Literal["agent", "user", "service"] = "agent",
        session_id: str | None = None,
        labels: dict[str, str] | None = None,
        attestation: Attestation = "assigned",
    ) -> "Principal":
        """Stamp *this* principal as the parent of a new child — build-01 §3.

        The establishment half of the spec: a hop is added by the parent's own
        credentialed context, so the chain is something the spawning side writes
        about itself, never something the child says about its parent. Every
        spawn path (hub, adapters, the gateway) goes through here so there is
        one place where that rule is either kept or broken.
        """
        return Principal(
            id=id,
            kind=kind,
            session_id=session_id,
            labels=labels or {},
            attestation=attestation,
            on_behalf_of=[
                *self.chain(),
                Hop(id=self.id, kind=self.kind, attestation=self.attestation),
            ],
        )


class ActionContext(BaseModel):
    """Where the action came from. Free-form `extra` is canonicalized like params."""

    model_config = ConfigDict(extra="forbid")

    origin: str = "unknown"  # interception point: mcp | sdk | gateway | http
    workspace: str | None = None
    trace_id: str | None = None
    span_id: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict)


class Action(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["unified.action/v1"] = SCHEMA_VERSION
    id: str  # ULID — unique per observed action, even for identical payloads
    ts: str  # ISO-8601 UTC
    principal: Principal
    tool: str  # tool URI: mcp://<server>/<tool>, sdk://..., https://host/path
    verb: str  # call | read | write | delete | execute | ...
    resource: str  # what is acted on: repo:acme/api, table:billing.invoices, "*"
    params: dict[str, Any] = Field(default_factory=dict)
    context: ActionContext = Field(default_factory=ActionContext)

    @classmethod
    def build(
        cls,
        *,
        principal: Principal,
        tool: str,
        verb: str,
        resource: str,
        params: dict[str, Any] | None = None,
        context: ActionContext | None = None,
    ) -> "Action":
        return cls(
            id=str(ULID()),
            ts=_utcnow_iso(),
            principal=principal,
            tool=tool,
            verb=verb,
            resource=resource,
            params=params or {},
            context=context or ActionContext(),
        )

    def canonical(self, *, strict: bool = True) -> bytes:
        """Canonical bytes of the full action. Strict (the default, and required
        for signing) raises CanonicalizationError on payloads that cannot be
        represented deterministically (e.g. floats); strict=False is for
        integrations whose params are pre-existing free-form JSON (see
        canonical.py)."""
        return canonical_bytes(self.model_dump(mode="json"), strict=strict)

    def digest(self, *, strict: bool = True) -> str:
        return sha256_hex(self.canonical(strict=strict))
