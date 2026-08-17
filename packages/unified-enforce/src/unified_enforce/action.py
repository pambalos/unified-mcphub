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

from pydantic import BaseModel, ConfigDict, Field
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

    def lineage(self) -> list[str]:
        """This principal and its parent, nearest first. One level today.

        A list rather than a pair because the frameworks nest further than one
        level, and a caller that walks a list keeps working when a chain
        arrives. Returning `[id]` for an orphan means no caller needs a branch.
        """
        return [self.id] if self.parent_id is None else [self.id, self.parent_id]


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
