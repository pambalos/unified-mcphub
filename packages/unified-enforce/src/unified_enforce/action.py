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


class Principal(BaseModel):
    """Who is acting. `id` is namespaced: agent:<name>, user:<name>, service:<name>."""

    model_config = ConfigDict(extra="forbid")

    id: str
    kind: Literal["agent", "user", "service"] = "agent"
    session_id: str | None = None
    labels: dict[str, str] = Field(default_factory=dict)


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
