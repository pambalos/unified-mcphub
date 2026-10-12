"""Workspace rules may name the company-policy clauses they implement.

policy-records.v1: the hub passes `implements` to the engine rule it
compiles, the decision carries it, and the `received` audit entry records it.
A workspace that does not use the key compiles to the same policy digest and
hashes to the same config hash as before the key existed.
"""

from __future__ import annotations

import json

import pytest

from pydantic import ValidationError

from unified_mcphub.audit import AuditLog
from unified_mcphub.authz import AuthzResolver, Effect
from unified_mcphub.config import Authz, DangerousCommands, Rule, Workspace


def _resolver(rules: list[Rule]) -> AuthzResolver:
    return AuthzResolver(Workspace(authz=Authz(rules=rules)), DangerousCommands())


def test_a_rule_names_its_clauses_on_the_decision():
    resolver = _resolver(
        [
            Rule(
                tool="mcp://claims/approve",
                effect="prompt",
                implements=["claims-authority#4", "human-oversight#2"],
            ),
            Rule(tool="mcp://claims/get_*", effect="allow"),
        ]
    )
    d = resolver.resolve("mcp://claims/approve", {}, "claims-agent")
    assert d.effect is Effect.PROMPT
    assert d.implements == ("claims-authority#4", "human-oversight#2")
    assert d.engine is not None and d.engine.implements == d.implements
    assert resolver.resolve("mcp://claims/get_one", {}, "claims-agent").implements == ()


def test_unset_and_empty_compile_to_the_same_policy_as_before():
    plain = _resolver([Rule(tool="mcp://claims/get_*", effect="allow")])
    empty = _resolver([Rule(tool="mcp://claims/get_*", effect="allow", implements=[])])
    assert plain._engine.policy_digest == empty._engine.policy_digest
    linked = _resolver(
        [Rule(tool="mcp://claims/get_*", effect="allow", implements=["claims-authority#1"])]
    )
    assert linked._engine.policy_digest != plain._engine.policy_digest


def test_an_unset_key_stays_out_of_the_config_dump():
    """The hub's config hash is over `model_dump()`; a workspace that does not
    use the key must not look changed after an upgrade."""
    assert "implements" not in Rule(tool="mcp://x/y", effect="allow").model_dump()
    assert Rule(tool="mcp://x/y", effect="allow", implements=["a#1"]).model_dump()[
        "implements"
    ] == ["a#1"]


def test_a_malformed_reference_is_a_config_error():
    with pytest.raises(ValidationError, match="not a clause reference"):
        Rule(tool="mcp://x/y", effect="allow", implements=["not a ref"])


def test_the_received_entry_records_the_clauses(tmp_path):
    log = AuditLog(tmp_path)
    log.start()
    common = dict(
        trace_id="t",
        span_id="s",
        caller_id="claims-agent",
        caller_token_id=None,
        mcp_server="claims",
        tool="approve",
        args={},
        authz_decision="allow",
        authz_rule="mcp://claims/approve",
        audit_level="standard",
    )
    log.write_received(request_id="r1", implements=("claims-authority#4",), **common)
    log.write_received(request_id="r2", **common)
    log.stop()
    entries = [
        json.loads(line) for f in tmp_path.glob("*.jsonl") for line in f.read_text().splitlines()
    ]
    by_id = {e["request_id"]: e for e in entries}
    assert by_id["r1"]["implements"] == ["claims-authority#4"]
    assert "implements" not in by_id["r2"]


def test_an_evidence_pack_counts_hub_decisions_per_clause(tmp_path):
    """The verifier reads clauses off hub `received` entries too, with the
    verdict the hub ships (a `prompt_allowed` is an allow)."""
    from datetime import UTC, datetime, timedelta

    from unified_enforce.evidence_pack import ChainSource, build
    from unified_enforce.pack_verify import CLAUSE_DECISIONS, verify_pack

    log = AuditLog(tmp_path / "audit")
    log.start()
    for n, (decision, refs) in enumerate(
        [
            ("prompt_allowed", ("claims-authority#4",)),
            ("prompt_denied", ("claims-authority#4",)),
            ("allow", ()),
        ]
    ):
        log.write_received(
            request_id=f"r{n}",
            trace_id="t",
            span_id="s",
            caller_id="claims-agent",
            caller_token_id=None,
            mcp_server="claims",
            tool="approve",
            args={},
            authz_decision=decision,
            authz_rule="mcp://claims/approve",
            audit_level="standard",
            implements=refs,
        )
    log.stop()
    pack = build(
        out=tmp_path / "pack",
        title="hub",
        fleet_id="acme",
        start=datetime(2000, 1, 1, tzinfo=UTC),
        end=datetime.now(UTC) + timedelta(days=1),
        csv_path=None,
        chains=[ChainSource(name="hub", directory=tmp_path / "audit")],
        policies=[],
        root_key=None,
        keyset_path=None,
    )
    tally = json.loads((pack / CLAUSE_DECISIONS).read_text())
    assert tally["decisions"] == 3
    assert tally["clauses"]["claims-authority#4"]["verdicts"] == {"allow": 1, "deny": 1}
    report = verify_pack(pack)
    check = next(c for c in report.checks if c.name == "policy records: decisions per clause")
    assert check.ok, check.detail
