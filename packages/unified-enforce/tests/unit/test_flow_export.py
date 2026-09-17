"""The gateway as egress-log exporter — build-14 S-2, `flow.v1`.

Every connection and request the gateway decides on becomes one flow record
in a second shipper. Facts only, deterministic digest, and never a change to
the verdict.
"""

from __future__ import annotations

from datetime import UTC, datetime

from unified_enforce import CheckInput, ConnInput, Enforcer, ExtAuthzCore, PolicyEngine
from unified_enforce import flows
from unified_enforce.evidence import EvidenceShipper
from unified_enforce.policy import Decision, Verdict

POLICY = """
version: 1
rules:
  - id: postgres-ok
    match: {principal: "agent:crew-*", tool: "tcp://10.0.5.10:5432", verb: connect}
    effect: allow
  - id: api-ok
    match: {principal: "agent:crew-*", tool: "https://api.example.com/**"}
    effect: allow
"""
NOW = datetime(2026, 9, 17, 12, 0, 0, 123456, tzinfo=UTC)


class Collecting:
    def __init__(self) -> None:
        self.batches: list[list[dict]] = []

    def send(self, batch):
        self.batches.append(list(batch))

    @property
    def records(self) -> list[dict]:
        return [r for batch in self.batches for r in batch]


def core(shipper=None):
    return ExtAuthzCore(
        Enforcer(PolicyEngine.from_yaml(POLICY)), default_principal="agent:crew-1", flows=shipper
    )


def allow() -> Decision:
    return Decision(verdict=Verdict.ALLOW, rule_id="r", source="exact", reason="")


def deny() -> Decision:
    return Decision(verdict=Verdict.DENY, rule_id=None, source="default", reason="")


# --- the record --------------------------------------------------------------------


def test_a_connection_becomes_a_flow_named_by_its_sni():
    conn = ConnInput(
        principal_id="agent:crew-1",
        destination_address="10.0.9.4",
        destination_port=443,
        source_address="10.0.1.7",
        sni="api.openai.com",
    )
    record = flows.from_connection(conn, allow(), now=NOW)
    assert record == {
        "digest": record["digest"],
        "source": "10.0.1.7",
        "dst_host": "api.openai.com",
        "dst_port": 443,
        "protocol": "tcp",
        "bytes": 0,
        "verdict": "allowed",
        "seen_at": "2026-09-17T12:00:00+00:00",
    }
    assert len(record["digest"]) == 64
    assert "payload" not in record and "path" not in record and "headers" not in record


def test_without_sni_the_address_is_the_name():
    conn = ConnInput(
        principal_id="agent:crew-1", destination_address="10.0.5.10", destination_port=5432
    )
    record = flows.from_connection(conn, deny(), now=NOW)
    assert record["dst_host"] == "10.0.5.10" and record["verdict"] == "denied"
    assert record["source"] == "agent:crew-1", "no source address: the principal stands in"


def test_the_digest_is_deterministic_to_the_second():
    conn = ConnInput(
        principal_id="agent:crew-1", destination_address="10.0.5.10", destination_port=5432
    )
    a = flows.from_connection(conn, allow(), now=NOW)
    b = flows.from_connection(conn, allow(), now=NOW.replace(microsecond=999))
    c = flows.from_connection(conn, allow(), now=NOW.replace(second=1))
    assert a["digest"] == b["digest"] != c["digest"]


def test_a_request_becomes_a_flow_without_its_path_or_headers():
    req = CheckInput(
        principal_id="agent:crew-1",
        method="POST",
        host="api.example.com",
        path="/v1/secret?token=abc",
        headers={"authorization": "Bearer x", "x-forwarded-for": "10.0.1.7, 10.0.0.1"},
        body_size=512,
    )
    record = flows.from_request(req, allow(), now=NOW)
    assert record["dst_host"] == "api.example.com" and record["dst_port"] == 443
    assert record["source"] == "10.0.1.7" and record["bytes"] == 512
    assert "secret" not in str(record) and "Bearer" not in str(record)
    plain = CheckInput(
        principal_id="agent:crew-1", method="GET", host="h:8080", path="/", scheme="http"
    )
    assert flows.from_request(plain, allow(), now=NOW)["dst_port"] == 8080


def test_an_ipv6_authority_keeps_its_host_and_port():
    """`[::1]:8080` split on the first colon is a host of `[`, which folded
    every IPv6 destination into one bucket with the wrong port."""
    v6 = CheckInput(
        principal_id="agent:crew-1", method="GET", host="[::1]:8080", path="/", scheme="http"
    )
    record = flows.from_request(v6, allow(), now=NOW)
    assert (record["dst_host"], record["dst_port"]) == ("::1", 8080)
    bare = CheckInput(
        principal_id="agent:crew-1", method="GET", host="[fd00::5]", path="/", scheme="https"
    )
    record = flows.from_request(bare, allow(), now=NOW)
    assert (record["dst_host"], record["dst_port"]) == ("fd00::5", 443)
    odd = CheckInput(principal_id="agent:crew-1", method="GET", host="h:notaport", path="/")
    assert flows.from_request(odd, allow(), now=NOW)["dst_port"] == 443


# --- the gateway emits ---------------------------------------------------------------


def test_the_connection_check_emits_one_flow_per_check():
    sink = Collecting()
    shipper = EvidenceShipper(sink, interval_seconds=0.01)
    c = core(shipper)
    ok = c.check_connection(
        ConnInput(
            principal_id="agent:crew-1", destination_address="10.0.5.10", destination_port=5432
        )
    )
    refused = c.check_connection(
        ConnInput(
            principal_id="agent:crew-1",
            destination_address="10.0.9.4",
            destination_port=443,
            sni="api.openai.com",
        )
    )
    assert ok.allowed and not refused.allowed
    shipper.flush()
    assert [(r["dst_host"], r["verdict"]) for r in sink.records] == [
        ("10.0.5.10", "allowed"),
        ("api.openai.com", "denied"),
    ]


def test_the_http_check_emits_too():
    sink = Collecting()
    shipper = EvidenceShipper(sink, interval_seconds=0.01)
    c = core(shipper)
    result = c.check(
        CheckInput(principal_id="agent:crew-1", method="GET", host="api.example.com", path="/v1/x")
    )
    assert result.allowed
    shipper.flush()
    (record,) = sink.records
    assert record["dst_host"] == "api.example.com" and record["verdict"] == "allowed"


def test_no_shipper_means_no_emission_and_the_same_verdicts():
    c = core(None)
    assert c.check_connection(
        ConnInput(
            principal_id="agent:crew-1", destination_address="10.0.5.10", destination_port=5432
        )
    ).allowed


def test_a_broken_shipper_never_changes_the_verdict():
    class Exploding:
        def submit(self, record):
            raise RuntimeError("spool on fire")

    c = core(Exploding())
    result = c.check_connection(
        ConnInput(
            principal_id="agent:crew-1", destination_address="10.0.5.10", destination_port=5432
        )
    )
    assert result.allowed and result.headers["x-unified-verdict"] == "allow"


def test_flow_shipper_targets_the_flows_endpoint():
    shipper = flows.flow_shipper("https://cp.example", "uai_sc_x")
    sink = shipper._sink  # noqa: SLF001
    assert sink._url == "https://cp.example/api/v1/evidence/flows"  # noqa: SLF001
    assert sink._field == "flows"  # noqa: SLF001
