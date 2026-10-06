"""A joined hub's prompts, answered at the control plane — and its evidence,
pointing at the hub's own entries.

The dogfooding problem this closes: a `prompt` answered at the hub's terminal
was recorded locally (`prompt_allowed`, `decided_by: terminal`) while the
control plane only ever received the DEFER, so its console showed real calls
as unresolved deferrals with nobody's name on them. In console mode the DEFER
is queued at the control plane, an authenticated approver answers it there,
and the hub's `received` entry carries that approver and the control plane's
signature over the answer.

The remote channel is faked at the `RemoteApprovals` boundary for the hub
tests (what the hub does with an attested answer), and exercised for real —
signatures and all — at the `Approval` level (that a forged answer denies).
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest
import yaml

from unified_enforce import (
    ApprovalKind,
    ApprovalResponse,
    Approver,
    SignedResolution,
)
from unified_enforce.policy import Verdict
from unified_enforce.remote_approvals import RemoteApprovals

from unified_mcphub import audit_reader
from unified_mcphub.approval import Approval, TerminalChannel
from unified_mcphub.config import ControlPlaneConfig, audit_dir, load_config, workspace_local_path
from unified_mcphub.fleet import ConsoleApprovals, FleetLink
from unified_mcphub.hub import Hub

from test_fleet import FLEET, NOW, FakeControlPlane, Key  # noqa: E402  (shared fake plane)

FAKE_SERVER = Path(__file__).parent.parent / "fixtures" / "fake_mcp_server.py"
RULE = "mcp://filesystem/read_file"
SUBJECT = "google:117000000000000000001"


def _workspace(hub_home, *, approvals: str = "console") -> None:
    (hub_home / "workspaces" / "default.yaml").write_text(
        textwrap.dedent(
            f"""
            servers:
              filesystem:
                upstream:
                  command: {sys.executable}
                  args: ["{FAKE_SERVER}"]
            authz:
              rules:
                - tool: "{RULE}"
                  effect: prompt
                - tool: "mcp://filesystem/list_*"
                  effect: allow
            """
        ).strip()
        + "\n"
    )
    cfg = hub_home / "config.yaml"
    cfg.write_text(
        cfg.read_text()
        + textwrap.dedent(
            f"""
            control_plane:
              url: https://control-plane.invalid
              fleet_id: {FLEET}
              root_public_key: placeholder
              approvals: {approvals}
            """
        )
    )


@pytest.fixture
def plane():
    return FakeControlPlane(Key(), Key())


def _hub(hub_home, plane: FakeControlPlane, *, approvals: str = "console") -> Hub:
    _workspace(hub_home, approvals=approvals)
    config = load_config()
    config.hub.control_plane.root_public_key = plane.root.public
    original = FleetLink.__init__

    def patched(self, cfg, *, on_containment=None, transport=None):
        original(self, cfg, on_containment=on_containment, transport=plane)

    FleetLink.__init__ = patched  # type: ignore[method-assign]
    try:
        hub = Hub(config)
    finally:
        FleetLink.__init__ = original  # type: ignore[method-assign]
    return hub


class FakeRemote:
    """Stands where `RemoteApprovals` stands: records the request, answers."""

    def __init__(self, kind: ApprovalKind = ApprovalKind.ALLOW, scope: Any = None) -> None:
        self.kind = kind
        self.scope = scope
        self.requests: list[Any] = []

    async def ask(self, request):
        self.requests.append(request)
        return ApprovalResponse(
            kind=self.kind,
            decided_by=SUBJECT,
            scope=self.scope,
            approver=Approver(
                subject=SUBJECT,
                email="alice@acme.test",
                session_id="sess-1",
                authenticated_at_ms=1_785_999_000_000,
            ),
            attestation=SignedResolution(
                signature="c2ln",
                key_id="decision-kid",
                nonce="n-1",
                resolved_at_ms=1_786_000_000_000,
                expires_at_ms=1_786_003_600_000,
                fleet_id=FLEET,
            ),
        )


def _bind(hub: Hub, remote: FakeRemote) -> None:
    assert hub.fleet is not None and hub.fleet.approvals is not None
    hub.fleet.approvals._remote = remote  # noqa: SLF001


def _call(hub: Hub, tool: str = "read_file", args: dict | None = None):
    return hub._handle_call(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": f"filesystem__{tool}", "arguments": args or {"path": "x"}},
        },
        "crew-1",
    )


@pytest.fixture
async def started(hub_home, plane):
    """A joined, console-mode hub with a verified snapshot and a stub upstream."""
    hub = _hub(hub_home, plane)
    hub.audit.start()
    hub.fleet.distribution.refresh(now=NOW)
    forwarded: list[tuple] = []

    async def forward(*a):
        forwarded.append(a)
        return {"content": [{"type": "text", "text": "ok"}]}

    hub._forward = forward  # type: ignore[method-assign]
    hub.forwarded = forwarded  # type: ignore[attr-defined]
    try:
        yield hub
    finally:
        hub.audit.stop()


# --- config and selection ------------------------------------------------------


def test_console_is_the_default_and_both_new_settings_are_validated():
    cp = ControlPlaneConfig(url="https://cp", fleet_id="a", root_public_key="k")
    assert cp.approvals == "console" and cp.console_approvals
    assert cp.approval_timeout_seconds == 300
    assert not ControlPlaneConfig().console_approvals, "standalone hubs have no console"
    with pytest.raises(ValueError, match="approvals"):
        ControlPlaneConfig(url="https://cp", fleet_id="a", root_public_key="k", approvals="email")
    with pytest.raises(ValueError, match="approval_timeout_seconds"):
        ControlPlaneConfig(
            url="https://cp", fleet_id="a", root_public_key="k", approval_timeout_seconds=0
        )


def test_console_mode_never_selects_the_terminal(hub_home, plane, monkeypatch):
    """Even attached to a TTY: a joined console-mode hub has one approver."""
    monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=False)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True, raising=False)
    hub = _hub(hub_home, plane)
    assert hub.approval.console and hub.approval.channel is None


def test_terminal_mode_keeps_todays_selection(hub_home, plane, monkeypatch):
    import unified_mcphub.hub as hub_mod

    class Tty:
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr(hub_mod.sys, "stdin", Tty())
    monkeypatch.setattr(hub_mod.sys, "stdout", Tty())
    hub = _hub(hub_home, plane, approvals="terminal")
    assert hub.fleet is not None and hub.fleet.approvals is None
    assert not hub.approval.console and isinstance(hub.approval.channel, TerminalChannel)


def test_bind_builds_the_engine_client_with_the_fleets_keys_and_timeout():
    built: dict[str, Any] = {}

    def factory(url, credential, **kwargs):
        built.update(url=url, credential=credential, **kwargs)
        return FakeRemote()

    cfg = ControlPlaneConfig(
        url="https://cp.example",
        fleet_id="acme",
        root_public_key="k",
        approval_timeout_seconds=42,
    )

    def keys():
        return {}

    channel = ConsoleApprovals(cfg, keys, factory=factory)
    assert not channel.bound
    channel.bind("uc_cred")
    assert channel.bound
    assert built == {
        "url": "https://cp.example",
        "credential": "uc_cred",
        "fleet_id": "acme",
        "keys": keys,
        "deadline_seconds": 42,
    }


# --- the call path -------------------------------------------------------------


@pytest.mark.asyncio
async def test_an_unbound_console_denies(started):
    """No credential, no approvals — and no quiet fallback to some other yes."""
    body = await _call(started)
    assert body["error"]["code"] == -32003
    assert started.forwarded == []
    (received,) = audit_reader.search(audit_dir(), phase="received")
    assert received["authz_decision"] == "prompt_denied"
    assert received["reason"] == "approval_channel_error"
    assert "approver" not in received


@pytest.mark.asyncio
async def test_a_console_approval_is_recorded_with_its_approver(started):
    remote = FakeRemote()
    _bind(started, remote)

    body = await _call(started)
    assert "result" in body and len(started.forwarded) == 1

    (request,) = remote.requests
    # The approver is told which rule asked — the readable pattern — not
    # "rule_id: None, source: prompt" as every request said before.
    assert request.decision.verdict is Verdict.DEFER
    assert request.decision.rule_id == RULE
    assert request.decision.policy_digest is not None

    (received,) = audit_reader.search(audit_dir(), phase="received")
    # The same canonical Action the verdict was made on is the one queued.
    assert received["action_digest"] == request.digest
    assert received["authz_decision"] == "prompt_allowed"
    assert received["authz_rule"] == RULE
    assert received["decided_by"] == SUBJECT
    assert received["approver"] == {
        "subject": SUBJECT,
        "email": "alice@acme.test",
        "session_id": "sess-1",
        "authenticated_at_ms": 1_785_999_000_000,
    }
    assert received["attestation"]["key_id"] == "decision-kid"
    assert received["attestation"]["fleet_id"] == FLEET
    assert set(received["attestation"]) == {
        "signature",
        "key_id",
        "nonce",
        "resolved_at_ms",
        "expires_at_ms",
        "fleet_id",
    }
    assert audit_reader.verify(audit_dir()).ok


@pytest.mark.asyncio
async def test_a_console_allow_always_without_scope_persists_nothing(started):
    """ADR-0025: a remote click must not write tool-wide trust into this hub."""
    _bind(started, FakeRemote(ApprovalKind.ALLOW_ALWAYS))
    body = await _call(started)
    assert "result" in body, "honoured for this call"
    assert not workspace_local_path("default").exists()
    assert started.config.workspace.authz.rules[0].tool == RULE, "no rule prepended"


@pytest.mark.asyncio
async def test_a_scoped_console_allow_always_persists_like_the_terminal(started):
    scope = {"path": {"equals": ["x"]}}
    _bind(started, FakeRemote(ApprovalKind.ALLOW_ALWAYS, scope=scope))
    await _call(started)
    learned = yaml.safe_load(workspace_local_path("default").read_text())
    assert learned[0]["tool"] == RULE and learned[0]["args_filter"] == scope
    # The rebuilt resolver keeps the fleet: containment and evidence survive
    # a persisted answer (they did not, before).
    assert started.authz._enforcer._distribution is started.fleet.distribution  # noqa: SLF001
    assert started.authz._evidence is started.fleet.evidence  # noqa: SLF001


@pytest.mark.asyncio
async def test_a_console_scope_the_hub_cannot_express_is_not_persisted(started):
    _bind(started, FakeRemote(ApprovalKind.ALLOW_ALWAYS, scope={"path": {"glob": "x*"}}))
    body = await _call(started)
    assert "result" in body
    assert not workspace_local_path("default").exists()


# --- evidence points at the hub's own entry -------------------------------------


def _shipped(hub: Hub, plane: FakeControlPlane) -> list[dict]:
    assert hub.fleet is not None and hub.fleet.evidence is not None
    hub.fleet.evidence.flush()
    return plane.evidence


@pytest.mark.asyncio
async def test_evidence_carries_the_received_entrys_seq_and_hash(started, plane):
    await _call(started, "list_files", {})
    (received,) = audit_reader.search(audit_dir(), phase="received")
    (row,) = _shipped(started, plane)
    assert row["chain_seq"] == received["seq"]
    assert row["chain_hash"] == received["hash"]
    assert row["verdict"] == "allow" and row["rule_id"] == "mcp://filesystem/list_*"


@pytest.mark.asyncio
async def test_a_prompt_ships_its_resolution_not_the_deferral(started, plane):
    """One row per digest at the control plane, so it is the row that matches
    the entry it cites: the resolved verdict, the deferring rule kept."""
    _bind(started, FakeRemote())
    await _call(started)
    (received,) = audit_reader.search(audit_dir(), phase="received")
    (row,) = _shipped(started, plane)
    assert row["verdict"] == "allow" and row["source"] == "approval"
    assert row["rule_id"] == RULE
    assert (row["chain_seq"], row["chain_hash"]) == (received["seq"], received["hash"])


@pytest.mark.asyncio
async def test_a_deny_is_shipped_against_its_entry_too(started, plane):
    await _call(started, "delete_file", {"path": "x"})  # default deny
    (received,) = audit_reader.search(audit_dir(), phase="received")
    (row,) = _shipped(started, plane)
    assert row["verdict"] == "deny" and row["chain_hash"] == received["hash"]


@pytest.mark.asyncio
async def test_nothing_ships_when_the_entry_could_not_be_written(started, plane):
    """Only ship what the chain holds — the hub's chain, now."""

    def broken(**kwargs):
        raise RuntimeError("audit_error: disk full")

    started.audit.write_received = broken  # type: ignore[method-assign]
    with pytest.raises(RuntimeError):
        await _call(started, "list_files", {})
    assert _shipped(started, plane) == []


@pytest.mark.asyncio
async def test_signed_evidence_from_a_signing_hub(started, plane):
    from unified_enforce.attest import accept_evidence

    from unified_mcphub import signing

    signer = signing.signer_from_secret(signing.generate_seed())
    started.fleet.evidence.signer = signer
    await _call(started, "list_files", {})
    (row,) = _shipped(started, plane)
    assert row["key_id"] == signer.key_id
    assert accept_evidence(row, signing.public_key_b64u(signer))


# --- the real client, through the hub's adapter ---------------------------------


def _signed_channel(monkeypatch, *, forge: bool = False):
    sys.path.insert(0, str(Path(__file__).parents[3] / "unified-enforce" / "tests" / "unit"))
    from test_remote_approvals import fresh, keys_for, signer as decision_signer

    s = decision_signer()
    cfg = ControlPlaneConfig(
        url="https://cp.example", fleet_id=FLEET, root_public_key="k", approval_timeout_seconds=5
    )
    channel = ConsoleApprovals(cfg, lambda: keys_for(s))
    channel.bind("uc_cred")
    remote: RemoteApprovals = channel._remote  # noqa: SLF001
    digests: list[str] = []

    def post(path, body):
        digests.append(body["action_digest"])
        assert body["decision"]["rule_id"] == RULE
        return {"id": "ap-1", "status": "pending"}

    def get(path):
        answer = fresh(s, digests[-1])
        if forge:
            answer = {**answer, "approver": {**answer["approver"], "sub": "google:mallory"}}
        return answer

    monkeypatch.setattr(remote, "_post", post)
    monkeypatch.setattr(remote, "_get", get)
    return channel


async def _resolve(channel) -> Any:
    from unified_enforce.policy import Decision

    return await Approval(enabled=True, channel=None, console=channel).resolve(
        RULE,
        "crew-1",
        "read_file(x)",
        {"path": "x"},
        deferral=Decision(verdict=Verdict.DEFER, rule_id=RULE, source="exact"),
    )


@pytest.mark.asyncio
async def test_a_genuinely_signed_console_answer_allows(monkeypatch):
    outcome = await _resolve(_signed_channel(monkeypatch))
    assert outcome.allowed and outcome.authz_decision == "prompt_allowed"
    assert outcome.approver["subject"].startswith("google:")
    assert outcome.attestation["fleet_id"] == FLEET
    assert outcome.decision.rule_id == RULE and outcome.decision.source == "approval"


@pytest.mark.asyncio
async def test_a_rewritten_approver_denies(monkeypatch):
    outcome = await _resolve(_signed_channel(monkeypatch, forge=True))
    assert not outcome.allowed and outcome.reason == "approval_channel_error"
    assert outcome.approver is None and outcome.attestation is None
