"""`unified-mcphub fleet join | status` — enrolment by command.

The fake control plane is an `httpx.MockTransport` (the pattern test_oauth.py
uses), so what is checked is exactly what crosses the wire: the join token,
`kind: sidecar`, and an `evidence_key` that is the public half of the signing
key now sitting in the hub's secrets store. The other half of the contract is
what must *not* happen — a second enrolment over an existing block, a
credential stored for the wrong fleet, a secret on stdout.
"""

from __future__ import annotations

import base64
import json

import httpx
import pytest
import yaml

from unified_enforce.attest import b64u, key_id
from unified_enforce.signing import Signer

from unified_mcphub import fleet_join
from unified_mcphub.cli import main
from unified_mcphub.config import load_hub_config
from unified_mcphub.secrets import SecretsStore

URL = "https://cp.example.test"
JOIN_TOKEN = "jt_" + "J" * 40
CREDENTIAL = "uc_" + "C" * 40
ROOT_KEY = b64u(Signer.generate("root").public_bytes())


@pytest.fixture
def store(hub_home, fake_keyring, monkeypatch):
    """A keyring-backed store on any OS, and the CLI pointed at it."""
    s = SecretsStore(backend="keyring")
    monkeypatch.setattr(fleet_join.SecretsStore, "from_config", classmethod(lambda cls, *a: s))
    return s


@pytest.fixture
def plane(monkeypatch):
    """Records enrolment requests; answers as the real control plane does."""
    seen: list[dict] = []
    state = {"status": 201, "fleet_id": "acme"}

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen.append({"url": str(request.url), "body": body})
        if state["status"] != 201:
            return httpx.Response(
                state["status"], json={"detail": "join token is unknown, expired, or already used"}
            )
        return httpx.Response(
            201,
            json={
                "token": CREDENTIAL,
                "credential_id": "cred-123",
                "fleet_id": state["fleet_id"],
                "kind": "sidecar",
                "expires_at": "2027-01-01T00:00:00Z",
                "control_plane_key": "x",
                "control_plane_key_id": "y",
                "root_key": ROOT_KEY,
                "root_key_id": key_id(ROOT_KEY),
                "keyset": {},
            },
        )

    real = httpx.Client
    monkeypatch.setattr(
        fleet_join.httpx,
        "Client",
        lambda *a, **k: real(transport=httpx.MockTransport(handler), **k),
    )
    return seen, state


def _join(*extra: str) -> int:
    return main(
        ["fleet", "join", "--url", URL, "--fleet", "acme", "--join-token", JOIN_TOKEN, *extra]
    )


def test_join_enrols_with_the_signing_key_and_writes_the_block(hub_home, store, plane, capsys):
    seen, _ = plane
    config = hub_home / "config.yaml"
    config.write_text("# operator's note: keep this\n" + config.read_text())

    assert _join() == 0

    (call,) = seen
    assert call["url"] == f"{URL}/api/v1/enrol"
    assert call["body"]["join_token"] == JOIN_TOKEN
    assert call["body"]["kind"] == "sidecar"

    # The evidence key registered is the public half of the stored seed.
    seed = store.get("hub-signing-key")
    assert seed is not None
    signer = Signer.from_private_bytes(base64.b64decode(seed), "k")
    assert call["body"]["evidence_key"] == b64u(signer.public_bytes())

    assert store.get("control-plane-credential") == CREDENTIAL

    text = config.read_text()
    assert text.startswith("# operator's note: keep this"), "ruamel round-trip keeps comments"
    cp = load_hub_config().control_plane
    assert cp.enabled and cp.url == URL and cp.fleet_id == "acme"
    assert cp.root_public_key == ROOT_KEY
    assert cp.on_stale == "keep" and cp.approvals == "console"
    assert (config.stat().st_mode & 0o777) == 0o600

    out = capsys.readouterr()
    for secret in (JOIN_TOKEN, CREDENTIAL, seed):
        assert secret not in out.out and secret not in out.err, "never print a secret"
    assert "cred-123" in out.out and key_id(call["body"]["evidence_key"]) in out.out


def test_an_existing_block_is_not_replaced_without_force(hub_home, store, plane, capsys):
    """Checked before the token is spent: no request is made at all."""
    seen, _ = plane
    assert _join() == 0
    seen.clear()

    assert _join() == 1
    assert seen == [], "a refused join must not spend the single-use token"
    assert "--force" in capsys.readouterr().err


def test_force_re_enrols_and_keeps_the_rest_of_the_block(hub_home, store, plane):
    seen, _ = plane
    assert _join("--approvals", "terminal") == 0
    data = yaml.safe_load((hub_home / "config.yaml").read_text())
    data["control_plane"]["poll_seconds"] = 7
    (hub_home / "config.yaml").write_text(yaml.safe_dump(data))
    seed_before = store.get("hub-signing-key")

    assert _join("--force") == 0
    assert len(seen) == 2
    cp = load_hub_config().control_plane
    assert cp.approvals == "console" and cp.poll_seconds == 7
    # The existing key is reused, so a re-enrolment does not orphan a chain.
    assert store.get("hub-signing-key") == seed_before
    assert seen[1]["body"]["evidence_key"] == seen[0]["body"]["evidence_key"]


def test_a_token_for_another_fleet_stores_nothing(hub_home, store, plane, capsys):
    _, state = plane
    state["fleet_id"] = "globex"
    assert _join() == 1
    assert store.get("control-plane-credential") is None
    assert not load_hub_config().control_plane.enabled
    assert "globex" in capsys.readouterr().err


def test_a_refused_enrolment_changes_no_config(hub_home, store, plane, capsys):
    _, state = plane
    state["status"] = 401
    before = (hub_home / "config.yaml").read_text()
    assert _join() == 1
    assert (hub_home / "config.yaml").read_text() == before
    assert store.get("control-plane-credential") is None
    err = capsys.readouterr().err
    assert "401" in err and JOIN_TOKEN not in err


def test_status_is_offline_and_reports_signing(hub_home, store, plane, capsys, monkeypatch):
    def no_network(*a, **k):
        raise AssertionError("status must not touch the network")

    assert main(["fleet", "status"]) == 0
    assert "standalone" in capsys.readouterr().out

    assert _join() == 0
    capsys.readouterr()
    monkeypatch.setattr(fleet_join.httpx, "Client", no_network)
    monkeypatch.setattr(store, "get", no_network)  # nor the secrets store

    from unified_mcphub.signing import note_first_signed, signer_from_secret

    seed = SecretsStore.get(store, "hub-signing-key")
    note_first_signed(signer_from_secret(seed), 42)

    assert main(["fleet", "status", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["joined"] and data["fleet_id"] == "acme" and data["approvals"] == "console"
    assert data["signing"]["since_seq"] == 42
    assert main(["fleet", "status"]) == 0
    out = capsys.readouterr().out
    assert "since seq 42" in out and "console (timeout 300s)" in out
