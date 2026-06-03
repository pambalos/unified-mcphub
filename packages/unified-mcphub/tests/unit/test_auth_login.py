"""`auth login` redirect-URL validation — clear errors instead of a KeyError."""

from __future__ import annotations

import textwrap

import pytest

from unified_mcphub.cli import main
from unified_mcphub.config import workspace_path


def _seed_oauth_server(name: str = "linear") -> None:
    # Static oauth config so build_flow needs no network (no issuer → no discovery).
    workspace_path("default").write_text(
        textwrap.dedent(
            f"""
            servers:
              {name}:
                upstream: {{ url: "https://mcp.linear.app/mcp" }}
                oauth:
                  authorize_url: "https://as/authorize"
                  token_url: "https://as/token"
                  client_id: "cid"
            authz:
              rules: []
            """
        ).strip()
        + "\n"
    )


def test_auth_login_rejects_url_without_code(hub_home, fake_keyring, monkeypatch):
    _seed_oauth_server()
    # Paste the bare callback URL (no ?code=&state=) — the exact mistake to guard.
    monkeypatch.setattr("builtins.input", lambda *a: "http://127.0.0.1:7712/oauth/callback")
    with pytest.raises(SystemExit, match="paste the FULL URL"):
        main(["auth", "login", "linear"])


def test_auth_login_surfaces_oauth_error(hub_home, fake_keyring, monkeypatch):
    _seed_oauth_server()
    monkeypatch.setattr(
        "builtins.input",
        lambda *a: (
            "http://127.0.0.1:7712/oauth/callback?error=access_denied&error_description=nope"
        ),
    )
    with pytest.raises(SystemExit, match="authorization denied: access_denied — nope"):
        main(["auth", "login", "linear"])
