"""Unit tests for the OAuth (Auth Code + PKCE) flow — spec §3.4 (MCP-HUB-5)."""

from __future__ import annotations

import base64
import hashlib
import urllib.parse

import httpx
import pytest

from unified_mcphub import oauth


class FakeStore:
    def __init__(self):
        self.data: dict[str, str] = {}

    def set(self, name, value):
        self.data[name] = value

    def get(self, name):
        return self.data.get(name)


def _mock_async_client(monkeypatch, json_body):
    real = httpx.AsyncClient

    def handler(_request):
        return httpx.Response(200, json=json_body)

    monkeypatch.setattr(
        httpx, "AsyncClient", lambda *a, **k: real(transport=httpx.MockTransport(handler))
    )


def test_challenge_is_s256_of_verifier():
    verifier = "test-verifier-value"
    expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    assert oauth.challenge(verifier) == expected


def test_authorization_url_has_pkce_and_state():
    flow = oauth.OAuthFlow("github", "https://gh/auth", "https://gh/token", "cid", FakeStore())
    url = flow.authorization_url()
    params = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    assert params["code_challenge_method"] == ["S256"]
    assert params["code_challenge"] and params["state"]
    assert params["state"][0] in flow._pending


async def test_state_mismatch_raises():
    flow = oauth.OAuthFlow("github", "https://gh/auth", "https://gh/token", "cid", FakeStore())
    flow.authorization_url()
    with pytest.raises(ValueError, match="state mismatch"):
        await flow.exchange_code("code", "bogus-state")


async def test_exchange_persists_refresh_token(monkeypatch):
    store = FakeStore()
    flow = oauth.OAuthFlow("github", "https://gh/auth", "https://gh/token", "cid", store)
    url = flow.authorization_url()
    state = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)["state"][0]
    _mock_async_client(monkeypatch, {"access_token": "a", "refresh_token": "r1"})
    tokens = await flow.exchange_code("the-code", state)
    assert tokens["access_token"] == "a"
    assert store.get("github-oauth-refresh") == "r1"


async def test_refresh_rotates_token(monkeypatch):
    store = FakeStore()
    store.set("github-oauth-refresh", "r1")
    flow = oauth.OAuthFlow("github", "https://gh/auth", "https://gh/token", "cid", store)
    _mock_async_client(monkeypatch, {"access_token": "a2", "refresh_token": "r2"})
    await flow.refresh()
    assert store.get("github-oauth-refresh") == "r2"
