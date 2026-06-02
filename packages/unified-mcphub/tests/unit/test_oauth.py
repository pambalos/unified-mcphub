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
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    )
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


# --- Dynamic Client Registration -------------------------------------------------

_META = {
    "authorization_endpoint": "https://as/auth",
    "token_endpoint": "https://as/token",
    "registration_endpoint": "https://as/register",
}


def _route_mock(monkeypatch, *, on_get, on_post):
    """Route mock httpx requests by method, tracking POST (registration) count."""
    real = httpx.AsyncClient
    counts = {"get": 0, "post": 0}

    def handler(request):
        if request.method == "GET":
            counts["get"] += 1
            return httpx.Response(200, json=on_get)
        counts["post"] += 1
        return httpx.Response(200, json=on_post)

    monkeypatch.setattr(
        httpx, "AsyncClient", lambda *a, **k: real(transport=httpx.MockTransport(handler))
    )
    return counts


async def test_build_flow_static_does_no_network():
    flow = await oauth.build_flow(
        "gh", FakeStore(), authorize_url="https://gh/a", token_url="https://gh/t", client_id="cid"
    )
    assert (flow.authorize_url, flow.token_url, flow.client_id) == (
        "https://gh/a",
        "https://gh/t",
        "cid",
    )


async def test_build_flow_dcr_discovers_and_registers(monkeypatch):
    store = FakeStore()
    counts = _route_mock(monkeypatch, on_get=_META, on_post={"client_id": "dyn-123"})
    flow = await oauth.build_flow("linear", store, issuer="https://as", scopes=["read"])
    assert flow.authorize_url == "https://as/auth"
    assert flow.token_url == "https://as/token"
    assert flow.client_id == "dyn-123"
    assert store.get("linear-oauth-client-id") == "dyn-123"  # cached for reuse
    assert counts["post"] == 1  # registered exactly once


async def test_build_flow_reuses_cached_client_id(monkeypatch):
    store = FakeStore()
    store.set("linear-oauth-client-id", "cached-cid")
    counts = _route_mock(monkeypatch, on_get=_META, on_post={"client_id": "should-not-be-used"})
    flow = await oauth.build_flow("linear", store, issuer="https://as")
    assert flow.client_id == "cached-cid"
    assert counts["post"] == 0  # no re-registration


async def test_build_flow_no_client_no_registration_errors():
    with pytest.raises(ValueError, match="registration endpoint"):
        await oauth.build_flow("x", FakeStore(), authorize_url="https://a", token_url="https://t")
