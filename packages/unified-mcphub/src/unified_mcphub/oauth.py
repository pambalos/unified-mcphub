"""Upstream OAuth — Authorization Code + PKCE — spec §3.4.

Loopback callback at http://127.0.0.1:7712/oauth/callback; `state` and the PKCE
verifier are validated; refresh-token rotation is supported. The flow persists
the refresh token through an injected `TokenStore` (the hub wires the real
secrets store) so this module has no hard dependency on secrets.py.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import urllib.parse
from dataclasses import dataclass, field
from typing import Protocol

import httpx

DEFAULT_REDIRECT_URI = "http://127.0.0.1:7712/oauth/callback"


class TokenStore(Protocol):
    def set(self, name: str, value: str) -> None: ...
    def get(self, name: str) -> str | None: ...


def new_verifier() -> str:
    return secrets.token_urlsafe(64)  # 86 chars, within the 43-128 PKCE range


def challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")  # S256, no padding


def new_state() -> str:
    return secrets.token_urlsafe(24)


@dataclass
class OAuthFlow:
    server: str
    authorize_url: str
    token_url: str
    client_id: str
    store: TokenStore
    redirect_uri: str = DEFAULT_REDIRECT_URI
    scopes: list[str] = field(default_factory=list)
    _pending: dict[str, str] = field(default_factory=dict)  # state -> verifier

    @property
    def _refresh_key(self) -> str:
        return f"{self.server}-oauth-refresh"

    def authorization_url(self) -> str:
        verifier = new_verifier()
        state = new_state()
        self._pending[state] = verifier
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": " ".join(self.scopes),
            "state": state,
            "code_challenge": challenge(verifier),
            "code_challenge_method": "S256",
        }
        return f"{self.authorize_url}?{urllib.parse.urlencode(params)}"

    async def exchange_code(self, code: str, state: str) -> dict:
        verifier = self._pending.pop(state, None)
        if verifier is None:
            raise ValueError("oauth state mismatch (unknown or already-used state)")
        payload = {
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": self.redirect_uri,
            "client_id": self.client_id,
        }
        async with httpx.AsyncClient() as client:
            response = await client.post(self.token_url, data=payload)
            response.raise_for_status()
            tokens = response.json()
        self._persist_refresh(tokens)
        return tokens

    async def refresh(self) -> dict:
        refresh_token = self.store.get(self._refresh_key)
        if refresh_token is None:
            raise ValueError(f"no stored refresh token for '{self.server}'")
        payload = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self.client_id,
        }
        async with httpx.AsyncClient() as client:
            response = await client.post(self.token_url, data=payload)
            response.raise_for_status()
            tokens = response.json()
        self._persist_refresh(tokens)  # rotate if the provider returned a new one
        return tokens

    def _persist_refresh(self, tokens: dict) -> None:
        if tokens.get("refresh_token"):
            self.store.set(self._refresh_key, tokens["refresh_token"])


# --- Dynamic Client Registration (RFC 8414 discovery + RFC 7591 registration) ---


async def discover_metadata(issuer: str) -> dict:
    """Fetch an authorization server's metadata (`authorization_endpoint`,
    `token_endpoint`, `registration_endpoint`, …) from its well-known URL."""
    url = issuer.rstrip("/") + "/.well-known/oauth-authorization-server"
    async with httpx.AsyncClient(follow_redirects=True) as client:
        response = await client.get(url)
        response.raise_for_status()
        return response.json()


async def register_client(
    registration_url: str,
    *,
    redirect_uri: str,
    scopes: list[str],
    client_name: str = "unified-mcphub",
) -> dict:
    """Register a public (PKCE) client and return the issued credentials.

    `token_endpoint_auth_method: none` → no client secret; the Authorization Code
    + PKCE flow is what authenticates us, matching how MCP clients self-register."""
    body = {
        "client_name": client_name,
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "scope": " ".join(scopes),
    }
    async with httpx.AsyncClient() as client:
        response = await client.post(registration_url, json=body)
        response.raise_for_status()
        return response.json()


async def build_flow(
    server: str,
    store: TokenStore,
    *,
    authorize_url: str | None = None,
    token_url: str | None = None,
    client_id: str | None = None,
    issuer: str | None = None,
    registration_url: str | None = None,
    scopes: list[str] | None = None,
    redirect_uri: str = DEFAULT_REDIRECT_URI,
) -> OAuthFlow:
    """Resolve an OAuthFlow from either a static config (all of authorize/token/
    client_id given) or via Dynamic Client Registration (an `issuer` to discover
    endpoints + register a client). A registered `client_id` is cached in the
    store and reused, so registration happens once per server."""
    scopes = scopes or []
    if issuer and not (authorize_url and token_url):
        meta = await discover_metadata(issuer)
        authorize_url = authorize_url or meta.get("authorization_endpoint")
        token_url = token_url or meta.get("token_endpoint")
        registration_url = registration_url or meta.get("registration_endpoint")

    client_id_key = f"{server}-oauth-client-id"
    if client_id is None:
        client_id = store.get(client_id_key)  # reuse a prior dynamic registration
    if client_id is None:
        if not registration_url:
            raise ValueError(
                f"'{server}': no client_id and no registration endpoint — set "
                "oauth.client_id, or oauth.issuer/registration_url for dynamic registration"
            )
        registered = await register_client(
            registration_url, redirect_uri=redirect_uri, scopes=scopes
        )
        client_id = registered["client_id"]
        store.set(client_id_key, client_id)

    if not (authorize_url and token_url):
        raise ValueError(f"'{server}': could not resolve authorize_url/token_url")
    return OAuthFlow(
        server=server,
        authorize_url=authorize_url,
        token_url=token_url,
        client_id=client_id,
        store=store,
        redirect_uri=redirect_uri,
        scopes=scopes,
    )
