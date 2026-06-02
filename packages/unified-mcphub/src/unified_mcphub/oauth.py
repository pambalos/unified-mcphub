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
