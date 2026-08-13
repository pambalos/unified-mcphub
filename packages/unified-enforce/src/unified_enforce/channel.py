"""Proving a request came from the holder of the credential, not just its bearer.

A bearer credential is possession-is-identity: a stolen one works until it is
revoked or expires. mTLS is the usual fix and does not fit where this runs — the
control plane sits behind a TLS terminator, so the application never sees a
client certificate and would have to trust a forwarded header the proxy is
supposed to have stripped. That is the UAI-137 failure, and a binding whose
correctness depends on a proxy behaving is silently absent in the deployment
that got it wrong.

So the sidecar signs each request with a key it registered at enrolment. The
private half never leaves it, so a stolen token alone buys nothing.

One helper, used by every client that talks to the control plane, because a
per-caller implementation is one somebody forgets at the caller that matters —
and the caller that matters is whichever one an attacker found first.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from .attest import sign_request


class ChannelKey:
    """The sidecar's half of the binding: a signer and the credential it belongs to.

    Holds no secret of its own beyond the signer it was handed, so a deployment
    that keeps its key in an agent or an HSM passes one in rather than working
    around this class.
    """

    #: The header a proof travels in.
    HEADER = "x-unified-proof"

    def __init__(self, signer: Any, credential_id: str) -> None:
        self._signer = signer
        self._credential_id = credential_id

    def headers(self, method: str, path: str, body: bytes | None) -> dict[str, str]:
        """The proof header for one request. Bound to this method, path and body.

        Called per request rather than per session, deliberately: a proof that
        covered only the credential would be a second bearer token, and the
        binding to *this* request is the whole point.
        """
        return {
            self.HEADER: sign_request(
                signer=self._signer,
                credential_id=self._credential_id,
                method=method,
                path=path,
                body=body,
                now=int(datetime.now(UTC).timestamp()),
            )
        }
