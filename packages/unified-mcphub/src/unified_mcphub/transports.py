"""Transports — spec §3.1.

Unix socket (primary, mode 0600) + TCP loopback (fallback). Both serve the same
ASGI app (the hub's MCP server surface). Each harness uses whichever it supports.
"""

from __future__ import annotations

import asyncio
import errno
import os
import socket
from pathlib import Path

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from .config import ListenConfig


class PortInUseError(RuntimeError):
    """Raised when the configured TCP port is already bound (errno EADDRINUSE).

    Carries the port so the CLI can print a one-line, traceback-free message
    instead of uvicorn's bind failure + sys.exit(1) noise.
    """

    def __init__(self, port: int) -> None:
        self.port = port
        super().__init__(f"TCP {port} in use — another hub is running; pass --port or --no-tcp")


def _authenticate(request: Request, hub) -> tuple[str | None, str | None]:
    """Resolve (caller_id, caller_token_id) for a request.

    Unix socket: trusted (filesystem perms); caller from X-Caller-Id header, no
    token. TCP loopback: require a valid `Authorization: Bearer <token>` mapped
    to a caller (spec §3.1, §3.2). caller is None if a TCP caller is unauthed.
    """
    if request.client is None or not request.client.host:
        return request.headers.get("X-Caller-Id", "unknown"), None  # uds peer
    auth = request.headers.get("Authorization", "")
    token = auth[len("Bearer ") :] if auth.startswith("Bearer ") else ""
    caller = hub.tokens.resolve(token) if token else None
    token_id = hub.tokens.caller_token_id(token) if caller else None
    return caller, token_id


def build_app(hub) -> Starlette:
    async def mcp_endpoint(request: Request) -> Response:
        caller, token_id = _authenticate(request, hub)
        if caller is None:
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        message = await request.json()
        result = await hub.handle_mcp(message, caller, token_id)
        if result is None:
            return Response(status_code=202)  # notification — no response body
        return JSONResponse(result)

    async def status_endpoint(_: Request) -> Response:
        return JSONResponse(hub.status())

    return Starlette(
        routes=[
            Route("/mcp", mcp_endpoint, methods=["POST"]),
            Route("/status", status_endpoint, methods=["GET"]),
        ]
    )


class TransportServer:
    def __init__(self, app: Starlette, listen: ListenConfig) -> None:
        self._app = app
        self._listen = listen
        self._servers: list[uvicorn.Server] = []
        self._tasks: list[asyncio.Task] = []
        self.uds_path: str | None = None

    @staticmethod
    def _preflight_tcp(host: str, port: int) -> None:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Mirror uvicorn's bind (SO_REUSEADDR on) so a port merely in TIME_WAIT
        # is not misreported as in use — only an active listener trips EADDRINUSE.
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind((host, port))
        except OSError as exc:
            if exc.errno == errno.EADDRINUSE:
                raise PortInUseError(port) from None
            raise
        finally:
            probe.close()

    async def start(self) -> None:
        configs: list[uvicorn.Config] = []

        if self._listen.unix_socket:
            uds = str(Path(self._listen.unix_socket).expanduser())
            Path(uds).parent.mkdir(parents=True, exist_ok=True)
            if os.path.exists(uds):
                os.unlink(uds)  # stale socket from a prior run
            self.uds_path = uds
            configs.append(uvicorn.Config(self._app, uds=uds, log_level="warning"))

        if self._listen.tcp_enabled:
            host, port = self._listen.host, self._listen.port
            # Pre-flight the bind so a port collision surfaces as a clean one-liner
            # here, instead of uvicorn logging the OSError + sys.exit(1) inside its
            # serve task (which our started-poll would otherwise see as a timeout).
            self._preflight_tcp(host, port)
            configs.append(uvicorn.Config(self._app, host=host, port=port, log_level="warning"))

        for cfg in configs:
            server = uvicorn.Server(cfg)
            server.install_signal_handlers = lambda: None  # we own signals (hub lifecycle)
            self._servers.append(server)
            self._tasks.append(asyncio.create_task(server.serve()))

        for server in self._servers:
            for _ in range(200):
                if server.started:
                    break
                await asyncio.sleep(0.02)
            else:
                raise RuntimeError("transport failed to start within timeout")

        if self.uds_path:
            os.chmod(self.uds_path, 0o600)

    async def stop(self) -> None:
        for server in self._servers:
            server.should_exit = True
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        if self.uds_path and os.path.exists(self.uds_path):
            os.unlink(self.uds_path)
