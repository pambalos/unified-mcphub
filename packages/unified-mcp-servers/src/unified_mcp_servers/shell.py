"""shell MCP server — mcp://shell/*

A thin, honest wrapper over the system shell. All in-tool denylists, danger
heuristics, confirmation callbacks and command-chain pre-validation are DROPPED
(spec §"Safeties dropped"): the hub's dangerous-commands floor (ADR-0006) forces
approval on dangerous patterns and is the single source of truth. This server
just runs the command and reports the result.
"""

from __future__ import annotations

import subprocess
import time

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("shell")

_STDOUT_CAP = 10_000
_STDERR_CAP = 5_000


@mcp.tool()
def execute_command(command: str, working_directory: str = ".", timeout: int = 30) -> dict:
    """Run a shell command and capture its output."""
    start = time.monotonic()
    try:
        proc = subprocess.run(
            command,
            shell=True,
            cwd=working_directory,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "success": False,
            "command": command,
            "timed_out": True,
            "timeout": timeout,
            "stdout": (exc.stdout or "")[:_STDOUT_CAP] if isinstance(exc.stdout, str) else "",
            "stderr": (exc.stderr or "")[:_STDERR_CAP] if isinstance(exc.stderr, str) else "",
            "duration": round(time.monotonic() - start, 3),
        }
    except OSError as exc:
        return {"success": False, "command": command, "error": str(exc)}
    return {
        "success": proc.returncode == 0,
        "command": command,
        "exit_code": proc.returncode,
        "stdout": proc.stdout[:_STDOUT_CAP],
        "stderr": proc.stderr[:_STDERR_CAP],
        "duration": round(time.monotonic() - start, 3),
        "timed_out": False,
    }


def main(argv: list[str] | None = None) -> None:
    mcp.run()


if __name__ == "__main__":
    main()
