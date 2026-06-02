"""Slim, stdlib-only safety helpers shared across servers.

The hub is the authoritative security layer (ADR-0006 authz + the
``dangerous-commands.yaml`` floor + ADR-0018 approval). The servers keep only
``is_path_safe`` — a cheap defense-in-depth blocklist against reading or
clobbering OS-sensitive paths. It is *not* redundant with the floor (which is
command-pattern, not path-based).
"""

from __future__ import annotations

import os

# OS-sensitive paths a tool should never read or write. Prefix-matched after
# expanduser+abspath, so e.g. "~/.ssh" covers "~/.ssh/id_rsa".
RESTRICTED_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssl/private",
    "/sys",
    "/proc",
    "~/.ssh",
    "~/.aws",
    "~/.gnupg",
    "~/.config/gcloud",
    "~/.azure",
    "~/.kube",
    "~/.npmrc",
    "~/.pypirc",
]


def resolve(path: str) -> str:
    """Absolute, user-expanded path (no symlink resolution — match orchestrator)."""
    return os.path.abspath(os.path.expanduser(path))


def is_path_safe(path: str) -> bool:
    """False if ``path`` is at or under any RESTRICTED_PATHS entry."""
    abs_path = resolve(path)
    for restricted in RESTRICTED_PATHS:
        r = resolve(restricted)
        if abs_path == r or abs_path.startswith(r + os.sep):
            return False
    return True


def path_error(path: str) -> dict:
    """Standard failure payload for a path-safety rejection."""
    return {
        "success": False,
        "error": f"path is restricted by the server's safety blocklist: {path}",
        "path": path,
    }


def format_bytes(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"


def format_numbered(content: str, start_line: int = 1) -> str:
    """Render text with right-aligned line-number prefixes (display only)."""
    lines = content.split("\n")
    width = len(str(start_line + len(lines) - 1))
    return "\n".join(f"{start_line + i:>{width}}→{line}" for i, line in enumerate(lines))
