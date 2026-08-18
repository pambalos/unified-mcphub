"""Slim, stdlib-only safety helpers shared across servers.

The hub is the authoritative security layer (ADR-0006 authz + the
``dangerous-commands.yaml`` floor + ADR-0018 approval). The servers keep only
``is_path_safe`` — a cheap defense-in-depth blocklist against reading or
clobbering OS-sensitive paths. It is *not* redundant with the floor (which is
command-pattern, not path-based).
"""

from __future__ import annotations

import os

from unified_paths import canonical, is_under

# OS-sensitive paths a tool should never read or write. Compared by canonical
# containment, so e.g. "~/.ssh" covers "~/.ssh/id_rsa" — and also covers a
# symlink pointing into it, which a lexical prefix did not.
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
    """Absolute, user-expanded, symlink-resolved path.

    Shared with the policy engine (`unified_paths.canonical`) so that the
    component deciding whether this call is allowed and this server opening the
    file cannot disagree about which file that is. Relative paths resolve
    against this process's directory, which for a hub-supervised server is the
    hub's — the same base the hub authorised against.

    Falls back to the un-resolved absolute form only for a value the filesystem
    refuses to parse at all; `is_path_safe` treats that case as unsafe.
    """
    c = canonical(path, base=os.getcwd())
    return c if c is not None else os.path.abspath(os.path.expanduser(path))


def is_path_safe(path: str) -> bool:
    """False if ``path`` is at or under any RESTRICTED_PATHS entry.

    Canonical containment, not a string prefix. `~/.ssh/id_rsa` was refused
    while a symlink to the same file was allowed straight through, because the
    old comparison never resolved the link.
    """
    abs_path = canonical(path, base=os.getcwd())
    if abs_path is None:
        # No single location to check. Refuse rather than guess.
        return False
    for restricted in RESTRICTED_PATHS:
        r = canonical(restricted)
        if r is not None and is_under(abs_path, r):
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
