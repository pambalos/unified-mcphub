"""Shared install mechanics — spec §11.

Each harness installer prefers the harness's own MCP-registration CLI, else
merges its config file (with a timestamped backup), and mints a per-caller
bearer token for the TCP transport. Kept here so each `<harness>.py` stays tiny.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

from unified_mcphub.util import utcnow

# Secrets that must never reach a terminal or transcript: per-caller bearer
# tokens are 64-hex (TokenStore.mint -> secrets.token_hex(32)); harness CLIs
# like `claude mcp add/get` echo them back in an Authorization header.
_BEARER_RE = re.compile(r"(Bearer\s+)[0-9a-fA-F]{16,}")
_HEX64_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")


def redact_secrets(text: str) -> str:
    """Mask bearer tokens / 64-hex caller tokens in text before it is shown."""
    text = _BEARER_RE.sub(r"\1[REDACTED]", text)
    return _HEX64_RE.sub("[REDACTED-TOKEN]", text)


def harness_cli_present(binary: str) -> bool:
    return shutil.which(binary) is not None


def run_cli(cmd: list[str], *, dry_run: bool, check: bool = True) -> None:
    if dry_run:
        print(f"[dry-run] would run: {redact_secrets(' '.join(cmd))}")
        return
    # Capture so a token the harness CLI echoes back never hits the terminal raw.
    proc = subprocess.run(cmd, capture_output=True, text=True)
    shown = redact_secrets((proc.stdout or "") + (proc.stderr or ""))
    if shown.strip():
        print(shown, end="" if shown.endswith("\n") else "\n")
    if check and proc.returncode != 0:
        # Never surface the raw argv — it carries the bearer token.
        raise SystemExit(
            f"`{cmd[0]} {cmd[1] if len(cmd) > 1 else ''}` failed (exit {proc.returncode}); "
            "see redacted output above"
        )


def _utc_ts() -> str:
    return utcnow().strftime("%Y%m%dT%H%M%SZ")


def _load(path: Path) -> tuple[str, dict]:
    raw = path.read_text() if path.exists() else ""
    return raw, (json.loads(raw) if raw.strip() else {})


def _write_with_backup(path: Path, previous: str, data: dict, *, dry_run: bool) -> None:
    rendered = json.dumps(data, indent=2)
    if dry_run:
        print(f"[dry-run] would write {path}:\n{rendered}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    if previous:
        path.with_name(f"{path.name}.backup-{_utc_ts()}").write_text(previous)
    path.write_text(rendered)


def merge_json(path: Path, key_path: list[str], name: str, entry: dict, *, dry_run: bool) -> None:
    previous, data = _load(path)
    node = data
    for key in key_path:
        node = node.setdefault(key, {})
    node[name] = entry  # idempotent: re-running rewrites the same entry
    _write_with_backup(path, previous, data, dry_run=dry_run)


def remove_json(path: Path, key_path: list[str], name: str, *, dry_run: bool) -> None:
    if not path.exists():
        return
    previous, data = _load(path)
    node = data
    for key in key_path:
        if not isinstance(node, dict) or key not in node:
            return
        node = node[key]
    if isinstance(node, dict):
        node.pop(name, None)
    _write_with_backup(path, previous, data, dry_run=dry_run)


def merge_hook(path: Path, *, event: str, group: dict, marker: str, dry_run: bool) -> None:
    """Idempotently add a hook group to a Claude Code settings.json.

    Any prior group whose command contains `marker` is dropped first, so
    re-running rewrites (rather than duplicates) our hook. Other hooks are left
    untouched.
    """
    previous, data = _load(path)
    groups = data.setdefault("hooks", {}).setdefault(event, [])
    groups[:] = [g for g in groups if not _group_has_marker(g, marker)]
    groups.append(group)
    _write_with_backup(path, previous, data, dry_run=dry_run)


def remove_hook(path: Path, *, event: str, marker: str, dry_run: bool) -> None:
    if not path.exists():
        return
    previous, data = _load(path)
    groups = data.get("hooks", {}).get(event)
    if not isinstance(groups, list):
        return
    groups[:] = [g for g in groups if not _group_has_marker(g, marker)]
    _write_with_backup(path, previous, data, dry_run=dry_run)


def _group_has_marker(group: dict, marker: str) -> bool:
    return any(marker in h.get("command", "") for h in group.get("hooks", []))


def append_guidance(path: Path, *, dry_run: bool) -> None:
    section = (
        "\n## MCP hub guidance\n\n"
        "Tool calls route through the local unified MCP hub, which gates them by "
        "your policy and records a full audit log. See `~/.unified-ai/mcphub/`.\n"
    )
    if dry_run:
        print(f"[dry-run] would append MCP hub guidance to {path}")
        return
    with path.open("a") as handle:
        handle.write(section)
