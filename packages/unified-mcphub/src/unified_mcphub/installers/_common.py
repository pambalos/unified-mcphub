"""Shared install mechanics — spec §11.

Each harness installer prefers the harness's own MCP-registration CLI, else
merges its config file (with a timestamped backup), and mints a per-caller
bearer token for the TCP transport. Kept here so each `<harness>.py` stays tiny.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from unified_mcphub.util import utcnow


def harness_cli_present(binary: str) -> bool:
    return shutil.which(binary) is not None


def run_cli(cmd: list[str], *, dry_run: bool) -> None:
    if dry_run:
        print(f"[dry-run] would run: {' '.join(cmd)}")
        return
    subprocess.run(cmd, check=True)


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
