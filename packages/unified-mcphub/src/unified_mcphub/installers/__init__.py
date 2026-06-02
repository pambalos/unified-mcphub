"""Harness installers — spec §11.

`install <harness>` / `uninstall <harness>` dispatch to a per-harness module.
M0 ships claude-code + opencode; add more as small modules (M0.75 / M1+).
"""

from __future__ import annotations

from . import claude_code, opencode

INSTALLERS = {"claude-code": claude_code.install, "opencode": opencode.install}
UNINSTALLERS = {"claude-code": claude_code.uninstall, "opencode": opencode.uninstall}


def list_harnesses() -> list[str]:
    return sorted(INSTALLERS)


def _require(registry: dict, name: str):
    if name not in registry:
        raise SystemExit(f"unknown harness '{name}'. Supported: {', '.join(list_harnesses())}")
    return registry[name]


def dispatch_install(name: str, *, dry_run: bool = False, append_instructions: str | None = None) -> None:
    _require(INSTALLERS, name)(dry_run=dry_run, append_instructions=append_instructions)


def dispatch_uninstall(name: str, *, dry_run: bool = False) -> None:
    _require(UNINSTALLERS, name)(dry_run=dry_run)
