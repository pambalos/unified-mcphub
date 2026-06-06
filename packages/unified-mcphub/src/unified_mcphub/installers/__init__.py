"""Harness installers — spec §11.

`install <harness>` / `uninstall <harness>` dispatch to a per-harness module.
M0 ships claude-code + opencode; openclaw is the first-class reference harness
(UAI-108); add more as small modules (M1+).
"""

from __future__ import annotations

from . import claude_code, openclaw, opencode

INSTALLERS = {
    "claude-code": claude_code.install,
    "opencode": opencode.install,
    "openclaw": openclaw.install,
}
UNINSTALLERS = {
    "claude-code": claude_code.uninstall,
    "opencode": opencode.uninstall,
    "openclaw": openclaw.uninstall,
}


def list_harnesses() -> list[str]:
    return sorted(INSTALLERS)


def _require(registry: dict, name: str):
    if name not in registry:
        raise SystemExit(f"unknown harness '{name}'. Supported: {', '.join(list_harnesses())}")
    return registry[name]


def dispatch_install(
    name: str,
    *,
    dry_run: bool = False,
    append_instructions: str | None = None,
    scope: str = "local",
    with_redaction_hook: bool = False,
) -> None:
    _require(INSTALLERS, name)(
        dry_run=dry_run,
        append_instructions=append_instructions,
        scope=scope,
        with_redaction_hook=with_redaction_hook,
    )


def dispatch_uninstall(name: str, *, dry_run: bool = False, scope: str = "local") -> None:
    _require(UNINSTALLERS, name)(dry_run=dry_run, scope=scope)
