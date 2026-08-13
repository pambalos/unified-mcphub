"""Properties this repository must have to be safe as a public one. UAI-82.

All three currently hold. That is exactly why they are tests: "CI passes from a
clean clone" and "no workflow has more permission than it needs" are true today
and are the kind of thing a single convenient commit makes false — a private
dependency added for a good reason, a `packages: write` pasted from a release
workflow, a token dropped into an `env:` block during a debugging session.

None of this is a substitute for the secret scan, which looks for credentials in
the *content*. This looks at the shape of the build and the workflows.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[4]
WORKFLOWS = ROOT / ".github" / "workflows"

#: Jobs allowed more than read access, with the reason. Anything else fails.
#: Written out so raising a permission is a visible act rather than a line in a
#: diff nobody looks at twice.
ELEVATED: dict[str, str] = {}


def workflows() -> list[tuple[Path, dict]]:
    found = [(p, yaml.safe_load(p.read_text())) for p in sorted(WORKFLOWS.glob("*.yml"))]
    assert found, f"no workflows found under {WORKFLOWS} — this guard would pass vacuously"
    return found


# --- least privilege -----------------------------------------------------------------


def test_every_workflow_defaults_to_read_only():
    """A workflow with no `permissions:` inherits the repository default, which
    on many repositories is write. For a public repository that means a
    malicious pull request from a fork runs with a token that can push."""
    offenders = []
    for path, document in workflows():
        permissions = document.get("permissions")
        if permissions is None:
            offenders.append(f"{path.name}: no top-level permissions block")
        elif permissions != {"contents": "read"} and not isinstance(permissions, str):
            # A narrower-but-different set is fine as long as it is not write;
            # checked per key below.
            for scope, level in permissions.items():
                if level == "write":
                    offenders.append(f"{path.name}: top-level {scope}: write")

    assert not offenders, (
        f"workflows without least-privilege defaults: {offenders}. Add "
        "`permissions: {contents: read}` at the top level and let individual "
        "jobs opt up with a reason."
    )


def test_no_job_grants_write_without_a_stated_reason():
    offenders = []
    for path, document in workflows():
        for name, job in (document.get("jobs") or {}).items():
            permissions = job.get("permissions") or {}
            if isinstance(permissions, str):
                continue
            for scope, level in permissions.items():
                if level == "write" and name not in ELEVATED:
                    offenders.append(f"{path.name}:{name} wants {scope}: write")

    assert not offenders, (
        f"jobs asking for write access with no reason recorded: {offenders}. Add "
        "them to ELEVATED with why, or narrow the permission."
    )


def test_no_workflow_hardcodes_a_credential():
    """`${{ secrets.X }}` is how a secret is supposed to arrive. A literal in an
    `env:` block is how one ends up in the repository."""
    suspicious = ("token", "secret", "key", "password", "credential")
    offenders = []

    for path, document in workflows():
        text = path.read_text()
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or ":" not in stripped:
                continue
            name, _, value = stripped.partition(":")
            value = value.strip().strip("\"'")
            if not value or "${{" in value:
                continue
            if any(word in name.lower() for word in suspicious) and len(value) > 16:
                offenders.append(f"{path.name}: {stripped[:80]}")

    assert not offenders, f"possible literal credentials in workflows: {offenders}"


# --- a clean clone --------------------------------------------------------------------


def test_no_dependency_comes_from_somewhere_a_stranger_cannot_reach():
    """The clean-clone property, checked at its source.

    A `git+ssh` dependency or a private index makes the build work for us and
    fail for everybody else — and it fails *at install*, which reads as a broken
    project rather than as a permission problem. Every source here must be a
    workspace member or a public index.
    """
    offenders = []
    for pyproject in sorted(ROOT.glob("packages/*/pyproject.toml")) + [ROOT / "pyproject.toml"]:
        document = tomllib.loads(pyproject.read_text())
        uv = document.get("tool", {}).get("uv", {})

        for name, source in (uv.get("sources") or {}).items():
            if isinstance(source, dict) and source.get("workspace"):
                continue
            offenders.append(f"{pyproject.parent.name}: {name} -> {source}")

        for key in ("index-url", "extra-index-url", "index"):
            if uv.get(key):
                offenders.append(f"{pyproject.parent.name}: {key} is set")

    assert not offenders, (
        f"dependencies a stranger cannot resolve: {offenders}. A clean clone must "
        "build from public indexes and workspace members alone."
    )


def test_the_lockfile_is_committed():
    """`uv sync --frozen` in CI is only meaningful against a committed lock, and
    a missing one turns every CI run into a fresh resolution — which is both
    slower and a supply-chain surface."""
    assert (ROOT / "uv.lock").exists()


@pytest.mark.parametrize("required", ["SECURITY.md", "LICENSE", "README.md"])
def test_the_files_a_public_repository_needs_exist(required):
    """LICENSE especially: an unlicensed public repository is legally
    all-rights-reserved, which is the opposite of what publishing it means."""
    assert (ROOT / required).exists(), f"{required} is missing"
