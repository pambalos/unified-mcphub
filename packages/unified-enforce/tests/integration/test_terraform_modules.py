"""Every Terraform artifact we ship, validated. UAI-140 / C3.

Covers `deploy/terraform/` (deployment-mode modules) and the standalone egress
template, discovered rather than listed — a new module that nobody adds here
would otherwise ship unchecked, which is how the Envoy templates once shipped
invalid.

Honest about its reach: `validate` checks syntax, provider schema and variable
wiring. It never contacts AWS and says nothing about whether traffic is
actually blocked. Real enforcement proof needs an account and belongs with the
design-partner deployment work (G2). What this does catch is the failure mode
these artifacts have actually had — malformed, or drifted from what the docs
say they do.

The `check` blocks inside the examples are the interesting part: they encode
the invariant each deployment mode exists to hold (air-gapped reaches no
control plane; BYOC's allowlist is not the whole internet), so a future edit
that quietly breaks the posture fails at plan time rather than in review.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

REPO = Path(__file__).resolve().parents[4]
TERRAFORM_ROOT = REPO / "deploy" / "terraform"
EGRESS = Path(__file__).resolve().parents[2] / "deploy" / "egress"

needs_terraform = pytest.mark.skipif(
    shutil.which("terraform") is None, reason="terraform not installed"
)


def _terraform_dirs() -> list[Path]:
    """Every directory holding .tf files, found rather than enumerated."""
    if not TERRAFORM_ROOT.exists():  # pragma: no cover - repo layout guard
        return []
    return sorted({tf.parent for tf in TERRAFORM_ROOT.rglob("*.tf")})


def _run(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=600)


@needs_terraform
@pytest.mark.parametrize("directory", _terraform_dirs(), ids=lambda p: p.name)
def test_every_terraform_directory_validates(directory: Path):
    init = _run(["terraform", "init", "-backend=false", "-input=false"], directory)
    if init.returncode != 0:
        pytest.skip(f"terraform init could not fetch providers (offline?): {init.stderr[-300:]}")
    result = _run(["terraform", "validate", "-no-color"], directory)
    assert result.returncode == 0, f"{directory.name}:\n{result.stdout}{result.stderr}"


@needs_terraform
def test_everything_is_formatted():
    """`terraform fmt` drift is noise in every future diff, and it is free to
    prevent."""
    result = _run(["terraform", "fmt", "-recursive", "-check", "-list=true"], TERRAFORM_ROOT)
    assert result.returncode == 0, f"unformatted:\n{result.stdout}"


@needs_terraform
def test_the_standalone_egress_template_validates(tmp_path):
    """`deploy/egress/aws-security-groups.tf` is the flat, readable version of
    the same rules; it ships on its own and has to stand on its own."""
    work = tmp_path / "tf"
    work.mkdir()
    (work / "main.tf").write_text((EGRESS / "aws-security-groups.tf").read_text())
    init = _run(["terraform", "init", "-backend=false", "-input=false"], work)
    if init.returncode != 0:
        pytest.skip("terraform init could not fetch providers (offline?)")
    result = _run(["terraform", "validate", "-no-color"], work)
    assert result.returncode == 0, f"{result.stdout}{result.stderr}"


# --- the postures the modes exist to hold ---


def test_the_air_gapped_example_opens_no_path_to_us():
    """Read as text on purpose: this is a claim about what the file *says*, and
    it should fail if someone edits the example rather than only if a plan
    runs."""
    body = (TERRAFORM_ROOT / "examples" / "self-hosted" / "main.tf").read_text()
    assert "control_plane_cidrs = []" in body
    assert "upstream_cidrs      = []" in body


def test_every_example_guards_its_own_invariant():
    """Each deployment mode carries a `check` block. Without one the difference
    between modes is a comment, and comments do not fail a plan."""
    for mode in ("self-hosted", "byoc", "hybrid"):
        body = (TERRAFORM_ROOT / "examples" / mode / "main.tf").read_text()
        assert "check " in body, f"{mode} has no check block asserting its posture"


def test_no_module_grants_blanket_egress():
    """`0.0.0.0/0` on an agent path is the one edit that silently removes the
    guarantee, so it must never appear as a default anywhere in the tree."""
    for tf in TERRAFORM_ROOT.rglob("*.tf"):
        for number, line in enumerate(tf.read_text().splitlines(), start=1):
            stripped = line.strip()
            # Only *quoted* occurrences are HCL values. Unquoted mentions are
            # prose in a `description` heredoc — several of which exist
            # precisely to warn operators off it, and flagging those would
            # punish the documentation for saying the right thing.
            if stripped.startswith("#") or '"0.0.0.0/0"' not in stripped:
                continue
            assert "contains(" in stripped, (
                f"{tf.relative_to(REPO)}:{number} grants 0.0.0.0/0 — "
                "an allowlist that includes everything is not an allowlist"
            )
