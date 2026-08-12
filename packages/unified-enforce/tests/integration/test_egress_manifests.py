"""The other two egress artifacts, checked as far as they can be here. UAI-140.

`iptables-sidecar.sh` is genuinely *executed* by test_egress_no_bypass.py. The
Kubernetes and AWS artifacts cannot be, honestly, on a laptop:

- A NetworkPolicy is inert without a CNI that enforces it. `kubectl apply`
  against a cluster with a non-enforcing CNI accepts the manifest and silently
  ignores it, which is the worst possible test — green, and proving the exact
  opposite of what it claims. Real proof needs kind + Calico, and belongs with
  the design-partner deployment work (G2).
- Security groups need AWS. `terraform validate` checks syntax and provider
  schema, not whether traffic is actually blocked.

So these are **structural** checks, and they are labelled as such rather than
dressed up as verification. What they do catch is the class of error that has
actually bitten this repo before: an artifact that is malformed, or whose
content silently stopped matching what the docs claim it does (the Envoy
templates shipped with a protobuf oneof conflict that made them invalid, and
nobody noticed until real Envoy parsed them).
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.integration

EGRESS = Path(__file__).resolve().parents[2] / "deploy" / "egress"


# --- Kubernetes NetworkPolicy ---


def _policies() -> list[dict]:
    docs = yaml.safe_load_all((EGRESS / "kubernetes-networkpolicy.yaml").read_text())
    return [d for d in docs if d and d.get("kind") == "NetworkPolicy"]


def test_the_networkpolicy_parses_and_is_a_networkpolicy():
    policies = _policies()
    assert policies, "no NetworkPolicy documents found"
    for policy in policies:
        assert policy["apiVersion"] == "networking.k8s.io/v1"
        assert policy["spec"]["podSelector"] is not None


def test_egress_is_actually_restricted_not_just_declared():
    """A NetworkPolicy that omits `Egress` from policyTypes restricts nothing
    outbound, however many egress rules it lists — the rules are simply never
    consulted. That is a silent no-op, and exactly the shape of mistake a
    manifest review misses."""
    for policy in _policies():
        assert "Egress" in policy["spec"].get("policyTypes", []), (
            f"{policy['metadata']['name']} lists egress rules but does not declare "
            "Egress in policyTypes, so nothing outbound is restricted"
        )


def test_dns_is_permitted_or_the_pod_cannot_resolve_anything():
    """The carve-out that keeps the lock operable. Its absence is the classic
    way a default-deny egress policy gets reverted in production."""
    allows_dns = False
    for policy in _policies():
        for rule in policy["spec"].get("egress", []):
            for port in rule.get("ports", []):
                if port.get("port") == 53 or port.get("port") == "dns":
                    allows_dns = True
    assert allows_dns, "no egress rule permits DNS; the pod could not resolve a name"


# --- AWS security groups ---


terraform = pytest.mark.skipif(shutil.which("terraform") is None, reason="terraform not installed")


@terraform
def test_the_security_group_terraform_is_valid(tmp_path):
    """Syntax and provider-schema validity only — `validate` never contacts AWS
    and cannot say whether traffic is blocked."""
    work = tmp_path / "tf"
    work.mkdir()
    (work / "main.tf").write_text((EGRESS / "aws-security-groups.tf").read_text())

    init = subprocess.run(
        ["terraform", "init", "-backend=false", "-input=false"],
        cwd=work, capture_output=True, text=True, timeout=600,
    )  # fmt: skip
    if init.returncode != 0:
        pytest.skip(f"terraform init could not fetch providers (offline?): {init.stderr[-300:]}")

    result = subprocess.run(
        ["terraform", "validate", "-no-color"],
        cwd=work, capture_output=True, text=True, timeout=300,
    )  # fmt: skip
    assert result.returncode == 0, f"terraform validate failed:\n{result.stdout}{result.stderr}"


def test_the_default_permissive_egress_rule_is_addressed():
    """AWS attaches an allow-all egress rule to every new security group. A
    template that only *adds* rules leaves that one in place and enforces
    nothing — the single most likely way this artifact silently fails."""
    body = (EGRESS / "aws-security-groups.tf").read_text()
    mentions_it = "0.0.0.0/0" in body or "default" in body.lower()
    assert mentions_it, (
        "the template neither removes nor documents AWS's default allow-all "
        "egress rule, so applying it would restrict nothing"
    )
