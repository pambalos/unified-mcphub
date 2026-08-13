"""Make a skipped integration test a failure where it was supposed to run.

Every test in this directory is guarded on something the machine may not have —
a Docker daemon, a Terraform binary, a registry it can reach. Locally that is
right: a developer without Docker should still be able to run the suite.

In CI it is the failure this whole session kept finding. A runner that lost
Docker, or a `setup-terraform` step that quietly failed, produces a **green job
that tested none of the things the job exists for** — the Envoy fail-closed
behaviour, the egress lock, the Terraform modules. "The integration suite
passed" and "the integration suite ran" are different sentences, and only one of
them was being checked.

So CI sets `UNIFIED_REQUIRE_INTEGRATION=1` and every skip in this directory
becomes an error.

**A hook rather than a flag threaded through each guard**, deliberately. There
are eight guards across five files today — three `skipif` markers, three inline
`pytest.skip` calls for an unreachable provider registry, and two more that will
be added by whoever writes the next integration test. A per-site opt-in is one
somebody forgets at exactly the site that matters; a hook covers the ones that
do not exist yet.
"""

from __future__ import annotations

import os

import pytest

#: Set by CI. Its absence is what keeps the suite runnable on a laptop.
REQUIRED = os.environ.get("UNIFIED_REQUIRE_INTEGRATION") == "1"


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """Turn a skip into a failure when this environment promised to be capable.

    Covers setup as well as call, because a `skipif` marker and a fixture that
    skips both resolve during setup — and the marker case is the common one.
    """
    outcome = yield
    if not REQUIRED:
        return

    report = outcome.get_result()
    if not report.skipped or report.when not in ("setup", "call"):
        return

    reason = ""
    if isinstance(report.longrepr, tuple) and len(report.longrepr) == 3:
        reason = report.longrepr[2]

    report.outcome = "failed"
    report.longrepr = (
        f"{item.nodeid} was skipped, and UNIFIED_REQUIRE_INTEGRATION=1 says this "
        f"environment was supposed to be able to run it.\n\n"
        f"    {reason}\n\n"
        "This is the check the guard exists for: a runner that lost Docker, or a "
        "Terraform step that quietly failed, otherwise produces a green job that "
        "tested none of what the job is for. Fix the environment, or stop claiming "
        "it is complete."
    )


def test_the_environment_is_what_ci_claims() -> None:
    """A named check, so an empty run is distinguishable from a passing one.

    The hook above only fires on tests that actually ran and skipped. If
    collection found nothing at all — a rename, a moved directory, a broken
    import — there would be no skips to convert and the job would be green
    having executed nothing. This fails instead.
    """
    if not REQUIRED:
        pytest.skip("local run; the guards below are allowed to skip")

    import shutil
    import subprocess

    assert shutil.which("docker"), "docker is not installed on this runner"
    assert subprocess.run(["docker", "info"], capture_output=True, timeout=60).returncode == 0, (
        "the docker daemon is not reachable"
    )
    assert shutil.which("terraform"), "terraform is not installed on this runner"
