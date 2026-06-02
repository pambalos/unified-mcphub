"""The require_pinned_versions load-time lint (Hub._pinning_ok)."""

from __future__ import annotations

from unified_mcphub.config import ServerSpec, Upstream, load_config
from unified_mcphub.hub import Hub


def _hub(hub_home):
    return Hub(load_config())


def _unpinned():
    return ServerSpec(upstream=Upstream(command="npx", args=["-y", "pkg"]))


def _pinned():
    return ServerSpec(upstream=Upstream(command="npx", args=["-y", "pkg@1.2.3"]))


def test_unpinned_refused_when_policy_on(hub_home):
    hub = _hub(hub_home)
    assert hub.config.hub.require_pinned_versions is True  # default-on
    assert hub._pinning_ok("bad", _unpinned()) is False


def test_pinned_allowed(hub_home):
    hub = _hub(hub_home)
    assert hub._pinning_ok("good", _pinned()) is True


def test_allow_unpinned_per_server_bypass(hub_home):
    hub = _hub(hub_home)
    spec = ServerSpec(upstream=Upstream(command="npx", args=["-y", "pkg"]), allow_unpinned=True)
    assert hub._pinning_ok("ok", spec) is True


def test_policy_off_disables_lint(hub_home):
    hub = _hub(hub_home)
    hub.config.hub.require_pinned_versions = False
    assert hub._pinning_ok("bad", _unpinned()) is True


def test_non_fetch_command_always_ok(hub_home):
    hub = _hub(hub_home)
    spec = ServerSpec(upstream=Upstream(command="python", args=["-m", "x"]))
    assert hub._pinning_ok("py", spec) is True
