"""The hub decides and forwards the same path.

The engine used to canonicalise privately for the decision and then hand the
server the agent's original text. Two components, two resolutions, one window
in between — which is where a repointed symlink walks a write past a check that
looked at a different file. These cover the hub end of closing that.
"""

from __future__ import annotations

import os

from unified_mcphub.config import (
    Config,
    DangerousCommands,
    HubConfig,
    ServerSpec,
    Upstream,
    Workspace,
)
from unified_mcphub.hub import Hub


def _hub(path_args=("path", "directory"), cwd=None):
    ws = Workspace(
        name="w",
        servers={
            "filesystem": ServerSpec(
                upstream=Upstream(command="python", args=[], cwd=cwd),
                path_args=list(path_args),
            ),
            # Declares nothing: `path` here is not a filesystem path.
            "api": ServerSpec(upstream=Upstream(url="https://example.test")),
        },
    )
    return Hub(
        Config(
            hub=HubConfig(),
            workspace_name="w",
            workspace=ws,
            dangerous=DangerousCommands(),
        )
    )


def test_declared_path_args_are_canonicalised():
    hub = _hub()
    out = hub._canonical_path_args("filesystem", {"path": "/srv/app/../data/f.txt"})
    assert out["path"] == "/srv/data/f.txt"


def test_a_relative_path_resolves_against_the_declared_cwd():
    hub = _hub(cwd="/srv/app")
    out = hub._canonical_path_args("filesystem", {"path": "notes.txt"})
    assert out["path"] == "/srv/app/notes.txt"


def test_without_a_declared_cwd_the_base_is_the_hub_process_directory():
    """What a stdio child inherits when no cwd is set — so the base is the one
    the process opening the file will actually use."""
    hub = _hub()
    out = hub._canonical_path_args("filesystem", {"path": "notes.txt"})
    assert out["path"] == os.path.join(os.getcwd(), "notes.txt")


def test_undeclared_arguments_are_left_alone():
    """`old_string` is content, not a location."""
    hub = _hub()
    out = hub._canonical_path_args("filesystem", {"path": "/a/b", "old_string": "../x"})
    assert out["old_string"] == "../x"


def test_a_server_that_declares_nothing_is_untouched():
    """On another server `path` may be a URL path or an object key; rewriting
    it would corrupt the call."""
    hub = _hub()
    args = {"path": "v1/users"}
    assert hub._canonical_path_args("api", args) == args


def test_an_unresolvable_value_is_passed_through_unchanged():
    """The engine sees it as indeterminate and fails closed; the hub does not
    invent a value to make it look resolvable."""
    hub = _hub()
    out = hub._canonical_path_args("filesystem", {"path": "\0"})
    assert out["path"] == "\0"


def test_an_unknown_server_is_untouched():
    hub = _hub()
    args = {"path": "x"}
    assert hub._canonical_path_args("nope", args) == args


def test_the_declared_cwd_reaches_the_subprocess():
    """Declared rather than inherited: the base the policy resolves against has
    to be the one the server actually runs in."""
    from unified_mcphub.supervisor import build_connection

    spec = ServerSpec(upstream=Upstream(command="python", args=["-c", "1"], cwd="/srv/app"))
    conn = build_connection(spec, name="filesystem")
    assert conn._params.cwd == "/srv/app"


def test_no_declared_cwd_still_inherits_the_hub_directory():
    """The prior behaviour, now a stated default rather than an accident."""
    from unified_mcphub.supervisor import build_connection

    spec = ServerSpec(upstream=Upstream(command="python", args=["-c", "1"]))
    assert build_connection(spec, name="filesystem")._params.cwd is None
