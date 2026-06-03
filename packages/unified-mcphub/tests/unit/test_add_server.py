"""Unit tests for `add-server` / `remove-server` (servers.py)."""

from __future__ import annotations

import io

import pytest
from mcp import types

from unified_mcphub import servers
from unified_mcphub.config import ServerSpec, Upstream, load_workspace, workspace_path


def _spec(command=None, args=None, url=None):
    if url:
        return ServerSpec(upstream=Upstream(url=url))
    return ServerSpec(upstream=Upstream(command=command, args=args or []))


# --- classify (three tiers) ---------------------------------------------------


@pytest.mark.parametrize(
    "name,effect",
    [
        ("read_graph", "allow"),
        ("list_files", "allow"),
        ("get_node", "allow"),
        ("search_nodes", "allow"),
        ("query_graph", "allow"),
        ("delete_entities", "deny"),
        ("remove_observations", "deny"),
        ("drop_index", "deny"),
        ("destroy_world", "deny"),
        ("create_entities", "prompt"),
        ("add_observations", "prompt"),
        ("execute_command", "prompt"),
        ("shortest_path", "prompt"),  # unrecognized -> safe default
        ("searchNodes", "allow"),  # camelCase boundary
        ("getNode", "allow"),
        ("removeAll", "deny"),  # destructive camelCase
        ("find", "allow"),  # exact verb
        ("findings_purge", "prompt"),  # 'find' substring is NOT a read boundary
        ("queryset_wipe", "prompt"),  # 'query' not at a boundary -> not auto-allowed
        ("hub_repo_search", "allow"),  # trailing read verb (HF-style naming)
        ("hf_doc_fetch", "allow"),  # trailing read verb
        ("query-docs", "allow"),  # hyphenated leading read verb (Context7-style)
        ("get-library-docs", "allow"),  # hyphenated leading read verb
        ("repo-delete", "deny"),  # hyphenated trailing destructive verb
        ("repo_delete", "deny"),  # trailing destructive verb wins
        ("create_repo", "prompt"),  # leading mutate
        ("hf_whoami", "prompt"),  # no verb at either boundary
    ],
)
def test_classify(name, effect):
    assert servers.classify(name) == effect


def test_is_recognized():
    assert servers.is_recognized("read_graph")
    assert servers.is_recognized("delete_x")
    assert servers.is_recognized("searchNodes")
    assert not servers.is_recognized("shortest_path")
    assert not servers.is_recognized("findings_purge")  # boundary keeps it unrecognized


# --- is_pinned ----------------------------------------------------------------


@pytest.mark.parametrize(
    "command,args,pinned",
    [
        ("npx", ["-y", "@scope/pkg@1.2.3"], True),
        ("npx", ["-y", "pkg@1.2.3"], True),
        ("npx", ["-y", "pkg@1.2.3-beta.1"], True),  # prerelease is still exact
        ("npx", ["-y", "pkg"], False),
        ("npx", ["-y", "pkg@latest"], False),
        ("npx", ["-y", "pkg@^1.2.3"], False),  # caret range
        ("npx", ["-y", "pkg@1.2.x"], False),  # wildcard range
        ("npx", ["-y", "pkg@1"], False),  # bare major drifts
        ("npx", ["-y", "pkg@1.2"], False),  # partial drifts
        ("npx", ["-p", "pkg@1.0.0", "tool"], True),  # -p value form
        ("uvx", ["mcp-server-time"], False),
        ("uvx", ["mcp-server-time==1.0.0"], True),
        ("uvx", ["--from", "pkg==1.2.3", "tool"], True),
        ("uvx", ["git+ssh://git@github.com/o/r"], False),  # userinfo '@' is not a pin
        ("python", ["-m", "x"], True),  # not a fetch launcher -> out of scope
    ],
)
def test_is_pinned(command, args, pinned):
    assert servers.is_pinned(_spec(command, args)) is pinned


def test_is_pinned_url_and_image_out_of_scope():
    assert servers.is_pinned(_spec(url="https://x")) is True


# --- build_spec ---------------------------------------------------------------


def test_build_spec_npx_shorthand():
    spec = servers.build_spec(npx="pkg@1.0.0", args=["serve"])
    assert spec.upstream.command == "npx"
    assert spec.upstream.args == ["-y", "pkg@1.0.0", "serve"]


def test_build_spec_uvx_shorthand_with_env():
    spec = servers.build_spec(uvx="tool==1.0", env={"K": "V"}, disabled=True)
    assert spec.upstream.command == "uvx"
    assert spec.upstream.args == ["tool==1.0"]
    assert spec.upstream.env == {"K": "V"}
    assert spec.enabled is False


def test_build_spec_requires_exactly_one_source():
    with pytest.raises(SystemExit):
        servers.build_spec()
    with pytest.raises(SystemExit):
        servers.build_spec(npx="a", uvx="b")


# --- preflight ----------------------------------------------------------------


def test_preflight_missing_command_errors():
    with pytest.raises(SystemExit, match="not on PATH"):
        servers.preflight(_spec("definitely-not-a-real-binary-xyz", []))


def test_preflight_python_and_url_ok():
    servers.preflight(_spec("python", ["-m", "x"]))  # hub interpreter, always present
    servers.preflight(_spec(url="https://x"))  # no command to resolve


# --- shared connection builder resolves auth for the probe --------------------


class _Store:
    def __init__(self, data):
        self.data = data

    def get(self, name):
        return self.data.get(name)

    def set(self, name, value):
        self.data[name] = value


async def test_probe_auth_resolves_bearer_secret():
    from unified_mcphub.supervisor import build_connection, resolve_auth_headers

    spec = ServerSpec(upstream=Upstream(url="https://mcp.example.com"), auth_secret_ref="tok")
    headers = await resolve_auth_headers(spec, _Store({"tok": "S3KRET"}), name="ex")
    # The probe now authenticates an HTTP upstream instead of connecting bare.
    assert headers == {"Authorization": "Bearer S3KRET"}
    assert build_connection(spec, auth_headers=headers)._resolve_headers() == headers


async def test_probe_auth_no_secret_sends_no_header():
    from unified_mcphub.supervisor import resolve_auth_headers

    spec = ServerSpec(upstream=Upstream(url="https://mcp.example.com"))  # no auth_secret_ref
    assert await resolve_auth_headers(spec, _Store({}), name="ex") == {}


async def test_probe_auth_custom_header_raw_value():
    """An API-key server with a custom header + no scheme sends the raw secret."""
    from unified_mcphub.supervisor import resolve_auth_headers

    spec = ServerSpec(
        upstream=Upstream(url="https://mcp.context7.com/mcp"),
        auth_secret_ref="c7",
        auth_header="CONTEXT7_API_KEY",
        auth_scheme=None,
    )
    headers = await resolve_auth_headers(spec, _Store({"c7": "KEY123"}), name="context7")
    assert headers == {"CONTEXT7_API_KEY": "KEY123"}


def test_build_spec_custom_auth_persists_non_default():
    """build_spec carries a custom header/scheme; defaults are dropped from the node."""
    spec = servers.build_spec(
        url="https://x", auth_secret_ref="c7", auth_header="X-API-Key", auth_scheme=""
    )
    assert spec.auth_header == "X-API-Key"
    assert spec.auth_scheme is None  # empty string normalized to None (raw value)


# --- configure_perms wizard ---------------------------------------------------


def test_configure_perms_override_and_default(monkeypatch):
    tools = [
        types.Tool(name="read_graph", inputSchema={"type": "object"}),
        types.Tool(name="create_entities", inputSchema={"type": "object"}),
    ]
    # First tool: type 'd' (override allow->deny); second: Enter (keep default prompt).
    monkeypatch.setattr("sys.stdin", io.StringIO("d\n\n"))
    rules = servers.configure_perms("memory", tools)
    assert rules[0].tool == "mcp://memory/read_graph"
    assert rules[0].effect == "deny"  # overridden
    assert rules[1].effect == "prompt"  # Enter kept default


# --- write_workspace (ruamel round-trip) --------------------------------------


def test_write_workspace_preserves_comments_and_adds_rules(hub_home):
    path = workspace_path("default")
    # Inject a comment to prove the round-trip preserves it (safe_dump would drop it).
    path.write_text("# SENTINEL COMMENT\n" + path.read_text())

    spec = servers.build_spec(npx="pkg@1.0.0")
    rules = [
        servers._rule_for("newsrv", "read_x", "allow"),
        servers._rule_for("newsrv", "delete_x", "deny"),
    ]
    servers.write_workspace("default", "newsrv", spec, rules, dry_run=False, force=False)

    text = path.read_text()
    assert "# SENTINEL COMMENT" in text  # comment survived
    ws = load_workspace("default")
    assert "newsrv" in ws.servers
    scoped = [r for r in ws.authz.rules if servers.is_server_scoped(r.tool, "newsrv")]
    assert {r.effect for r in scoped} == {"allow", "deny"}


def test_write_workspace_collision_requires_force(hub_home):
    spec = servers.build_spec(npx="pkg@1.0.0")
    servers.write_workspace("default", "dup", spec, [], dry_run=False, force=False)
    with pytest.raises(SystemExit, match="already exists"):
        servers.write_workspace("default", "dup", spec, [], dry_run=False, force=False)
    # --force overwrites cleanly.
    servers.write_workspace("default", "dup", spec, [], dry_run=False, force=True)


def test_write_workspace_dry_run_writes_nothing(hub_home, capsys):
    path = workspace_path("default")
    before = path.read_text()
    spec = servers.build_spec(npx="pkg@1.0.0")
    servers.write_workspace("default", "ghost", spec, [], dry_run=True, force=False)
    assert path.read_text() == before  # untouched
    assert "ghost" in capsys.readouterr().out  # rendered to stdout


def test_write_workspace_reads_idempotent(hub_home):
    """Re-adding a server replaces its scoped rules instead of duplicating them."""
    spec = servers.build_spec(npx="pkg@1.0.0")
    servers.write_workspace(
        "default",
        "srv",
        spec,
        [servers._rule_for("srv", "read_a", "allow")],
        dry_run=False,
        force=False,
    )
    servers.write_workspace(
        "default",
        "srv",
        spec,
        [servers._rule_for("srv", "read_a", "allow")],
        dry_run=False,
        force=True,
    )
    ws = load_workspace("default")
    scoped = [r for r in ws.authz.rules if servers.is_server_scoped(r.tool, "srv")]
    assert len(scoped) == 1


# --- remove_server ------------------------------------------------------------


def test_remove_server_drops_entry_and_scoped_rules_keeps_wildcards(hub_home):
    spec = servers.build_spec(npx="pkg@1.0.0")
    rules = [
        servers._rule_for("memory", "read_graph", "allow"),
        servers._rule_for("memory", "delete_entities", "deny"),
    ]
    servers.write_workspace("default", "memory", spec, rules, dry_run=False, force=False)
    # The seeded default workspace has a shared wildcard rule mcp://*/list_*.
    servers.remove_server("default", "memory", assume_yes=True, dry_run=False)

    ws = load_workspace("default")
    assert "memory" not in ws.servers
    assert not any(servers.is_server_scoped(r.tool, "memory") for r in ws.authz.rules)
    assert any(servers.server_segment(r.tool) == "*" for r in ws.authz.rules)  # wildcard kept


def test_remove_server_missing_errors(hub_home):
    with pytest.raises(SystemExit, match="not found"):
        servers.remove_server("default", "nope", assume_yes=True, dry_run=False)
