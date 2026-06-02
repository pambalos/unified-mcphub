"""`add-server` / `remove-server` — guided workspace editing (spec
`specs/mcphub/add-server-cli.v1.md`).

`add-server` writes an external server into the active (or named) workspace,
**probes** it once to propose authz rules from a name heuristic, and persists
both while **preserving the workspace file's comments** (ruamel round-trip).
`remove-server` reverses it, deleting the entry plus the rules scoped exactly to
that server.

Two safety gates run before anything is written:
- **Pinning** (`require_pinned_versions`, default on): refuse an unpinned
  fetch-and-run upstream (`npx -y pkg`, bare `uvx pkg`) unless the server opts
  out with `allow_unpinned`. A drift guard — see the README "Supply chain"
  section. The stdio analog of image-digest pinning.
- **Preflight**: the upstream command must be on PATH (hard error otherwise),
  since `supervisor._make_connection` only rewrites a bare `python`.
"""

from __future__ import annotations

import asyncio
import io
import re
import shutil
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq

from unified_mcp_client import types

from .config import (
    Rule,
    ServerSpec,
    Upstream,
    load_hub_config,
    workspace_path,
)
from .util import secure_write


def _note(message: str) -> None:
    """Progress / advisory output → stderr, so `--dry-run` stdout stays pure YAML."""
    print(message, file=sys.stderr, flush=True)


# --- pinning heuristic --------------------------------------------------------

# Launchers that fetch-and-run a package at spawn time (the ones pinning is about).
_FETCH_COMMANDS = {"npx", "pnpx", "bunx", "uvx"}
_NPM_LAUNCHERS = {"npx", "pnpx", "bunx"}
# An exact npm version: full major.minor.patch with optional prerelease/build. This
# is deliberately strict — a bare major (`1`), partial (`1.2`), wildcard (`1.2.x`),
# or range (`^1.2.3`, `>=1.0`) all still drift, so none of them count as pinned.
_NPM_EXACT_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?$")


def _basename(command: str) -> str:
    return Path(command).name


def _package_token(command: str, args: Sequence[str]) -> str | None:
    """The package spec a fetch launcher will install, or None if not found.

    Reliable for the shorthands we generate (`-y pkg`, `pkg`); best-effort for a
    hand-written `--command`. Handles `npx -p <pkg>` and `uvx --from <pkg>`.
    """
    name = _basename(command)
    value_flags = {"-p", "--package"} if name in _NPM_LAUNCHERS else {"--from", "--with"}
    it = iter(args)
    for arg in it:
        if arg in value_flags:
            return next(it, None)
        if arg.startswith("-"):
            continue  # a bare flag (e.g. -y); skip
        return arg  # first positional = the package
    return None


def _npm_pinned(token: str) -> bool:
    body = token[1:] if token.startswith("@") else token  # strip scoped leading @
    _, sep, version = body.partition("@")
    return bool(sep) and bool(_NPM_EXACT_RE.match(version))


def _uv_pinned(token: str) -> bool:
    # uv/pip: an exact pin is `==`. Everything else (ranges, a bare name, or a git
    # URL whose `@` is userinfo or a mutable branch) is treated as unpinned — fail
    # closed. A deliberate git/URL ref is opted in with `--allow-unpinned`.
    return "==" in token


def is_pinned(spec: ServerSpec) -> bool:
    """True if the upstream is not an unpinned fetch-and-run package.

    url/image upstreams and non-fetch commands (python, an absolute binary) are
    out of scope and return True.
    """
    up = spec.upstream
    if not up.command or _basename(up.command) not in _FETCH_COMMANDS:
        return True
    token = _package_token(up.command, up.args)
    if token is None:
        return False  # a fetch launcher with no identifiable package
    if _basename(up.command) in _NPM_LAUNCHERS:
        return _npm_pinned(token)
    return _uv_pinned(token)


# --- preflight ----------------------------------------------------------------


def preflight(spec: ServerSpec) -> None:
    """Hard-error if the upstream command isn't runnable, before we write config."""
    up = spec.upstream
    if not up.command or up.command in ("python", "python3"):
        return  # url/image, or the hub interpreter (always present)
    if shutil.which(up.command) is None:
        raise SystemExit(
            f"`{up.command}` is not on PATH — install it (e.g. Node for npx, uv for "
            f"uvx), or pass --command with an absolute path. Use --no-preflight to skip."
        )


# --- tool classification ------------------------------------------------------


def _verb_matcher(verbs: tuple[str, ...]) -> "Callable[[str], bool]":
    """Match a verb at a word boundary, leading OR trailing:
    - leading: `read_graph`, camelCase `searchNodes`, bare `find` — verb at start,
      followed by `_`, an uppercase/digit, or end.
    - trailing (snake): `hub_repo_search`, `hf_doc_fetch` — verb at the end,
      preceded by `_` (many remote servers name tools `<noun>_<verb>`).
    `findings_purge` matches nothing (no boundary), staying out of the tier. The
    verb is case-insensitive; the boundary is not."""
    alt = "|".join(verbs)
    lead = re.compile(r"^(?i:" + alt + r")(?=_|[A-Z0-9]|$)")
    trail = re.compile(r"_(?i:" + alt + r")$")

    def matches(name: str) -> bool:
        return bool(lead.match(name) or trail.search(name))

    return matches


_is_read = _verb_matcher(("read", "list", "get", "search", "find", "query", "fetch"))
_is_destructive = _verb_matcher(("delete", "remove", "drop", "destroy"))
_is_mutate = _verb_matcher(
    (
        "create",
        "add",
        "update",
        "edit",
        "write",
        "set",
        "execute",
        "run",
        "modify",
        "put",
        "patch",
        "insert",
        "upsert",
        "send",
        "move",
        "rename",
        "append",
        "generate",
    )
)


def classify(tool_name: str) -> str:
    """Map a tool name to a default effect: allow | prompt | deny (three tiers).

    Destructive ops fail closed (`deny`); reads open (`allow`); other mutations
    and anything unrecognized go to `prompt` (the safe middle). A verb is matched
    at either end of the name (`read_x`, `x_search`), with destructive winning.
    """
    if _is_destructive(tool_name):
        return "deny"
    if _is_read(tool_name):
        return "allow"
    return "prompt"  # known mutations + unrecognized both land here


def is_recognized(tool_name: str) -> bool:
    """Whether `classify` matched a known verb (vs. defaulting to prompt). Shares
    the same matchers as `classify`, so the two can't drift."""
    return _is_destructive(tool_name) or _is_read(tool_name) or _is_mutate(tool_name)


# --- probe (warm + list) ------------------------------------------------------


def _probe_connection(spec: ServerSpec):
    # Build the probe connection exactly as the hub will run it (shared builder),
    # resolving `auth_secret_ref` so an authenticated remote server can be probed.
    from .secrets import SecretsStore
    from .supervisor import build_connection

    return build_connection(spec, secret_resolver=SecretsStore().get)


def probe(spec: ServerSpec, *, timeout: float = 120.0) -> list[types.Tool]:
    """Connect once and list tools, returning [] on any failure.

    The single connect absorbs a cold `npx`/`uvx` download (spawn + initialize +
    list happen on the one warm process), bounded by a generous `timeout` that is
    **decoupled from the supervisor's 30s wait_ready** — so a first-run download
    never races a tight limit.
    """

    async def _run() -> list[types.Tool]:
        conn = _probe_connection(spec)
        async with conn:
            return await conn.list_tools()

    _note(f"[add-server] probing (first run may download the package; up to {int(timeout)}s)…")
    try:
        return asyncio.run(asyncio.wait_for(_run(), timeout))
    except Exception as exc:  # noqa: BLE001 - probe is best-effort; fall back to scaffold
        _note(f"[add-server] probe failed ({exc}); writing the server with no rules.")
        return []


# --- rule proposal ------------------------------------------------------------


def _rule_for(server: str, tool_name: str, effect: str) -> Rule:
    return Rule(tool=f"mcp://{server}/{tool_name}", effect=effect)


def propose_rules(server: str, tools: Sequence[types.Tool]) -> list[Rule]:
    """One server-scoped rule per tool, effect from `classify` (self-documenting)."""
    return [_rule_for(server, t.name, classify(t.name)) for t in tools]


_PERM_KEYS = {"a": "allow", "p": "prompt", "d": "deny"}


def configure_perms(server: str, tools: Sequence[types.Tool]) -> list[Rule]:
    """Interactive per-tool wizard: Enter keeps the heuristic default."""
    _note("\nconfigure permissions per tool — [a]llow / [p]rompt / [d]eny, Enter = default:")
    rules: list[Rule] = []
    for tool in tools:
        default = classify(tool.name)
        print(f"  {tool.name}  ({default}): ", end="", file=sys.stderr, flush=True)
        line = sys.stdin.readline()
        key = line.strip()[:1].lower() if line else ""
        rules.append(_rule_for(server, tool.name, _PERM_KEYS.get(key, default)))
    return rules


# --- rule scope helpers (shared with remove) ----------------------------------


def server_segment(tool_pattern: str) -> str | None:
    """The server name in an `mcp://NAME/tool` pattern, or None."""
    if not isinstance(tool_pattern, str) or not tool_pattern.startswith("mcp://"):
        return None
    seg = tool_pattern[len("mcp://") :].partition("/")[0]
    return seg or None


def is_server_scoped(tool_pattern: str, server: str) -> bool:
    """True only for rules bound exactly to this server (not shared `mcp://*/...`)."""
    return server_segment(tool_pattern) == server


# --- ruamel round-trip writes -------------------------------------------------


def _yaml() -> YAML:
    y = YAML()
    y.preserve_quotes = True
    y.width = 4096  # don't fold long values (e.g. an absolute command path) onto new lines
    y.indent(mapping=2, sequence=4, offset=2)  # match the seeded workspace style
    return y


def _load_doc(yaml_rt: YAML, path: Path) -> CommentedMap:
    if not path.exists():
        return CommentedMap()
    return yaml_rt.load(path.read_text()) or CommentedMap()


def _dump(yaml_rt: YAML, data: CommentedMap) -> str:
    buf = io.StringIO()
    yaml_rt.dump(data, buf)
    return buf.getvalue()


def _spec_node(spec: ServerSpec) -> CommentedMap:
    up = CommentedMap()
    if spec.upstream.command:
        up["command"] = spec.upstream.command
        args = CommentedSeq(spec.upstream.args)
        args.fa.set_flow_style()  # render `args: ["-y", "pkg@1.2.3"]` inline like the seed
        up["args"] = args
        if spec.upstream.env:
            up["env"] = CommentedMap(spec.upstream.env)
    elif spec.upstream.url:
        up["url"] = spec.upstream.url
    node = CommentedMap()
    node["enabled"] = spec.enabled
    node["upstream"] = up
    if spec.auth_secret_ref:
        node["auth_secret_ref"] = spec.auth_secret_ref
    if spec.auth_header != "Authorization":  # only persist non-default header/scheme
        node["auth_header"] = spec.auth_header
    if spec.auth_scheme != "Bearer":
        node["auth_scheme"] = spec.auth_scheme
    if spec.allow_unpinned:
        node["allow_unpinned"] = True
    return node


def _rule_node(rule: Rule) -> CommentedMap:
    node = CommentedMap()
    node["tool"] = rule.tool
    node["effect"] = rule.effect
    return node


def _drop_scoped_rules(rules: CommentedSeq, server: str) -> int:
    """Remove rules bound exactly to `server`, in place. Returns the count."""
    keep = [r for r in rules if not is_server_scoped(r.get("tool", ""), server)]
    removed = len(rules) - len(keep)
    rules[:] = keep
    return removed


def write_workspace(
    name: str,
    server: str,
    spec: ServerSpec,
    rules: Sequence[Rule],
    *,
    dry_run: bool,
    force: bool,
) -> str:
    """Insert the server + its rules into the workspace, preserving comments.

    Returns the rendered YAML (also printed on `--dry-run` instead of written).
    """
    path = workspace_path(name)
    yaml_rt = _yaml()
    data = _load_doc(yaml_rt, path)

    servers = data.get("servers")
    if servers is None:
        servers = CommentedMap()
        data["servers"] = servers
    if server in servers and not force:
        raise SystemExit(
            f"server '{server}' already exists in workspace '{name}'. "
            f"Re-run with --force to overwrite it."
        )
    servers[server] = _spec_node(spec)

    if rules:
        authz = data.get("authz")
        if authz is None:
            authz = CommentedMap()
            data["authz"] = authz
        rule_list = authz.get("rules")
        if rule_list is None:
            rule_list = CommentedSeq()
            authz["rules"] = rule_list
        _drop_scoped_rules(rule_list, server)  # idempotent re-add
        for rule in rules:
            rule_list.append(_rule_node(rule))

    rendered = _dump(yaml_rt, data)
    if dry_run:
        print(rendered, end="" if rendered.endswith("\n") else "\n")
    else:
        secure_write(path, rendered.encode())
    return rendered


def remove_server(
    name: str,
    server: str,
    *,
    assume_yes: bool,
    dry_run: bool,
) -> None:
    """Delete the server entry + all rules scoped exactly to it (after a prompt)."""
    path = workspace_path(name)
    yaml_rt = _yaml()
    data = _load_doc(yaml_rt, path)
    servers = data.get("servers") or {}
    if server not in servers:
        raise SystemExit(f"server '{server}' not found in workspace '{name}'")

    rule_list = (data.get("authz") or {}).get("rules") or CommentedSeq()
    scoped = sum(1 for r in rule_list if is_server_scoped(r.get("tool", ""), server))
    shared = [
        r.get("tool")
        for r in rule_list
        if server_segment(r.get("tool", "")) == "*"  # belongs to every server; left in place
    ]

    if not assume_yes and not dry_run and sys.stdin.isatty():
        answer = input(f"remove server '{server}' and its {scoped} scoped rule(s)? [y/N]: ")
        if answer.strip().lower() not in ("y", "yes"):
            print("aborted")
            return

    del servers[server]
    if rule_list:
        _drop_scoped_rules(rule_list, server)

    rendered = _dump(yaml_rt, data)
    if dry_run:
        print(rendered, end="" if rendered.endswith("\n") else "\n")
        return
    secure_write(path, rendered.encode())
    print(f"removed server '{server}' and {scoped} scoped rule(s) from workspace '{name}'")
    if shared:
        print(f"  note: left {len(shared)} shared wildcard rule(s) untouched: {', '.join(shared)}")


# --- spec construction --------------------------------------------------------


def build_spec(
    *,
    command: str | None = None,
    args: Sequence[str] | None = None,
    env: Mapping[str, str] | None = None,
    url: str | None = None,
    npx: str | None = None,
    uvx: str | None = None,
    auth_secret_ref: str | None = None,
    auth_header: str = "Authorization",
    auth_scheme: str | None = "Bearer",
    disabled: bool = False,
    allow_unpinned: bool = False,
) -> ServerSpec:
    """Turn CLI inputs into a validated ServerSpec. Exactly one of
    npx/uvx/command/url must be given."""
    extra = list(args or [])
    chosen = [k for k, v in (("npx", npx), ("uvx", uvx), ("command", command), ("url", url)) if v]
    if len(chosen) != 1:
        raise SystemExit("specify exactly one of --npx / --uvx / --command / --url")

    if npx:
        upstream = Upstream(command="npx", args=["-y", npx, *extra], env=dict(env or {}))
    elif uvx:
        upstream = Upstream(command="uvx", args=[uvx, *extra], env=dict(env or {}))
    elif command:
        upstream = Upstream(command=command, args=extra, env=dict(env or {}))
    else:
        upstream = Upstream(url=url)

    return ServerSpec(
        upstream=upstream,
        auth_secret_ref=auth_secret_ref,
        auth_header=auth_header,
        auth_scheme=auth_scheme or None,  # empty string → raw secret (no scheme)
        enabled=not disabled,
        allow_unpinned=allow_unpinned,
    )


def _print_proposed(server: str, rules: Sequence[Rule], tools: Sequence[types.Tool]) -> None:
    by_effect: dict[str, list[str]] = {"allow": [], "prompt": [], "deny": []}
    for rule in rules:
        by_effect[rule.effect].append(rule.tool.rsplit("/", 1)[-1])
    _note(f"\nproposed rules for '{server}' ({len(rules)} tool(s)):")
    for effect in ("allow", "prompt", "deny"):
        if by_effect[effect]:
            _note(f"  {effect:>6}: {', '.join(by_effect[effect])}")
    unknown = [t.name for t in tools if not is_recognized(t.name)]
    if unknown:
        _note(f"  note: not matching a known verb (defaulted to prompt): {', '.join(unknown)}")


# --- orchestration (called by cli.py) -----------------------------------------


def add_server(
    server: str,
    *,
    command: str | None = None,
    args: Sequence[str] | None = None,
    env: Mapping[str, str] | None = None,
    url: str | None = None,
    npx: str | None = None,
    uvx: str | None = None,
    auth_secret_ref: str | None = None,
    auth_header: str = "Authorization",
    auth_scheme: str | None = "Bearer",
    disabled: bool = False,
    allow_unpinned: bool = False,
    workspace: str | None = None,
    no_probe: bool = False,
    configure: bool = False,
    no_preflight: bool = False,
    probe_timeout: float = 120.0,
    assume_yes: bool = False,
    dry_run: bool = False,
    force: bool = False,
) -> None:
    hub = load_hub_config()
    name = workspace or hub.active_workspace
    spec = build_spec(
        command=command,
        args=args,
        env=env,
        url=url,
        npx=npx,
        uvx=uvx,
        auth_secret_ref=auth_secret_ref,
        auth_header=auth_header,
        auth_scheme=auth_scheme,
        disabled=disabled,
        allow_unpinned=allow_unpinned,
    )

    # Gate 1 — pinning (drift guard). Skipped when the policy is off or the server
    # explicitly opts out.
    if hub.require_pinned_versions and not allow_unpinned and not is_pinned(spec):
        token = _package_token(spec.upstream.command or "", spec.upstream.args)
        raise SystemExit(
            f"'{token}' is unpinned — require_pinned_versions is on. Pin a version "
            f"(npm: pkg@1.2.3, uv: 'pkg==1.2.3'), or pass --allow-unpinned. Better still, "
            f"pre-install it and point --command at the binary (no fetch-and-run at all)."
        )
    if not is_pinned(spec) and (allow_unpinned or not hub.require_pinned_versions):
        _note(
            "[add-server] note: unpinned fetch-and-run upstream — it downloads and executes "
            "remote code at startup. Pin a version or pre-install to harden."
        )

    # Gate 2 — preflight (command must be runnable).
    if not no_preflight:
        preflight(spec)

    # Probe → propose/configure rules (or scaffold with none).
    rules: list[Rule] = []
    if no_probe:
        _note("[add-server] --no-probe: writing the server with no rules.")
    else:
        tools = probe(spec, timeout=probe_timeout)
        if tools and configure and sys.stdin.isatty() and not assume_yes:
            rules = configure_perms(server, tools)
        elif tools:
            rules = propose_rules(server, tools)
            _print_proposed(server, rules, tools)
            if not assume_yes and sys.stdin.isatty():
                answer = input("\nwrite the server with these rules? [Y/n]: ")
                if answer.strip().lower() in ("n", "no"):
                    _note("aborted")
                    return

    write_workspace(name, server, spec, rules, dry_run=dry_run, force=force)
    if not dry_run:
        print(
            f"added server '{server}' to workspace '{name}' with {len(rules)} rule(s). "
            f"A running hub applies it on the next file-watch tick."
        )
    if not rules and not no_probe:
        _note(
            "  warning: no rules were written — only tools matched by existing wildcard "
            "rules will be reachable; everything else is default-denied."
        )
