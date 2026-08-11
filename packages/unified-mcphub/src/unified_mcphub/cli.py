"""unified-mcphub CLI entry point — command surface per spec §13 (argparse)."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import logging
import sys
import urllib.parse

from unified_mcphub import audit_reader, installers, introspect, oauth, servers
from unified_mcphub.config import audit_dir, bootstrap, load_hub_config, load_workspace
from unified_mcphub.hub import run
from unified_mcphub.secrets import SecretsStore
from unified_mcphub.transports import PortInUseError


# --- command handlers ---------------------------------------------------------


def cmd_init(args: argparse.Namespace) -> int:
    created = bootstrap()
    for path in created:
        print(f"created {path}")
    print("ready — run `unified-mcphub start`" if created else "already initialized")
    return 0


def cmd_start(args: argparse.Namespace) -> int:
    # MCP-HUB-1: bind Unix socket + TCP, load workspace, supervise servers,
    # serve as MCP server; render approval TUI when approval.enabled.
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    try:
        asyncio.run(run(args.workspace, port=args.port, no_tcp=args.no_tcp))
    except KeyboardInterrupt:
        pass  # ctrl-C fallback when signal handlers aren't installed (e.g. Windows)
    except PortInUseError as exc:
        print(exc, file=sys.stderr)  # one line, no traceback
        return 1
    return 0


def cmd_workspace(args: argparse.Namespace) -> int:
    if args.ws_command == "list":
        active = introspect.active_workspace()
        for name in introspect.list_workspaces():
            print(f"* {name}" if name == active else f"  {name}")
    elif args.ws_command == "show":
        print(json.dumps(introspect.show_workspace(args.name), indent=2, default=str))
    elif args.ws_command == "use":
        introspect.use_workspace(args.name)
        print(f"active_workspace set to '{args.name}' (restart the hub to apply)")
    return 0


def cmd_install(args: argparse.Namespace) -> int:
    if args.list:
        for harness in installers.list_harnesses():
            print(harness)
        return 0
    if not args.harness:
        raise SystemExit(
            "specify a harness (or --list). Supported: " + ", ".join(installers.list_harnesses())
        )
    installers.dispatch_install(
        args.harness,
        dry_run=args.dry_run,
        append_instructions=args.append_instructions,
        scope=args.scope,
        with_redaction_hook=args.with_redaction_hook,
    )
    return 0


def cmd_uninstall(args: argparse.Namespace) -> int:
    installers.dispatch_uninstall(args.harness, scope=args.scope)
    return 0


def _parse_env(pairs: list[str] | None) -> dict[str, str]:
    env: dict[str, str] = {}
    for item in pairs or []:
        key, sep, value = item.partition("=")
        if not sep or not key:
            raise SystemExit(f"--env expects KEY=VALUE, got {item!r}")
        env[key] = value
    return env


def cmd_add_server(args: argparse.Namespace) -> int:
    servers.add_server(
        args.name,
        command=args.command,
        args=args.arg,
        env=_parse_env(args.env),
        url=args.url,
        npx=args.npx,
        uvx=args.uvx,
        auth_secret_ref=args.auth_secret_ref,
        auth_header=args.auth_header,
        auth_scheme=args.auth_scheme,
        oauth_issuer=args.oauth_issuer,
        oauth_authorize_url=args.oauth_authorize_url,
        oauth_token_url=args.oauth_token_url,
        oauth_client_id=args.oauth_client_id,
        oauth_scopes=args.oauth_scope,
        disabled=args.disabled,
        allow_unpinned=args.allow_unpinned,
        workspace=args.workspace,
        no_probe=args.no_probe,
        configure=args.configure_perms,
        no_preflight=args.no_preflight,
        probe_timeout=args.probe_timeout,
        assume_yes=args.yes,
        dry_run=args.dry_run,
        force=args.force,
    )
    return 0


def cmd_remove_server(args: argparse.Namespace) -> int:
    servers.remove_server(
        args.workspace or load_hub_config().active_workspace,
        args.name,
        assume_yes=args.yes,
        dry_run=args.dry_run,
    )
    return 0


def cmd_secrets(args: argparse.Namespace) -> int:
    store = SecretsStore()
    if args.sec_command == "set":
        store.set(args.name, getpass.getpass(f"value for '{args.name}' (no echo): "))
        print(f"stored secret '{args.name}'")
    elif args.sec_command == "list":
        for name in store.list():
            print(name)
    elif args.sec_command == "remove":
        store.remove(args.name)
        print(f"removed secret '{args.name}'")
    return 0


def cmd_auth(args: argparse.Namespace) -> int:
    store = SecretsStore()
    if args.auth_command == "revoke":
        store.remove(f"{args.server}-oauth-refresh")
        print(f"revoked OAuth for '{args.server}'")
        return 0

    spec = load_workspace(load_hub_config().active_workspace).servers.get(args.server)
    if spec is None or spec.oauth is None:
        raise SystemExit(f"server '{args.server}' has no `oauth:` config in the active workspace")

    async def _login() -> dict:
        # build_flow resolves a static client_id or discovers + dynamically
        # registers one (DCR) when only an `issuer` is configured.
        flow = await oauth.build_flow(
            args.server,
            store,
            authorize_url=spec.oauth.authorize_url,
            token_url=spec.oauth.token_url,
            client_id=spec.oauth.client_id,
            issuer=spec.oauth.issuer,
            registration_url=spec.oauth.registration_url,
            scopes=spec.oauth.scopes,
        )
        print(
            f"Open this URL in a browser and approve. You'll be redirected to a\n"
            f"127.0.0.1 page that won't load — copy that FULL address-bar URL (it has\n"
            f"?code=…&state=…) and paste it below:\n\n  {flow.authorization_url()}\n"
        )
        params = urllib.parse.parse_qs(urllib.parse.urlparse(input("redirect URL: ").strip()).query)
        if "error" in params:
            detail = params.get("error_description", [""])[0]
            raise SystemExit(
                f"authorization denied: {params['error'][0]}{f' — {detail}' if detail else ''}"
            )
        if "code" not in params or "state" not in params:
            raise SystemExit(
                "that URL has no ?code=…&state=… — paste the FULL URL the browser landed on "
                "AFTER you approved (not the bare callback URL). The page won't load; copy it "
                "from the address bar."
            )
        return await flow.exchange_code(params["code"][0], params["state"][0])

    tokens = asyncio.run(_login())
    print("authorized; refresh token stored" if tokens.get("refresh_token") else "authorized")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    if args.command == "list-servers":
        for server in introspect.list_servers():
            print(f"{server['name']}\t{server['kind']}")
    elif args.command == "list-tools":
        result = introspect.list_tools()
        print(f"# source: {result['source']}")
        for name in result["tools"]:
            print(name)
    elif args.command == "list-packs":
        for pattern in introspect.list_packs():
            print(pattern)
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    directory = audit_dir()
    cmd = args.audit_command
    if cmd in ("show", "pair"):
        print(json.dumps(audit_reader.pair(directory, args.request_id), indent=2, default=str))
    elif cmd == "search":
        results = audit_reader.search(
            directory,
            caller=args.caller,
            tool=args.tool,
            server=args.server,
            decision=args.decision,
            status=args.status,
            since=args.since,
            until=args.until,
            phase=args.phase,
            limit=int(args.limit) if args.limit else None,
        )
        for entry in results:
            print(json.dumps(entry, default=str))
    elif cmd == "tail":
        for entry in audit_reader.tail(directory):
            print(json.dumps(entry, default=str))
    elif cmd == "lint":
        problems = audit_reader.lint(directory)
        for problem in problems:
            print(problem)
        print(f"{len(problems)} problem(s)")
    elif cmd == "prune":
        removed = audit_reader.prune(directory, load_hub_config().audit.retention_days)
        print(f"removed {len(removed)} file(s): {', '.join(removed) or '(none)'}")
    elif cmd == "verify":
        result = audit_reader.verify(directory)
        if result.ok:
            print(f"chain OK: {result.entries} entries verified (anchor {result.anchor})")
        else:
            print(f"chain BROKEN after {result.entries} entries: {result.error}")
            return 1
    return 0


# --- parser -------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="unified-mcphub", description="Local MCP hub")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="seed default config into ~/.unified-ai/mcphub").set_defaults(
        func=cmd_init
    )

    p_start = sub.add_parser("start", help="run the hub in the foreground")
    p_start.add_argument("--workspace", help="workspace name (default: config active_workspace)")
    tcp_group = p_start.add_mutually_exclusive_group()
    tcp_group.add_argument(
        "--port",
        type=int,
        help="TCP port to bind (overrides config; precedence CLI > config.yaml > 7712)",
    )
    tcp_group.add_argument(
        "--no-tcp",
        action="store_true",
        help="serve the unix socket only — disables TCP (and TCP-harness `install`)",
    )
    p_start.set_defaults(func=cmd_start)

    p_ws = sub.add_parser("workspace", help="manage workspaces")
    ws_sub = p_ws.add_subparsers(dest="ws_command", required=True)
    ws_sub.add_parser("list", help="list workspaces").set_defaults(func=cmd_workspace)
    p_ws_show = ws_sub.add_parser("show", help="show a workspace")
    p_ws_show.add_argument("name", nargs="?")
    p_ws_show.set_defaults(func=cmd_workspace)
    p_ws_use = ws_sub.add_parser("use", help="set active workspace")
    p_ws_use.add_argument("name")
    p_ws_use.set_defaults(func=cmd_workspace)

    p_install = sub.add_parser("install", help="wire a harness to the hub")
    p_install.add_argument("harness", nargs="?", help="claude-code | opencode")
    p_install.add_argument("--list", action="store_true", help="list supported harnesses")
    p_install.add_argument("--dry-run", action="store_true")
    p_install.add_argument("--append-instructions", metavar="PATH")
    p_install.add_argument(
        "--scope",
        choices=["local", "user", "project"],
        default="local",
        help="scope for harnesses that support it (claude-code: local=this project, "
        "user=global/all projects, project=shared ./.mcp.json). default: local",
    )
    p_install.add_argument(
        "--with-redaction-hook",
        action="store_true",
        help="claude-code only: also install a user-scope PreToolUse hook that "
        "redacts bearer tokens from `claude mcp` command output (opt-in)",
    )
    p_install.set_defaults(func=cmd_install)

    p_uninstall = sub.add_parser("uninstall", help="reverse a harness install")
    p_uninstall.add_argument("harness")
    p_uninstall.add_argument(
        "--scope",
        choices=["local", "user", "project"],
        default="local",
        help="scope the entry was installed at (default: local)",
    )
    p_uninstall.set_defaults(func=cmd_uninstall)

    p_add = sub.add_parser("add-server", help="add an external MCP server to a workspace")
    p_add.add_argument("name", help="name for the server (the `mcp://NAME/...` prefix)")
    src = p_add.add_mutually_exclusive_group(required=True)
    src.add_argument(
        "--npx", metavar="PKG", help="Node stdio server: `npx -y PKG` (pin: PKG@1.2.3)"
    )
    src.add_argument(
        "--uvx", metavar="PKG", help="Python stdio server: `uvx PKG` (pin: 'PKG==1.2.3')"
    )
    src.add_argument("--command", metavar="CMD", help="raw stdio command (the blessed path)")
    src.add_argument("--url", metavar="URL", help="remote streamable-HTTP MCP server")
    p_add.add_argument(
        "--arg", action="append", default=[], help="extra arg for the command (repeatable)"
    )
    p_add.add_argument("--env", action="append", metavar="KEY=VALUE", help="env var (repeatable)")
    p_add.add_argument(
        "--auth-secret-ref", metavar="NAME", help="secrets-store name → auth header (url servers)"
    )
    p_add.add_argument(
        "--auth-header",
        default="Authorization",
        metavar="HEADER",
        help="header to carry the secret (default: Authorization)",
    )
    p_add.add_argument(
        "--auth-scheme",
        default="Bearer",
        metavar="SCHEME",
        help="scheme prefix (default: Bearer; pass '' to send the raw secret, e.g. X-API-Key servers)",
    )
    p_add.add_argument(
        "--oauth-issuer",
        metavar="URL",
        help="OAuth via Dynamic Client Registration: the auth server issuer (endpoints "
        "discovered, client auto-registered on `auth login`)",
    )
    p_add.add_argument(
        "--oauth-authorize-url", metavar="URL", help="static OAuth authorize endpoint"
    )
    p_add.add_argument("--oauth-token-url", metavar="URL", help="static OAuth token endpoint")
    p_add.add_argument("--oauth-client-id", metavar="ID", help="static OAuth client id")
    p_add.add_argument(
        "--oauth-scope", action="append", metavar="SCOPE", help="OAuth scope (repeatable)"
    )
    p_add.add_argument("--workspace", help="target workspace (default: active)")
    p_add.add_argument("--disabled", action="store_true", help="write enabled: false")
    p_add.add_argument(
        "--allow-unpinned",
        action="store_true",
        help="opt this server out of require_pinned_versions (explicit, audited)",
    )
    p_add.add_argument(
        "--no-probe", action="store_true", help="skip connecting to list tools / propose rules"
    )
    p_add.add_argument(
        "--configure-perms",
        action="store_true",
        help="step through each probed tool to set its permission (Enter = heuristic default)",
    )
    p_add.add_argument("--no-preflight", action="store_true", help="skip the command-on-PATH check")
    p_add.add_argument(
        "--probe-timeout",
        type=float,
        default=120.0,
        metavar="SECONDS",
        help="max seconds for the probe (absorbs first-run downloads; default 120)",
    )
    p_add.add_argument("--yes", action="store_true", help="non-interactive: accept proposed rules")
    p_add.add_argument(
        "--dry-run", action="store_true", help="print the resulting workspace YAML, write nothing"
    )
    p_add.add_argument(
        "--force", action="store_true", help="overwrite an existing entry of the same name"
    )
    p_add.set_defaults(func=cmd_add_server)

    p_rm = sub.add_parser(
        "remove-server", help="remove a server + its scoped rules from a workspace"
    )
    p_rm.add_argument("name")
    p_rm.add_argument("--workspace", help="target workspace (default: active)")
    p_rm.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    p_rm.add_argument(
        "--dry-run", action="store_true", help="print the resulting workspace YAML, write nothing"
    )
    p_rm.set_defaults(func=cmd_remove_server)

    p_secrets = sub.add_parser("secrets", help="manage encrypted secrets")
    sec_sub = p_secrets.add_subparsers(dest="sec_command", required=True)
    p_sec_set = sec_sub.add_parser("set", help="set a secret (prompts, no echo)")
    p_sec_set.add_argument("name")
    p_sec_set.set_defaults(func=cmd_secrets)
    sec_sub.add_parser("list", help="list secret names").set_defaults(func=cmd_secrets)
    p_sec_rm = sec_sub.add_parser("remove", help="remove a secret")
    p_sec_rm.add_argument("name")
    p_sec_rm.set_defaults(func=cmd_secrets)

    p_auth = sub.add_parser("auth", help="upstream OAuth")
    auth_sub = p_auth.add_subparsers(dest="auth_command", required=True)
    p_auth_login = auth_sub.add_parser("login", help="OAuth login for a server")
    p_auth_login.add_argument("server")
    p_auth_login.set_defaults(func=cmd_auth)
    p_auth_revoke = auth_sub.add_parser("revoke", help="revoke + delete local token")
    p_auth_revoke.add_argument("server")
    p_auth_revoke.set_defaults(func=cmd_auth)

    for name, help_text in (
        ("list-servers", "list configured servers"),
        ("list-tools", "list available tools"),
        ("list-packs", "list rule packs"),
    ):
        sub.add_parser(name, help=help_text).set_defaults(func=cmd_list)

    p_audit = sub.add_parser("audit", help="audit log")
    aud_sub = p_audit.add_subparsers(dest="audit_command", required=True)
    p_aud_show = aud_sub.add_parser("show")
    p_aud_show.add_argument("request_id")
    p_aud_show.set_defaults(func=cmd_audit)
    p_aud_pair = aud_sub.add_parser("pair")
    p_aud_pair.add_argument("request_id")
    p_aud_pair.set_defaults(func=cmd_audit)
    p_aud_search = aud_sub.add_parser("search")
    for flag in (
        "--caller",
        "--tool",
        "--server",
        "--decision",
        "--status",
        "--since",
        "--until",
        "--phase",
        "--limit",
    ):
        p_aud_search.add_argument(flag)
    p_aud_search.set_defaults(func=cmd_audit)
    aud_sub.add_parser("tail").set_defaults(func=cmd_audit)
    aud_sub.add_parser("lint").set_defaults(func=cmd_audit)
    aud_sub.add_parser("prune").set_defaults(func=cmd_audit)
    aud_sub.add_parser("verify", help="verify the audit hash chain").set_defaults(func=cmd_audit)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
