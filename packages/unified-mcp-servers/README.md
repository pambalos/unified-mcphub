# unified-mcp-servers

First-party **light/safe** MCP servers bundled as the [unified-mcphub](../unified-mcphub)
default tier. Five stdio servers, stdlib-only logic, one dependency (`mcp`):

| Server | `python -m …` | Tools |
|---|---|---|
| `filesystem` | `unified_mcp_servers.filesystem` | file_info, read_file, create_file, edit_file, list_files, delete_file, search_files, glob_files, find_files |
| `shell` | `unified_mcp_servers.shell` | execute_command |
| `fetch` | `unified_mcp_servers.fetch` | fetch_webpage, search_internet |
| `python` | `unified_mcp_servers.python` | check_syntax, find_function |
| `documents` | `unified_mcp_servers.documents` | read_document |

See [specs/mcphub/default-core-hub-packages.md](../../specs/mcphub/default-core-hub-packages.md).

## Security model

**The hub is the security layer** (ADR-0006 authz + `dangerous-commands.yaml`
floor + ADR-0018 approval TUI). These servers do *not* re-implement command
denylists or approval prompts. They keep one cheap defense-in-depth check —
`is_path_safe` (a slim OS-sensitive-path blocklist).

### fetch SSRF

The guard is **off by default** (matching the ecosystem norm — most fetch tools
fetch any URL, including localhost). The only thing blocked out of the box is a
short `blocked_hosts` list, seeded by the hub's `default.yaml` with the
cloud-metadata addresses. localhost / private / LAN fetches are allowed with no
flag and no prompt.

- `--block-host HOST|IP|CIDR` (repeatable) — hosts to refuse. The shipped
  `default.yaml` seeds the metadata addresses here; edit that list to add or
  remove blocks. A bare run with no `--block-host` blocks nothing.
- per-call `allow_blocked=true` — override the block list for one call. The hub
  is seeded to **prompt** (with a warning) whenever this is set, so reaching a
  blocked host stays an explicit, audited decision (ADR-0018).
- `--search-backend auto|duckduckgo|brave|none` (default `auto` = Brave if
  `BRAVE_API_KEY` is set, else DuckDuckGo).

## Flags

| Server | Flag | Default | Effect |
|---|---|---|---|
| filesystem | `--delete-mode soft\|hard` | `soft` | soft → move to trash; hard → unlink |
| filesystem | `--trash-dir PATH` | `~/.unified-ai/mcphub/trash` | where soft-deletes go |
| fetch | `--block-host HOST\|IP\|CIDR` | (none; seeded in default.yaml) | refuse these hosts |
| fetch | `--search-backend auto\|duckduckgo\|brave\|none` | `auto` | search engine |
| fetch | env `BRAVE_API_KEY` | — | key for the Brave backend |
