"""unified-mcp-graphify — an MCP server that builds and queries graphify
knowledge graphs for *arbitrary* repos on demand (per-call ``path``).

Why this exists: vanilla ``graphify.serve`` is read-only and bound to ONE graph
at launch, and the build step is a CLI command, not an MCP tool. This wrapper
adds ``build_graph`` over MCP and makes every tool repo-relative, so an agent can
"build the graph for this project, then query it" without leaving the harness.

See ``specs/mcphub/graphify-integration.v1.md`` (Part B).
"""

__version__ = "0.1.0"
