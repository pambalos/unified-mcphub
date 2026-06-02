"""fetch MCP server — mcp://fetch/*

Web fetch + internet search over the stdlib (urllib + html.parser).

SSRF posture (per spec review): the guard is OFF by default — localhost,
private and LAN fetches just work, matching the ecosystem norm. The only thing
refused is a configurable ``blocked_hosts`` list, seeded by the hub's
default.yaml with the cloud-metadata addresses. A blocked host can be reached
per-call with ``allow_blocked=true``, which the hub is seeded to prompt on
(ADR-0018) so the privilege is explicit and audited.

Flags:
  --block-host HOST|IP|CIDR    (repeatable) hosts to refuse; default.yaml seeds metadata
  --search-backend auto|duckduckgo|brave|none   default auto (Brave if BRAVE_API_KEY else DDG)
"""

from __future__ import annotations

import argparse
import gzip
import html
import ipaddress
import json
import os
import re
import socket
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from html.parser import HTMLParser

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fetch")

_UA = "unified-mcphub-fetch/0.1 (+https://github.com/unified-ai)"

# Reasonable default seed; the hub's default.yaml passes these explicitly via
# --block-host so the list is visible and editable. A bare run blocks nothing.
METADATA_HOSTS = ["169.254.169.254", "fd00:ec2::254"]


@dataclass
class Config:
    blocked_hosts: list[str] = field(default_factory=list)
    search_backend: str = "auto"


CONFIG = Config()


# --- SSRF block list ----------------------------------------------------------


def _host_blocked(host: str) -> bool:
    """True if host (literal) or any IP it resolves to matches blocked_hosts."""
    entries = CONFIG.blocked_hosts
    if not entries:
        return False
    host_l = host.lower()
    for e in entries:
        if e.lower() == host_l:
            return True
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False  # unresolvable; let the fetch fail naturally
    ips = {info[4][0] for info in infos}
    for ip in ips:
        try:
            ipobj = ipaddress.ip_address(ip)
        except ValueError:
            continue
        for e in entries:
            try:
                if "/" in e:
                    if ipobj in ipaddress.ip_network(e, strict=False):
                        return True
                elif ipobj == ipaddress.ip_address(e):
                    return True
            except ValueError:
                continue  # e is a hostname (already matched literally above)
    return False


# --- HTML → text --------------------------------------------------------------


class _TextExtractor(HTMLParser):
    _SKIP = {"script", "style", "noscript", "head", "title"}

    def __init__(self) -> None:
        super().__init__()
        self._skip_depth = 0
        self.chunks: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag in self._SKIP:
            self._skip_depth += 1

    def handle_endtag(self, tag):
        if tag in self._SKIP and self._skip_depth:
            self._skip_depth -= 1

    def handle_data(self, data):
        if self._skip_depth == 0:
            text = data.strip()
            if text:
                self.chunks.append(text)


def _read_url(url: str, timeout: int = 10) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept-Encoding": "gzip"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - scheme checked by caller
        raw = resp.read()
        if resp.headers.get("Content-Encoding") == "gzip":
            raw = gzip.decompress(raw)
        return raw


@mcp.tool()
def fetch_webpage(url: str, max_chars: int = 50000, allow_blocked: bool = False) -> dict:
    """Fetch a URL and return its visible text. Blocked hosts require allow_blocked=true."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return {"success": False, "error": "only http/https URLs are supported", "url": url}
    host = parsed.hostname or ""
    if not allow_blocked and _host_blocked(host):
        return {
            "success": False,
            "error": "blocked_host",
            "url": url,
            "host": host,
            "hint": "host is in the server's blocked_hosts list; retry with allow_blocked=true to override (the hub will prompt)",
        }
    try:
        raw = _read_url(url)
    except Exception as exc:  # noqa: BLE001 - report any fetch failure to the caller
        return {"success": False, "error": str(exc), "url": url}
    body = raw.decode("utf-8", errors="ignore")
    title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    title = html.unescape(title_match.group(1).strip()) if title_match else ""
    extractor = _TextExtractor()
    extractor.feed(body)
    text = "\n".join(extractor.chunks)
    truncated = len(text) > max_chars
    return {
        "success": True,
        "url": url,
        "title": title,
        "text": text[:max_chars],
        "char_count": len(text),
        "truncated": truncated,
    }


# --- search backends ----------------------------------------------------------


def _resolve_backend() -> str:
    if CONFIG.search_backend != "auto":
        return CONFIG.search_backend
    return "brave" if os.environ.get("BRAVE_API_KEY") else "duckduckgo"


def _search_brave(query: str, count: int) -> dict:
    key = os.environ.get("BRAVE_API_KEY")
    if not key:
        return {"success": False, "error": "BRAVE_API_KEY not set", "query": query}
    qs = urllib.parse.urlencode({"q": query, "count": count})
    req = urllib.request.Request(
        f"https://api.search.brave.com/res/v1/web/search?{qs}",
        headers={"User-Agent": _UA, "Accept": "application/json", "X-Subscription-Token": key},
    )
    with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
        data = json.loads(resp.read().decode("utf-8"))
    results = [
        {
            "title": r.get("title", ""),
            "url": r.get("url", ""),
            "description": r.get("description", ""),
        }
        for r in data.get("web", {}).get("results", [])[:count]
    ]
    return {
        "success": True,
        "backend": "brave",
        "query": query,
        "result_count": len(results),
        "results": results,
    }


# DuckDuckGo has no free results API; we scrape the no-JS "lite" endpoint, which
# is far more scrape-tolerant than the html endpoint (which bot-blocks). Still
# best-effort by nature — set BRAVE_API_KEY for a reliable, supported backend.
_BROWSER_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
)
_DDG_ANOMALY = ("captcha", "anomaly", "unusual traffic")


class _DDGLiteParser(HTMLParser):
    """Scrape result anchors from lite.duckduckgo.com/lite/ (<a class=result-link>)."""

    def __init__(self) -> None:
        super().__init__()
        self.results: list[dict] = []
        self._in_result = False
        self._href = ""
        self._buf: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            ad = dict(attrs)
            if "result-link" in (ad.get("class", "") or ""):
                self._in_result = True
                self._href = ad.get("href", "")
                self._buf = []

    def handle_endtag(self, tag):
        if tag == "a" and self._in_result:
            self._in_result = False
            title = html.unescape("".join(self._buf)).strip()
            url = self._unwrap(self._href)
            if title and url:
                self.results.append({"title": title, "url": url, "description": ""})

    def handle_data(self, data):
        if self._in_result:
            self._buf.append(data)

    @staticmethod
    def _unwrap(href: str) -> str:
        # DDG sometimes wraps targets as //duckduckgo.com/l/?uddg=<encoded-url>
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(href).query)
        if "uddg" in qs:
            return qs["uddg"][0]
        if href.startswith("//"):
            return f"https:{href}"
        return href


def _search_ddg(query: str, count: int) -> dict:
    qs = urllib.parse.urlencode({"q": query})
    req = urllib.request.Request(
        f"https://lite.duckduckgo.com/lite/?{qs}", headers={"User-Agent": _BROWSER_UA}
    )
    with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
        body = resp.read().decode("utf-8", errors="ignore")
    parser = _DDGLiteParser()
    parser.feed(body)
    results = parser.results[:count]
    if not results:
        # Distinguish "blocked" from "genuinely empty" — never report success on a block.
        blocked = any(w in body.lower() for w in _DDG_ANOMALY)
        return {
            "success": False,
            "backend": "duckduckgo",
            "query": query,
            "result_count": 0,
            "results": [],
            "error": "duckduckgo returned no parseable results"
            + (" (rate-limited / bot-blocked)" if blocked else "")
            + " — set BRAVE_API_KEY for a reliable search backend",
        }
    return {
        "success": True,
        "backend": "duckduckgo",
        "query": query,
        "result_count": len(results),
        "results": results,
    }


@mcp.tool()
def search_internet(query: str, count: int = 10) -> dict:
    """Search the web via the configured backend (auto/brave/duckduckgo/none)."""
    count = max(1, min(20, count))
    backend = _resolve_backend()
    try:
        if backend == "none":
            return {
                "success": False,
                "error": "search backend is disabled (--search-backend none)",
                "query": query,
            }
        if backend == "brave":
            return _search_brave(query, count)
        return _search_ddg(query, count)
    except Exception as exc:  # noqa: BLE001 - surface backend failures to the caller
        return {"success": False, "error": str(exc), "backend": backend, "query": query}


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="unified_mcp_servers.fetch")
    parser.add_argument(
        "--block-host",
        action="append",
        default=[],
        dest="block_hosts",
        help="host/IP/CIDR to refuse (repeatable)",
    )
    parser.add_argument(
        "--search-backend", choices=["auto", "duckduckgo", "brave", "none"], default="auto"
    )
    args = parser.parse_args(argv)
    CONFIG.blocked_hosts = args.block_hosts
    CONFIG.search_backend = args.search_backend
    mcp.run()


if __name__ == "__main__":
    main()
