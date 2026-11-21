"""fixture: deliberately imperfect local guards + their KNOWN-GAP manifests.

CANARY LAW: the battery must re-find exactly the gaps each fixture is known
to have, deterministically, before it is ever pointed at a real target
(tests/test_battery_fixture.py; `ssrf-battery.py selftest`). Zero third-party
targets are involved — everything here runs against 127.0.0.1 in-process or on
an ephemeral loopback socket.

Three fixtures, three lessons:

  naive    mirrors the most-blocked advisory shape in the corpus: a manually
           maintained CIDR list (ToolHive GHSA-pph6-vfjv-vpjw) that names the
           classic v4/v6 internals but none of the transition encodings
           (NAT64/6to4/Teredo/mapped/compat), and never resolves hostnames —
           so every name-shaped internal probe (IDNA best-fit, dword, ...)
           walks through. Known gaps: nat64_wk, nat64_local, v4_mapped,
           v4_compat, sixto4, teredo, ipv4_alt_notation, idna_bestfit, and
           the parser-differential allowlist_fragment_at. It DOES hold
           ipv6_literal_variant and allowlist_userinfo (urlsplit sees through
           userinfo) — a naive guard is not an empty guard, and the battery
           must not score held probes as gaps.

  strict   the hardened control: unwraps every transition encoding via netsem
           and default-denies hostnames (no resolver available at validation
           time). ZERO gaps expected — proves the battery is not a yes-machine
           that calls everything a bypass. Costs one overblock: ctl-safe-name.

  rewrite  the return-a-URL shape: returns a (possibly rewritten) URL instead of
           raising. It rewrites plaintext 127.0.0.1 to example.com — and only
           that — so every encoding of 127.0.0.1 sails through untouched while
           the plain control is neutralized. Exercises the rewrote/neutralized
           classification path end to end.
"""

from __future__ import annotations

import ipaddress
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, urlunsplit, parse_qs

# ---- naive fixture: the advisory-shaped manual CIDR list -------------------

NAIVE_BLOCKED_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
        "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "168.63.129.16/32",
        "::1/128", "fc00::/7", "fe80::/10",
    )
]


def naive_guard(url: str) -> tuple[bool, str]:
    """(blocked, reason). Literal IPs checked against the manual list; names
    are waved through (no resolution — the documented gap)."""
    host = urlsplit(url).hostname or ""
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False, f"name host {host!r} not resolved (gap)"
    if any(ip in net for net in NAIVE_BLOCKED_NETS):
        return True, f"{ip} in manual blocklist"
    return False, f"{ip} not in manual blocklist (gap)"


# The canary manifest: exactly what a correct battery must find on the naive
# fixture. Encoding-level (not class-level) because the fixture holds some
# encodings of an otherwise-gappy class — the whole point of classification.
NAIVE_KNOWN_GAPS = {
    "nat64_wk", "nat64_local", "v4_mapped_dec", "v4_mapped_hex", "v4_compat",
    "sixto4", "teredo", "ipv4_dword", "ipv4_hex_dword", "ipv4_octal_dotted",
    "ipv4_hex_dotted", "ipv4_short", "idna_circled", "idna_fullwidth",
    "idna_ideographic_dot", "allowlist_fragment_at",
}
NAIVE_KNOWN_HELD = {
    "v6_exploded", "v6_canonical", "allowlist_userinfo",
}


# ---- strict fixture: the hardened control ----------------------------------

def strict_guard(url: str) -> tuple[bool, str]:
    """(blocked, reason). Unwraps transition encodings; default-denies names."""
    from . import netsem
    host = urlsplit(url).hostname or ""
    ip, via, internal = netsem.destination(host)
    if ip is None:
        return True, f"name host {host!r} default-denied (no resolution here)"
    if internal:
        return True, f"{ip} internal via {via}"
    return False, f"{ip} public via {via}"


# ---- rewrite fixture: the return-a-URL shape --------------------------------

def rewrite_guard(url: str) -> str:
    """Return-a-URL-shaped: returns the URL to fetch. Rewrites only the exact
    plaintext host 127.0.0.1 to example.com; everything else passes through."""
    parts = urlsplit(url)
    if (parts.hostname or "") == "127.0.0.1":
        netloc = "example.com"
        if parts.port:
            netloc = f"example.com:{parts.port}"
        return urlunsplit((parts.scheme, netloc, parts.path or "/", parts.query, parts.fragment))
    return url


FIXTURES = {
    "naive": naive_guard,
    "strict": strict_guard,
}


# ---- endpoint-mode fixture server (loopback only) --------------------------

class _Handler(BaseHTTPRequestHandler):
    server_version = "ssrf-battery-fixture/0.1"

    def do_GET(self):  # noqa: N802 - http.server API
        parts = urlsplit(self.path)
        qs = parse_qs(parts.query)
        urls = qs.get("u", [])
        if not urls:
            self._json(400, {"action": "error", "why": "missing ?u="})
            return
        target = urls[0]
        guard = self.server.guard  # noqa: SLF001 - our own server object
        if self.server.returns_url:  # noqa: SLF001
            try:
                out = guard(target)
            except Exception as exc:  # rejected shape if it ever raises
                self._json(403, {"action": "blocked", "why": f"{type(exc).__name__}"})
                return
            self._json(200, {"action": "allowed", "rewritten_url": out, "original": target})
            return
        blocked, why = guard(target)
        if blocked:
            self._json(403, {"action": "blocked", "why": why})
        else:
            self._json(200, {"action": "allowed", "why": why, "original": target})

    def _json(self, status, doc):
        body = json.dumps(doc).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # quiet: report-grade runs stay clean
        pass


def start_fixture_server(guard_name: str = "naive", returns_url: bool = False):
    """(server, base_url) bound to 127.0.0.1 on an ephemeral port. serve_forever
    in a thread; call shutdown() + server_close() when done."""
    if guard_name == "rewrite":
        guard, returns_url = rewrite_guard, True
    else:
        guard = FIXTURES[guard_name]
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.guard = guard            # type: ignore[attr-defined]
    server.returns_url = returns_url  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    return server, f"http://127.0.0.1:{port}/fetch?u={{URL}}"
