"""netsem: ground-truth address semantics shared by classifier and fixtures.

One place answers "what IPv4/IPv6 does this literal host REALLY name, and is
that destination internal?" — including the transition-technology unwraps
(NAT64, 6to4, Teredo, IPv4-mapped/compatible) that the advisory corpus proves
guards keep missing:

- MCP fetch server treated 64:ff9b::/96 as public        GHSA-66qx-2266-pmj6
- pydantic-ai missed v4-compat + 64:ff9b:1::/48          GHSA-cg7w-rg45-pc59
- ToolHive manual CIDR list omitted NAT64 ranges         GHSA-pph6-vfjv-vpjw
- Roundcube is_local_url() NAT64 bypass                  CVE-2026-114730
- open-webui NAT64-encoded internal reach                CVE-2026-70485

The battery's verdicts are only as honest as this module; every unwrap is
unit-tested against hand-computed literals in tests/test_probes.py.
"""

from __future__ import annotations

import ipaddress

NAT64_WELL_KNOWN = ipaddress.ip_network("64:ff9b::/96")   # RFC 6052
NAT64_LOCAL_USE = ipaddress.ip_network("64:ff9b:1::/48")  # RFC 8215

# Destination space a fetch guard must treat as internal. Provider-specific
# entries (Azure Wire Server) ride along because real advisories block them.
INTERNAL_V4_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",        # "this host"
        "10.0.0.0/8",
        "100.64.0.0/10",    # CGN carrier space
        "127.0.0.0/8",
        "169.254.0.0/16",   # link-local incl. cloud metadata
        "172.16.0.0/12",
        "192.168.0.0/16",
        "168.63.129.16/32", # Azure Wire Server
    )
]
INTERNAL_V6_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "::1/128",
        "fc00::/7",         # ULA (fd00::/8 in practice)
        "fe80::/10",
    )
]


def unwrap_literal(host: str):
    """Return (ip, via) for a literal host string, else (None, None).

    `via` names the encoding that carried an embedded IPv4: 'v4', 'v4_mapped',
    'v4_compat', 'nat64_wk', 'nat64_local', 'sixto4', 'teredo'. Bracketed
    IPv6 hosts ([::1]) are accepted. Hostname-shaped input returns (None, None)
    — name resolution is out of scope by law (no DNS infrastructure here).
    """
    if not host:
        return None, None
    text = host.strip("[]")
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return None, None

    if isinstance(ip, ipaddress.IPv4Address):
        return ip, "v4"

    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped, "v4_mapped"
    if ip.sixtofour is not None:
        return ip.sixtofour, "sixto4"
    if ip.teredo is not None:
        # teredo hosts[1] is the client address (obfuscated with ^0xffffffff)
        return ip.teredo[1], "teredo"
    if ip in NAT64_WELL_KNOWN:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF), "nat64_wk"
    if ip in NAT64_LOCAL_USE:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF), "nat64_local"
    if int(ip) >> 32 == 0 and int(ip) != 0:
        # deprecated IPv4-compatible ::a.b.c.d (not ::, not ::1 which is v6 loopback)
        if ip != ipaddress.IPv6Address("::1"):
            return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF), "v4_compat"
    return ip, "v6"


def is_internal_ip(ip) -> bool:
    if isinstance(ip, ipaddress.IPv4Address):
        return any(ip in net for net in INTERNAL_V4_NETS)
    if isinstance(ip, ipaddress.IPv6Address):
        return any(ip in net for net in INTERNAL_V6_NETS)
    return False


def destination(host: str):
    """(ip_or_None, via, internal_bool) for a URL host string."""
    ip, via = unwrap_literal(host)
    return ip, via, (is_internal_ip(ip) if ip is not None else False)
