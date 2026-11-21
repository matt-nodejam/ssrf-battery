"""probespec: expands the declarative corpus (probes.json) into concrete probes.

Every probe is target x encoding, no hand-written payloads. The expansion is
pure string templating over values computed from the target IP — deterministic
by construction, which is what lets the canary test assert byte-identical
double runs.
"""

from __future__ import annotations

import hashlib
import json
import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from . import netsem

CORPUS = Path(__file__).with_name("probes.json")

CIRCLED_ZERO = "⓪"  # U+24EA
IDEOGRAPHIC_DOT = "。"  # U+3002
FULLWIDTH_DOT = "．"  # U+FF0E


@dataclass(frozen=True)
class Probe:
    id: str
    encoding_id: str
    probe_class: str          # technique class (nat64_wk, idna_bestfit, ...)
    url: str
    host: str                 # netloc host the guard will see (brackets kept)
    polarity: str             # bypass | safe | internal   (controls use these)
    parse_expectation: str    # ip_literal | name
    ground_truth: str         # destination this URL names when all is said+done
    reachability: str         # direct | dual-stack | nat64-egress | conditional | ...
    rationale: str
    citations: list = field(default_factory=list)


def _short_form(ip: ipaddress.IPv4Address) -> str:
    """inet_aton classful compression: a.b/c.d -> a.b/<c.d as 16-bit> or a/<b.c.d as 24-bit>."""
    o = [int(x) for x in str(ip).split(".")]
    if o[1] == 0 and o[2] == 0:
        return f"{o[0]}.{o[3]}"                 # a.<d>
    return f"{o[0]}.{o[1]}.{(o[2] << 8) | o[3]}"  # a.b.<c.d>


def _octal_dotted(ip: ipaddress.IPv4Address) -> str:
    parts = []
    for octet in str(ip).split("."):
        parts.append("0" if int(octet) == 0 else f"0{int(octet):o}")
    return ".".join(parts)


def _hex_dotted(ip: ipaddress.IPv4Address) -> str:
    return ".".join(f"0x{int(x):x}" for x in str(ip).split("."))


def _circled(ip: ipaddress.IPv4Address) -> str:
    out = []
    for ch in str(ip):
        if ch == ".":
            out.append(".")
        else:
            d = int(ch)
            out.append(CIRCLED_ZERO if d == 0 else chr(0x2460 + d - 1))
    return "".join(out)


def _fullwidth(ip: ipaddress.IPv4Address) -> str:
    return "".join(
        FULLWIDTH_DOT if ch == "." else chr(0xFF10 + int(ch)) for ch in str(ip)
    )


def _ideographic(ip: ipaddress.IPv4Address) -> str:
    return str(ip).replace(".", IDEOGRAPHIC_DOT)


def _transforms(ip_text: str) -> dict:
    """Every placeholder the corpus templates can ask for, for one target.

    IPv6 forms are built as real IPv6Address values and rendered with the
    stdlib's canonical compression, so the corpus carries exactly the strings
    a URL parser would hand a guard ([64:ff9b::7f00:1], not 7f00:0001).
    """
    if ":" in ip_text:  # ipv6 target
        ip6 = ipaddress.IPv6Address(ip_text)
        return {"V6": str(ip6), "V6FULL": str(ip6.exploded)}
    ip = ipaddress.IPv4Address(ip_text)
    n = int(ip)
    x = n ^ 0xFFFFFFFF  # teredo client obfuscation
    return {
        "IP": str(ip),
        "HEX32": f"{n:08x}",
        "NAT64": str(ipaddress.IPv6Address((0x64FF9B << 96) | n)),
        "NAT64_LU": str(ipaddress.IPv6Address((0x64FF9B0001 << 80) | n)),
        "MAPPED_HEX": str(ipaddress.IPv6Address((0xFFFF << 32) | n)),
        "COMPAT": str(ipaddress.IPv6Address(n)),
        "SIXTO4": str(ipaddress.IPv6Address((0x2002 << 112) | (n << 80))),
        "TEREDO": str(ipaddress.IPv6Address((0x2001 << 112) | x)),
        "DWORD": str(n),
        "OCT_DOTTED": _octal_dotted(ip),
        "HEX_DOTTED": _hex_dotted(ip),
        "SHORT": _short_form(ip),
        "CIRCLED": _circled(ip),
        "FULLWIDTH": _fullwidth(ip),
        "IDEO_DOT": _ideographic(ip),
    }


def load_spec(path: Path | None = None) -> dict:
    with open(path or CORPUS, encoding="utf-8") as fh:
        return json.load(fh)


def corpus_sha256(path: Path | None = None) -> str:
    data = (path or CORPUS).read_bytes()
    return hashlib.sha256(data).hexdigest()


def generate_probes(path: Path | None = None, url_path: str = "/") -> list[Probe]:
    """Expand spec -> probes. Deterministic: file order, no clocks, no randomness."""
    spec = load_spec(path)
    probes: list[Probe] = []

    for enc in spec["encodings"]:
        for tgt in spec["targets"]:
            if tgt["family"] not in enc["applies"]:
                continue
            tf = _transforms(tgt["value"])
            tf["PATH"] = url_path if url_path.startswith("/") else "/" + url_path
            if "host_form" in enc:
                host = enc["host_form"].format(**tf)
                url = f"http://{host}{tf['PATH']}"
            else:
                url = enc["url_form"].format(**tf)
                host = urlsplit(url).hostname or ""
                if ":" in host and not host.startswith("["):
                    host = f"[{host}]"
            probes.append(
                Probe(
                    id=f"{enc['id']}:{tgt['id']}",
                    encoding_id=enc["id"],
                    probe_class=enc["class"],
                    url=url,
                    host=host,
                    polarity="bypass",
                    parse_expectation=enc["parse"],
                    ground_truth=tgt["value"],
                    reachability=enc["reachability"],
                    rationale=enc["rationale"],
                    citations=list(enc.get("citations", [])),
                )
            )

    for ctl in spec.get("controls", []):
        host = urlsplit(ctl["url"]).hostname or ""
        probes.append(
            Probe(
                id=ctl["id"],
                encoding_id=ctl["id"],
                probe_class="control",
                url=ctl["url"],
                host=host,
                polarity=ctl["polarity"],
                parse_expectation=ctl.get("parse", "name"),
                ground_truth="public" if ctl["polarity"] == "safe" else "127.0.0.1",
                reachability="direct",
                rationale=ctl["rationale"],
                citations=[],
            )
        )

    _validate(probes)
    return probes


def _validate(probes: list[Probe]) -> None:
    """Fail loudly on corpus/self inconsistencies before any target sees them."""
    seen = set()
    for p in probes:
        if p.id in seen:
            raise ValueError(f"duplicate probe id {p.id}")
        seen.add(p.id)
        ip, via = netsem.unwrap_literal(p.host)
        if p.parse_expectation == "ip_literal" and ip is None:
            raise ValueError(f"{p.id}: expected literal host, got name: {p.host!r}")
        if p.parse_expectation == "name" and ip is not None:
            raise ValueError(f"{p.id}: expected name-shaped host, parsed as {ip}")
        if p.polarity == "bypass" and ip is not None:
            # ground truth must round-trip: the unwrapped destination IS the target
            tgt = ipaddress.ip_address(p.ground_truth)
            if tgt.version == 4 and ip != tgt:
                raise ValueError(f"{p.id}: unwraps to {ip}, target is {tgt}")
            if tgt.version == 6 and (ip.version != 6 or ip.compressed != tgt.compressed):
                raise ValueError(f"{p.id}: unwraps to {ip}, target is {tgt}")
        if p.polarity == "bypass" and not p.citations:
            raise ValueError(f"{p.id}: bypass probe without citation")
