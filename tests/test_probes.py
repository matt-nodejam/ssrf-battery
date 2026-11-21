"""Probe-corpus correctness: every NAT64/transition form really encodes the
target it claims to. [64:ff9b::7f00:1] MUST unwrap to 127.0.0.1, etc."""

import ipaddress

import pytest

from ssrf_battery import netsem, probespec


@pytest.fixture(scope="module")
def probes():
    return probespec.generate_probes()


def by_id(plist, pid):
    return next(p for p in plist if p.id == pid)


# -- hand-computed ground truths (published advisory values + RFC forms) --

HAND_CHECKS = {
    "nat64_wk:loopback": ("127.0.0.1", "nat64_wk"),            # 64:ff9b::7f00:1
    "nat64_wk:rfc1918-10": ("10.0.0.1", "nat64_wk"),           # 64:ff9b::a00:1
    "nat64_wk:metadata-aws": ("169.254.169.254", "nat64_wk"),  # 64:ff9b::a9fe:a9fe
    "nat64_wk:azure-wire": ("168.63.129.16", "nat64_wk"),
    "nat64_local:loopback": ("127.0.0.1", "nat64_local"),
    "v4_mapped_dec:loopback": ("127.0.0.1", "v4_mapped"),
    "v4_mapped_hex:loopback": ("127.0.0.1", "v4_mapped"),
    "v4_compat:loopback": ("127.0.0.1", "v4_compat"),
    "sixto4:loopback": ("127.0.0.1", "sixto4"),
    "teredo:loopback": ("127.0.0.1", "teredo"),
}


@pytest.mark.parametrize("pid", sorted(HAND_CHECKS))
def test_hand_computed_unwraps(probes, pid):
    p = by_id(probes, pid)
    want_ip, want_via = HAND_CHECKS[pid]
    ip, via, internal = netsem.destination(p.host)
    assert ip == ipaddress.ip_address(want_ip), f"{pid}: {p.host} -> {ip}, wanted {want_ip}"
    assert via == want_via
    assert internal


def test_canonical_nat64_literals(probes):
    """The exact NAT64 literal strings from the published advisory class."""
    urls = {by_id(probes, "nat64_wk:loopback").url,
            by_id(probes, "nat64_wk:rfc1918-10").url,
            by_id(probes, "nat64_wk:metadata-aws").url}
    assert "http://[64:ff9b::7f00:1]/" in urls
    assert "http://[64:ff9b::a00:1]/" in urls
    assert "http://[64:ff9b::a9fe:a9fe]/" in urls


def test_every_ip_literal_probe_unwraps_to_target(probes):
    """For all bypass probes whose host is a literal: unwrapped == ground truth."""
    checked = 0
    for p in probes:
        if p.polarity != "bypass" or p.parse_expectation != "ip_literal":
            continue
        ip, via, internal = netsem.destination(p.host)
        assert ip is not None, f"{p.id}: host {p.host!r} does not parse as literal"
        assert internal, f"{p.id}: {p.host} unwraps to non-internal {ip}"
        target = ipaddress.ip_address(p.ground_truth)
        if target.version == 4:
            assert ip == target, f"{p.id}: {ip} != {target}"
        else:
            assert ip.version == 6 and ip.compressed == target.compressed
        checked += 1
    # corpus shape pin: 7 v4-embedding encodings x 6 v4 targets + 2 v6 encodings
    # x 2 v6 targets + 6 userinfo probes = 52 literal probes
    assert checked == 52, f"literal probe count drifted: {checked}"


def test_alt_notation_probes_are_name_shaped(probes):
    """dword/octal/hex/short forms must NOT parse as literals (that IS the gap)."""
    from urllib.parse import urlsplit
    for p in probes:
        if p.probe_class == "ipv4_alt_notation":
            host = urlsplit(p.url).hostname
            with pytest.raises(ValueError):
                ipaddress.ip_address(host)
            assert host  # non-empty


def test_alt_notation_values_inet_aton_correct(probes):
    """The classic forms use inet_aton semantics — verify by reimplementation."""
    def inet_aton(s):
        parts = s.split(".")
        if len(parts) > 4:
            raise ValueError
        val = 0
        for i, part in enumerate(parts):
            if part.lower().startswith("0x"):
                n = int(part, 16)
            elif part.startswith("0") and len(part) > 1:
                n = int(part, 8)
            else:
                n = int(part)
            shift = 8 * (4 - min(len(parts) - i, 4) + (0 if i == len(parts) - 1 else 1))
            if i == len(parts) - 1:
                # last part may carry multiple octets (classful compression)
                remaining = 4 - (len(parts) - 1)
                if n >= 1 << (8 * remaining):
                    raise ValueError
                val = (val << (8 * remaining)) | n
            else:
                if not 0 <= n < 256:
                    raise ValueError
                val = (val << 8) | n
        return val

    for p in probes:
        if p.probe_class != "ipv4_alt_notation":
            continue
        from urllib.parse import urlsplit
        host = urlsplit(p.url).hostname
        want = int(ipaddress.ip_address(p.ground_truth))
        assert inet_aton(host) == want, f"{p.id}: {host} != {p.ground_truth}"


def test_idna_probe_strings(probes):
    """Circled/fullwidth/ideographic forms carry the exact unicode classes."""
    circled = by_id(probes, "idna_circled:loopback")
    assert circled.url == "http://①②⑦.⓪.⓪.①/"
    fw = by_id(probes, "idna_fullwidth:loopback")
    assert fw.url == "http://１２７．０．０．１/"
    ide = by_id(probes, "idna_ideographic_dot:loopback")
    assert ide.url == "http://127。0。0。1/"


def test_teredo_obfuscation(probes):
    """127.0.0.1 ^ 0xffffffff = 80fffffe; the probe must carry exactly that
    (canonical compression: 2001::80ff:fffe)."""
    p = by_id(probes, "teredo:loopback")
    assert p.host == "[2001::80ff:fffe]"
    assert "[2001:0:0:0:0:0:80ff:fffe]" not in p.url  # compressed, not long-form


def test_v6_target_forms(probes):
    exploded = by_id(probes, "v6_exploded:loopback-v6")
    assert exploded.url == "http://[0000:0000:0000:0000:0000:0000:0000:0001]/"
    canon = by_id(probes, "v6_canonical:loopback-v6")
    assert canon.url == "http://[::1]/"
    gcp = by_id(probes, "v6_canonical:metadata-gcp-v6")
    assert gcp.url == "http://[fd00:ec2::254]/"


def test_generation_deterministic():
    a = probespec.generate_probes()
    b = probespec.generate_probes()
    assert [p.id for p in a] == [p.id for p in b]
    assert [p.url for p in a] == [p.url for p in b]


def test_unique_ids_and_citations(probes):
    ids = [p.id for p in probes]
    assert len(ids) == len(set(ids))
    for p in probes:
        if p.polarity == "bypass":
            assert p.citations, f"{p.id} bypass probe without citation"
            assert p.rationale


def test_corpus_sha_stable():
    assert probespec.corpus_sha256() == probespec.corpus_sha256()
    assert len(probespec.corpus_sha256()) == 64


def test_url_path_substitution():
    plist = probespec.generate_probes(url_path="/latest/meta-data/")
    assert any(p.url == "http://[64:ff9b::7f00:1]/latest/meta-data/" for p in plist)


def test_allowlist_probe_shapes(probes):
    ui = by_id(probes, "allowlist_userinfo:loopback")
    assert ui.url == "http://safe.example.@127.0.0.1/"
    fa = by_id(probes, "allowlist_fragment_at:loopback")
    assert fa.url == r"http://127.0.0.1\@safe.example/"


# -- netsem unwrap unit tests (hand-computed) -------------------------------

@pytest.mark.parametrize("host,want_ip,want_via", [
    ("64:ff9b::7f00:1", "127.0.0.1", "nat64_wk"),
    ("[64:ff9b::a9fe:a9fe]", "169.254.169.254", "nat64_wk"),
    ("64:ff9b:1::a9fe:a9fe", "169.254.169.254", "nat64_local"),
    ("::ffff:127.0.0.1", "127.0.0.1", "v4_mapped"),
    ("::ffff:a00:1", "10.0.0.1", "v4_mapped"),
    ("::7f00:1", "127.0.0.1", "v4_compat"),
    ("2002:7f00:1::", "127.0.0.1", "sixto4"),
    ("2001:0:0:0:0:0:80ff:fffe", "127.0.0.1", "teredo"),
    ("::1", "::1", "v6"),
    ("fd00:ec2::254", "fd00:ec2::254", "v6"),
    ("8.8.8.8", "8.8.8.8", "v4"),
    ("example.com", None, None),
])
def test_netsem_unwrap(host, want_ip, want_via):
    ip, via = netsem.unwrap_literal(host)
    if want_ip is None:
        assert ip is None and via is None
    else:
        assert ip == ipaddress.ip_address(want_ip)
        assert via == want_via


def test_netsem_internal_boundaries():
    assert netsem.is_internal_ip(ipaddress.ip_address("169.254.169.254"))
    assert netsem.is_internal_ip(ipaddress.ip_address("168.63.129.16"))
    assert netsem.is_internal_ip(ipaddress.ip_address("100.64.0.1"))
    assert not netsem.is_internal_ip(ipaddress.ip_address("8.8.8.8"))
    assert not netsem.is_internal_ip(ipaddress.ip_address("2001:db8::1"))


def test_netsem_nat64_subnet_address():
    """64:ff9b::0 (the /96 subnet address) is still inside the prefix: it
    unwraps to 0.0.0.0, which lands in 0/8 — internal, consistently."""
    ip, via, internal = netsem.destination("[64:ff9b::0]")
    assert via == "nat64_wk"
    assert ip == ipaddress.ip_address("0.0.0.0")
    assert internal
