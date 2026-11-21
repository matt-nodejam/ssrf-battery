"""The canary: battery vs local fixtures, run through tests_canary (shared
with `ssrf-battery.py selftest`), plus endpoint-mode e2e over real sockets."""

import pytest

import tests_canary
from ssrf_battery import classifier, cli, fixture, guards, probespec


def test_canary_battery_vs_fixtures():
    assert tests_canary.canary_assertions(verbose=False), \
        f"canary failures: {tests_canary.FAILURES}"


def test_canary_manifest_matches_corpus_arithmetic():
    """The manifest isn't magic: gap set must equal the encodings that apply to
    v4 targets and are NOT the held ones, plus v6 held pair — sanity by size."""
    probes = probespec.generate_probes()
    v4_encodings = {p.encoding_id for p in probes
                    if p.polarity == "bypass" and p.parse_expectation == "ip_literal"
                    and p.ground_truth.count(".") == 3}
    # held = v6 literal variants + userinfo; gaps = everything else bypass
    expected_gaps = v4_encodings - fixture.NAIVE_KNOWN_HELD - {"v6_canonical", "v6_exploded"}
    expected_gaps |= {"ipv4_dword", "ipv4_hex_dword", "ipv4_octal_dotted",
                      "ipv4_hex_dotted", "ipv4_short", "idna_circled",
                      "idna_fullwidth", "idna_ideographic_dot",
                      "allowlist_fragment_at"}
    assert expected_gaps == set(fixture.NAIVE_KNOWN_GAPS)


def test_endpoint_mode_rewrite_fixture_e2e():
    """HTTP e2e for the rewrote path: server returns rewritten_url in JSON."""
    server, template = fixture.start_fixture_server("rewrite")
    try:
        guard = guards.EndpointGuard(template)
        probes, actions, verdicts, roll = cli.run_battery(guard)
        by_id = {p.id: p for p in probes}
        assert verdicts["ctl-internal-plain"] == classifier.CONTROL_NEUTRALIZED
        assert actions["ctl-internal-plain"].rewritten_url == "http://example.com/"
        assert verdicts["nat64_wk:loopback"] == classifier.GAP
    finally:
        server.shutdown()
        server.server_close()


def test_endpoint_mode_status_response_map():
    """--response status interpretation against a raw 403/200 pair."""
    server, template = fixture.start_fixture_server("naive")
    try:
        guard = guards.EndpointGuard(template, response="status",
                                     status_map="2xx=accepted,403=rejected")
        probes, actions, verdicts, roll = cli.run_battery(guard)
        assert verdicts["nat64_wk:loopback"] == classifier.GAP
        assert verdicts["ctl-internal-plain"] == classifier.CONTROL_INTERNAL_OK
    finally:
        server.shutdown()
        server.server_close()


def test_function_guard_reject_exception_recorded():
    def raiser(url):
        raise RuntimeError("SSRFError: blocked by proxy")
    g = guards.FunctionGuard(raiser, "test")
    action = g.probe("http://127.0.0.1/")
    assert action.kind == "rejected"
    assert "RuntimeError" in action.detail


def test_function_guard_returned_url_is_rewrote():
    g = guards.FunctionGuard(lambda u: u.replace("127.0.0.1", "example.com"), "test")
    action = g.probe("http://127.0.0.1/")
    assert action.kind == "rewrote"
    assert action.rewritten_url == "http://example.com/"


def test_naive_fixture_direct_semantics():
    """The fixture's own semantics, spot-checked at the source level."""
    blocked, why = fixture.naive_guard("http://127.0.0.1/")
    assert blocked
    blocked, _ = fixture.naive_guard("http://[64:ff9b::7f00:1]/")
    assert not blocked
    blocked, _ = fixture.naive_guard("http://example.com/")
    assert not blocked
    blocked, _ = fixture.strict_guard("http://[64:ff9b::7f00:1]/")
    assert blocked
