"""Report-format tests: determinism, structure, and the evidence shape."""

import json

import pytest

from ssrf_battery import classifier, cli, guards, report


@pytest.fixture(scope="module")
def naive_run():
    guard = cli._fixture_function_guard("naive")
    probes, actions, verdicts, roll = cli.run_battery(guard)
    return probes, actions, verdicts, roll


def _build(naive_run):
    probes, actions, verdicts, roll = naive_run
    return report.build("fixture:naive", probes, verdicts, actions, roll,
                        command=["ssrf-battery", "run", "--validator", "x"], stable=True)


def test_report_json_roundtrip(naive_run):
    doc = _build(naive_run)
    blob = json.dumps(doc)
    assert json.loads(blob) == doc


def test_report_markdown_shape(naive_run):
    doc = _build(naive_run)
    md = report.to_markdown(doc)
    assert "# SSRF-guard battery report — fixture:naive" in md
    assert "## Verdict" in md
    assert "GUARD GAPS" in md
    assert "`nat64_wk`" in md                      # names the missed encoding
    assert "## Controls" in md
    assert "## Per-probe evidence" in md
    assert "## Citations" in md
    assert "GHSA-66qx-2266-pmj6" in md             # published advisory cited
    assert doc["command"] == ["ssrf-battery", "run", "--validator", "x"]


def test_report_stable_is_byte_deterministic(tmp_path):
    outs = []
    for i in range(2):
        guard = cli._fixture_function_guard("naive")
        probes, actions, verdicts, roll = cli.run_battery(guard)
        doc = report.build("x", probes, verdicts, actions, roll,
                           command=["c"], stable=True)
        outs.append(report.to_markdown(doc))
    assert outs[0] == outs[1]


def test_report_records_gap_and_verdict_per_probe(naive_run):
    doc = _build(naive_run)
    nat64 = next(p for p in doc["probes"] if p["id"] == "nat64_wk:loopback")
    assert nat64["verdict"] == "GAP"
    assert nat64["action"] == "accepted"
    assert nat64["ground_truth"] == "127.0.0.1"
    assert nat64["reachability"] == "nat64-egress"
    ctl = next(p for p in doc["probes"] if p["id"] == "ctl-internal-plain")
    assert ctl["verdict"] == "CONTROL_INTERNAL_OK"


def test_report_write_roundtrip(tmp_path, naive_run):
    doc = _build(naive_run)
    md_path, json_path = report.write(tmp_path / "out", doc)
    body = open(md_path, encoding="utf-8").read()
    assert body == report.to_markdown(doc)
    loaded = json.load(open(json_path, encoding="utf-8"))
    assert loaded == doc


def test_endpoint_report_carries_engagement(naive_run, tmp_path):
    """A non-loopback run (consent satisfied) must echo the engagement id."""
    probes, actions, verdicts, roll = naive_run
    doc = report.build("t", probes, verdicts, actions, roll, command=["c"],
                       stable=True, engagement_id="eng-0001")
    assert doc["engagement"] == "eng-0001"
    assert "engagement" in report.to_markdown(doc)
