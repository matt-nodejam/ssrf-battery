"""Classifier unit tests: every action x polarity combination gets the right
verdict, and the rollup names the missed encodings."""

import pytest

from ssrf_battery import classifier
from ssrf_battery.classifier import GuardAction
from ssrf_battery.probespec import Probe


def probe(polarity="bypass", **kw):
    base = dict(
        id="t", encoding_id="nat64_wk", probe_class="nat64_wk",
        url="http://[64:ff9b::7f00:1]/", host="[64:ff9b::7f00:1]",
        polarity=polarity, parse_expectation="ip_literal",
        ground_truth="127.0.0.1", reachability="nat64-egress",
        rationale="t", citations=["x"],
    )
    base.update(kw)
    return Probe(**base)


@pytest.mark.parametrize("action,expected", [
    (GuardAction("accepted"), classifier.GAP),
    (GuardAction("rejected", detail="SSRFError"), classifier.HELD),
    (GuardAction("rewrote", rewritten_url="http://[64:ff9b::7f00:1]:8080/"), classifier.GAP_REWRITE),
    (GuardAction("rewrote", rewritten_url="http://example.com/"), classifier.NEUTRALIZED),
    (GuardAction("redirected", redirect_url="http://[64:ff9b::7f00:1]/x"), classifier.GAP),
    (GuardAction("redirected", redirect_url="http://example.com/x"), classifier.NEUTRALIZED),
    (GuardAction("redirected", redirect_url="http://attacker.test/"), classifier.NEUTRALIZED),  # name = unverifiable, never GAP
    (GuardAction("error", detail="transport"), classifier.ERROR),
])
def test_bypass_probe_verdicts(action, expected):
    assert classifier.classify(probe(), action) == expected


@pytest.mark.parametrize("action,expected", [
    (GuardAction("accepted"), classifier.CONTROL_SAFE_OK),
    (GuardAction("rejected"), classifier.CONTROL_SAFE_BLOCKED),
    (GuardAction("rewrote", rewritten_url="http://example.com/"), classifier.CONTROL_SAFE_OK),
    (GuardAction("rewrote", rewritten_url="http://[64:ff9b::7f00:1]/"), classifier.GAP_REWRITE),
])
def test_safe_control_verdicts(action, expected):
    p = probe(polarity="safe", ground_truth="public")
    assert classifier.classify(p, action) == expected


@pytest.mark.parametrize("action,expected", [
    (GuardAction("accepted"), classifier.CONTROL_INTERNAL_ACCEPTED),
    (GuardAction("rejected"), classifier.CONTROL_INTERNAL_OK),
    (GuardAction("rewrote", rewritten_url="http://example.com/"), classifier.CONTROL_NEUTRALIZED),
    (GuardAction("rewrote", rewritten_url="http://10.0.0.1/"), classifier.CONTROL_REWRITTEN_INTERNAL),
])
def test_internal_control_verdicts(action, expected):
    assert classifier.classify(probe(polarity="internal"), action) == expected


def test_rollup_names_missed_encodings():
    probes = [
        probe(id="a", encoding_id="nat64_wk", probe_class="nat64_wk"),
        probe(id="b", encoding_id="nat64_wk", probe_class="nat64_wk"),
        probe(id="c", encoding_id="idna_circled", probe_class="idna_bestfit"),
    ]
    verdicts = {"a": classifier.GAP, "b": classifier.HELD, "c": classifier.GAP_REWRITE}
    roll = classifier.rollup(probes, verdicts)
    assert roll["nat64_wk"]["gaps"] == 1 and roll["nat64_wk"]["held"] == 1
    assert roll["idna_circled"]["gaps"] == 1
    assert classifier.missed_classes(roll) == ["nat64_wk", "idna_bestfit"]


def test_rollup_excludes_controls():
    probes = [probe(id="ctl", polarity="safe", ground_truth="public")]
    roll = classifier.rollup(probes, {"ctl": classifier.CONTROL_SAFE_OK})
    assert dict(roll) == {}


def test_error_never_a_gap():
    probes = [probe(id="e", encoding_id="nat64_wk")]
    roll = classifier.rollup(probes, {"e": classifier.ERROR})
    assert roll["nat64_wk"]["errors"] == 1 and roll["nat64_wk"]["gaps"] == 0
    assert classifier.missed_classes(roll) == []
