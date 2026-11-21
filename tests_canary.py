"""tests_canary: the canary-law engine — battery vs fixtures, exactly.

One function, canary_assertions(), used by `ssrf-battery.py selftest` and by
tests/test_battery_fixture.py. It proves, against LOCAL fixtures only:

  1. naive fixture   -> battery finds EXACTLY NAIVE_KNOWN_GAPS (no more, no
                        less) and exactly NAIVE_KNOWN_HELD; controls correct.
  2. endpoint mode   -> same verdicts over HTTP against the fixture server.
  3. strict fixture  -> zero gaps (the battery is not a yes-machine) and the
                        one documented overblock shows up as CONTROL_SAFE_BLOCKED.
  4. rewrite fixture -> return-a-URL guard: untouched encodings
                        are GAP, the rewritten control is CONTROL_NEUTRALIZED.
  5. determinism     -> two stable reports are byte-identical.
  6. consent wall    -> non-loopback endpoint template is refused without an
                        engagement record and accepted with one.
"""

from __future__ import annotations

import json
import tempfile
from collections import OrderedDict
from pathlib import Path

from ssrf_battery import classifier, cli, fixture, guards, probespec, report

FAILURES: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> bool:
    ok = bool(cond)
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  [{detail}]" if detail and not ok else ""))
    if not ok:
        FAILURES.append(name)
    return ok


def _gap_encodings(roll) -> set:
    return {enc for enc, row in roll.items() if row["gaps"]}


def _run_function(guard):
    probes, actions, verdicts, roll = cli.run_battery(guard)
    return probes, actions, verdicts, roll


def canary_assertions(verbose: bool = True) -> bool:
    FAILURES.clear()
    bypass_encodings = {p.encoding_id for p in probespec.generate_probes() if p.polarity == "bypass"}

    # -- 1. naive fixture, function mode ------------------------------------
    guard = cli._fixture_function_guard("naive")
    probes, actions, verdicts, roll = _run_function(guard)
    detected = _gap_encodings(roll)
    check("naive: gap encodings exactly the manifest",
          detected == set(fixture.NAIVE_KNOWN_GAPS),
          f"extra={sorted(detected - set(fixture.NAIVE_KNOWN_GAPS))} "
          f"missing={sorted(set(fixture.NAIVE_KNOWN_GAPS) - detected)}")
    held = {enc for enc, row in roll.items() if row["held"] and not row["gaps"]}
    check("naive: held encodings exactly the manifest",
          held == set(fixture.NAIVE_KNOWN_HELD),
          f"got {sorted(held)}")
    check("naive: ctl-safe-name accepted", verdicts["ctl-safe-name"] == classifier.CONTROL_SAFE_OK)
    check("naive: ctl-safe-literal accepted", verdicts["ctl-safe-literal"] == classifier.CONTROL_SAFE_OK)
    check("naive: ctl-internal-plain blocked", verdicts["ctl-internal-plain"] == classifier.CONTROL_INTERNAL_OK)
    check("naive: no ERROR verdicts",
          not any(v == classifier.ERROR for v in verdicts.values()))
    check("naive: every probe classified", len(verdicts) == len(probes))
    check("naive: NAT64 loopback probe is a GAP",
          verdicts.get("nat64_wk:loopback") == classifier.GAP)
    check("naive: NAT64 metadata probe is a GAP",
          verdicts.get("nat64_wk:metadata-aws") == classifier.GAP)

    # -- 2. endpoint mode over HTTP ------------------------------------------
    server, template = fixture.start_fixture_server("naive")
    try:
        eguard = guards.EndpointGuard(template)
        eprobes, eactions, everdicts, eroll = cli.run_battery(eguard)
        check("endpoint: same gap set as function mode",
              _gap_encodings(eroll) == detected,
              f"diff={sorted(_gap_encodings(eroll) ^ detected)}")
        check("endpoint: same verdicts as function mode", everdicts == verdicts)
    finally:
        server.shutdown()
        server.server_close()

    # -- 3. strict fixture: no wolf-crying ------------------------------------
    sguard = cli._fixture_function_guard("strict")
    _, _, sverdicts, sroll = _run_function(sguard)
    check("strict: zero gaps", not _gap_encodings(sroll),
          f"gaps={sorted(_gap_encodings(sroll))}")
    check("strict: safe-name overblocked (documented cost)",
          sverdicts["ctl-safe-name"] == classifier.CONTROL_SAFE_BLOCKED)
    check("strict: safe-literal accepted", sverdicts["ctl-safe-literal"] == classifier.CONTROL_SAFE_OK)
    check("strict: internal-plain blocked", sverdicts["ctl-internal-plain"] == classifier.CONTROL_INTERNAL_OK)
    check("strict: NAT64 held", sverdicts.get("nat64_wk:metadata-aws") == classifier.HELD)

    # -- 4. rewrite fixture (return-a-URL shape) -------------------------------
    rguard = guards.FunctionGuard(fixture.rewrite_guard, "fixture:rewrite")
    _, _, rverdicts, rroll = _run_function(rguard)
    check("rewrite: every bypass encoding still gappy",
          _gap_encodings(rroll) == bypass_encodings,
          f"got={sorted(_gap_encodings(rroll))}")
    check("rewrite: internal control neutralized",
          rverdicts["ctl-internal-plain"] == classifier.CONTROL_NEUTRALIZED)
    check("rewrite: userinfo:loopback neutralized (host rewritten safe)",
          rverdicts.get("allowlist_userinfo:loopback") == classifier.NEUTRALIZED)
    check("rewrite: userinfo of non-loopback target still GAP",
          rverdicts.get("allowlist_userinfo:rfc1918-10") == classifier.GAP)

    # -- 5. determinism: byte-identical stable double run ----------------------
    doc1 = report.build("canary", probes, verdicts, actions, roll,
                        command=["ssrf-battery", "selftest"], stable=True)
    probes2, actions2, verdicts2, roll2 = _run_function(cli._fixture_function_guard("naive"))
    doc2 = report.build("canary", probes2, verdicts2, actions2, roll2,
                        command=["ssrf-battery", "selftest"], stable=True)
    md1, md2 = report.to_markdown(doc1), report.to_markdown(doc2)
    check("determinism: second run byte-identical (stable)",
          md1 == md2 and json.dumps(doc1) == json.dumps(doc2))

    # -- 6. consent wall --------------------------------------------------------
    try:
        guards.EndpointGuard("https://api.example.com/fetch?u={URL}")
        check("consent: non-loopback refused without engagement", False, "no exception")
    except guards.ConsentRequired:
        check("consent: non-loopback refused without engagement", True)
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump({"engagement": "test-engagement-0001", "scope": ["api.example.com"]}, fh)
        eng_path = fh.name
    try:
        eg = guards.EndpointGuard("https://api.example.com/fetch?u={URL}", engagement=eng_path)
        check("consent: engagement record unlocks non-loopback",
              eg.engagement_record["engagement"] == "test-engagement-0001")
    except guards.ConsentRequired as exc:
        check("consent: engagement record unlocks non-loopback", False, str(exc))

    return not FAILURES
