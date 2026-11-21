"""classifier: turns (probe, guard action) into a verdict, then rolls up classes.

Guard-semantics classification is the tool's core novelty: prior art generates
payloads (PortSwigger cheat sheet) or fires exploits (SSRFmap); nothing records
WHAT THE GUARD DID per probe so the output can name the exact encodings a
given guard misses. Action vocabulary, inspired by what real guards do
(some validators return a rewritten URL; fetch servers return 403 JSON;
redirectors 30x):

    accepted   guard let the URL through unchanged
    rejected   guard refused (exception, 403, blocked-marker, ...)
    rewrote    guard returned a different URL (return-a-URL shape)
    redirected endpoint answered 3xx to elsewhere
    error      transport/crash we could not interpret (never counted as a gap)

Verdicts:

    GAP / GAP_REWRITE          internal destination survived the guard
    HELD / NEUTRALIZED         guard refused it / rewrote it somewhere safe
    CONTROL_SAFE_OK            safe control accepted (guard not blanket-deny)
    CONTROL_SAFE_BLOCKED       safe control refused (overblocking, reported)
    CONTROL_INTERNAL_OK        plaintext internal refused (guard exists)
    CONTROL_INTERNAL_ACCEPTED  plaintext internal accepted (no guard at all)
    CONTROL_NEUTRALIZED        internal control rewritten safe
    CONTROL_REWRITTEN_INTERNAL internal control "handled" by rewriting to internal
    ERROR                      action inconclusive

Name-class probes (IDNA, alt-notation, parser-differentials) whose reachability
depends on a downstream resolver are still GAP when accepted — the guard let an
internal-destination URL through — but carry reachability=conditional in the
report so impact framing stays honest.
"""

from __future__ import annotations

from collections import OrderedDict
from urllib.parse import urlsplit

from . import netsem
from .probespec import Probe

# verdict codes
GAP = "GAP"
GAP_REWRITE = "GAP_REWRITE"          # rewritten, destination still internal
HELD = "HELD"
NEUTRALIZED = "NEUTRALIZED"          # rewritten to a non-internal destination
CONTROL_SAFE_OK = "CONTROL_SAFE_OK"
CONTROL_SAFE_BLOCKED = "CONTROL_SAFE_BLOCKED"
CONTROL_INTERNAL_OK = "CONTROL_INTERNAL_OK"
CONTROL_INTERNAL_ACCEPTED = "CONTROL_INTERNAL_ACCEPTED"
CONTROL_NEUTRALIZED = "CONTROL_NEUTRALIZED"
CONTROL_REWRITTEN_INTERNAL = "CONTROL_REWRITTEN_INTERNAL"
ERROR = "ERROR"


class GuardAction:
    __slots__ = ("kind", "detail", "rewritten_url", "redirect_url")

    def __init__(self, kind: str, detail: str = "", rewritten_url: str = "", redirect_url: str = ""):
        self.kind = kind            # accepted|rejected|rewrote|redirected|error
        self.detail = detail        # exception name / status / marker, recorded verbatim
        self.rewritten_url = rewritten_url
        self.redirect_url = redirect_url

    def __repr__(self):
        extra = self.rewritten_url or self.redirect_url or self.detail
        return f"GuardAction({self.kind}{', ' + extra if extra else ''})"


def _host_of(url: str) -> str:
    try:
        h = urlsplit(url).hostname or ""
    except ValueError:
        h = ""
    return f"[{h}]" if ":" in h and not h.startswith("[") else h


def _rewritten_still_internal(action: GuardAction) -> bool:
    ip, _, internal = netsem.destination(_host_of(action.rewritten_url))
    return internal


def classify(probe: Probe, action: GuardAction) -> str:
    if action.kind == "error":
        return ERROR

    if probe.polarity == "safe":
        if action.kind in ("accepted",):
            return CONTROL_SAFE_OK
        if action.kind == "rewrote":
            # rewriting a safe URL is odd but not a bypass; record and move on
            return CONTROL_SAFE_OK if not _rewritten_still_internal(action) else GAP_REWRITE
        return CONTROL_SAFE_BLOCKED

    if probe.polarity == "internal":
        if action.kind == "rejected":
            return CONTROL_INTERNAL_OK
        if action.kind == "rewrote":
            return CONTROL_REWRITTEN_INTERNAL if _rewritten_still_internal(action) else CONTROL_NEUTRALIZED
        return CONTROL_INTERNAL_ACCEPTED

    # bypass probes: ground truth destination is internal by corpus construction
    if action.kind == "accepted":
        return GAP
    if action.kind == "rewrote":
        return GAP_REWRITE if _rewritten_still_internal(action) else NEUTRALIZED
    if action.kind == "redirected":
        # a redirect answers the probe question with another hop; the guard
        # itself did not refuse the URL. GAP only when the redirect target is
        # PROVABLY internal — name targets are unverifiable without DNS (out
        # of scope by law), so they land NEUTRALIZED, never GAP.
        _, _, internal = netsem.destination(_host_of(action.redirect_url))
        return GAP if internal else NEUTRALIZED
    return HELD


def rollup(probes, verdicts: dict[str, str]) -> "OrderedDict[str, dict]":
    """Per-encoding accepted/total for bypass probes — 'the exact encodings
    this guard misses'. Ordered by corpus order, deterministic."""
    out: OrderedDict[str, dict] = OrderedDict()
    for p in probes:
        if p.polarity != "bypass":
            continue
        row = out.setdefault(
            p.encoding_id,
            {"class": p.probe_class, "total": 0, "gaps": 0, "held": 0, "errors": 0,
             "reachability": p.reachability, "citations": list(p.citations)},
        )
        row["total"] += 1
        v = verdicts.get(p.id, ERROR)
        if v in (GAP, GAP_REWRITE):
            row["gaps"] += 1
        elif v == HELD:
            row["held"] += 1
        else:
            row["errors"] += 1
    return out


def missed_classes(roll: dict) -> list[str]:
    """Technique classes with >=1 gap, most-missed first, ties by corpus order."""
    classes: OrderedDict[str, int] = OrderedDict()
    for enc_id, row in roll.items():
        if row["gaps"]:
            classes[row["class"]] = classes.get(row["class"], 0) + row["gaps"]
    return [c for c, _ in sorted(classes.items(), key=lambda kv: -kv[1])]
