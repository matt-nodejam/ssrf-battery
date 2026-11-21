"""report: deterministic, evidence-grade output (markdown + JSON).

Built as vulnerability-report evidence: header
with exact command line + corpus hash, verdict summary that names the missed
encodings, per-class rollup, then every probe with its ground truth, the
guard's action, and the verdict. Byte-deterministic in --stable mode (no
clock, fixed run id) so double runs diff clean — the canary-law evidence
pattern. Secrets law: nothing here ever embeds credentials; probes are
address encodings by construction.
"""

from __future__ import annotations

import hashlib
import json
import platform
import sys
from collections import OrderedDict

from . import classifier
from .probespec import corpus_sha256

TOOL = "ssrf-battery/0.1.0"

VERDICT_ORDER = [
    "GAP", "GAP_REWRITE", "HELD", "NEUTRALIZED", "ERROR",
    "CONTROL_SAFE_OK", "CONTROL_SAFE_BLOCKED", "CONTROL_INTERNAL_OK",
    "CONTROL_INTERNAL_ACCEPTED", "CONTROL_NEUTRALIZED",
    "CONTROL_REWRITTEN_INTERNAL",
]


def build(target_desc: str, probes, verdicts: OrderedDict, actions: dict,
          roll: OrderedDict, command: list[str], stable: bool = False,
          engagement_id: str | None = None) -> dict:
    gap_count = sum(1 for v in verdicts.values() if v in (classifier.GAP, classifier.GAP_REWRITE))
    doc = OrderedDict()
    doc["tool"] = TOOL
    doc["mode"] = "stable" if stable else "run"
    doc["run_id"] = "stable" if stable else hashlib.sha256(
        (target_desc + json.dumps(verdicts)).encode()).hexdigest()[:16]
    doc["target"] = target_desc
    doc["command"] = command
    doc["python"] = sys.version.split()[0]
    doc["platform"] = platform.platform()
    doc["probe_corpus_sha256"] = corpus_sha256()
    doc["probe_count"] = len(probes)
    doc["gap_count"] = gap_count
    doc["missed_classes"] = classifier.missed_classes(roll)
    if engagement_id:
        doc["engagement"] = engagement_id
    doc["rollup"] = roll
    doc["probes"] = [
        OrderedDict(
            id=p.id,
            cls=p.probe_class,
            encoding=p.encoding_id,
            url=p.url,
            ground_truth=p.ground_truth,
            reachability=p.reachability,
            action=actions[p.id].kind,
            action_detail=actions[p.id].detail,
            rewritten_url=actions[p.id].rewritten_url,
            verdict=verdicts[p.id],
            citations=p.citations,
        )
        for p in probes
    ]
    return doc


def to_markdown(doc: dict) -> str:
    lines = []
    a = lines.append
    a(f"# SSRF-guard battery report — {doc['target']}")
    a("")
    a(f"run `{doc['run_id']}` · {doc['tool']} · python {doc['python']} · {doc['platform']}")
    a("")
    a(f"command: `{' '.join(doc['command'])}`")
    a("")
    a(f"probe corpus sha256 `{doc['probe_corpus_sha256'][:16]}…` · {doc['probe_count']} probes")
    if doc.get("engagement"):
        a(f"engagement: `{doc['engagement']}` (authorization record)")
        a("")
    missed = doc["missed_classes"]
    a("## Verdict")
    a("")
    if missed:
        a(f"**GUARD GAPS: {doc['gap_count']}** — missed technique classes: " + ", ".join(missed))
        a("")
        a("| encoding | class | missed | of | reachability |")
        a("|---|---|---|---|---|")
        for enc, row in doc["rollup"].items():
            if row["gaps"]:
                a(f"| `{enc}` | {row['class']} | **{row['gaps']}** | {row['total']} | {row['reachability']} |")
    else:
        a(f"**No gaps detected** across {doc['probe_count']} probes (see controls below before trusting this).")
    held = [c for c, r in doc["rollup"].items() if r["held"] and not r["gaps"]]
    if held:
        a("")
        a(f"Held clean: {', '.join('`' + h + '`' for h in held)}")
    a("")
    a("## Controls")
    a("")
    a("| control | verdict |")
    a("|---|---|")
    for p in doc["probes"]:
        if p["id"].startswith("ctl-"):
            a(f"| `{p['id']}` ({p['url']}) | {p['verdict']} |")
    a("")
    a("## Per-probe evidence")
    a("")
    a("| probe | class | url | ground truth | guard action | verdict |")
    a("|---|---|---|---|---|---|")
    for p in doc["probes"]:
        act = p["action"] + (f" → {p['rewritten_url']}" if p["rewritten_url"] else "")
        a(f"| `{p['id']}` | {p['cls']} | `{p['url']}` | {p['ground_truth']} | {act} | {p['verdict']} |")
    a("")
    cites = OrderedDict()
    for p in doc["probes"]:
        for c in p["citations"]:
            cites.setdefault(c, p["encoding"])
    a("## Citations")
    a("")
    for c, enc in cites.items():
        a(f"- `{c}` — first carried by `{enc}`")
    a("")
    return "\n".join(lines) + "\n"


def write(out_dir, doc: dict) -> tuple[str, str]:
    from pathlib import Path
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    md_path = out / "report.md"
    json_path = out / "report.json"
    md_path.write_text(to_markdown(doc), encoding="utf-8")
    json_path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return str(md_path), str(json_path)
