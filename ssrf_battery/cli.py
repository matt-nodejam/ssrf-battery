"""cli: runs the battery against a guard and writes the evidence report."""

from __future__ import annotations

import argparse
import sys
from collections import OrderedDict
from pathlib import Path

from . import classifier, fixture, guards, probespec, report


def run_battery(guard, url_path: str = "/", corpus: Path | None = None):
    """Drive every probe through guard -> (probes, actions, verdicts, rollup)."""
    probes = probespec.generate_probes(corpus, url_path=url_path)
    actions, verdicts = {}, OrderedDict()
    for p in probes:
        action = guard.probe(p.url)
        actions[p.id] = action
        verdicts[p.id] = classifier.classify(p, action)
    roll = classifier.rollup(probes, verdicts)
    return probes, actions, verdicts, roll


def _fixture_function_guard(name: str) -> guards.FunctionGuard:
    if name == "rewrite":
        return guards.FunctionGuard(fixture.rewrite_guard, f"fixture:{name}")
    if name not in fixture.FIXTURES:
        raise SystemExit(f"unknown fixture {name!r} (naive|strict|rewrite)")

    def validate(url: str, _guard=fixture.FIXTURES[name]) -> str:
        blocked, why = _guard(url)
        if blocked:
            raise ValueError(f"blocked: {why}")
        return url

    return guards.FunctionGuard(validate, f"fixture:{name}")


def cmd_run(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="ssrf-battery run")
    ap.add_argument("--validator", help="function mode: pkg.module:callable (e.g. myapp.url_guard:validate_url)")
    ap.add_argument("--endpoint", help="endpoint mode: URL template containing {URL}")
    ap.add_argument("--response", default="json", choices=["json", "status"],
                    help="endpoint response interpretation (default: fixture JSON contract)")
    ap.add_argument("--status-map", default="", help="for --response status: '2xx=accepted,403=rejected'")
    ap.add_argument("--engagement", default=None, help="engagement record JSON (signed authorization) when endpoint is not loopback")
    ap.add_argument("--path", default="/", help="request path the probes carry (e.g. /latest/meta-data/)")
    ap.add_argument("--corpus", default=None, help="alternate probe corpus JSON")
    ap.add_argument("--out", default="out", help="output directory (report.md + report.json)")
    ap.add_argument("--stable", action="store_true", help="byte-deterministic report (canary-law double runs)")
    ap.add_argument("--name", default=None, help="human name for the target in the report")
    args = ap.parse_args(argv)

    corpus = Path(args.corpus) if args.corpus else None
    if args.validator:
        guard = guards.FunctionGuard.from_spec(args.validator)
        target = args.name or f"function:{args.validator}"
    elif args.endpoint:
        guard = guards.EndpointGuard(args.endpoint, response=args.response,
                                     status_map=args.status_map, engagement=args.engagement)
        target = args.name or f"endpoint:{args.endpoint}"
    else:
        ap.error("one of --validator or --endpoint is required")

    probes, actions, verdicts, roll = run_battery(guard, url_path=args.path, corpus=corpus)
    doc = report.build(target, probes, verdicts, actions, roll,
                       command=["ssrf-battery"] + argv, stable=args.stable,
                       engagement_id=(guard.engagement_record or {}).get("engagement")
                       if isinstance(guard, guards.EndpointGuard) else None)
    md_path, json_path = report.write(args.out, doc)
    gaps = doc["gap_count"]
    missed = ", ".join(doc["missed_classes"]) or "none"
    print(f"probes {doc['probe_count']}  gaps {gaps}  missed classes: {missed}")
    print(f"report: {md_path}  json: {json_path}")
    return 0


def cmd_selftest(argv: list[str]) -> int:
    """Canary law in one command: battery vs fixtures, determinism check."""
    from tests_canary import canary_assertions  # shipped next to the tool
    ok = canary_assertions(verbose=True)
    return 0 if ok else 1


def cmd_serve(argv: list[str]) -> int:
    """Stand up a fixture fetch endpoint locally (endpoint-mode practice target)."""
    ap = argparse.ArgumentParser(prog="ssrf-battery serve")
    ap.add_argument("--fixture", default="naive", choices=["naive", "strict", "rewrite"])
    args = ap.parse_args(argv)
    server, template = fixture.start_fixture_server(args.fixture)
    print(f"fixture {args.fixture} listening; endpoint template:")
    print(f"  {template}")
    print("Ctrl-C to stop.", flush=True)
    try:
        while True:
            import time
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()
    return 0


def cmd_list(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="ssrf-battery list")
    ap.add_argument("--corpus", default=None)
    ap.add_argument("--class", dest="probe_class", default=None)
    args = ap.parse_args(argv)
    for p in probespec.generate_probes(Path(args.corpus) if args.corpus else None):
        if args.probe_class and p.probe_class != args.probe_class:
            continue
        print(f"{p.id:34} {p.probe_class:20} {p.url}")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print("usage: ssrf-battery {run|selftest|list} …", file=sys.stderr)
        return 2
    cmd, rest = argv[0], argv[1:]
    if cmd == "run":
        return cmd_run(rest)
    if cmd == "selftest":
        return cmd_selftest(rest)
    if cmd == "list":
        return cmd_list(rest)
    if cmd == "serve":
        return cmd_serve(rest)
    print(f"unknown subcommand {cmd!r}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
