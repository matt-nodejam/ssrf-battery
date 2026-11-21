# ssrf-battery

[![tests](https://github.com/matt-nodejam/ssrf-battery/actions/workflows/ci.yml/badge.svg)](https://github.com/matt-nodejam/ssrf-battery/actions/workflows/ci.yml)

Test any URL-validation surface for SSRF-guard bypasses — and get an
evidence-grade report naming the **exact encodings** the guard misses.

Most SSRF tooling generates payloads or fires exploits. ssrf-battery does
something different: it classifies **guard semantics**. A declarative corpus
of **109 probes** (106 bypass encodings + 3 controls) is fired at one guard —
an imported validator function or an HTTP fetch endpoint — and every probe is
classified by *what the guard did* (accepted / rejected / rewrote /
redirected). The report then names the exact technique encodings that guard
misses, the ones it holds clean, and how the controls behaved. Prior art and
the full taxonomy: [PRIOR-ART.md](PRIOR-ART.md).

Stdlib-only Python ≥ 3.12. Nothing leaves the machine unless you point
endpoint mode at a target — and non-loopback endpoints are refused without an
engagement record (`--engagement`). See
[Authorized use](#authorized-use).

## The threat class it tests

Every service that fetches a user-supplied URL has a **validation
chokepoint**: an SSRF blocklist, a metadata-service guard, a webhook fetcher,
an MCP/AI fetch tool, a link-preview worker. These guards are usually built
as *a list of bad addresses* — and the list is checked against the form of
the address the guard happens to parse, not the address the fetcher will
actually connect to. IPv6 transition technologies (NAT64, 6to4, Teredo,
v4-mapped), alternative IPv4 notations, and IDNA best-fit normalization all
let an internal destination wear a public-looking costume. This class is not
speculative — it landed repeatedly in 2025–2026
(GHSA-66qx-2266-pmj6, GHSA-cg7w-rg45-pc59, GHSA-pph6-vfjv-vpjw,
CVE-2026-114730, CVE-2026-70485, CVE-2026-101910, CVE-2026-81678…).

## Probe taxonomy — 109 probes, 10 technique classes

Counts verified from the corpus generator, not from documentation:

| class | probes | what it encodes | established by |
|---|---|---|---|
| **nat64_wk** | 6 | RFC 6052 well-known `64:ff9b::/96`, internal v4 in low 32 bits (`64:ff9b::7f00:1` = 127.0.0.1, `64:ff9b::a9fe:a9fe` = cloud metadata). IANA marks it globally routable → `is_global` guards pass it. | GHSA-66qx-2266-pmj6, GHSA-pph6-vfjv-vpjw, CVE-2026-114730, CVE-2026-70485 |
| **nat64_local** | 6 | RFC 8215 local-use `64:ff9b:1::/48`. | GHSA-cg7w-rg45-pc59, CVE-2026-101910 |
| **v4_mapped** | 12 | `::ffff:127.0.0.1` / `::ffff:7f00:1`. | GHSA-cg7w-rg45-pc59, PortSwigger cheat sheet |
| **v4_compat** | 6 | deprecated `::7f00:1`. | GHSA-cg7w-rg45-pc59 |
| **sixto4** | 6 | `2002:7f00:1::` (v4 in bits 81–112). | OWASP SSRF prevention cheat sheet |
| **teredo** | 6 | `2001::80ff:fffe` (client v4 XOR 0xffffffff). | OWASP SSRF prevention cheat sheet |
| **ipv4_alt_notation** | 30 | dword `2130706433`, hex-dword, octal/hex dotted, short `127.1` — name-shaped to `ipaddress`, numeric to `inet_aton`/`getaddrinfo`. | PayloadsAllTheThings, PortSwigger cheat sheet |
| **idna_bestfit** | 18 | circled digits `①②⑦.⓪.⓪.①`, fullwidth, ideographic dots — best-fit/IDNA normalizes to internal before resolution. | curl H1 #2552179, url-parse #241 |
| **ipv6_literal_variant** | 4 | exploded/canonical IPv6 literal forms. | — |
| **allowlist_confusion** | 12 | userinfo `http://safe.example.@127.0.0.1/`, backslash-@ `http://127.0.0.1\@safe.example/`. | PortSwigger cheat sheet, Claroty URL-parsing confusion |
| *(controls)* | 3 | safe-public, safe-name, plaintext-internal — calibrate the guard before scoring it. | — |

*(phase 2: **dns_rebinding** — check-time vs connect-time TOCTOU. Deliberately
not built; see [below](#phase-2--dns-rebinding).)*

Every bypass probe carries its **ground truth** destination — the corpus
generator refuses to emit a literal that does not unwrap to its target, and
this is unit-tested — plus a **reachability** tag (`direct`, `dual-stack`,
`nat64-egress`, `resolver-conditional`, `bestfit-conditional`), so impact
framing stays honest: a NAT64 gap is high-impact on v6-first egress,
defense-in-depth on v4-only.

## Quick start

```sh
git clone https://github.com/matt-nodejam/ssrf-battery && cd ssrf-battery
python3 ssrf-battery.py selftest    # prove the battery against local fixtures first
python3 ssrf-battery.py list        # eyeball the probe corpus
python3 ssrf-battery.py serve       # stand up a local practice target (naive|strict|rewrite)
python3 ssrf-battery.py run \
  --endpoint 'http://127.0.0.1:PORT/fetch?u={URL}' --out out/demo
```

Tests: `pip install -r requirements-dev.txt && python3 -m pytest -q`

## The canary law — why every probe carries evidence markers

This is the differentiator, so it deserves its own section.

A battery that cries "GAP!" on everything is useless — you cannot tell a
finding from a false positive, and neither can a triager. ssrf-battery is
built to produce **evidence that survives triage**:

1. **Ground truth on every probe.** Each bypass probe records the internal
   destination it actually names (`[64:ff9b::a9fe:a9fe]` → `169.254.169.254`).
   The generator validates this at build time; the tests re-verify it
   independently. A probe that cannot prove its destination does not ship.
2. **Citations on every probe.** Each technique encoding carries the public
   advisory or writeup that established the class — a triager can check the
   class against history in one hop.
3. **The battery is tested against guards with known gaps.** `selftest` runs
   the whole corpus against three local fixtures: **naive** (a manually
   maintained CIDR blocklist — the most common real-world shape) with a
   manifest of exactly 16 gappy encodings and 3 held-clean ones, **strict**
   (unwraps every transition encoding — zero gaps must be reported, proving
   the tool is not a yes-machine), and **rewrite** (a return-a-URL validator).
   The battery must find *exactly* the known gap set — no more, no less —
   in function mode and again over HTTP in endpoint mode.
4. **Deterministic evidence.** With `--stable`, double runs are
   byte-identical (verified in the tests): same corpus sha256, same verdicts,
   same markdown. Attach the report; anyone can re-run and diff.

If any of that breaks, the tests fail before you ever point the tool at
something real.

## The two modes

**Function mode** — import the target's validator and test it in-process
(no prior tool supports this; exploiters are all HTTP-out):

```sh
python3 ssrf-battery.py run \
  --validator myapp.url_guard:validate_url \
  --out out/myapp --name 'myapp validate_url @ <commit>'
```

The callable receives each probe URL; a return value is `accepted` (or
`rewrote` when it differs), an exception is `rejected` (exception class
recorded verbatim).

**Endpoint mode** — probe an HTTP fetch endpoint through a `{URL}` template:

```sh
python3 ssrf-battery.py serve --fixture naive     # local practice target
python3 ssrf-battery.py run \
  --endpoint 'http://127.0.0.1:PORT/fetch?u={URL}' --out out/x
```

Interpretation is either the JSON contract (`{"action": "allowed"|"blocked",
"rewritten_url": …}` — what the bundled fixture speaks) or a status map:
`--response status --status-map '2xx=accepted,403=rejected,302=redirected'`.
Redirects are recorded, never followed.

**Consent wall:** an endpoint template whose host is not loopback raises
`ConsentRequired` unless `--engagement <file>.json` names an engagement
record (JSON with an `engagement` id) for a target you are authorized to
test, which is echoed into the report. No third-party target gets touched by
accident.

## Verdicts and output

Per probe: `GAP` (internal destination survived), `GAP_REWRITE` (rewritten,
still internal), `HELD`, `NEUTRALIZED` (rewrote/redirected somewhere provably
not internal), `CONTROL_*` (safe-accepted / safe-blocked / internal-blocked /
internal-accepted / neutralized), `ERROR` (never counted as a gap). The
rollup names **missed encodings** (`nat64_wk 6/6`) and held-clean ones; the
summary line prints the missed technique classes.

`out/<name>/report.md` + `report.json`: deterministic in `--stable` mode,
command line + corpus sha256 + per-probe citations recorded — ready to drop
into a vulnerability report.

## Phase 2 — DNS rebinding (documented recipe, deliberately not built)

No DNS infrastructure in v0.1.0 — no resolver dependency, and nothing that
could accidentally become third-party infrastructure. The TOCTOU class
(check-time vs connect-time resolution) is real and current
(CVE-2026-42344, CVE-2026-84301, CVE-2026-41488, CVE-2026-87996); when you
need it, the recipe is:

1. Stand up an authoritative nameserver for a domain you control (`nsd`, or a
   small Python authoritative server).
2. Serve **two A records with divergent TTLs**: TTL 1 answer = public bait IP
   (check-time resolution sees "global"), TTL 0 second answer = the internal
   target. Rebinding happens between the guard's `getaddrinfo` and the
   client's connect.
3. Add a `rebind` encoding family whose probes are the rebinding hostnames;
   the classifier gains one nuance: check-time-accepted +
   connect-time-internal. This needs an instrumented fetch endpoint (the
   fixture server logs both resolutions).
4. Consent still applies: pointing a guard at a hostname you control that
   answers with internal IPs is a test against the *target's* guard — run it
   only under authorization.

## Authorized use

This tool is for testing **your own** URL-validation code, or targets covered
by explicit written authorization (a bug-bounty program's scope, a pentest
contract). Read the program's rules before running anything; the consent wall
is a guardrail, not permission. Disclosure-first: report what you find
through the channel the program defines.

## Status

v0.1.0. The corpus classes are drawn from published advisory history — every
citation was verified at source before release (see
[PRIOR-ART.md](PRIOR-ART.md)). Built for and used in authorized security
audits; disclosed findings get linked here as their advisories publish.

Author: **Matt Jesc** ([matt-nodejam](https://github.com/matt-nodejam)) —
[security writeups](https://github.com/matt-nodejam/security-writeups) ·
[blog](https://matt-nodejam.github.io/)

## License

[MIT](LICENSE)
