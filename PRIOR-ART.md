# Prior art — what exists, what it covers, what it misses

Sweep done 2026-11-20, before a line of code was written. Each entry:
what it is, what it covers, and the gap ssrf-battery fills.

## Generators (payload lists, no target semantics)

**PortSwigger URL Validation Bypass Cheat Sheet** (web app, Sep 2024 —
https://portswigger.net/research/introducing-the-url-validation-bypass-cheat-sheet)
The closest prior art. Generates loopback-address representations (IPv4
octal/hex/dword/short, **IPv4-mapped IPv6**), domain allow-list confusion,
fake relative URLs, and unicode normalization tricks (zero-width, U+2028/29).
JSON payloads on GitHub. **Misses: NAT64 entirely (not mentioned), RFC 8215
local-use prefix, 6to4/Teredo, IDNA best-fit hostname classes, IPv6 literal
variant enumeration; it is a browser tool that generates payloads — it never
records what a target guard did with them.**

**PayloadsAllTheThings — SSRF** (swisskyrepo): the classic static payload
list (dword/octal/hex/short IPv4, [::] variants, redirect + rebinding notes).
Same miss: no NAT64/IDNA families, no guard-semantics output.

**bypass-url-parser** (laluka, AGPL-3.0 — sometimes mis-attributed to
TheLupusDev, which does not exist): a "dirty curl wrapper" for **401/403 access-control
bypass** (path traversal, header tampering, verb tricks). Different problem
class entirely — reaching a protected page, not testing SSRF address-space
validation. Not a competitor; noted to keep the port honest.

## Exploitation frameworks (need a live target, no classifier)

**SSRFmap** (swisskyrepo, MIT): fuzzer/exploiter pointed at a request file +
parameter; modules for redis/fastcgi/metadata/etc. Bypass = `--level 1-5`
payload tweaks (e.g. `[::]`, `0000:`). **Misses: NAT64 (absent), IDNA,
v4-mapped; no classification of guard behavior — it fires payloads and keeps
loot.** Wrong shape for this tool: ssrf-battery tests a *guard* (often
in-process), not a parameter in a captured request.

**SSRF-to-RCE-Scanner, bane, gobypass403** and similar: scanners/targeted
exploiters; none carry the transition-encoding corpus or guard-semantics
classification.

## Advisories that established the technique classes (our citations)

The NAT64 class is not speculative — it landed repeatedly in 2025–2026:

- MCP fetch server: `64:ff9b::/96` treated as public — **GHSA-66qx-2266-pmj6**
- pydantic-ai: IPv4-compat + `64:ff9b:1::/48` + operator prefixes — **GHSA-cg7w-rg45-pc59**
- ToolHive: manual CIDR list omits NAT64 ranges — **GHSA-pph6-vfjv-vpjw**
- Roundcube: `is_local_url()` NAT64 bypass — **CVE-2026-114730**
- open-webui: internal services via NAT64 — **CVE-2026-70485**
- ip-address lib: no classifier knows `64:ff9b:1::/48` — **CVE-2026-101910**
- WWBN AVideo: NAT64/hex SSRF filter bypass — **CVE-2026-81678**, **CVE-2026-82648**
- IDNA best-fit: curl H1 **#2552179**, url-parse **#241**, MCP fetch IDNA
  check-vs-connect differential (corpus: modelcontextprotocol/servers)
- DNS-rebinding TOCTOU on outbound guards (FastGPT **CVE-2026-42344** /
  **CVE-2026-84301**, langchain **CVE-2026-41488**,
  open-webui Playwright **CVE-2026-87996**) — deliberately not built in v0.1.0
  (needs DNS infrastructure; the recipe is documented in the README)

## The demonstrated gaps = exactly what ssrf-battery adds

1. **The NAT64 battery** (RFC 6052 /96 + RFC 8215 /48) across every internal
   family — loopback, RFC1918, link-local/metadata, provider nets. No tool
   generates this family at all.
2. **IDNA/unicode-hostname + IPv6-literal variant corpus** in one declarative
   file with per-probe ground truth and reachability honesty.
3. **Guard-semantics classification**: for every probe the tool records
   accepted / rejected / rewrote / redirected (+ rewritten URL), then names
   the exact encodings the guard misses, held-clean encodings, and control
   verdicts. Nothing in prior art does this — generators stop at payload
   lists, exploiters stop at loot.
4. **Report-grade evidence output**: deterministic (stable-mode double runs
   are byte-identical), command line + corpus sha256 recorded, per-probe
   verdict table, citations per class — ready to drop into a vulnerability
   report.
5. **Function mode** (import the target's validator in-process — the
   return-a-URL validator shape) which no prior tool supports; they are all
   HTTP-out.
