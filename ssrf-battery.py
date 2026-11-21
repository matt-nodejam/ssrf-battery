#!/usr/bin/env python3
"""ssrf-battery: test any URL-validation surface for SSRF-guard bypasses.

Usage:
    ./ssrf-battery.py run --validator myapp.url_guard:validate_url --out out/demo
    ./ssrf-battery.py run --endpoint 'http://127.0.0.1:8787/fetch?u={URL}' --out out/fixture
    ./ssrf-battery.py serve         # stand up a local fixture endpoint to point at
    ./ssrf-battery.py selftest      # canary law: battery vs local fixtures
    ./ssrf-battery.py list          # dump the probe corpus

Stdlib-only; python >= 3.12. Endpoint mode touches loopback only unless
--engagement names a signed engagement record. Docs: README.md.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ssrf_battery.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
