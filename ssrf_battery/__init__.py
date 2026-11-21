"""ssrf-battery: guard-semantics classifier for SSRF validation surfaces.

Battery of address-encoding probes (NAT64/IDNA/IPv6-literal/alt-notation/
parser-differential) run against a URL-validation guard — in-process function
or HTTP fetch endpoint — producing report-grade evidence of exactly which
encodings the guard misses. Prior art and taxonomy: see PRIOR-ART.md, README.
"""

__version__ = "0.1.0"
