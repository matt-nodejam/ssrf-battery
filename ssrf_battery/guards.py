"""guards: adapters that drive a target through every probe and report actions.

Two modes, one Action vocabulary:

  FunctionGuard  import a validator (e.g. your app's validate_url) and call it
                 in-process. Returns -> accepted/rewrote; raises -> rejected
                 (exception name recorded) unless --strict-exceptions marks
                 unexpected types as error.

  EndpointGuard  probe an HTTP fetch endpoint (template with {URL}). Speaks a
                 JSON contract by default (fixture server) or a status-code
                 map. Redirects are recorded, not followed.

Consent wall (machine-enforced): EndpointGuard refuses any template host
that is not loopback unless --engagement names an engagement record for a
target you are authorized to test (JSON with an "engagement" id), which is
echoed into the report. Zero third-party targets get touched by accident.
"""

from __future__ import annotations

import json
import socket
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import build_opener, Request

from .classifier import GuardAction

LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


class ConsentRequired(RuntimeError):
    """Raised when the endpoint template points off-loopback with no engagement."""


def check_endpoint_consent(template: str, engagement_path: str | None) -> dict | None:
    host = urlsplit(template).hostname or ""
    if host in LOOPBACK_HOSTS or host.lower() in LOOPBACK_HOSTS:
        return None
    if not engagement_path:
        raise ConsentRequired(
            f"endpoint host {host!r} is not loopback; point at a local fixture, or "
            "pass --engagement <engagement record>.json (your signed authorization)"
        )
    try:
        with open(engagement_path, encoding="utf-8") as fh:
            record = json.load(fh)
    except (OSError, ValueError) as exc:
        raise ConsentRequired(f"--engagement file unreadable: {exc}") from exc
    if not isinstance(record, dict) or not record.get("engagement"):
        raise ConsentRequired("--engagement file has no engagement id; engagement record required")
    return record


class FunctionGuard:
    """In-process validator adapter. fn(url) -> url' | None | truthy; raises to reject."""

    def __init__(self, fn, name: str, reject_exceptions: tuple = (Exception,), strict: bool = False):
        self.fn = fn
        self.name = name
        self.reject_exceptions = reject_exceptions
        self.strict = strict

    def probe(self, url: str) -> GuardAction:
        try:
            result = self.fn(url)
        except self.reject_exceptions as exc:
            if self.strict and not isinstance(exc, self.reject_exceptions):
                return GuardAction("error", detail=type(exc).__name__)
            return GuardAction("rejected", detail=f"{type(exc).__name__}: {exc}"[:200])
        if isinstance(result, str) and result != url:
            return GuardAction("rewrote", detail="return-value", rewritten_url=result)
        return GuardAction("accepted", detail="returned")

    @classmethod
    def from_spec(cls, spec: str, **kw) -> "FunctionGuard":
        """'pkg.module:attr' or 'pkg.module:Class.method' -> callable."""
        module_name, _, attr = spec.partition(":")
        if not attr:
            raise ValueError("--validator must look like module.path:function")
        import importlib
        mod = importlib.import_module(module_name)
        obj = mod
        for part in attr.split("."):
            obj = getattr(obj, part)
        return cls(obj, spec, **kw)


def _no_redirect_opener():
    from urllib.request import HTTPRedirectHandler
    handler = type("Stop", (HTTPRedirectHandler,), {"redirect_request": lambda self, *a, **k: None})
    return build_opener(handler)


class EndpointGuard:
    """HTTP fetch-endpoint adapter.

    response='json'   fixture contract: {"action": allowed|blocked, "rewritten_url": ...}
    response='status' --map like '2xx=accepted,403=rejected,302=redirected'
    """

    def __init__(self, template: str, response: str = "json", status_map: str = "",
                 timeout: float = 5.0, engagement: str | None = None):
        if "{URL}" not in template:
            raise ValueError("endpoint template must contain {URL}")
        self.engagement_record = check_endpoint_consent(template, engagement)
        self.template = template
        self.response = response
        self.timeout = timeout
        self.map = self._parse_map(status_map) if response == "status" else None
        self.opener = _no_redirect_opener()

    @staticmethod
    def _parse_map(spec: str) -> dict:
        out = {}
        for pair in (spec or "2xx=accepted,3xx=redirected,403=rejected,401=rejected").split(","):
            code, _, action = pair.partition("=")
            out[code.strip()] = action.strip()
        return out

    def _map_status(self, status: int) -> str:
        for key, action in self.map.items():
            if key.endswith("xx"):
                if len(key) == 3 and status // 100 == int(key[0]):
                    return action
            elif key.isdigit() and status == int(key):
                return action
        return "error"

    def probe(self, url: str) -> GuardAction:
        from urllib.parse import quote
        target = self.template.replace("{URL}", quote(url, safe=""))
        req = Request(target, headers={"User-Agent": "ssrf-battery/0.1"})
        try:
            resp = self.opener.open(req, timeout=self.timeout)
            status, body = resp.status, resp.read(65536).decode("utf-8", "replace")
        except HTTPError as exc:
            status = exc.code
            if 300 <= status < 400:
                loc = exc.headers.get("Location", "")
                return GuardAction("redirected", detail=f"HTTP {status}", redirect_url=loc)
            body = exc.read(65536).decode("utf-8", "replace") if exc.fp else ""
        except (URLError, socket.timeout, OSError) as exc:
            return GuardAction("error", detail=f"transport: {exc}"[:200])

        if self.response == "json":
            try:
                doc = json.loads(body)
                action = doc.get("action", "")
                if action == "allowed":
                    rw = doc.get("rewritten_url", "")
                    if rw and rw != url:
                        return GuardAction("rewrote", detail="json-contract", rewritten_url=rw)
                    return GuardAction("accepted", detail=f"HTTP {status} allowed")
                if action == "blocked":
                    return GuardAction("rejected", detail=f"HTTP {status} blocked")
            except ValueError:
                pass
            # fall through to status semantics if the body is not the contract
            if 200 <= status < 300:
                return GuardAction("accepted", detail=f"HTTP {status} (non-contract body)")
            return GuardAction("error", detail=f"HTTP {status} uninterpretable body")

        kind = self._map_status(status)
        if kind == "redirected":
            return GuardAction("redirected", detail=f"HTTP {status}")
        return GuardAction(kind if kind in ("accepted", "rejected") else "error",
                           detail=f"HTTP {status}")
