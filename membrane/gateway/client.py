"""Small HTTP client for the gateway. The canary and the kill drill use it."""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request


def default_gateway_url() -> str:
    return os.environ.get("MEMBRANE_GATEWAY_URL", "http://127.0.0.1:8750")


class GatewayUnreachable(Exception):
    """The gateway did not answer."""


def call_tool(base_url: str, identity_token: str | None, body: dict, timeout: float = 30.0,
              traceparent: str | None = None) -> tuple[int, dict]:
    headers = {"Content-Type": "application/json"}
    if identity_token:
        headers["Authorization"] = f"Bearer {identity_token}"
    if traceparent:
        headers["traceparent"] = traceparent
    req = urllib.request.Request(base_url.rstrip("/") + "/v1/tools/call", data=json.dumps(body).encode(),
                                 headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - operator-set URL
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw or b"{}")
        except ValueError:
            return exc.code, {"raw": raw.decode(errors="replace")}
    except (urllib.error.URLError, OSError) as exc:
        raise GatewayUnreachable(str(exc)) from exc


def healthz(base_url: str, timeout: float = 5.0) -> bool:
    try:
        with urllib.request.urlopen(base_url.rstrip("/") + "/healthz", timeout=timeout) as resp:  # noqa: S310
            return resp.status == 200
    except (urllib.error.URLError, OSError):
        return False
