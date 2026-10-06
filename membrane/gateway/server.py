"""Reference tool gateway HTTP server.

POST /v1/tools/call  body {tool, resource, args, delegator, approval_token?}
                     headers Authorization: Bearer <identity token>, traceparent (optional)
GET  /healthz

Every POST produces exactly one `decision` evidence record, including
malformed requests and policy failures. Policy failures deny (fail closed).
"""
from __future__ import annotations

import json
import math
import re
import secrets
import sys
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .. import evidence
from . import approvals
from .backends import BackendRequestError, ToolBackend
from .opa import PolicyError, default_data_path, default_policy_dir, evaluate, snapshot
from .rate_limits import RateLimitStateError, SQLiteRateLimiter
from .state import read_overrides
from .tokens import TokenError, action_sha256, decode_unverified, verify_identity

MAX_BODY = 1 << 20
TRACEPARENT_RE = re.compile(r"^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")
SOURCE = "membrane.gateway"
BACKEND_SOURCE = "membrane.gateway.mock_backend"


def parse_traceparent(value: str | None) -> str:
    """Return the W3C trace id from traceparent, or a new random one."""
    if value:
        m = TRACEPARENT_RE.match(value.strip())
        if m and m.group(1) != "ff" and m.group(2) != "0" * 32 and m.group(3) != "0" * 16:
            return m.group(2)
    return secrets.token_hex(16)


@dataclass
class GatewayConfig:
    policy_dir: Path = field(default_factory=default_policy_dir)
    data_path: Path = field(default_factory=default_data_path)
    opa_bin: str | None = None
    opa_url: str | None = None
    rate_limit_db: Path | None = None


class RateLimiter:
    """Sliding 60 second window per (agent, tool). Counts only admitted calls."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._hits: dict[tuple[str, str], deque] = {}

    def admit(self, agent_id: str, tool: str, limit_per_min: int | None, now: float | None = None) -> bool:
        if not limit_per_min:
            return True
        now = time.monotonic() if now is None else now
        with self._lock:
            q = self._hits.setdefault((agent_id, tool), deque())
            while q and now - q[0] >= 60.0:
                q.popleft()
            if len(q) >= limit_per_min:
                return False
            q.append(now)
            return True


class MockToolBackend:
    """Stands in for real tools. It executes nothing. It writes `tool_exec` evidence.

    Records use mode "simulated" because no real system took the action.
    """

    def validate_request(self, *, tool: str, resource, args: dict, irreversible) -> None:
        pass

    def execute(self, *, decision_id: str, agent_id: str, tool: str, resource, args: dict, action_hash: str,
                irreversible, approval_id, trace_id: str) -> dict:
        exec_id = str(uuid.uuid4())
        payload = {"exec_id": exec_id, "decision_id": decision_id, "agent_id": agent_id, "tool": tool,
                   "resource": resource, "action_sha256": action_hash, "irreversible": irreversible,
                   "approval_id": approval_id, "executed_at": evidence.now_rfc3339(), "result": "ok"}
        evidence.emit("tool_exec", BACKEND_SOURCE, payload, mode="simulated", agent_id=agent_id, trace_id=trace_id)
        return {"status": "ok", "exec_id": exec_id}


class Gateway:
    def __init__(self, config: GatewayConfig | None = None, backend: ToolBackend | None = None) -> None:
        self.config = config or GatewayConfig()
        self.backend = backend or MockToolBackend()
        self.limiter = (SQLiteRateLimiter(self.config.rate_limit_db)
                        if self.config.rate_limit_db is not None else RateLimiter())
        self._tls = threading.local()

    # The whole request path. Returns (http status, response body).
    # Every call writes exactly one decision record. An unexpected error before the
    # record gives a deny record with reason gateway_error. An error after the
    # record does not write a second one.
    def handle_call(self, raw_body: bytes, authorization: str | None, traceparent: str | None) -> tuple[int, dict]:
        call = {"t0": time.perf_counter(), "trace_id": None, "decision_id": str(uuid.uuid4()),
                "rec": _empty_rec()}
        self._tls.written = False
        try:
            return self._handle_call(call, raw_body, authorization, traceparent)
        except Exception as exc:  # noqa: BLE001 - fail closed with a record
            detail = f"internal error: {exc!r}"[:300]
            if getattr(self._tls, "written", False):
                print(f"gateway error after the decision record {call['decision_id']}: {json.dumps(detail)}",
                      file=sys.stderr, flush=True)
                return 500, {"decision": "deny", "reasons": ["gateway_error"], "decision_id": call["decision_id"],
                             "trace_id": call["trace_id"], "action_sha256": call["rec"].get("action_sha256")}
            trace_id = call["trace_id"] or secrets.token_hex(16)
            return self._finish(500, "deny", ["gateway_error"], call["rec"], call["decision_id"], trace_id,
                                call["t0"], detail=detail)

    def _handle_call(self, call: dict, raw_body: bytes, authorization: str | None,
                     traceparent: str | None) -> tuple[int, dict]:
        t0 = call["t0"]
        trace_id = call["trace_id"] = parse_traceparent(traceparent)
        decision_id = call["decision_id"]
        rec = call["rec"]

        # 1. Identity. An invalid token still yields a claimed id for the log.
        verified_claims, claims = None, {}
        token = None
        if authorization and authorization.startswith("Bearer "):
            token = authorization[len("Bearer "):].strip()
        if token:
            try:
                verified_claims = verify_identity(token)
                claims = verified_claims
            except TokenError:
                try:
                    claims = decode_unverified(token)
                except TokenError:
                    claims = {}
        agent_id = claims.get("agent_id") if isinstance(claims.get("agent_id"), str) else None
        manifest_hash = claims.get("manifest_sha256") if isinstance(claims.get("manifest_sha256"), str) else None
        rec.update(agent_id=agent_id, manifest_sha256=manifest_hash)

        # 2. Request body.
        try:
            body = parse_request_json(raw_body or b"")
            if not isinstance(body, dict):
                raise ValueError("body must be a JSON object")
            tool = body.get("tool")
            if not isinstance(tool, str) or not tool:
                raise ValueError("tool must be a non-empty string")
            resource = body.get("resource")
            if resource is not None and not isinstance(resource, str):
                raise ValueError("resource must be a string or null")
            args = body.get("args", {})
            if args is None:
                args = {}
            if not isinstance(args, dict):
                raise ValueError("args must be an object")
            delegator = body.get("delegator")
            if delegator is not None and not isinstance(delegator, str):
                raise ValueError("delegator must be a string or null")
            if isinstance(delegator, str) and not delegator.strip():
                delegator = None  # empty or white space: no delegator (policy rule 7 decides)
            if delegator is not None and not approvals.is_email(delegator):
                raise ValueError("delegator must be an email address with no white space")
            approval_token = body.get("approval_token")
            if approval_token is not None and not isinstance(approval_token, str):
                raise ValueError("approval_token must be a string")
        except ValueError as exc:
            return self._finish(403, "deny", ["policy_error"], rec, decision_id, trace_id, t0,
                                detail=f"request parse error: {exc}")
        act_hash = action_sha256(agent_id or "", tool, resource, args)
        rec.update(tool=tool, resource=resource, delegator=delegator or None, action_sha256=act_hash)

        # 3. Approval token. OPA gets only the verified flag and the claims.
        approval_obj = approvals.check_token(approval_token) if approval_token else None
        if approval_obj:
            rec.update(approval_id=approval_obj.get("approval_id"), approver=approval_obj.get("approver"))

        input_doc = {"agent_id": agent_id or "", "identity_verified": verified_claims is not None,
                     "manifest_sha256": manifest_hash or "", "tool": tool, "action_sha256": act_hash,
                     "delegator": delegator or None, "approval": approval_obj}

        # 4. Policy. Every failure here is policy_error.
        try:
            overrides = read_overrides(strict=False)
            snap = snapshot(self.config.policy_dir, self.config.data_path, overrides)
            rec.update(policy_sha256=snap.policy_sha256, data_sha256=snap.data_sha256)
            man = snap.data["membrane"]["manifests"].get(agent_id or "")
            tool_def = (man or {}).get("tools", {}).get(tool) if isinstance(man, dict) else None
            if isinstance(man, dict):
                rec["tier"] = man.get("tier")
            if isinstance(tool_def, dict):
                rec["irreversible"] = tool_def.get("irreversible")
            result = evaluate(snap, input_doc, opa_bin=self.config.opa_bin, opa_url=self.config.opa_url)
        except (PolicyError, ValueError, OSError, TypeError, AttributeError, KeyError) as exc:
            # A data document with the wrong shape is a policy error too.
            return self._finish(403, "deny", ["policy_error"], rec, decision_id, trace_id, t0, detail=repr(exc))

        decision, reasons = result["decision"], result["reasons"]

        # Validate backend scope before issuing or consuming an approval. This never runs a tool.
        if decision in {"allow", "require_approval"}:
            try:
                self.backend.validate_request(tool=tool, resource=resource, args=args,
                                              irreversible=rec["irreversible"])
            except BackendRequestError:
                decision, reasons = "deny", ["backend_request_invalid"]

        # 5. Gateway rate limit. It only tightens an allow.
        if decision == "allow":
            limit = tool_def.get("rate_limit_per_min") if isinstance(tool_def, dict) else None
            entry = overrides.get(agent_id or "")
            if isinstance(entry, dict) and entry.get("mode") == "throttled" and limit:
                limit = max(1, int(limit) // 2)
            try:
                if not self.limiter.admit(agent_id or "", tool, limit):
                    decision, reasons = "deny", ["rate_limited"]
            except RateLimitStateError:
                return self._finish(403, "deny", ["policy_error"], rec, decision_id, trace_id, t0,
                                    detail="shared rate limit state failed")

        # 6. Single use approval. It only tightens an allow.
        if decision == "allow" and approval_obj and approval_obj.get("verified"):
            if not approvals.consume(approval_obj["approval_id"], decision_id):
                decision, reasons = "deny", ["approval_mismatch", "approval_consumed"]

        if decision == "require_approval":
            pending = approvals.create_pending(agent_id=agent_id or "", tool=tool, resource=resource,
                                               args=args, action_sha256=act_hash, delegator=delegator or None,
                                               decision_id=decision_id, trace_id=trace_id)
            rec["approval_id"], rec["approver"] = pending["approval_id"], None
            return self._finish(202, decision, reasons, rec, decision_id, trace_id, t0)

        if decision == "deny":
            return self._finish(403, decision, reasons, rec, decision_id, trace_id, t0)

        status, body_out = self._finish(200, decision, reasons, rec, decision_id, trace_id, t0)
        body_out["result"] = self.backend.execute(
            decision_id=decision_id, agent_id=agent_id or "", tool=tool, resource=resource,
            args=args, action_hash=act_hash, irreversible=rec["irreversible"],
            approval_id=rec["approval_id"] if approval_obj else None, trace_id=trace_id)
        if body_out["result"]["status"] != "ok":
            status = 502
        return status, body_out

    def _finish(self, status: int, decision: str, reasons: list[str], rec: dict, decision_id: str,
                trace_id: str, t0: float, detail: str | None = None) -> tuple[int, dict]:
        otel = {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.call.id": decision_id}
        if rec["agent_id"]:
            otel["gen_ai.agent.id"] = rec["agent_id"]
            otel["gen_ai.agent.name"] = rec["agent_id"]
        if rec["tool"]:
            otel["gen_ai.tool.name"] = rec["tool"]
        payload = {"decision_id": decision_id, "decision": decision, "reasons": list(reasons), **rec,
                   "latency_ms": round((time.perf_counter() - t0) * 1000.0, 3), "otel": otel}
        evidence.emit("decision", SOURCE, payload, mode="live", agent_id=rec["agent_id"], trace_id=trace_id)
        self._tls.written = True
        # JSON-encode every caller-controlled field, so a field cannot start a new log line.
        print(f"decision {decision:16} {','.join(reasons):40} agent={json.dumps(rec['agent_id'])} "
              f"tool={json.dumps(rec['tool'])} trace={json.dumps(trace_id)}"
              + (f" detail={json.dumps(detail)}" if detail else ""), file=sys.stderr, flush=True)
        out = {"decision": decision, "reasons": list(reasons), "decision_id": decision_id, "trace_id": trace_id,
               "action_sha256": rec["action_sha256"]}
        if decision == "require_approval":
            out["approval_id"] = rec["approval_id"]
        return status, out


def _empty_rec() -> dict:
    return {"agent_id": None, "manifest_sha256": None, "tier": None, "delegator": None, "tool": None,
            "irreversible": None, "resource": None, "action_sha256": None, "approval_id": None,
            "approver": None, "policy_sha256": None, "data_sha256": None}


class _Handler(BaseHTTPRequestHandler):
    server_version = "membrane-gateway/0.1"
    gateway: Gateway  # set on the subclass

    def log_message(self, fmt, *args):  # noqa: D401 - silence default access log
        return

    def _send(self, status: int, body: dict, trace_id: str | None = None) -> None:
        raw = json.dumps(body, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        if trace_id:
            self.send_header("traceparent", f"00-{trace_id}-{secrets.token_hex(8)}-01")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):  # noqa: N802
        if self.path == "/healthz":
            self._send(200, {"status": "ok"})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802
        if self.path != "/v1/tools/call":
            self._send(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        try:
            raw = self.rfile.read(length) if 0 <= length <= MAX_BODY else b"<invalid length>"
        except OSError:  # includes socket timeout: the client sent less than Content-Length
            raw = b"<body read timeout>"
        if 0 <= length <= MAX_BODY and len(raw) != length:
            raw = b"<short body>"
        try:
            status, body = self.gateway.handle_call(raw, self.headers.get("Authorization"),
                                                    self.headers.get("traceparent"))
        except Exception as exc:  # noqa: BLE001 - never leak a 500 without a deny
            print(f"gateway internal error: {exc!r}", file=sys.stderr)
            self._send(500, {"decision": "deny", "reasons": ["gateway_error"]})
            return
        try:
            self._send(status, body, body.get("trace_id"))
        except OSError:
            pass  # the client left; the decision record is already written


def _exact_float(literal: str) -> float:
    """Accept a JSON number with a fraction or exponent only when the float is finite and denotes
    exactly the same decimal value as the literal. Then two different literals never parse to one
    float, and one action hash never covers two different sent values."""
    value = float(literal)
    if not math.isfinite(value):
        raise ValueError(f"number out of range: {literal[:40]!r}")
    try:
        exact = Decimal(repr(value)) == Decimal(literal)
    except InvalidOperation as exc:
        raise ValueError(f"bad number: {literal[:40]!r}") from exc
    if not exact:
        raise ValueError(f"number not exact as a 64-bit float: {literal[:40]!r}")
    return value


def _reject_constant(name: str):
    raise ValueError(f"non-finite number not allowed: {name}")


MAX_DEPTH = 32


def _check_depth(obj) -> None:
    """Reject nesting deeper than MAX_DEPTH. Iterative, so it cannot overflow the stack."""
    stack = [(obj, 1)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, (dict, list)):
            if depth > MAX_DEPTH:
                raise ValueError(f"JSON nesting deeper than {MAX_DEPTH}")
            stack.extend((v, depth + 1) for v in (node.values() if isinstance(node, dict) else node))


def parse_request_json(raw: bytes):
    """Parse a request body. Reject duplicate keys, NaN, Infinity, inexact or out-of-range numbers,
    and nesting deeper than MAX_DEPTH. The args object that this returns is the object that the
    action hash covers and that the tool backend receives."""
    try:
        obj = json.loads(raw, object_pairs_hook=_no_duplicate_keys, parse_float=_exact_float,
                         parse_constant=_reject_constant)
    except RecursionError as exc:
        raise ValueError("JSON nesting too deep") from exc
    _check_depth(obj)
    return obj


def _no_duplicate_keys(pairs):
    """Reject JSON objects with a repeated key. Parsers disagree on which value wins."""
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"duplicate JSON key: {key!r}")
        obj[key] = value
    return obj


READ_TIMEOUT_SECONDS = 10.0


def make_server(host: str, port: int, gateway: Gateway | None = None,
                read_timeout: float = READ_TIMEOUT_SECONDS) -> ThreadingHTTPServer:
    # `timeout` sets a socket timeout on each connection. A client that sends less body than
    # its Content-Length then gets a deny (with a decision record) instead of holding a thread.
    handler = type("GatewayHandler", (_Handler,), {"gateway": gateway or Gateway(), "timeout": read_timeout})
    srv = ThreadingHTTPServer((host, port), handler)
    srv.daemon_threads = True
    return srv
