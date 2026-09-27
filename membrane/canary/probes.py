"""Canary probe definitions and runner."""
from __future__ import annotations

import secrets
import time
import uuid
from pathlib import Path

from .. import evidence
from ..gateway import approvals
from ..gateway.client import GatewayUnreachable, call_tool
from ..gateway.tokens import (IDENTITY_KEY, _b64d, _b64e, issue_identity, sign, spiffe_id_for)
from ..manifest import Manifest, sha256_hex

UNREGISTERED_ID = "membrane-canary-unregistered"
DELEGATOR = "canary-delegator@example.com"
APPROVER = "canary-approver@example.com"
FORBIDDEN_TOOL = "erp.post_adjustment"
SOURCE = "membrane.canary"
NOT_RUN = [
    {"probe": "egress_fqdn_outside_manifest",
     "reason": "needs an agent pod in a cluster with Cilium; membrane canary run cannot send pod egress"},
    {"probe": "egress_direct_ip",
     "reason": "needs an agent pod in a cluster; membrane canary run cannot send pod egress"},
]


class CanaryError(Exception):
    """The canary cannot run at all."""


def _forged(token: str) -> str:
    """Change the payload and keep the old signature. The HMAC check must fail."""
    import json
    body_s, mac_s = token.split(".")
    obj = json.loads(_b64d(body_s))
    obj["manifest_sha256"] = "0" * 64
    return _b64e(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()) + "." + mac_s


def run_canary(reg: dict[str, Manifest], gateway_url: str, agent_id: str = "canary") -> tuple[dict, Path]:
    m = reg.get(agent_id)
    if m is None:
        raise CanaryError(f"canary agent {agent_id!r} is not in the registry")
    if not m.spec.get("canary"):
        raise CanaryError(f"agent {agent_id!r} does not have canary: true")
    if UNREGISTERED_ID in reg:
        raise CanaryError(f"{UNREGISTERED_ID!r} must not be in the registry")
    tool = sorted(t["name"] for t in m.spec["tools"] if not t["irreversible"])[0]
    if FORBIDDEN_TOOL in {t["name"] for t in m.spec["tools"]}:
        raise CanaryError(f"canary manifest must not list {FORBIDDEN_TOOL}")

    run_id = str(uuid.uuid4())
    trace_id = secrets.token_hex(16)
    spiffe = spiffe_id_for(m)
    good = issue_identity(m.id, m.sha256, spiffe, ttl=600)
    tokens = {
        "unregistered": issue_identity(UNREGISTERED_ID, sha256_hex(b"unregistered"),
                                       spiffe.rsplit("/sa/", 1)[0] + "/sa/unregistered", ttl=600),
        "wrong_hash": sign({"agent_id": m.id, "manifest_sha256": sha256_hex(b"tampered manifest"),
                            "spiffe_id": spiffe, "exp": int(time.time()) + 600}, IDENTITY_KEY),
        "expired": issue_identity(m.id, m.sha256, spiffe, ttl=-60),
        "forged": _forged(good),
    }

    def call(token, body):
        tp = f"00-{trace_id}-{secrets.token_hex(8)}-01"
        return call_tool(gateway_url, token, body, traceparent=tp)

    def body(t, args, delegator=DELEGATOR, **extra):
        return {"tool": t, "resource": f"canary/{run_id}", "args": {"run_id": run_id, **args},
                "delegator": delegator, **extra}

    probes: list[dict] = []

    def record(name, expected_decision, expected_reason, status, resp):
        observed = f"{resp.get('decision')}/{','.join(resp.get('reasons') or [])}"
        ok = resp.get("decision") == expected_decision and expected_reason in (resp.get("reasons") or [])
        probes.append({"probe": name, "expected": f"{expected_decision}/{expected_reason}",
                       "observed": observed, "reasons": list(resp.get("reasons") or []),
                       "http_status": status, "pass": bool(ok)})
        return resp

    plan = [
        ("unregistered_agent", "deny", "agent_unregistered", tokens["unregistered"], body(tool, {"p": "a"})),
        ("tool_not_in_manifest", "deny", "tool_not_in_manifest", good, body(FORBIDDEN_TOOL, {"p": "b"})),
        ("delegator_required", "deny", "delegator_required", good, body(tool, {"p": "c"}, delegator=None)),
        ("approval_required", "require_approval", "approval_required", good, body(tool, {"p": "d"})),
    ]
    first = True
    pending = None
    for name, dec, reason, tok, b in plan:
        try:
            status, resp = call(tok, b)
        except GatewayUnreachable as exc:
            if first:
                raise CanaryError(f"gateway {gateway_url} unreachable: {exc}. No evidence written.") from exc
            status, resp = 0, {"decision": "unreachable", "reasons": []}
        first = False
        record(name, dec, reason, status, resp)
        if name == "approval_required":
            pending = resp.get("approval_id")

    # (e) Replay: approve action A (probe d), present the token for action B.
    if pending:
        try:
            token_a, _, _ = approvals.approve(pending, APPROVER, ttl=300)
            status, resp = call(good, body(tool, {"p": "e-other-action"}, approval_token=token_a))
        except approvals.ApprovalError as exc:
            status, resp = 0, {"decision": f"approve_failed:{exc}", "reasons": []}
    else:
        status, resp = 0, {"decision": "skipped_no_pending_approval", "reasons": []}
    # CONTRACTS section 3, rule 9: a presented approval that does not match
    # this action hash is denied. It must not open a new approval request.
    record("approval_replay", "deny", "approval_mismatch", status, resp)

    for name, dec, reason, tok in [
        ("manifest_hash_mismatch", "deny", "manifest_hash_mismatch", tokens["wrong_hash"]),
        ("expired_identity", "deny", "identity_unverified", tokens["expired"]),
        ("forged_identity", "deny", "identity_unverified", tokens["forged"]),
    ]:
        try:
            status, resp = call(tok, body(tool, {"p": name}))
        except GatewayUnreachable:
            status, resp = 0, {"decision": "unreachable", "reasons": []}
        record(name, dec, reason, status, resp)

    payload = {"run_id": run_id, "gateway": gateway_url, "probes": probes, "not_run": NOT_RUN,
               "all_pass": all(p["pass"] for p in probes)}
    evidence.emit("canary", SOURCE, payload, mode="live", agent_id=m.id, trace_id=trace_id)
    return payload, evidence.evidence_dir() / "canary.jsonl"
