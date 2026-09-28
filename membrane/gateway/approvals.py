"""Pending approvals, approval issue, and single use.

The gateway stores a pending approval in <state>/approvals/<id>.json when
policy returns require_approval. The pending record holds the full action:
agent_id, tool, resource, args, delegator, and action_sha256.
`membrane approve` shows that action to the approver. It signs only when the
approver restates the action hash with --confirm-action-sha256, and only when
the stored action still hashes to that value. The `approval` evidence record
carries the args that the approver saw.

Extra gateway rules (not in OPA, because OPA never sees secrets or state):
- The approver must differ from the delegator of the pending request.
- An approval token is single use. After one allowed call, the gateway marks
  the approval consumed and later presentations verify as false. OPA then
  denies with approval_mismatch.
"""
from __future__ import annotations

import json
import re
import time
import unicodedata
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .. import evidence
from .state import approvals_dir, atomic_write_json, locked
from .tokens import TokenError, action_sha256, issue_approval, verify_approval

# Strict form. Use fullmatch: "$" in re.match also matches before a final newline.
EMAIL_RE = re.compile(r"[^@\s\x00-\x1f\x7f]+@[^@\s\x00-\x1f\x7f]+\.[^@\s\x00-\x1f\x7f]+")


def is_email(value) -> bool:
    return isinstance(value, str) and EMAIL_RE.fullmatch(value) is not None


def normalize_identity(value) -> str:
    """Compare form for a person identity: strip, NFKC, casefold."""
    return unicodedata.normalize("NFKC", str(value or "")).strip().casefold()
DEFAULT_APPROVAL_TTL = 900


class ApprovalError(Exception):
    """The approval request is invalid."""


def _path(approval_id: str) -> Path:
    try:
        uuid.UUID(approval_id)
    except ValueError as exc:
        raise ApprovalError(f"approval id must be a UUID: {approval_id!r}") from exc
    return approvals_dir() / f"{approval_id}.json"


def _rfc3339(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def create_pending(*, agent_id: str, tool: str, resource, args: dict, action_sha256: str, delegator,
                   decision_id: str, trace_id: str) -> dict:
    approval_id = str(uuid.uuid4())
    rec = {"approval_id": approval_id, "action_sha256": action_sha256, "agent_id": agent_id,
           "tool": tool, "resource": resource, "args": args, "delegator": delegator, "decision_id": decision_id,
           "trace_id": trace_id, "requested_at": evidence.now_rfc3339(), "status": "pending"}
    atomic_write_json(_path(approval_id), rec, mode=0o600)
    return rec


def load(approval_id: str) -> dict:
    path = _path(approval_id)
    if not path.exists():
        raise ApprovalError(f"no pending approval {approval_id}")
    return json.loads(path.read_text(encoding="utf-8"))


def verify_pending_action(rec: dict) -> None:
    """Fail unless the stored action (agent_id, tool, resource, args) hashes to the stored action_sha256.
    So the action that the approver sees is the action that the token binds."""
    if "args" not in rec or not isinstance(rec.get("args"), dict):
        raise ApprovalError("pending approval has no args; the approver cannot see the action")
    try:
        got = action_sha256(rec["agent_id"], rec["tool"], rec["resource"], rec["args"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ApprovalError(f"pending approval is malformed: {exc}") from exc
    if got != rec.get("action_sha256"):
        raise ApprovalError("the stored action does not match the stored action_sha256; do not approve")


def describe(rec: dict) -> str:
    """The action as the approver must see it. args are canonical JSON."""
    from ..manifest import canonical_json
    return "\n".join([
        f"approval_id:    {rec.get('approval_id')}",
        f"agent_id:       {rec.get('agent_id')}",
        f"tool:           {rec.get('tool')}",
        f"resource:       {rec.get('resource')}",
        f"delegator:      {rec.get('delegator')}",
        f"args:           {canonical_json(rec.get('args')).decode('utf-8')}",
        f"requested_at:   {rec.get('requested_at')}",
        f"status:         {rec.get('status')}",
        f"action_sha256:  {rec.get('action_sha256')}",
    ])


def approve(approval_id: str, approver: str, ttl: int = DEFAULT_APPROVAL_TTL, *,
            confirm_action_sha256: str) -> tuple[str, dict, Path]:
    """Sign an approval token. Write `approval` evidence. Return (token, payload, evidence path).

    confirm_action_sha256 is the action hash that the approver reviewed. It must equal the stored hash.
    """
    if not is_email(approver):
        raise ApprovalError(f"approver must be an email address: {approver!r}")
    with locked(f"approval-{approval_id}"):
        rec = load(approval_id)
        if rec.get("status") != "pending":
            raise ApprovalError(f"approval {approval_id} is {rec.get('status')}, not pending")
        if not isinstance(confirm_action_sha256, str) or confirm_action_sha256 != rec.get("action_sha256"):
            raise ApprovalError("--confirm-action-sha256 does not equal the action hash of this request; "
                                "review the action and restate its action_sha256")
        verify_pending_action(rec)
        if rec.get("delegator") and normalize_identity(rec["delegator"]) == normalize_identity(approver):
            raise ApprovalError("approver must differ from the delegator of the request")
        now = time.time()
        exp = int(now) + int(ttl)
        token = issue_approval(approval_id, rec["action_sha256"], approver, exp)
        payload = {"approval_id": approval_id, "action_sha256": rec["action_sha256"],
                   "agent_id": rec["agent_id"], "tool": rec["tool"], "resource": rec["resource"],
                   "args": rec["args"], "delegator": rec.get("delegator"), "approver": approver,
                   # The reference takes the approver from a CLI flag. Nothing authenticates it.
                   "approver_authenticated": False, "requested_at": rec["requested_at"],
                   "approved_at": _rfc3339(now), "expires_at": _rfc3339(exp)}
        rec.update(status="approved", approver=approver, approved_at=payload["approved_at"],
                   expires_at=payload["expires_at"])
        atomic_write_json(_path(approval_id), rec, mode=0o600)
    evidence.emit("approval", "membrane.approve", payload, mode="live",
                  agent_id=rec["agent_id"], trace_id=rec.get("trace_id"))
    return token, payload, evidence.evidence_dir() / "approval.jsonl"


def check_token(token: str) -> dict:
    """Return the OPA `approval` input object. Never raises.

    verified is true only when the HMAC is valid, exp is in the future, the
    approval record exists in state as approved, and it is not consumed.
    """
    try:
        claims = verify_approval(token)
    except TokenError:
        return _unverified(token)
    try:
        rec = load(claims["approval_id"])
    except (ApprovalError, ValueError):
        return {**_claims_obj(claims), "verified": False}
    ok = (rec.get("status") == "approved" and rec.get("action_sha256") == claims["action_sha256"])
    return {**_claims_obj(claims), "verified": bool(ok)}


def _claims_obj(claims: dict) -> dict:
    return {"action_sha256": claims.get("action_sha256"), "approver": claims.get("approver"),
            "approval_id": claims.get("approval_id")}


def _unverified(token: str) -> dict:
    from .tokens import decode_unverified
    try:
        claims = decode_unverified(token)
    except TokenError:
        claims = {}
    obj = _claims_obj(claims)
    # Never echo a claim that is not a plain string.
    obj = {k: (v if isinstance(v, str) else None) for k, v in obj.items()}
    return {**obj, "verified": False}


def consume(approval_id: str, decision_id: str) -> bool:
    """Mark an approved approval as consumed. Return False if it was not approved."""
    with locked(f"approval-{approval_id}"):
        try:
            rec = load(approval_id)
        except ApprovalError:
            return False
        if rec.get("status") != "approved":
            return False
        rec.update(status="consumed", consumed_at=evidence.now_rfc3339(), consumed_by_decision=decision_id)
        atomic_write_json(_path(approval_id), rec, mode=0o600)
        return True
