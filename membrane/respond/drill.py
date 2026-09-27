"""Kill drill: measure time from a kill decision to the first denial at the gateway."""
from __future__ import annotations

import time
import uuid
from datetime import datetime
from pathlib import Path

from .. import evidence
from ..gateway.client import GatewayUnreachable, call_tool
from ..gateway.state import read_overrides
from ..gateway.tokens import issue_identity, spiffe_id_for
from ..manifest import Manifest
from . import playbook

SOURCE = "membrane.drill"


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def run_kill_drill(m: Manifest, gateway_url: str, *, sla_seconds: float = 300.0, actor: str = "kill-drill",
                   poll_interval: float = 0.25) -> dict:
    """Kill, poll until denial with override_killed, record, then restore the prior state.

    Returns {"kill_drill": payload, "paths": [...], "error": str | None}.
    """
    drill_id = str(uuid.uuid4())
    trace_id = uuid.uuid4().hex
    prior = read_overrides().get(m.id)
    tool = sorted(t["name"] for t in m.spec["tools"])[0]
    token = issue_identity(m.id, m.sha256, spiffe_id_for(m), ttl=int(sla_seconds) + 120)
    body = {"tool": tool, "resource": f"drill/{drill_id}", "args": {"drill_id": drill_id},
            "delegator": "kill-drill@example.com"}

    decided_at = evidence.now_rfc3339()
    t_decided = time.monotonic()
    paths: list[Path] = []
    error = None
    _, p = playbook.apply(m.id, "kill", reason=f"kill drill {drill_id}", actor=actor, manifest=m,
                          decided_at=decided_at, trace_id=trace_id)
    paths.append(p)

    observed_at = None
    try:
        while time.monotonic() - t_decided <= sla_seconds:
            status, resp = call_tool(gateway_url, token, body, traceparent=f"00-{trace_id}-{uuid.uuid4().hex[:16]}-01")
            if resp.get("decision") == "deny" and "override_killed" in (resp.get("reasons") or []):
                observed_at = evidence.now_rfc3339()
                break
            time.sleep(poll_interval)
    except GatewayUnreachable as exc:
        error = f"gateway unreachable: {exc}"
    finally:
        _, p = playbook.apply(m.id, "restore", reason=f"kill drill {drill_id} complete", actor=actor,
                              manifest=m, restore_to=prior, trace_id=trace_id)
        paths.append(p)

    seconds = round((_parse(observed_at) - _parse(decided_at)).total_seconds(), 3) if observed_at else None
    payload = {"drill_id": drill_id, "agent_id": m.id, "decided_at": decided_at,
               "denial_observed_at": observed_at, "seconds_to_denial": seconds,
               "sla_seconds": sla_seconds, "within_sla": bool(seconds is not None and seconds <= sla_seconds)}
    if error is None:
        evidence.emit("kill_drill", SOURCE, payload, mode="live", agent_id=m.id, trace_id=trace_id)
        paths.append(evidence.evidence_dir() / "kill_drill.jsonl")
    return {"kill_drill": payload, "paths": paths, "error": error}
