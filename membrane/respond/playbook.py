"""Graduated response steps. Each step updates the overrides file atomically
and lists the external actions an operator (or automation) runs in the cluster.

This module never runs kubectl or spire-server. External actions always carry
dry_run true and result "not_run".
"""
from __future__ import annotations

from pathlib import Path

from .. import evidence
from ..gateway.state import locked, read_overrides, write_overrides
from ..gateway.tokens import DEFAULT_TRUST_DOMAIN, spiffe_id_for
from ..manifest import Manifest

STEP_MODE = {"throttle": "throttled", "restrict": "restricted", "quarantine": "quarantined", "kill": "killed"}
STEPS = (*STEP_MODE, "restore")
AGENT_LABEL = "membrane.io/agent-id"
SOURCE = "membrane.respond"


def external_actions(step: str, m: Manifest | None, agent_id: str) -> list[dict]:
    """Commands this step WOULD run. None of them runs here."""
    rt = (m.spec.get("runtime") if m else None) or {}
    ns = rt.get("namespace") or "<namespace>"
    sel = f"{AGENT_LABEL}={agent_id}"
    spiffe = spiffe_id_for(m, DEFAULT_TRUST_DOMAIN) if m else f"spiffe://{DEFAULT_TRUST_DOMAIN}/<unknown>"
    cmds: list[tuple[str, str]] = []
    if step == "quarantine":
        cmds.append(("kubernetes", f"kubectl label pod -n {ns} -l {sel} membrane.io/quarantine=true --overwrite"))
    elif step == "kill":
        cmds += [
            ("kubernetes", f"kubectl label pod -n {ns} -l {sel} membrane.io/quarantine=true --overwrite"),
            ("kubernetes", f"kubectl scale deployment -n {ns} -l {sel} --replicas=0"),
            ("spire", f"spire-server entry delete -entryID <id from: spire-server entry show -spiffeID {spiffe}>"),
            ("identity", f"revoke dev identity tokens for {agent_id}: rotate var/state/dev-identity.key "
                         f"(the dev token has no per-token revocation; the gateway kill override denies meanwhile)"),
        ]
    elif step == "restore":
        cmds += [
            ("kubernetes", f"kubectl label pod -n {ns} -l {sel} membrane.io/quarantine-"),
            ("kubernetes", f"kubectl scale deployment -n {ns} -l {sel} --replicas=<replicas before kill>"),
            ("spire", "spire-server entry create -data out/generated/spire/entries.json "
                      "(re-create the entry for this agent if a kill deleted it)"),
        ]
    return [{"system": s, "command": c, "dry_run": True, "result": "not_run"} for s, c in cmds]


def apply(agent_id: str, step: str, *, reason: str, actor: str, manifest: Manifest | None,
          dry_run: bool = False, restore_to: dict | None = None, decided_at: str | None = None,
          trace_id: str | None = None) -> tuple[dict, Path | None]:
    """Apply one step. Return (response payload, evidence path or None for a dry run).

    restore_to: for step restore, the exact prior override entry to put back
    (None removes the override).
    """
    if step not in STEPS:
        raise ValueError(f"unknown step {step!r}")
    decided_at = decided_at or evidence.now_rfc3339()
    gateway_cmd = (f"set overrides.json {agent_id}.mode={STEP_MODE[step]}" if step in STEP_MODE
                   else (f"set overrides.json {agent_id} to prior entry {restore_to}" if restore_to
                         else f"remove {agent_id} from overrides.json"))
    actions = [{"system": "gateway", "command": gateway_cmd, "dry_run": dry_run,
                "result": "not_run" if dry_run else "applied"}]
    actions += external_actions(step, manifest, agent_id)
    effective_at = None
    if not dry_run:
        with locked("overrides"):
            data = read_overrides()
            if step in STEP_MODE:
                data[agent_id] = {"mode": STEP_MODE[step], "set_at": decided_at, "reason": reason}
            elif restore_to:
                data[agent_id] = restore_to
            else:
                data.pop(agent_id, None)
            write_overrides(data)
            effective_at = evidence.now_rfc3339()
    payload = {"step": step, "agent_id": agent_id, "reason": reason, "actor": actor, "actions": actions,
               "decided_at": decided_at, "effective_at": effective_at}
    if dry_run:
        return payload, None
    evidence.emit("response", SOURCE, payload, mode="live", agent_id=agent_id, trace_id=trace_id)
    return payload, evidence.evidence_dir() / "response.jsonl"
