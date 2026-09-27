"""One evaluator per check id.

Each evaluator gets an EvalContext and returns an Outcome. The engine sets
the status word. An evaluator only lists the population it examined and the
items that miss the target. Payload shapes follow docs/CONTRACTS.md
sections 4 and 5. A payload that lacks a needed field raises KeyError; the
engine treats that as an input error and fails closed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable

AGENT_LABEL = "membrane.io/agent-id"
HASH_ANNOTATION = "membrane.io/manifest-sha256"
COMPONENT_LABEL = "membrane.io/component"


def parse_time(value: str) -> datetime:
    dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError(f"timestamp without offset: {value!r}")
    return dt


@dataclass
class EvalContext:
    now: datetime
    registry: dict            # agent_id -> membrane.manifest.Manifest
    window: dict              # kind -> eligible records inside [now - max_age, now]
    eligible: dict            # kind -> every eligible record at or before now
    all_records: dict         # kind -> every record at or before now (any mode)


@dataclass
class Outcome:
    examined: int
    offending: list = field(default_factory=list)
    record_ids: list = field(default_factory=list)
    notes: list = field(default_factory=list)


def _newest(records: list[dict]) -> dict:
    return max(records, key=lambda r: (parse_time(r["collected_at"]), r["id"]))


def _newest_inventory_per_cluster(records: list[dict]) -> list[dict]:
    best: dict[str, dict] = {}
    for r in records:
        cluster = r["payload"]["cluster"]
        if cluster not in best or (parse_time(r["collected_at"]), r["id"]) > (parse_time(best[cluster]["collected_at"]), best[cluster]["id"]):
            best[cluster] = r
    return [best[k] for k in sorted(best)]


def _agent_namespaces(registry: dict) -> set[str]:
    return {m.spec["runtime"].get("namespace") for m in registry.values() if m.spec["runtime"].get("namespace")}


# ---------------------------------------------------------------- inventory

def agt_inv_01(ctx: EvalContext) -> Outcome:
    recs = _newest_inventory_per_cluster(ctx.window["inventory"])
    namespaces = _agent_namespaces(ctx.registry)
    out = Outcome(examined=0, record_ids=[r["id"] for r in recs])
    for r in recs:
        p = r["payload"]
        for w in p["workloads"]:
            labels = w.get("labels") or {}
            agent = labels.get(AGENT_LABEL)
            in_agent_ns = w["namespace"] in namespaces
            if agent is None and not in_agent_ns:
                continue
            out.examined += 1
            reason = None
            if agent is not None and agent not in ctx.registry:
                reason = "agent_id_not_registered"
            elif agent is None and COMPONENT_LABEL not in labels:
                reason = "no_agent_id_label_in_agent_namespace"
            if reason:
                out.offending.append({
                    "cluster": p["cluster"], "namespace": w["namespace"], "name": w["name"],
                    "kind": w.get("kind"), "agent_id": agent, "service_account": w.get("service_account"),
                    "reason": reason, "record_id": r["id"],
                })
    return out


def agt_inv_02(ctx: EvalContext) -> Outcome:
    recs = _newest_inventory_per_cluster(ctx.window["inventory"])
    out = Outcome(examined=0, record_ids=[r["id"] for r in recs])
    for r in recs:
        p = r["payload"]
        for w in p["workloads"]:
            agent = (w.get("labels") or {}).get(AGENT_LABEL)
            if agent is None or agent not in ctx.registry:
                continue  # AGT-INV-01 reports these
            out.examined += 1
            observed = (w.get("annotations") or {}).get(HASH_ANNOTATION)
            expected = ctx.registry[agent].sha256
            if observed != expected:
                out.offending.append({
                    "cluster": p["cluster"], "namespace": w["namespace"], "name": w["name"], "agent_id": agent,
                    "observed_sha256": observed, "registry_sha256": expected,
                    "reason": "manifest_hash_missing" if observed is None else "manifest_hash_mismatch",
                    "record_id": r["id"],
                })
    return out


def agt_iam_02(ctx: EvalContext) -> Outcome:
    recs = _newest_inventory_per_cluster(ctx.window["inventory"])
    out = Outcome(examined=0, record_ids=[r["id"] for r in recs])
    for r in recs:
        p = r["payload"]
        by_sa: dict[str, set[str]] = {}
        by_spiffe: dict[str, set[str]] = {}
        for w in p["workloads"]:
            agent = (w.get("labels") or {}).get(AGENT_LABEL)
            if agent is None:
                continue
            out.examined += 1
            if w.get("service_account"):
                by_sa.setdefault(f"{w['namespace']}/{w['service_account']}", set()).add(agent)
            if w.get("spiffe_id"):
                by_spiffe.setdefault(w["spiffe_id"], set()).add(agent)
        for id_type, table in (("service_account", by_sa), ("spiffe_id", by_spiffe)):
            for ident in sorted(table):
                agents = sorted(table[ident])
                if len(agents) > 1:
                    out.offending.append({
                        "cluster": p["cluster"], "identity_type": id_type, "identity": ident,
                        "agent_ids": agents, "record_id": r["id"],
                    })
    return out


# ---------------------------------------------------------------- secrets

def agt_iam_01(ctx: EvalContext) -> Outcome:
    r = _newest(ctx.window["secret_scan"])
    p = r["payload"]
    out = Outcome(examined=len(p["findings"]), record_ids=[r["id"]])
    for f in p["findings"]:
        if f["in_vault"] is not True:
            out.offending.append({
                "provider": f["provider"], "location": f["location"], "fingerprint": f["fingerprint"],
                "scanner": p["scanner"], "record_id": r["id"],
            })
    return out


# ---------------------------------------------------------------- gateway

def _decisions_by_id(records: list[dict]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for r in records:
        out.setdefault(r["payload"]["decision_id"], r)
    return out


def agt_au_01(ctx: EvalContext) -> Outcome:
    execs = ctx.window["tool_exec"]
    decisions = _decisions_by_id(ctx.eligible.get("decision", []))
    ineligible = _decisions_by_id([r for r in ctx.all_records.get("decision", []) if r["id"] not in {d["id"] for d in decisions.values()}])
    out = Outcome(examined=len(execs), record_ids=[r["id"] for r in execs])
    for r in execs:
        e = r["payload"]
        d = decisions.get(e["decision_id"])
        reason = None
        if d is None:
            reason = "decision_ineligible" if e["decision_id"] in ineligible else "decision_missing"
        else:
            dp = d["payload"]
            if dp["decision"] != "allow":
                reason = "decision_not_allow"
            elif (dp["agent_id"], dp["tool"], dp["action_sha256"]) != (e["agent_id"], e["tool"], e["action_sha256"]):
                reason = "decision_mismatch"
            out.record_ids.append(d["id"])
        if reason:
            out.offending.append({
                "exec_id": e["exec_id"], "decision_id": e["decision_id"], "agent_id": e["agent_id"],
                "tool": e["tool"], "resource": e.get("resource"), "reason": reason, "record_id": r["id"],
            })
    return out


def agt_ac_01(ctx: EvalContext) -> Outcome:
    execs = [r for r in ctx.window["tool_exec"] if r["payload"]["irreversible"] is True]
    approvals: dict[str, dict] = {}
    for a in ctx.eligible.get("approval", []):
        approvals.setdefault(a["payload"]["approval_id"], a)
    out = Outcome(examined=len(execs), record_ids=[r["id"] for r in execs])
    for r in execs:
        e = r["payload"]
        aid = e.get("approval_id")
        reason = None
        if not aid:
            reason = "approval_missing"
        elif aid not in approvals:
            reason = "approval_not_found"
        else:
            ap = approvals[aid]["payload"]
            out.record_ids.append(approvals[aid]["id"])
            if ap["action_sha256"] != e["action_sha256"]:
                reason = "approval_hash_mismatch"
            elif ap.get("expires_at") and parse_time(ap["expires_at"]) < parse_time(e["executed_at"]):
                reason = "approval_expired"
        if reason:
            out.offending.append({
                "exec_id": e["exec_id"], "agent_id": e["agent_id"], "tool": e["tool"],
                "resource": e.get("resource"), "action_sha256": e["action_sha256"],
                "approval_id": aid, "reason": reason, "record_id": r["id"],
            })
    return out


def agt_ac_02(ctx: EvalContext) -> Outcome:
    allows = [r for r in ctx.window["decision"] if r["payload"]["decision"] == "allow"]
    out = Outcome(examined=0, record_ids=[r["id"] for r in allows])
    for r in allows:
        d = r["payload"]
        m = ctx.registry.get(d["agent_id"])
        if m is None or not m.spec["delegation"]["requires_delegator"]:
            continue
        out.examined += 1
        if not d.get("delegator"):
            out.offending.append({
                "decision_id": d["decision_id"], "agent_id": d["agent_id"], "tool": d["tool"],
                "resource": d.get("resource"), "record_id": r["id"],
            })
    return out


# ---------------------------------------------------------------- network

def agt_sc_01(ctx: EvalContext) -> Outcome:
    recs = ctx.window["egress_flow"]
    out = Outcome(examined=0, record_ids=[r["id"] for r in recs])
    for r in recs:
        for f in r["payload"]["flows"]:
            if f["verdict"] != "allowed":
                continue
            out.examined += 1
            m = ctx.registry.get(f["agent_id"])
            reason = None
            if m is None:
                reason = "agent_unregistered"
            elif f["destination_fqdn"] not in (m.spec.get("egress") or []):
                reason = "destination_not_in_manifest"
            if reason:
                out.offending.append({
                    "agent_id": f["agent_id"], "namespace": f.get("namespace"), "pod": f.get("pod"),
                    "destination_fqdn": f["destination_fqdn"], "destination_ip": f.get("destination_ip"),
                    "port": f.get("port"), "count": f.get("count"), "reason": reason, "record_id": r["id"],
                })
    return out


# ---------------------------------------------------------------- pipeline

def agt_cm_01(ctx: EvalContext) -> Outcome:
    runs = [r for r in ctx.window["pipeline_run"] if r["payload"]["deployed"] is True]
    out = Outcome(examined=len(runs), record_ids=[r["id"] for r in runs])
    for r in runs:
        p = r["payload"]
        g = p["gates"]
        failed: list[str] = []
        if g["manifest_policy"] != "pass":
            failed.append(f"manifest_policy:{g['manifest_policy']}")
        if g["aibom"] != "present":
            failed.append(f"aibom:{g['aibom']}")
        if g["signature"] != "verified":
            failed.append(f"signature:{g['signature']}")
        m = ctx.registry.get(p["agent_id"])
        if m is None:
            failed.append("agent_unregistered")
        elif "evals" in m.spec:
            ev = g["evals"]
            min_pass = float(m.spec["evals"]["min_pass"])
            if ev["result"] != "pass":
                failed.append(f"evals:{ev['result']}")
            score = ev.get("score")
            if score is None or float(score) < min_pass:
                failed.append(f"evals_score:{score}<{min_pass}")
        if failed:
            out.offending.append({
                "run_id": p["run_id"], "agent_id": p["agent_id"], "commit": p.get("commit"),
                "image_digest": p.get("image_digest"), "failed_gates": failed, "record_id": r["id"],
            })
    return out


# ---------------------------------------------------------------- canary and drills

def agt_tst_01(ctx: EvalContext) -> Outcome:
    r = _newest(ctx.window["canary"])
    p = r["payload"]
    out = Outcome(examined=len(p["probes"]), record_ids=[r["id"]])
    for probe in p["probes"]:
        if probe["pass"] is not True:
            out.offending.append({
                "run_id": p["run_id"], "probe": probe["probe"], "expected": probe.get("expected"),
                "observed": probe.get("observed"), "record_id": r["id"],
            })
    if p["all_pass"] is not True and not out.offending:
        out.offending.append({"run_id": p["run_id"], "probe": None, "reason": "all_pass_false", "record_id": r["id"]})
    if not p["probes"]:
        out.offending.append({"run_id": p["run_id"], "probe": None, "reason": "no_probes", "record_id": r["id"]})
    return out


def agt_ir_01(ctx: EvalContext) -> Outcome:
    r = _newest(ctx.window["kill_drill"])
    p = r["payload"]
    out = Outcome(examined=1, record_ids=[r["id"]])
    std = p.get("seconds_to_denial")
    ok = p["within_sla"] is True and std is not None and float(std) <= float(p["sla_seconds"])
    if not ok:
        out.offending.append({
            "drill_id": p["drill_id"], "agent_id": p["agent_id"], "seconds_to_denial": std,
            "sla_seconds": p["sla_seconds"], "within_sla": p["within_sla"], "record_id": r["id"],
        })
    return out


EVALUATORS: dict[str, Callable[[EvalContext], Outcome]] = {
    "AGT-INV-01": agt_inv_01,
    "AGT-INV-02": agt_inv_02,
    "AGT-IAM-01": agt_iam_01,
    "AGT-IAM-02": agt_iam_02,
    "AGT-AU-01": agt_au_01,
    "AGT-AC-01": agt_ac_01,
    "AGT-AC-02": agt_ac_02,
    "AGT-SC-01": agt_sc_01,
    "AGT-CM-01": agt_cm_01,
    "AGT-TST-01": agt_tst_01,
    "AGT-IR-01": agt_ir_01,
}
