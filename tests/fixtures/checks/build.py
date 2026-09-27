"""Build the test-only evidence set for the check engine tests.

Run: python tests/fixtures/checks/build.py

This set covers every kind the checks read. It is for unit tests only.
Records use mode "live" so that the tests can exercise the live path
without --allow-nonlive. They are not observations of a real system.
The registry copy in ./registry pins the manifest hashes for these tests.

Anchor 2026-09-27T12:00:00Z. Tests run with --now 2026-09-27T13:00:00Z.

Deliberate problems, one or more per check:
- AGT-INV-01: ghost-agent (label not registered), shadow-job (no label in agents-finance).
- AGT-INV-02: code-runner drifted hash.
- AGT-IAM-01: one key outside the vault.
- AGT-IAM-02: ghost-agent reuses the kb-reader service account and SPIFFE id.
- AGT-AU-01: exec e3 with no decision, exec e5 on a deny decision.
- AGT-AC-01: irreversible exec e4 with no approval, exec e6 with an approval for another hash.
- AGT-AC-02: allow decision d3 for code-runner with no delegator.
- AGT-SC-01: invoice-reconciler to pastebin.example.net allowed.
- AGT-CM-01: invoice-reconciler deploy with eval score below min_pass.
- AGT-TST-01: newest canary run passes; an older run failed.
- AGT-IR-01: newest drill within SLA.
"""
from __future__ import annotations

import hashlib
import json
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent.parent
sys.path.insert(0, str(ROOT))

from membrane.evidence import make_record  # noqa: E402
from membrane.manifest import canonical_json, load_registry  # noqa: E402

ANCHOR = datetime(2026, 9, 27, 12, 0, 0, tzinfo=timezone.utc)
NS = uuid.UUID("a4f3e2d1-0c9b-5a8f-8e7d-6c5b4a392817")
REGISTRY = HERE / "registry"
OUT = HERE / "evidence"


def ts(**delta) -> str:
    return (ANCHOR + timedelta(**delta)).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def uid(*parts: str) -> str:
    return str(uuid.uuid5(NS, "|".join(parts)))


def rec(kind: str, key: str, payload: dict, at: str, *, mode: str = "live", agent_id: str | None = None) -> dict:
    r = make_record(kind, f"test-fixture:{kind}", payload, mode=mode, agent_id=agent_id, collected_at=at)
    r["id"] = uid("record", kind, key)
    return r


def action_hash(agent_id: str, tool: str, resource: str, args: dict) -> str:
    return hashlib.sha256(canonical_json({"agent_id": agent_id, "tool": tool, "resource": resource, "args": args})).hexdigest()


def workload(ns, name, sa, labels, annotations, spiffe=True):
    return {"namespace": ns, "name": name, "kind": "Deployment", "service_account": sa,
            "spiffe_id": f"spiffe://example.org/ns/{ns}/sa/{sa}" if spiffe else None,
            "labels": labels, "annotations": annotations, "images": [f"registry.example.com/{name}@sha256:" + "a" * 64]}


def agent_wl(m, sha=None, name=None, sa=None, agent_label=None):
    rt = m.spec["runtime"]
    return workload(rt["namespace"], name or m.id, sa or rt["service_account"],
                    {"membrane.io/agent-id": agent_label or m.id}, {"membrane.io/manifest-sha256": sha or m.sha256})


def decision(key, agent, tool, resource, *, verdict="allow", delegator="alice@example.com", irreversible=False,
             approval_id=None, at=None, reg=None):
    m = reg[agent]
    ah = action_hash(agent, tool, resource, {"k": key})
    p = {"decision_id": uid("decision", key), "decision": verdict, "reasons": ["within_manifest" if verdict == "allow" else "tool_not_in_manifest"],
         "agent_id": agent, "manifest_sha256": m.sha256, "tier": m.tier, "delegator": delegator,
         "tool": tool, "irreversible": irreversible, "resource": resource, "action_sha256": ah,
         "approval_id": approval_id, "approver": "bob@example.com" if approval_id else None,
         "policy_sha256": "1" * 64, "data_sha256": "2" * 64, "latency_ms": 2.5,
         "otel": {"gen_ai.operation.name": "execute_tool", "gen_ai.agent.id": agent, "gen_ai.tool.name": tool}}
    return rec("decision", key, p, at or ts(minutes=-30), agent_id=agent)


def tool_exec(key, d, *, decision_id=None, approval_id=None, irreversible=None, at=None, action_sha256=None):
    dp = d["payload"]
    p = {"exec_id": uid("exec", key), "decision_id": decision_id or dp["decision_id"], "agent_id": dp["agent_id"],
         "tool": dp["tool"], "resource": dp["resource"], "action_sha256": action_sha256 or dp["action_sha256"],
         "irreversible": dp["irreversible"] if irreversible is None else irreversible,
         "approval_id": approval_id, "executed_at": at or ts(minutes=-29), "result": "ok"}
    return rec("tool_exec", key, p, at or ts(minutes=-29), agent_id=dp["agent_id"])


def approval(key, d, *, action_sha256=None, expires=None):
    dp = d["payload"]
    p = {"approval_id": uid("approval", key), "action_sha256": action_sha256 or dp["action_sha256"],
         "agent_id": dp["agent_id"], "tool": dp["tool"], "resource": dp["resource"], "approver": "bob@example.com",
         "requested_at": ts(minutes=-40), "approved_at": ts(minutes=-35), "expires_at": expires or ts(minutes=20)}
    return rec("approval", key, p, ts(minutes=-35), agent_id=dp["agent_id"])


def build() -> dict[str, list[dict]]:
    reg = load_registry(REGISTRY)
    kb, tt, ir, cr, ca = (reg[x] for x in ("kb-reader", "ticket-triager", "invoice-reconciler", "code-runner", "canary"))

    inventory = [rec("inventory", "inv-1", {"cluster": "test-cluster", "observed_at": ts(minutes=-5), "workloads": [
        agent_wl(kb), agent_wl(tt), agent_wl(ir), agent_wl(cr, sha="f" * 64), agent_wl(ca),
        agent_wl(kb, name="ghost-agent", agent_label="ghost-agent", sha="e" * 64),
        workload("agents-finance", "shadow-job", "default", {"app": "shadow-job"}, {}, spiffe=False),
        workload("membrane-system", "membrane-gateway", "membrane-gateway", {"membrane.io/component": "gateway"}, {}),
        workload("kube-system", "coredns", "coredns", {"k8s-app": "kube-dns"}, {}),
    ]}, ts(minutes=-5))]

    secret_scan = [rec("secret_scan", "scan-1", {"scanner": "test-scanner", "scanned_at": ts(hours=-1), "targets": ["repo-a", "vault:kv"],
                                                 "findings": [
                                                     {"provider": "openai", "location": "repo-a:app.py:3", "fingerprint": "fp-1", "in_vault": False},
                                                     {"provider": "anthropic", "location": "vault:kv/agents/x", "fingerprint": "fp-2", "in_vault": True}]},
                       ts(hours=-1))]

    a1_id = uid("approval", "a1")
    d1 = decision("d1", "invoice-reconciler", "erp.post_adjustment", "invoice/INV-1001", irreversible=True, approval_id=a1_id, reg=reg)
    d2 = decision("d2", "kb-reader", "kb.search", "kb/doc-1", reg=reg)
    d3 = decision("d3", "code-runner", "sandbox.exec", "sandbox/s-1", delegator=None, reg=reg)
    d4 = decision("d4", "kb-reader", "kb.delete", "kb/doc-2", verdict="deny", reg=reg)
    d5 = decision("d5", "ticket-triager", "tickets.route", "ticket/T-9", delegator=None, reg=reg)
    d6 = decision("d6", "invoice-reconciler", "email.send_vendor_notice", "vendor/V-7", irreversible=True, reg=reg)
    a6_id = uid("approval", "a6")
    d7 = decision("d7", "invoice-reconciler", "erp.post_adjustment", "invoice/INV-1002", irreversible=True, approval_id=a6_id, reg=reg)
    decisions = [d1, d2, d3, d4, d5, d6, d7]

    a1 = approval("a1", d1)
    a6 = approval("a6", d7, action_sha256="0" * 64)
    approvals = [a1, a6]

    execs = [
        tool_exec("e1", d1, approval_id=a1_id),
        tool_exec("e2", d2),
        tool_exec("e3", d2, decision_id=uid("decision", "no-such-decision")),
        tool_exec("e4", d6),
        tool_exec("e5", d4),
        tool_exec("e6", d7, approval_id=a6_id),
        tool_exec("e7", d5),
    ]

    egress = [rec("egress_flow", "flow-1", {"window_start": ts(hours=-1), "window_end": ts(minutes=-1), "flows": [
        {"agent_id": "invoice-reconciler", "namespace": "agents-finance", "pod": "ir-1", "destination_fqdn": "erp.internal.example.com",
         "destination_ip": "10.0.0.5", "port": 443, "verdict": "allowed", "count": 10},
        {"agent_id": "invoice-reconciler", "namespace": "agents-finance", "pod": "ir-1", "destination_fqdn": "pastebin.example.net",
         "destination_ip": "198.51.100.23", "port": 443, "verdict": "allowed", "count": 1},
        {"agent_id": "code-runner", "namespace": "agents-sandbox", "pod": "cr-1", "destination_fqdn": "evil.example.net",
         "destination_ip": "198.51.100.66", "port": 443, "verdict": "denied", "count": 4},
    ]}, ts(minutes=-1))]

    def prun(key, agent, *, score, result="pass", at_h=-3, **gates):
        m = reg[agent]
        g = {"manifest_policy": "pass", "aibom": "present", "signature": "verified",
             "evals": {"suite": m.spec.get("evals", {}).get("suite", "none"), "score": score,
                       "min_pass": m.spec.get("evals", {}).get("min_pass"), "result": result}}
        g.update(gates)
        return rec("pipeline_run", key, {"run_id": key, "agent_id": agent, "commit": "c" * 40, "manifest_sha256": m.sha256,
                                         "image_digest": "sha256:" + "d" * 64, "gates": g, "deployed": True,
                                         "finished_at": ts(hours=at_h)}, ts(hours=at_h), agent_id=agent)

    pipeline = [
        prun("run-ok", "ticket-triager", score=0.95),
        prun("run-kb", "kb-reader", score=None, result="skipped"),
        prun("run-low", "invoice-reconciler", score=0.90),
    ]

    probes_ok = [{"probe": "irreversible_without_approval", "expected": "require_approval", "observed": "require_approval", "reasons": ["approval_required"], "pass": True},
                 {"probe": "canary_irreversible", "expected": "deny", "observed": "deny", "reasons": ["canary_irreversible_forbidden"], "pass": True}]
    probes_bad = [dict(probes_ok[0]), dict(probes_ok[1], observed="allow", reasons=["within_manifest"], **{"pass": False})]
    canary = [rec("canary", "c-old", {"run_id": uid("canary", "old"), "probes": probes_bad, "all_pass": False}, ts(hours=-6), agent_id="canary"),
              rec("canary", "c-new", {"run_id": uid("canary", "new"), "probes": probes_ok, "all_pass": True}, ts(hours=-2), agent_id="canary")]

    drills = [rec("kill_drill", "k1", {"drill_id": uid("drill", "k1"), "agent_id": "code-runner", "decided_at": ts(days=-10),
                                       "denial_observed_at": ts(days=-10, seconds=4), "seconds_to_denial": 4.2, "sla_seconds": 30,
                                       "within_sla": True}, ts(days=-10), agent_id="code-runner")]

    return {"inventory": inventory, "secret_scan": secret_scan, "decision": decisions, "approval": approvals,
            "tool_exec": execs, "egress_flow": egress, "pipeline_run": pipeline, "canary": canary, "kill_drill": drills}


def write_all(sets: dict[str, list[dict]], out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for kind, recs in sets.items():
        (out / f"{kind}.jsonl").write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in recs), encoding="utf-8")


if __name__ == "__main__":
    write_all(build(), OUT)
    print(f"wrote {OUT}")
