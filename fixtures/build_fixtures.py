"""Build fixture evidence for kinds that need a real cluster.

Run: python fixtures/build_fixtures.py

Output: fixtures/evidence/{inventory,egress_flow,secret_scan,pipeline_run}.jsonl

Every record has mode "fixture". The check engine treats these records as
INELIGIBLE unless the run passes --allow-nonlive. Timestamps sit at fixed
offsets from ANCHOR. Record ids are uuid5 values. The output is the same on
every run while the registry stays the same. Rebuild after a registry change,
because the inventory annotations carry the registry manifest hashes.

Deliberate problems (so a demonstration shows a mix of results):
- shadow-summarizer runs in namespace agents with no registry entry.
- code-runner runs with a manifest hash that differs from the registry.
- invoice-reconciler has an allowed flow to pastebin.example.net.
- an OpenAI key sits in a repository, not in the vault.
- a ticket-triager deploy went out with the evals gate skipped.
"""
from __future__ import annotations

import hashlib
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from membrane.evidence import make_record  # noqa: E402
from membrane.manifest import load_registry  # noqa: E402

ANCHOR = datetime(2026, 9, 27, 12, 0, 0, tzinfo=timezone.utc)
NAMESPACE = uuid.UUID("3d0c6a52-8f1e-5b7a-9c2d-4e6f8a0b1c2d")
OUT = ROOT / "fixtures" / "evidence"
CLUSTER = "prod-use1-agents"
TRUST_DOMAIN = "example.org"
SOURCE = "fixtures/build_fixtures.py"


def ts(delta: timedelta) -> str:
    return (ANCHOR + delta).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def rid(*parts: str) -> str:
    return str(uuid.uuid5(NAMESPACE, "|".join(parts)))


def record(kind: str, payload: dict, at: timedelta, key: str, agent_id: str | None = None,
           source: str = SOURCE) -> dict:
    rec = make_record(kind, source, payload, mode="fixture", agent_id=agent_id, collected_at=ts(at))
    rec["id"] = rid(kind, key)  # deterministic; the id is not part of the payload hash
    return rec


def write(kind: str, records: list[dict], out: Path = OUT) -> Path:
    import json
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"{kind}.jsonl"
    path.write_text("".join(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n" for r in records),
                    encoding="utf-8")
    return path


def agent_workload(m, *, sha: str | None = None, name: str | None = None) -> dict:
    rt = m.spec["runtime"]
    ns, sa = rt["namespace"], rt["service_account"]
    return {
        "namespace": ns, "name": name or m.id, "kind": "Deployment", "service_account": sa,
        "spiffe_id": f"spiffe://{TRUST_DOMAIN}/ns/{ns}/sa/{sa}",
        "labels": {"app.kubernetes.io/name": m.id, "membrane.io/agent-id": m.id,
                   "membrane.io/tier": str(m.tier)},
        "annotations": {"membrane.io/manifest-sha256": sha or m.sha256},
        "images": [rt["image"]],
    }


def build() -> dict[str, list[dict]]:
    reg = load_registry()
    need = {"kb-reader", "ticket-triager", "invoice-reconciler", "code-runner", "canary"}
    missing = need - set(reg)
    if missing:
        raise SystemExit(f"registry lacks {sorted(missing)}; fixtures expect these agents")

    drifted = "9f2c4b7e1a3d5f608192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8"
    workloads = [
        agent_workload(reg["kb-reader"]),
        agent_workload(reg["ticket-triager"]),
        agent_workload(reg["invoice-reconciler"]),
        agent_workload(reg["code-runner"], sha=drifted),
        agent_workload(reg["canary"]),
        {
            "namespace": "membrane-system", "name": "membrane-gateway", "kind": "Deployment",
            "service_account": "membrane-gateway",
            "spiffe_id": f"spiffe://{TRUST_DOMAIN}/ns/membrane-system/sa/membrane-gateway",
            "labels": {"app.kubernetes.io/name": "membrane-gateway", "membrane.io/component": "gateway"},
            "annotations": {},
            "images": ["registry.example.com/membrane/gateway@sha256:" + "6" * 64],
        },
        {
            "namespace": "agents", "name": "shadow-summarizer", "kind": "Deployment",
            "service_account": "default", "spiffe_id": None,
            "labels": {"app": "shadow-summarizer", "team": "marketing-ops"},
            "annotations": {},
            "images": ["docker.io/example/llm-summarizer:latest"],
        },
    ]
    inventory = [record("inventory", {
        "cluster": CLUSTER, "observed_at": ts(timedelta(minutes=-5)), "workloads": workloads,
    }, timedelta(minutes=-5), "inventory-1", source="fixture:kube-inventory")]

    flows = [
        {"agent_id": "invoice-reconciler", "namespace": "agents-finance", "pod": "invoice-reconciler-7d9f8c6b5-x2k4q",
         "destination_fqdn": "erp.internal.example.com", "destination_ip": "10.20.4.15", "port": 443,
         "verdict": "allowed", "count": 412},
        {"agent_id": "invoice-reconciler", "namespace": "agents-finance", "pod": "invoice-reconciler-7d9f8c6b5-x2k4q",
         "destination_fqdn": "api.vendor-bank.example.com", "destination_ip": "203.0.113.40", "port": 443,
         "verdict": "allowed", "count": 37},
        {"agent_id": "invoice-reconciler", "namespace": "agents-finance", "pod": "invoice-reconciler-7d9f8c6b5-x2k4q",
         "destination_fqdn": "pastebin.example.net", "destination_ip": "198.51.100.23", "port": 443,
         "verdict": "allowed", "count": 3},
        {"agent_id": "code-runner", "namespace": "agents-sandbox", "pod": "code-runner-5c8b9d7f6-p9w2m",
         "destination_fqdn": "pypi.org", "destination_ip": "151.101.0.223", "port": 443,
         "verdict": "allowed", "count": 58},
        {"agent_id": "code-runner", "namespace": "agents-sandbox", "pod": "code-runner-5c8b9d7f6-p9w2m",
         "destination_fqdn": "files.pythonhosted.org", "destination_ip": "151.101.64.223", "port": 443,
         "verdict": "allowed", "count": 121},
        {"agent_id": "code-runner", "namespace": "agents-sandbox", "pod": "code-runner-5c8b9d7f6-p9w2m",
         "destination_fqdn": "api.openai.com", "destination_ip": "162.159.140.245", "port": 443,
         "verdict": "denied", "count": 9},
        {"agent_id": "kb-reader", "namespace": "agents", "pod": "kb-reader-6f7c9b8d4-q1z8r",
         "destination_fqdn": "raw.githubusercontent.com", "destination_ip": "185.199.108.133", "port": 443,
         "verdict": "denied", "count": 2},
    ]
    egress = [record("egress_flow", {
        "window_start": ts(timedelta(hours=-1, minutes=-10)), "window_end": ts(timedelta(minutes=-10)),
        "flows": flows,
    }, timedelta(minutes=-10), "egress-1", source="fixture:cilium-hubble")]

    secret = [record("secret_scan", {
        "scanner": "gitleaks 8.21.2",
        "scanned_at": ts(timedelta(hours=-2)),
        "targets": ["git@git.example.com:analytics/notebooks.git", "git@git.example.com:agents/invoice-reconciler.git",
                    "git@git.example.com:agents/ticket-triager.git", "vault:kv/agents"],
        "findings": [
            {"provider": "openai", "location": "git@git.example.com:analytics/notebooks.git:summarize/run.py:14",
             "fingerprint": "sha256:4b1f0c9e2d7a6b3c", "in_vault": False},
            {"provider": "anthropic", "location": "vault:kv/agents/code-runner/model-key",
             "fingerprint": "sha256:a07e33d18c5f9b21", "in_vault": True},
        ],
    }, timedelta(hours=-2), "secret-scan-1", source="fixture:secret-scanner")]

    def run(agent: str, n: int, hours: int, *, evals: dict, manifest_policy: str = "pass",
            aibom: str = "present", signature: str = "verified", deployed: bool = True,
            manifest_sha: str | None = None) -> dict:
        m = reg[agent]
        payload = {
            "run_id": f"ci-{agent}-{n}", "agent_id": agent,
            "commit": hashlib.sha1(f"{agent}:{n}".encode()).hexdigest(),
            "manifest_sha256": manifest_sha or m.sha256,
            "image_digest": m.spec["runtime"]["image"].split("@", 1)[1],
            "gates": {"manifest_policy": manifest_policy, "evals": evals, "aibom": aibom, "signature": signature},
            "deployed": deployed, "finished_at": ts(timedelta(hours=-hours)),
        }
        return record("pipeline_run", payload, timedelta(hours=-hours), f"pipeline-{agent}-{n}",
                      agent_id=agent, source="fixture:ci")

    pipeline = [
        run("kb-reader", 14, 50, evals={"suite": "none", "score": None, "min_pass": None, "result": "skipped"}),
        run("ticket-triager", 31, 26, evals={"suite": "triage-v2", "score": None, "min_pass": 0.92, "result": "skipped"}),
        run("invoice-reconciler", 22, 70, evals={"suite": "finance-v3", "score": 0.981, "min_pass": 0.97, "result": "pass"}),
        run("code-runner", 9, 120, evals={"suite": "code-safety-v1", "score": 0.991, "min_pass": 0.98, "result": "pass"}),
        run("canary", 4, 200, evals={"suite": "none", "score": 1.0, "min_pass": 1.0, "result": "pass"}),
    ]
    return {"inventory": inventory, "egress_flow": egress, "secret_scan": secret, "pipeline_run": pipeline}


def main() -> int:
    for kind, recs in build().items():
        print(f"wrote {write(kind, recs)} ({len(recs)} record(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
