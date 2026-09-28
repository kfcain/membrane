"""Live admission and egress probes against a kind cluster.

Run by scripts/live/run.sh after the cluster, Cilium, Kyverno, and the
generated config exist. Each probe has an expected result. The script
writes one `canary` evidence record with mode `live` (source
`live-cluster`) through membrane.evidence.emit, writes probes.json, and
exits 1 if any probe fails.

What a PASS here shows: on this kind cluster, at this time, the generated
policies denied the listed actions and allowed the positive controls. It
does not show the same for any other cluster.
"""
from __future__ import annotations

import argparse
import copy
import json
import subprocess
import sys
import uuid
from pathlib import Path

from membrane import evidence
from membrane.manifest import load_registry

SOURCE = "live-cluster"
ZERO_HASH = "0" * 64
FAKE_DIGEST = "sha256:" + "a" * 64


# ----------------------------------------------------------------- pods

def agent_pod(m, image_ref: str, name: str | None = None) -> dict:
    """A pod that matches its manifest in every bound attribute."""
    rt = m.spec["runtime"]
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": name or f"{m.id}-live",
            "namespace": rt["namespace"],
            "labels": {"membrane.io/agent-id": m.id, "membrane.io/tier": str(m.tier)},
            "annotations": {"membrane.io/manifest-sha256": m.sha256},
        },
        "spec": {
            "serviceAccountName": rt["service_account"],
            "automountServiceAccountToken": False,
            "restartPolicy": "Never",
            "containers": [{
                "name": "agent",
                "image": image_ref,
                "command": ["sleep", "3600"],
                "securityContext": {"allowPrivilegeEscalation": False},
            }],
        },
    }


def admission_cases(reg: dict, image_ref: str) -> list[tuple[str, str, dict]]:
    """(probe name, expected 'admitted'|'denied', object)."""
    inv = reg["invoice-reconciler"]
    base = agent_pod(inv, image_ref, name="adm-probe")
    tag_ref = image_ref.split("@")[0] + ":latest"
    cases: list[tuple[str, str, dict]] = [("admission_valid_pod", "admitted", base)]

    def variant(probe: str, mutate) -> None:
        obj = copy.deepcopy(base)
        mutate(obj)
        cases.append((probe, "denied", obj))

    variant("admission_wrong_namespace", lambda o: o["metadata"].update(namespace="agents"))
    variant("admission_wrong_service_account", lambda o: o["spec"].update(serviceAccountName="not-the-agent"))
    variant("admission_wrong_tier_label", lambda o: o["metadata"]["labels"].update({"membrane.io/tier": "1"}))
    variant("admission_hash_mismatch", lambda o: o["metadata"]["annotations"].update({"membrane.io/manifest-sha256": ZERO_HASH}))
    variant("admission_unpinned_image", lambda o: o["spec"]["containers"][0].update(image=tag_ref))
    variant("admission_unregistered_digest", lambda o: o["spec"]["containers"][0].update(image=image_ref.split("@")[0] + "@" + FAKE_DIGEST))
    variant("admission_unpinned_init_container", lambda o: o["spec"].update(initContainers=[{"name": "init", "image": tag_ref, "command": ["true"]}]))
    variant("admission_token_automount_tier3", lambda o: o["spec"].update(automountServiceAccountToken=True))

    def unregistered(o):
        o["metadata"].update(namespace="agents", name="shadow-summarizer")
        o["metadata"]["labels"]["membrane.io/agent-id"] = "shadow-summarizer"
        o["spec"]["serviceAccountName"] = "default"
    variant("admission_unregistered_agent_id", unregistered)

    def unlabeled(o):
        o["metadata"].update(namespace="agents", name="no-label")
        o["metadata"]["labels"] = {}
        o["metadata"]["annotations"] = {}
        o["spec"]["serviceAccountName"] = "default"
    variant("admission_unlabeled_pod_in_agent_namespace", unlabeled)

    dep = {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": "adm-probe-deploy", "namespace": "agents-finance",
                     "labels": {"membrane.io/agent-id": inv.id}},
        "spec": {"replicas": 1, "selector": {"matchLabels": {"membrane.io/agent-id": inv.id}},
                 "template": {"metadata": copy.deepcopy(base["metadata"]), "spec": copy.deepcopy(base["spec"])}},
    }
    dep["spec"]["template"]["metadata"].pop("name")
    dep["spec"]["template"]["metadata"].pop("namespace")
    dep["spec"]["template"]["spec"].pop("restartPolicy")
    dep["spec"]["template"]["spec"]["serviceAccountName"] = "not-the-agent"
    cases.append(("admission_deployment_wrong_service_account", "denied", dep))
    return cases


# ------------------------------------------------------------ kubectl

def kubectl(args: list[str], stdin: str | None = None, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(["kubectl", *args], input=stdin, capture_output=True, text=True, timeout=timeout)


def annotate(level: str, title: str, message: str) -> None:
    """Emit a GitHub annotation. The public check-runs API can read it."""
    if __import__("os").environ.get("GITHUB_ACTIONS"):
        msg = message.replace("%", "%25").replace("\r", "").replace("\n", "%0A")
        print(f"::{level} title={title}::{msg}", flush=True)


def run_admission(cases, out: Path) -> list[dict]:
    results = []
    for probe, expected, obj in cases:
        cp = kubectl(["create", "--dry-run=server", "-o", "name", "-f", "-"], stdin=json.dumps(obj))
        err = (cp.stderr or "").strip()
        if cp.returncode == 0:
            observed = "admitted"
        elif "admission webhook" in err and "denied the request" in err:
            observed = "denied"
        else:
            observed = "error"  # an error is never a PASS
        results.append({
            "probe": probe, "expected": expected, "observed": observed,
            "reasons": [err[-600:]] if err else [], "pass": observed == expected,
        })
        print(f"{'PASS' if observed == expected else 'FAIL'} {probe:48} expected={expected:8} observed={observed}")
        annotate("notice" if observed == expected else "error", f"{'PASS' if observed == expected else 'FAIL'} {probe}",
                 f"expected={expected} observed={observed} {err[-400:]}")
    (out / "admission-objects.json").write_text(json.dumps([o for _, _, o in cases], indent=1))
    return results


# ------------------------------------------------------------- egress

# curl exit codes: 0 ok, 6 could not resolve host, 7 could not connect, 28 timeout.
EGRESS_CASES = [
    # (probe, agent, url, expected, note)
    ("egress_allowed_fqdn_positive_control", "invoice-reconciler", "https://example.com", "ok",
     "FQDN in the manifest egress list. Must connect, or the other probes prove nothing."),
    ("egress_fqdn_outside_manifest", "invoice-reconciler", "https://github.com", "dns_denied",
     "Name not in the egress list. The Cilium DNS proxy must refuse the lookup (R-23)."),
    ("egress_direct_ip", "invoice-reconciler", "https://1.1.1.1", "blocked",
     "Direct IP with no DNS. The network policy must drop it."),
    ("egress_no_list_agent_https", "kb-reader", "https://example.com", "blocked",
     "Agent with an empty egress list. HTTPS must be dropped."),
    ("egress_no_list_agent_direct_ip", "kb-reader", "https://1.1.1.1", "blocked",
     "Agent with an empty egress list. Direct IP must be dropped."),
]


def classify(code: int) -> str:
    if code == 0:
        return "ok"
    if code == 6:
        return "dns_denied"
    if code in (7, 28, 35, 56):
        return "blocked"
    return f"curl_exit_{code}"


def run_egress(reg: dict, image_ref: str, out: Path) -> tuple[list[dict], list[dict]]:
    for agent in sorted({a for _, a, _, _, _ in EGRESS_CASES}):
        pod = agent_pod(reg[agent], image_ref)
        cp = kubectl(["apply", "-f", "-"], stdin=json.dumps(pod))
        if cp.returncode != 0:
            raise SystemExit(f"FAIL could not create {agent} pod: {cp.stderr}")
    for agent in sorted({a for _, a, _, _, _ in EGRESS_CASES}):
        ns = reg[agent].spec["runtime"]["namespace"]
        cp = kubectl(["wait", "--for=condition=Ready", f"pod/{agent}-live", "-n", ns, "--timeout=180s"], timeout=200)
        if cp.returncode != 0:
            raise SystemExit(f"FAIL {agent} pod not ready: {cp.stderr}")
    results = []
    for probe, agent, url, expected, note in EGRESS_CASES:
        ns = reg[agent].spec["runtime"]["namespace"]
        cp = kubectl(["exec", "-n", ns, f"{agent}-live", "--", "curl", "-sS", "-o", "/dev/null",
                      "--connect-timeout", "8", "-m", "15", "-k", url], timeout=60)
        observed = classify(cp.returncode)
        results.append({
            "probe": probe, "expected": expected, "observed": observed,
            "reasons": [note, (cp.stderr or "").strip()[-300:]], "pass": observed == expected,
        })
        print(f"{'PASS' if observed == expected else 'FAIL'} {probe:48} expected={expected:10} observed={observed}")
        annotate("notice" if observed == expected else "error", f"{'PASS' if observed == expected else 'FAIL'} {probe}",
                 f"expected={expected} observed={observed} {(cp.stderr or '').strip()[-300:]}")
    # Known limit (LIMITS.md): an agent with no egress list keeps layer 4 DNS.
    ns = reg["kb-reader"].spec["runtime"]["namespace"]
    cp = kubectl(["exec", "-n", ns, "kb-reader-live", "--", "curl", "-sS", "-o", "/dev/null",
                  "--connect-timeout", "5", "-m", "8", "https://github.com"], timeout=60)
    known = [{"limit": "dns_open_for_agent_without_egress_list", "agent": "kb-reader",
              "observed": classify(cp.returncode),
              "note": "Documented in LIMITS.md. Not a probe. 'blocked' here means the name resolved and TCP was dropped."}]
    return results, known


# --------------------------------------------------------------- main

def versions() -> dict:
    def out(cmd):
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=30).stdout.strip()[:400]
        except (OSError, subprocess.TimeoutExpired):
            return "unknown"
    return {
        "kubectl": out(["kubectl", "version", "-o", "json"]),
        "cilium": out(["cilium", "version", "--client"]),
        "kyverno_image": out(["kubectl", "get", "deploy", "-n", "kyverno", "-o",
                              "jsonpath={.items[*].spec.template.spec.containers[*].image}"]),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--registry", required=True)
    ap.add_argument("--image-ref", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    reg = load_registry(Path(args.registry))

    admission = run_admission(admission_cases(reg, args.image_ref), out)
    egress, known = run_egress(reg, args.image_ref, out)
    probes = admission + egress
    all_pass = all(p["pass"] for p in probes)
    payload = {
        "run_id": str(uuid.uuid4()),
        "environment": "kind",
        "image_ref": args.image_ref,
        "versions": versions(),
        "probes": probes,
        "known_limits": known,
        "not_run": [],
        "all_pass": all_pass,
    }
    (out / "probes.json").write_text(json.dumps(payload, indent=1))
    rec = evidence.emit("canary", SOURCE, payload, mode="live", directory=out / "evidence")
    print(f"all_pass={all_pass}; evidence record {rec['id']} in {out / 'evidence'}")
    annotate("notice", "live known limits", json.dumps(known))
    annotate("notice" if all_pass else "error", "live probes summary",
             f"all_pass={all_pass} passed={sum(p['pass'] for p in probes)}/{len(probes)} image={args.image_ref}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
