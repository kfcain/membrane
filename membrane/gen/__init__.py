"""Generators: agent manifests to enforcement configuration, plus a drift check.

What it does:
- Reads the registry through membrane.manifest.load_registry() only.
- Writes out/generated/opa/data.json (CONTRACTS section 3 shape, manifests only).
- Writes out/generated/spire/entries.json for `spire-server entry create -data`.
  One entry per k8s agent, selectors k8s:ns and k8s:sa. The parent ID
  defaults to the node alias spiffe://example.org/spire/agent/k8s_psat/membrane.
  The operator must create that alias, for example:
  `spire-server entry create -node -spiffeID spiffe://example.org/spire/agent/k8s_psat/membrane -selector k8s_psat:cluster:<cluster>`.
  Use --parent-id to point at another alias or agent ID.
- Writes, per k8s agent, a Kubernetes NetworkPolicy that denies all egress.
  When the manifest lists egress, it also writes a CiliumNetworkPolicy that
  allows only those FQDNs on TCP 443, with the DNS proxy rule that FQDN
  policy needs. The plain policy then has no DNS allow, because a layer 4
  allow to port 53 would disable the Cilium DNS name rules. An agent with no
  egress list keeps a DNS allow to kube-dns in the plain policy.
- Writes one quarantine NetworkPolicy per agent namespace. The agent policies
  exclude pods labeled membrane.io/quarantine=true, so that label cuts all traffic.
- Writes the membrane-registry ConfigMap. One key per active agent. The value
  is JSON with the manifest hash, tier, namespace, service account, and image
  digests. Admission binds each pod to these values.
- `--check` regenerates in memory and compares with the files on disk. It exits 1 on drift.
- Every run writes one `generation` evidence record (mode "live").

What it does NOT prove:
- It does not prove that the cluster runs these objects. Only inventory and
  flow evidence from a real cluster can show that.
- Without Cilium, the FQDN policy does not apply. The plain NetworkPolicy then
  blocks all egress of an agent with an egress list, which fails closed.
- It does not prove that pods carry the membrane.io/agent-id label. Admission
  policy (policy/admission) enforces the label.
- A clean drift check proves only that the committed files match the registry.
"""
from __future__ import annotations

import sys
from pathlib import Path

from .. import evidence
from ..manifest import DEFAULT_REGISTRY, REPO_ROOT, ManifestError, load_registry, sha256_hex
from .generate import (DEFAULT_PARENT_ID, GENERATOR_VERSION, GenerationError, generate,
                       managed_files_on_disk, registry_sha256)

DEFAULT_OUT = REPO_ROOT / "out" / "generated"


def _display(out_dir: Path, rel: str) -> str:
    p = (out_dir / rel).resolve()
    try:
        return p.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return p.as_posix()


def diff(out_dir: Path, expected: dict[str, bytes]) -> list[tuple[str, str]]:
    """Return [(relative path, problem)] for drift between expected and disk."""
    problems = []
    for rel, data in expected.items():
        p = out_dir / rel
        if not p.exists():
            problems.append((rel, "missing on disk"))
        elif p.read_bytes() != data:
            problems.append((rel, "content differs"))
    for rel in managed_files_on_disk(out_dir):
        if rel not in expected:
            problems.append((rel, "not produced by the registry (stale file)"))
    return sorted(problems)


def write(out_dir: Path, expected: dict[str, bytes]) -> list[str]:
    """Write outputs. Remove stale managed files. Return removed paths."""
    for rel, data in expected.items():
        p = out_dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if not p.exists() or p.read_bytes() != data:
            p.write_bytes(data)
    removed = []
    for rel in list(managed_files_on_disk(out_dir)):
        if rel not in expected:
            (out_dir / rel).unlink()
            removed.append(rel)
    return removed


def _run(args) -> int:
    out_dir = Path(args.out)
    if not out_dir.is_absolute():
        out_dir = (Path.cwd() / out_dir)
    try:
        reg = load_registry(Path(args.registry))
        expected = generate(reg, parent_id=args.parent_id, trust_domain=args.trust_domain)
    except (ManifestError, GenerationError) as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 2

    outputs = {_display(out_dir, rel): sha256_hex(data) for rel, data in expected.items()}
    if args.check:
        problems = diff(out_dir, expected)
        payload = {"registry_sha256": registry_sha256(reg), "outputs": outputs,
                   "generator_version": GENERATOR_VERSION, "action": "check",
                   "drift": [{"path": _display(out_dir, r), "problem": why} for r, why in problems]}
        rec = evidence.emit("generation", "membrane.gen", payload, mode="live")
        if problems:
            print(f"DRIFT {len(problems)} file(s) differ from the registry:")
            for rel, why in problems:
                print(f"  {_display(out_dir, rel)}: {why}")
            print("Run `membrane gen` and commit the result.")
        else:
            print(f"OK   {len(expected)} generated files match the registry (registry_sha256={payload['registry_sha256'][:16]})")
        print(f"evidence written to {evidence.evidence_dir() / 'generation.jsonl'} (record {rec['id']})")
        return 1 if problems else 0

    removed = write(out_dir, expected)
    payload = {"registry_sha256": registry_sha256(reg), "outputs": outputs,
               "generator_version": GENERATOR_VERSION, "action": "write", "drift": []}
    rec = evidence.emit("generation", "membrane.gen", payload, mode="live")
    for rel in expected:
        print(f"wrote {_display(out_dir, rel)}")
    for rel in removed:
        print(f"removed stale {_display(out_dir, rel)}")
    print(f"evidence written to {evidence.evidence_dir() / 'generation.jsonl'} (record {rec['id']})")
    return 0


def register(sub) -> None:
    from ..gateway.tokens import DEFAULT_TRUST_DOMAIN
    p = sub.add_parser("gen", help="Generate OPA data, SPIRE entries, and network policies from the registry.")
    p.add_argument("--check", action="store_true", help="Compare generated output with disk. Exit 1 on drift.")
    p.add_argument("--registry", default=str(DEFAULT_REGISTRY))
    p.add_argument("--out", default=str(DEFAULT_OUT))
    p.add_argument("--parent-id", default=DEFAULT_PARENT_ID, help="SPIRE parent ID for every entry.")
    p.add_argument("--trust-domain", default=DEFAULT_TRUST_DOMAIN)
    p.set_defaults(func=_run)
