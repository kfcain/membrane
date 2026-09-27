"""Canary negative tests against a running gateway.

What it does:
- Mints its own dev identity tokens: one for the canary agent, one for an id
  that is not in the registry, one expired, and one validly signed with a
  wrong manifest hash.
- Sends forbidden calls and checks that the gateway returns the expected
  decision and reason. It also gets a real approval for one action and
  replays it on another action. Under CONTRACTS section 3 rule order, the
  replay gets require_approval (the canary needs approval for every tool),
  so the probe expects that. The replay must never allow.
- Writes one `canary` evidence record (mode "live") with expected and
  observed results per probe, and exits non-zero if any probe fails.

What it does NOT prove:
- Egress probes (DNS to a name outside the manifest, direct IP egress) need
  a pod in a real cluster. They do not run here. The record lists them under
  not_run. It does not report them as passed.
- It proves the gateway denies these cases now. It does not prove an agent
  cannot reach a tool by a path that skips the gateway.
- The canary needs the dev key files in the state directory, so it must run
  on the gateway host. That is a property of the dev token, not of SPIFFE.
- If the gateway does not answer at all, the run writes no record and exits 2.
"""
from __future__ import annotations

import sys
from pathlib import Path

from ..manifest import DEFAULT_REGISTRY, ManifestError, load_registry


def _run(args) -> int:
    from ..gateway.client import default_gateway_url
    from .probes import CanaryError, run_canary
    try:
        reg = load_registry(Path(args.registry))
    except ManifestError as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 2
    url = args.gateway or default_gateway_url()
    try:
        payload, path = run_canary(reg, url, agent_id=args.agent)
    except CanaryError as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 2
    for pr in payload["probes"]:
        mark = "PASS" if pr["pass"] else "FAIL"
        print(f"{mark} {pr['probe']:28} expected={pr['expected']:40} observed={pr['observed']}")
    for nr in payload["not_run"]:
        print(f"NOT RUN {nr['probe']:25} {nr['reason']}")
    print(f"all_pass={payload['all_pass']}; evidence written to {path}")
    return 0 if payload["all_pass"] else 1


def register(sub) -> None:
    p = sub.add_parser("canary", help="Negative tests against the gateway.")
    csub = p.add_subparsers(dest="canary_cmd", required=True)
    r = csub.add_parser("run", help="Run every canary probe once.")
    r.add_argument("--gateway", default=None, help="Default: MEMBRANE_GATEWAY_URL or http://127.0.0.1:8750")
    r.add_argument("--agent", default="canary", help="Registered canary agent id.")
    r.add_argument("--registry", default=str(DEFAULT_REGISTRY))
    r.set_defaults(func=_run)
