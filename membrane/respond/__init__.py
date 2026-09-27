"""Graduated response playbook and kill drill.

What it does:
- `membrane respond <agent> --step throttle|restrict|quarantine|kill|restore`
  sets or clears the agent entry in var/state/overrides.json. It writes a temp
  file and renames it, under a file lock. The gateway reads the file on every
  request, so the step takes effect on the next call.
- Each step writes a `response` evidence record. The record lists the
  external actions for the cluster (kubectl label for the quarantine
  NetworkPolicy, kubectl scale to zero, spire-server entry delete, token
  revocation). Those actions carry dry_run true and result not_run.
- `membrane drill kill <agent>` records the decision time, applies kill,
  polls the gateway with a valid identity token until it sees a deny with
  override_killed, writes a `kill_drill` record, then restores the prior
  override and writes a `response` restore record.

What it does NOT prove:
- It never runs kubectl or spire-server. The records do not prove that pods
  stopped, that the network cut traffic, or that SPIRE removed an entry.
- A kill drill measures denial at the gateway only. It does not measure
  time to stop a running pod or to cut a network path that bypasses the gateway.
- The dev identity token has no per-token revocation. The kill override is
  what denies the agent at the gateway.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from ..manifest import DEFAULT_REGISTRY, ManifestError, load_registry
from . import playbook


def _user() -> str:
    return os.environ.get("USER") or os.environ.get("LOGNAME") or "unknown"


def _load(registry: str, agent_id: str):
    reg = load_registry(Path(registry))
    return reg.get(agent_id)


def _respond(args) -> int:
    try:
        m = _load(args.registry, args.agent_id)
    except ManifestError as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 2
    if m is None and args.step != "restore":
        print(f"FAIL agent {args.agent_id!r} is not in the registry", file=sys.stderr)
        return 2
    actor = args.actor or _user()
    try:
        payload, path = playbook.apply(args.agent_id, args.step, reason=args.reason or f"manual {args.step}",
                                       actor=actor, manifest=m, dry_run=args.dry_run)
    except ValueError as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1
    print(f"{'DRY RUN ' if args.dry_run else ''}{args.step} {args.agent_id}")
    for a in payload["actions"]:
        print(f"  [{a['system']:10}] {'(dry run) ' if a['dry_run'] else ''}{a['command']}")
    if path:
        print(f"evidence written to {path}")
    else:
        print("dry run: overrides.json not changed; no evidence written")
    return 0


def _drill_kill(args) -> int:
    from ..gateway.client import default_gateway_url
    from .drill import run_kill_drill
    try:
        m = _load(args.registry, args.agent_id)
    except ManifestError as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 2
    if m is None:
        print(f"FAIL agent {args.agent_id!r} is not in the registry", file=sys.stderr)
        return 2
    res = run_kill_drill(m, args.gateway or default_gateway_url(), sla_seconds=args.sla,
                         actor=args.actor or _user())
    kd = res["kill_drill"]
    for p in res["paths"]:
        print(f"evidence written to {p}")
    if res["error"]:
        print(f"FAIL {res['error']}. No kill_drill record written. Prior state restored.", file=sys.stderr)
        return 2
    verdict = "PASS" if kd["within_sla"] else "FAIL"
    print(f"{verdict} kill drill {kd['drill_id']} agent={kd['agent_id']} seconds_to_denial={kd['seconds_to_denial']} "
          f"sla={kd['sla_seconds']}")
    return 0 if kd["within_sla"] else 1


def register(sub) -> None:
    p = sub.add_parser("respond", help="Apply a graduated response step to an agent.")
    p.add_argument("agent_id")
    p.add_argument("--step", required=True, choices=playbook.STEPS)
    p.add_argument("--reason", default=None)
    p.add_argument("--actor", default=None)
    p.add_argument("--dry-run", action="store_true", help="Print the plan. Change nothing. Write no evidence.")
    p.add_argument("--registry", default=str(DEFAULT_REGISTRY))
    p.set_defaults(func=_respond)

    p = sub.add_parser("drill", help="Response drills.")
    dsub = p.add_subparsers(dest="drill_cmd", required=True)
    k = dsub.add_parser("kill", help="Measure time from a kill decision to denial at the gateway.")
    k.add_argument("agent_id")
    k.add_argument("--gateway", default=None, help="Default: MEMBRANE_GATEWAY_URL or http://127.0.0.1:8750")
    k.add_argument("--sla", type=float, default=300.0)
    k.add_argument("--actor", default=None)
    k.add_argument("--registry", default=str(DEFAULT_REGISTRY))
    k.set_defaults(func=_drill_kill)
