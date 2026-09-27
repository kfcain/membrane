"""Shared registry subcommands: validate, list, hash."""
from __future__ import annotations

import json
from pathlib import Path

from .manifest import DEFAULT_REGISTRY, ManifestError, load_registry


def _validate(args) -> int:
    try:
        reg = load_registry(Path(args.registry))
    except ManifestError as exc:
        print(f"FAIL {exc}")
        return 1
    for m in reg.values():
        print(f"OK   {m.id:24} tier={m.tier} sha256={m.sha256[:16]}")
    return 0


def _list(args) -> int:
    reg = load_registry(Path(args.registry))
    print(json.dumps({k: {"tier": m.tier, "status": m.spec["status"], "sha256": m.sha256} for k, m in reg.items()}, indent=2))
    return 0


def register(sub) -> None:
    p = sub.add_parser("validate", help="Validate every manifest against the schema.")
    p.add_argument("--registry", default=str(DEFAULT_REGISTRY))
    p.set_defaults(func=_validate)
    p = sub.add_parser("list", help="List registered agents with tier, status, and manifest hash.")
    p.add_argument("--registry", default=str(DEFAULT_REGISTRY))
    p.set_defaults(func=_list)
