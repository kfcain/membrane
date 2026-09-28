"""Build a live-test copy of the registry.

The example manifests use placeholder image digests that no registry serves.
This script copies the registry, replaces each k8s image with one real image
pinned by digest, and gives invoice-reconciler one real, reachable egress
FQDN (example.com) as a positive control. It does not change the source
registry. The copy must still pass schema validation.

Usage: python scripts/live/prepare.py --image-ref repo@sha256:<64 hex> --out var/live/registry
"""
from __future__ import annotations

import argparse
import re
import shutil
import sys
from pathlib import Path

import yaml

from membrane.manifest import DEFAULT_REGISTRY, load_registry

POSITIVE_CONTROL_FQDN = "example.com"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--image-ref", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    if not re.fullmatch(r"[^@\s]+@sha256:[a-f0-9]{64}", args.image_ref):
        print(f"FAIL --image-ref must be repo@sha256:<64 hex>: {args.image_ref!r}", file=sys.stderr)
        return 2
    out = Path(args.out)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    for src in sorted(Path(DEFAULT_REGISTRY).glob("*.yaml")):
        doc = yaml.safe_load(src.read_text())
        spec = doc["spec"]
        if spec["runtime"]["type"] == "k8s":
            spec["runtime"]["image"] = args.image_ref
        if doc["metadata"]["id"] == "invoice-reconciler":
            spec["egress"] = [POSITIVE_CONTROL_FQDN]
        (out / src.name).write_text(yaml.safe_dump(doc, sort_keys=False))
    reg = load_registry(out)  # fail closed on a bad copy
    print(f"OK   wrote {len(reg)} live manifests to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
