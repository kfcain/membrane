"""Write the registry mock in policy/admission/kyverno/tests/values.yaml.

Run after `membrane gen` when the registry changes:
    python scripts/sync_kyverno_values.py

The Kyverno CLI has no cluster. The values file mocks the ConfigMap
membrane-system/membrane-registry for every rule that loads it. This script
copies the ConfigMap data from out/generated/k8s/membrane-registry.configmap.yaml,
so the mock and the generated ConfigMap stay equal. tests/test_policies.py
checks that they are equal.
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CONFIGMAP = ROOT / "out" / "generated" / "k8s" / "membrane-registry.configmap.yaml"
VALUES = ROOT / "policy" / "admission" / "kyverno" / "tests" / "values.yaml"
POLICY = "membrane-agent-workloads"
# Rules that load the registry ConfigMap.
RULES = [
    "pod-no-token-automount-tier3", "pod-registered", "pod-image-registered",
    "deployment-no-token-automount-tier3", "deployment-registered", "deployment-image-registered",
]
HEADER = """# Mock of ConfigMap membrane-system/membrane-registry and of namespace labels.
# The CLI has no cluster, so the values file supplies both.
# Do not edit the registry.data blocks by hand. Run: python scripts/sync_kyverno_values.py
"""


def build(values: dict, data: dict) -> dict:
    values["policies"] = [{"name": POLICY, "rules": [{"name": r, "values": {"registry.data": dict(data)}}
                                                      for r in RULES]}]
    return values


def main() -> int:
    data = yaml.safe_load(CONFIGMAP.read_text())["data"]
    values = yaml.safe_load(VALUES.read_text())
    VALUES.write_text(HEADER + yaml.safe_dump(build(values, data), sort_keys=False, width=1000))
    print(f"wrote {VALUES.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
