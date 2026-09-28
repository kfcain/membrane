"""Offline check of the live admission probe cases.

The live workflow sends these objects to a real Kyverno webhook. This test
sends the same objects through the Rego admission policy with the same
live-registry data, so a wrong expectation fails here before a cluster run.
It does not replace the live run.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "live"))

pytestmark = pytest.mark.skipif(shutil.which("opa") is None, reason="opa not on PATH")

IMAGE_REF = "curlimages/curl@sha256:" + "b" * 64
AGENT_NAMESPACES = ["agents", "agents-finance", "agents-sandbox"]


@pytest.fixture(scope="module")
def live(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("live")
    subprocess.run([sys.executable, str(ROOT / "scripts/live/prepare.py"), "--image-ref", IMAGE_REF,
                    "--out", str(tmp / "registry")], check=True, cwd=ROOT)
    subprocess.run(["membrane", "gen", "--registry", str(tmp / "registry"), "--out", str(tmp / "generated")],
                   check=True, cwd=ROOT, env={**__import__("os").environ, "MEMBRANE_EVIDENCE_DIR": str(tmp / "ev")})
    data = json.loads((tmp / "generated/opa/data.json").read_text())
    data["kubernetes"] = {"namespaces": {ns: {"metadata": {"labels": {"membrane.io/agent-namespace": "true"}}}
                                         for ns in AGENT_NAMESPACES}}
    (tmp / "data.json").write_text(json.dumps(data))
    from membrane.manifest import load_registry
    return tmp, load_registry(tmp / "registry")


def rego_denies(tmp: Path, obj: dict) -> list:
    inp = tmp / "input.json"
    inp.write_text(json.dumps(obj))
    cp = subprocess.run(["opa", "eval", "--format=json", "-d", str(ROOT / "policy/admission/rego/admission.rego"),
                         "-d", str(tmp / "data.json"), "-i", str(inp), "data.membrane.admission.deny"],
                        capture_output=True, text=True, check=True)
    return json.loads(cp.stdout)["result"][0]["expressions"][0]["value"]


def test_each_case_matches_expectation(live):
    import probes
    tmp, reg = live
    cases = probes.admission_cases(reg, IMAGE_REF)
    assert len(cases) >= 12
    mismatches = []
    for name, expected, obj in cases:
        denies = rego_denies(tmp, obj)
        observed = "denied" if denies else "admitted"
        if observed != expected:
            mismatches.append((name, expected, observed, denies))
    assert not mismatches, mismatches


def test_egress_positive_control_is_in_manifest(live):
    import probes
    _, reg = live
    assert "example.com" in reg["invoice-reconciler"].spec["egress"]
    assert reg["kb-reader"].spec["egress"] == []
    assert any(c[3] == "ok" for c in probes.EGRESS_CASES), "a positive control must exist"


def test_classify_never_maps_errors_to_pass_states():
    import probes
    assert probes.classify(0) == "ok"
    assert probes.classify(6) == "dns_denied"
    assert probes.classify(28) == "blocked"
    assert probes.classify(127).startswith("curl_exit_")
