"""Pytest wrappers for the policy part.

Each test skips when its binary is missing. Binaries resolve from PATH, or from
MEMBRANE_OPA_BIN, CONFTEST_BIN, and KYVERNO_BIN.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
POLICY = REPO / "policy"
CI = POLICY / "ci"
BAD = sorted((CI / "testdata" / "bad").glob("*.yaml"))
REGISTRY = sorted((REPO / "registry" / "agents").glob("*.yaml"))
RUNTIME_DATA = POLICY / "runtime" / "testdata" / "data.json"


def _bin(env: str, name: str) -> str | None:
    return shutil.which(os.environ.get(env, name))


OPA = _bin("MEMBRANE_OPA_BIN", "opa")
CONFTEST = _bin("CONFTEST_BIN", "conftest")
KYVERNO = _bin("KYVERNO_BIN", "kyverno")

needs_opa = pytest.mark.skipif(OPA is None, reason="opa binary not found")
needs_conftest = pytest.mark.skipif(CONFTEST is None, reason="conftest binary not found")
needs_kyverno = pytest.mark.skipif(KYVERNO is None, reason="kyverno binary not found")


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(list(args), cwd=REPO, capture_output=True, text=True, timeout=300)


def conftest(*files: Path) -> subprocess.CompletedProcess:
    return run(CONFTEST, "test", "--no-color", "--policy", str(CI), "--namespace", "membrane.ci", *map(str, files))


# ---------------------------------------------------------------- OPA / Rego


@needs_opa
def test_opa_check_strict():
    r = run(OPA, "check", "--strict", "policy/")
    assert r.returncode == 0, r.stdout + r.stderr


@needs_opa
def test_opa_fmt_clean():
    r = run(OPA, "fmt", "--list", "policy/")
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "", f"files need opa fmt: {r.stdout}"


@needs_opa
def test_opa_unit_tests():
    # YAML files under policy/ are conftest inputs and Kyverno documents, not OPA data.
    r = run(OPA, "test", "policy/", "--ignore", "*.yaml", "-v")
    assert r.returncode == 0, r.stdout + r.stderr
    m = re.search(r"PASS: (\d+)/(\d+)", r.stdout)
    assert m and m.group(1) == m.group(2), r.stdout


def _authz(req: dict, data_file: Path = RUNTIME_DATA) -> dict:
    r = subprocess.run(
        [OPA, "eval", "--format", "raw", "--stdin-input",
         "-d", str(POLICY / "runtime" / "authz.rego"), "-d", str(data_file),
         "data.membrane.authz.result"],
        input=json.dumps(req), cwd=REPO, capture_output=True, text=True, timeout=60,
    )
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


@needs_opa
def test_authz_against_registry_data():
    data = json.loads(RUNTIME_DATA.read_text())["membrane"]["manifests"]
    inv = {
        "agent_id": "invoice-reconciler", "identity_verified": True,
        "manifest_sha256": data["invoice-reconciler"]["sha256"],
        "tool": "erp.post_adjustment", "action_sha256": "a" * 64,
        "delegator": "alice@example.com", "approval": None,
    }
    assert _authz(inv) == {"decision": "require_approval", "reasons": ["approval_required"]}
    ok = dict(inv, approval={"verified": True, "action_sha256": "a" * 64, "approver": "bob@example.com", "approval_id": "x"})
    assert _authz(ok) == {"decision": "allow", "reasons": ["within_manifest"]}
    kb = {
        "agent_id": "kb-reader", "identity_verified": True,
        "manifest_sha256": data["kb-reader"]["sha256"], "tool": "kb.search",
        "action_sha256": "b" * 64, "delegator": "carol@example.com", "approval": None,
    }
    assert _authz(kb) == {"decision": "allow", "reasons": ["within_manifest"]}
    assert _authz(dict(kb, tool="kb.delete"))["reasons"] == ["tool_not_in_manifest"]


@needs_opa
def test_authz_killed_override(tmp_path):
    doc = json.loads(RUNTIME_DATA.read_text())
    doc["membrane"]["overrides"] = {"invoice-reconciler": {"mode": "killed", "set_at": "2026-09-27T00:00:00Z", "reason": "drill"}}
    f = tmp_path / "data.json"
    f.write_text(json.dumps(doc))
    req = {
        "agent_id": "invoice-reconciler", "identity_verified": True,
        "manifest_sha256": doc["membrane"]["manifests"]["invoice-reconciler"]["sha256"],
        "tool": "erp.read_invoices", "action_sha256": "c" * 64, "delegator": "alice@example.com",
        "approval": {"verified": True, "action_sha256": "c" * 64, "approver": "bob@example.com", "approval_id": "x"},
    }
    assert _authz(req, f) == {"decision": "deny", "reasons": ["override_killed"]}


def test_runtime_testdata_matches_registry():
    """policy/runtime/testdata/data.json must follow the registry (contract section 3 shape)."""
    from membrane.gen.generate import k8s_binding
    from membrane.manifest import load_registry

    want = {}
    for aid, m in load_registry().items():
        s = m.spec
        want[aid] = {
            "sha256": m.sha256, "tier": m.tier, "status": s["status"],
            "canary": bool(s.get("canary", False)),
            "requires_delegator": s["delegation"]["requires_delegator"],
            "approval_required_for": s["approval"]["required_for"],
            "tools": {
                t["name"]: {k: t[k] for k in ("scope", "irreversible", "rate_limit_per_min") if k in t}
                for t in s["tools"]
            },
        }
        if s["runtime"]["type"] == "k8s":
            want[aid]["k8s"] = k8s_binding(m)
    got = json.loads(RUNTIME_DATA.read_text())["membrane"]["manifests"]
    assert got == want, "policy/runtime/testdata/data.json is stale; rebuild it from the registry"


def test_kyverno_values_mock_matches_generated_configmap():
    """R-15: every rule that loads the registry ConfigMap gets the generated data in the CLI mock."""
    import yaml
    cm = yaml.safe_load((REPO / "out" / "generated" / "k8s" / "membrane-registry.configmap.yaml").read_text())
    values = yaml.safe_load((POLICY / "admission" / "kyverno" / "tests" / "values.yaml").read_text())
    policy = yaml.safe_load((POLICY / "admission" / "kyverno" / "membrane-agent-workloads.yaml").read_text())
    loaders = {r["name"] for r in policy["spec"]["rules"]
               if any(c.get("configMap", {}).get("name") == "membrane-registry" for c in r.get("context", []))}
    mocked = {r["name"]: r["values"]["registry.data"] for p in values["policies"] for r in p["rules"]}
    assert set(mocked) == loaders, "rerun python scripts/sync_kyverno_values.py"
    for name, data in mocked.items():
        assert data == cm["data"], f"{name}: stale registry mock; rerun python scripts/sync_kyverno_values.py"


def test_registry_configmap_binds_k8s_fields():
    """R-15: each ConfigMap value carries hash, tier, namespace, service account, and image digests."""
    import yaml
    from membrane.manifest import load_registry
    cm = yaml.safe_load((REPO / "out" / "generated" / "k8s" / "membrane-registry.configmap.yaml").read_text())
    for aid, m in load_registry().items():
        entry = json.loads(cm["data"][aid])
        rt = m.spec["runtime"]
        assert entry == {"sha256": m.sha256, "tier": str(m.tier), "namespace": rt["namespace"],
                         "service_account": rt["service_account"],
                         "image_digests": [rt["image"].split("@", 1)[1]]}


# ------------------------------------------------------------------ conftest


@needs_conftest
def test_conftest_registry_passes():
    assert REGISTRY, "no registry manifests found"
    r = conftest(*REGISTRY)
    assert r.returncode == 0, r.stdout + r.stderr


@needs_conftest
@pytest.mark.parametrize("path", BAD, ids=[p.stem for p in BAD])
def test_conftest_bad_manifest_fails(path: Path):
    expect = next((ln[len("# expect: "):].strip() for ln in path.read_text().splitlines() if ln.startswith("# expect: ")), None)
    assert expect, f"{path.name} has no '# expect:' line"
    r = conftest(path)
    assert r.returncode != 0, f"conftest passed bad manifest {path.name}"
    assert expect in r.stdout, f"{path.name}: expected message {expect!r}\n{r.stdout}"


@needs_conftest
def test_conftest_verify():
    r = run(CONFTEST, "verify", "--no-color", "--policy", str(CI))
    assert r.returncode == 0, r.stdout + r.stderr


# ------------------------------------------------------------------- kyverno


@needs_kyverno
def test_kyverno_suite():
    r = run(KYVERNO, "test", "--remove-color", "--require-tests", "policy/admission/kyverno")
    out = r.stdout + r.stderr
    assert r.returncode == 0, out
    # Kyverno CLI 1.14.1 counts "want fail, got pass" as a pass. Check every row reason.
    assert not re.search(r"Want [a-z]+, got [a-z]+", out), out
    assert "Excluded" not in out, out
    m = re.search(r"Test Summary: (\d+) tests passed and 0 tests failed", out)
    assert m and int(m.group(1)) > 0, out
