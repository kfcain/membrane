"""The Beacon drop-in reads results.json and keeps the status word unverified."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest
from _checks_util import run

from membrane.manifest import REPO_ROOT

BEACON_SRC = REPO_ROOT.parent / "kfcain" / "beacon"
PLUGIN_FILE = REPO_ROOT / "integrations" / "beacon" / "membrane_platform.py"


def _beacon_spec():
    try:
        from beacon.plugins import spec  # noqa: F401
        return spec
    except ImportError:
        if (BEACON_SRC / "beacon" / "plugins" / "spec.py").is_file():
            sys.path.insert(0, str(BEACON_SRC))
            from beacon.plugins import spec
            return spec
    pytest.skip("beacon is not importable")


@pytest.fixture(scope="module")
def plugin_mod():
    _beacon_spec()
    s = importlib.util.spec_from_file_location("membrane_platform_under_test", PLUGIN_FILE)
    mod = importlib.util.module_from_spec(s)
    s.loader.exec_module(mod)
    return mod


def test_plugin_contract(plugin_mod):
    spec = _beacon_spec()
    assert isinstance(plugin_mod.PLUGIN.spec, spec.FetcherSpec)
    assert plugin_mod.PLUGIN.spec.name == "membrane.checks"
    assert "AAT-39.13" in plugin_mod.PLUGIN.spec.scf_targets


def test_demo_results_are_fixture_mode(tmp_path, monkeypatch, plugin_mod):
    spec = _beacon_spec()
    _, _, out = run(tmp_path, allow_nonlive=True)
    monkeypatch.setenv("MEMBRANE_RESULTS_PATH", str(out / "results.json"))
    r = plugin_mod.PLUGIN.collect(spec.CollectContext(live=None))
    assert r.ok and r.mode == "fixture"
    assert r.payload["status"] == "unverified"
    text = json.dumps(r.payload).lower()
    for word in ("compliant", "evidenced", "proven"):
        assert word not in text


def test_live_results_are_live_mode(tmp_path, monkeypatch, plugin_mod):
    spec = _beacon_spec()
    _, res, out = run(tmp_path)
    monkeypatch.setenv("MEMBRANE_RESULTS_PATH", str(out / "results.json"))
    r = plugin_mod.PLUGIN.collect(spec.CollectContext(live=True))
    assert r.ok and r.mode == "live"
    assert [c["status"] for c in r.payload["checks"]] == [c["status"] for c in res["checks"]]
    r = plugin_mod.PLUGIN.collect(spec.CollectContext(live=False))
    assert r.mode == "fixture"


def test_missing_results_is_live_failed(tmp_path, monkeypatch, plugin_mod):
    spec = _beacon_spec()
    monkeypatch.setenv("MEMBRANE_RESULTS_PATH", str(tmp_path / "missing.json"))
    r = plugin_mod.PLUGIN.collect(spec.CollectContext(live=True))
    assert r.ok is False and r.mode == "live_failed" and r.scf_targets == ()


def test_unknown_status_word_fails(tmp_path, monkeypatch, plugin_mod):
    spec = _beacon_spec()
    _, _, out = run(tmp_path)
    res = json.loads((out / "results.json").read_text())
    res["checks"][0]["status"] = "COMPLIANT"
    p = Path(tmp_path / "bad.json")
    p.write_text(json.dumps(res))
    monkeypatch.setenv("MEMBRANE_RESULTS_PATH", str(p))
    r = plugin_mod.PLUGIN.collect(spec.CollectContext(live=True))
    assert r.ok is False and r.mode == "live_failed"


def test_r26_payload_has_no_claim_word_in_any_case(tmp_path, monkeypatch, plugin_mod):
    """R-26: Beacon's claim-word guard is case-sensitive. The payload must pass it in lower case too."""
    spec = _beacon_spec()
    for name, nonlive in (("demo", True), ("strict", False)):
        _, _, out = run(tmp_path / name, allow_nonlive=nonlive, name=name)
        monkeypatch.setenv("MEMBRANE_RESULTS_PATH", str(out / "results.json"))
        r = plugin_mod.PLUGIN.collect(spec.CollectContext(live=None))
        assert r.ok
        text = json.dumps(r.payload).lower()
        for word in ("compliant", "evidenced", "proven", "implemented", " met", '"met"', "met\""):
            assert word not in text, (name, word)
        statuses = {c["status"] for rows in r.payload["controls"].values() for c in rows}
        assert statuses <= {"rollup_all_pass", "rollup_some_pass", "rollup_none_pass"}
