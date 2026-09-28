"""Check source retention through Beacon's plugin and witness APIs."""
from __future__ import annotations

import importlib.util
import json
import os

import pytest

from membrane import evidence
from membrane.manifest import REPO_ROOT


@pytest.fixture
def plugin(monkeypatch):
    if os.environ.get("MEMBRANE_REQUIRE_BEACON_TESTS") == "1":
        import beacon.plugins.spec
    else:
        pytest.importorskip("beacon.plugins.spec")
    path = REPO_ROOT / "integrations/beacon/membrane_evidence.py"
    spec = importlib.util.spec_from_file_location("membrane_evidence_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.PLUGIN


def write_sources(tmp_path, monkeypatch, modes):
    directory = tmp_path / "sources"
    for mode in modes:
        evidence.emit("canary", "test", {"mode_test": mode}, mode=mode, directory=directory)
    monkeypatch.setenv("MEMBRANE_EVIDENCE_DIRS", json.dumps([str(directory)]))
    return directory


@pytest.mark.parametrize("modes,live,extra,expected", [
    (["live"], True, {}, "live"),
    (["live"], False, {}, "fixture"),
    (["fixture"], True, {}, "fixture"),
    (["live", "simulated"], True, {}, "fixture"),
    (["live"], None, {"force_fixture": True}, "fixture"),
    (["live"], True, {"force_fixture": True}, "live"),
])
def test_modes_and_no_control_claims(tmp_path, monkeypatch, plugin, modes, live, extra, expected):
    from beacon.plugins.spec import CollectContext
    write_sources(tmp_path, monkeypatch, modes)
    result = plugin.collect(CollectContext(live=live, extra=extra, target="AAT-39"))
    assert result.ok and result.mode == expected
    assert result.payload["status"] == "unverified"
    assert result.scf_targets == ()
    assert result.payload["bundle"]["record_modes"] == sorted(set(modes))
    if expected == "fixture":
        assert result.payload["demo"] is True
        assert "demonstration" in result.payload["note"].lower()


@pytest.mark.parametrize("live,expected", [(True, "live_failed"), (None, "live_failed"), (False, "fixture")])
def test_failed_read_returns_no_partial_bundle(tmp_path, monkeypatch, plugin, live, expected):
    from beacon.plugins.spec import CollectContext
    directory = write_sources(tmp_path, monkeypatch, ["live"])
    (directory / "broken.jsonl").write_text('{"secret": "do not copy this"}\n')
    result = plugin.collect(CollectContext(live=live))
    assert result.ok is False and result.mode == expected
    assert result.scf_targets == () and "bundle" not in result.payload
    assert "do not copy this" not in json.dumps(result.payload)


def test_default_dir_and_invalid_configuration(tmp_path, monkeypatch, plugin):
    from beacon.plugins.spec import CollectContext
    directory = write_sources(tmp_path, monkeypatch, ["live"])
    monkeypatch.delenv("MEMBRANE_EVIDENCE_DIRS")
    monkeypatch.setenv("MEMBRANE_EVIDENCE_DIR", str(directory))
    assert plugin.collect(CollectContext(live=True)).ok
    monkeypatch.setenv("MEMBRANE_EVIDENCE_DIRS", "[]")
    result = plugin.collect(CollectContext(live=True))
    assert result.ok is False and result.mode == "live_failed"


def test_beacon_seals_exact_source_bytes_and_detects_tampering(tmp_path, monkeypatch, plugin):
    from beacon.config import load_settings
    from beacon.crypto.witness import check_chain
    from beacon.errors import BeaconError
    from beacon.plugins.spec import CollectContext
    from beacon.scf.engine import collect_named
    from beacon.workspace import init_workspace

    # Use an isolated local workspace. Do not inherit remote publishing settings.
    for name in list(os.environ):
        if name.startswith("BEACON_"):
            monkeypatch.delenv(name)
    monkeypatch.setenv("BEACON_PLUGIN_PATH", str(REPO_ROOT / "integrations/beacon"))
    monkeypatch.setenv("BEACON_SCF_OFFLINE", "1")
    directory = write_sources(tmp_path, monkeypatch, ["live", "simulated"])
    path = directory / "canary.jsonl"
    raw = path.read_bytes()
    settings = load_settings(tmp_path / "beacon-workspace")
    init_workspace(settings)
    result = collect_named(settings, "membrane.evidence", CollectContext(live=True))
    assert result["ok"] and result["mode"] == "fixture"
    assert result["scf_targets"] == [] and result["checkpoint"]
    assert check_chain(settings)["ok"]
    sealed = settings.evidence_dir / f"{result['evidence_id']}.json"
    payload = json.loads(sealed.read_bytes())
    assert payload["bundle"]["artifacts"][0]["content_utf8"].encode("utf-8") == raw
    # The retained bytes survive deletion of the original file.
    path.unlink()
    assert check_chain(settings)["ok"]
    payload["bundle"]["artifacts"][0]["content_utf8"] += "changed"
    sealed.write_text(json.dumps(payload))
    with pytest.raises(BeaconError, match="evidence hash mismatch"):
        check_chain(settings)
