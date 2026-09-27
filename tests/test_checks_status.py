"""Status logic: NO_EVIDENCE, INELIGIBLE, STALE, --allow-nonlive, future records."""
from __future__ import annotations

import json
from pathlib import Path

from _checks_util import check, fixture_sets, run

from membrane.checks import execute
from membrane.manifest import REPO_ROOT


def _set_mode(sets, kinds, mode):
    for k in kinds:
        for r in sets.get(k, []):
            r["mode"] = mode


def test_no_evidence_when_kind_missing(tmp_path):
    sets = fixture_sets()
    del sets["tool_exec"]
    del sets["kill_drill"]
    _, res, _ = run(tmp_path, sets)
    assert check(res, "AGT-AU-01")["status"] == "NO_EVIDENCE"
    assert check(res, "AGT-AC-01")["status"] == "NO_EVIDENCE"
    assert check(res, "AGT-IR-01")["status"] == "NO_EVIDENCE"


def test_missing_supporting_kind_is_not_no_evidence(tmp_path):
    sets = fixture_sets()
    del sets["decision"]
    _, res, _ = run(tmp_path, sets)
    au = check(res, "AGT-AU-01")
    assert au["status"] == "FAIL"
    assert {o["reason"] for o in au["offending"]} == {"decision_missing"}
    assert check(res, "AGT-AC-02")["status"] == "NO_EVIDENCE"


def test_ineligible_without_allow_nonlive(tmp_path):
    sets = fixture_sets()
    _set_mode(sets, ["inventory"], "fixture")
    _set_mode(sets, ["canary"], "simulated")
    _, res, _ = run(tmp_path, sets)
    for cid in ("AGT-INV-01", "AGT-INV-02", "AGT-IAM-02", "AGT-TST-01"):
        c = check(res, cid)
        assert c["status"] == "INELIGIBLE", cid
        assert c["offending"] == []
    assert res["demo"] is False


def test_allow_nonlive_makes_nonlive_eligible_and_marks_demo(tmp_path):
    sets = fixture_sets()
    _set_mode(sets, list(sets), "fixture")
    code, res, out = run(tmp_path, sets, allow_nonlive=True)
    assert code == 0
    assert res["demo"] is True
    assert res["banner"] and "not an assessment" in res["banner"]
    assert all(c["demo"] is True for c in res["checks"])
    assert check(res, "AGT-INV-01")["status"] == "FAIL"
    assert check(res, "AGT-TST-01")["status"] == "PASS"
    report = (out / "report.md").read_text()
    assert "DEMONSTRATION RUN" in report
    poam = json.loads((out / "poam-candidates.json").read_text())
    assert poam["demo"] is True


def test_live_run_is_not_demo_even_with_live_records(tmp_path):
    _, res, out = run(tmp_path)
    assert res["demo"] is False and res["banner"] is None
    assert "DEMONSTRATION" not in (out / "report.md").read_text()


def test_stale_when_newest_is_old(tmp_path):
    # Inventory is at 11:55; max age 24 h.
    _, res, _ = run(tmp_path, now="2026-09-28T12:00:00Z")
    assert check(res, "AGT-INV-01")["status"] == "STALE"
    assert check(res, "AGT-IAM-01")["status"] == "STALE"
    # Pipeline runs have a 720 h window, so CM-01 still evaluates.
    assert check(res, "AGT-CM-01")["status"] == "FAIL"


def test_stale_uses_newest_eligible_record(tmp_path):
    sets = fixture_sets()
    # A fresh fixture inventory does not rescue a stale live one without --allow-nonlive.
    fresh = json.loads(json.dumps(sets["inventory"][0]))
    fresh["id"] = "00000000-0000-4000-8000-000000000001"
    fresh["mode"] = "fixture"
    fresh["collected_at"] = "2026-09-28T11:00:00.000Z"
    sets["inventory"].append(fresh)
    _, res, _ = run(tmp_path, sets, now="2026-09-28T12:00:00Z")
    assert check(res, "AGT-INV-01")["status"] == "STALE"
    _, res, _ = run(tmp_path, sets, now="2026-09-28T12:00:00Z", allow_nonlive=True, name="demo")
    assert check(res, "AGT-INV-01")["status"] == "FAIL"


def test_future_records_are_ignored(tmp_path):
    _, res, _ = run(tmp_path, now="2026-09-27T11:50:00Z")
    # Inventory (11:55) and egress (11:59) come after --now; they do not exist for this run.
    assert check(res, "AGT-INV-01")["status"] == "NO_EVIDENCE"
    assert check(res, "AGT-SC-01")["status"] == "NO_EVIDENCE"
    assert len(res["ignored_future_records"]) >= 2


def test_default_dirs_with_allow_nonlive_use_repo_fixtures(tmp_path, monkeypatch):
    monkeypatch.setenv("MEMBRANE_EVIDENCE_DIR", str(tmp_path / "empty"))
    out = tmp_path / "out"
    import io
    code = execute(allow_nonlive=True, out=str(out), now="2026-09-27T13:00:00Z", emit_record=False,
                   stream=io.StringIO())
    assert code == 0
    res = json.loads((out / "results.json").read_text())
    assert res["run"]["evidence_dirs"] == ["fixtures/evidence"]
    assert res["demo"] is True
    got = {c["id"]: c["status"] for c in res["checks"]}
    assert got["AGT-INV-01"] == "FAIL" and got["AGT-AU-01"] == "NO_EVIDENCE"


def test_repo_fixtures_are_ineligible_without_flag(tmp_path, monkeypatch):
    import io
    out = tmp_path / "out"
    code = execute(evidence=[str(REPO_ROOT / "fixtures" / "evidence")], out=str(out),
                   now="2026-09-27T13:00:00Z", emit_record=False, stream=io.StringIO())
    assert code == 0
    res = json.loads((out / "results.json").read_text())
    for cid in ("AGT-INV-01", "AGT-INV-02", "AGT-IAM-01", "AGT-IAM-02", "AGT-SC-01", "AGT-CM-01"):
        assert check(res, cid)["status"] == "INELIGIBLE"


def test_check_result_record_is_emitted(tmp_path, monkeypatch):
    import io
    ev = tmp_path / "var-ev"
    monkeypatch.setenv("MEMBRANE_EVIDENCE_DIR", str(ev))
    out = tmp_path / "out"
    code = execute(evidence=[str(REPO_ROOT / "tests" / "fixtures" / "checks" / "evidence")],
                   registry=str(REPO_ROOT / "tests" / "fixtures" / "checks" / "registry"),
                   out=str(out), now="2026-09-27T13:00:00Z", stream=io.StringIO())
    assert code == 0
    lines = (ev / "check_result.jsonl").read_text().splitlines()
    rec = json.loads(lines[-1])
    assert rec["kind"] == "check_result" and rec["mode"] == "live"
    import hashlib
    assert rec["payload"]["results_sha256"] == hashlib.sha256((out / "results.json").read_bytes()).hexdigest()

    code = execute(allow_nonlive=True, evidence=[str(REPO_ROOT / "fixtures" / "evidence")], out=str(out),
                   now="2026-09-27T13:00:00Z", stream=io.StringIO())
    rec = json.loads((ev / "check_result.jsonl").read_text().splitlines()[-1])
    assert rec["mode"] == "simulated" and rec["payload"]["demo"] is True
    assert Path(out / "results.json").exists()
