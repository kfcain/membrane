"""Control rollup and POA&M candidates."""
from __future__ import annotations

import json

from _checks_util import run

from membrane.checks.engine import rollup


def _r(cid, status, nist=(), scf=()):
    return {"id": cid, "status": status, "controls": {"nist_800_53": list(nist), "scf_ao": list(scf)}}


def test_rollup_rules():
    rows = rollup([
        _r("A", "PASS", nist=["AC-3", "CM-8"]),
        _r("B", "FAIL", nist=["AC-3"]),
        _r("C", "PASS", nist=["CM-8"]),
        _r("D", "NO_EVIDENCE", nist=["IR-3"]),
        _r("E", "STALE", nist=["IR-3"], scf=["AAT-39.13_A01"]),
        _r("F", "INELIGIBLE", scf=["AAT-39.13_A01"]),
        _r("G", "PASS", scf=["IRO-09_A04"]),
    ])
    nist = {r["control_id"]: r["status"] for r in rows["nist_800_53"]}
    scf = {r["control_id"]: r["status"] for r in rows["scf_ao"]}
    assert nist == {"AC-3": "PARTIAL", "CM-8": "MET", "IR-3": "NOT MET"}
    assert scf == {"AAT-39.13_A01": "NOT MET", "IRO-09_A04": "MET"}


def test_unmapped_control_does_not_appear():
    rows = rollup([_r("A", "PASS", nist=["AC-3"])])
    assert [r["control_id"] for r in rows["nist_800_53"]] == ["AC-3"]
    assert rows["scf_ao"] == []


def test_only_three_control_words(tmp_path):
    _, res, _ = run(tmp_path)
    words = {r["status"] for rows in res["controls"].values() for r in rows}
    assert words <= {"MET", "PARTIAL", "NOT MET"}
    # AC-3 maps AU-01 (FAIL), AC-01 (FAIL), AC-02 (FAIL): NOT MET.
    ac3 = next(r for r in res["controls"]["nist_800_53"] if r["control_id"] == "AC-3")
    assert ac3["status"] == "NOT MET"
    # IR-3 maps IR-01 only (PASS): MET.
    ir3 = next(r for r in res["controls"]["nist_800_53"] if r["control_id"] == "IR-3")
    assert ir3["status"] == "MET"


def test_poam_candidates(tmp_path):
    sets = __import__("_checks_util").fixture_sets()
    del sets["kill_drill"]
    _, res, out = run(tmp_path, sets, now="2026-09-28T13:00:00Z")
    poam = json.loads((out / "poam-candidates.json").read_text())
    assert "not a POA&M" in poam["note"]
    by = {i["check_id"]: i for i in poam["items"]}
    statuses = {c["id"]: c["status"] for c in res["checks"]}
    want = {cid for cid, s in statuses.items() if s in ("FAIL", "NO_EVIDENCE", "STALE")}
    assert set(by) == want
    assert by["AGT-IR-01"]["check_status"] == "NO_EVIDENCE"
    assert by["AGT-INV-01"]["check_status"] == "STALE"
    assert by["AGT-CM-01"]["check_status"] == "FAIL"
    assert by["AGT-CM-01"]["offending_items"][0]["run_id"] == "run-low"
    assert by["AGT-CM-01"]["controls"]["nist_800_53"] == ["CM-3", "CM-3(2)", "SA-11"]
    for item in poam["items"]:
        assert item["suggested_remediation"].endswith(".")
