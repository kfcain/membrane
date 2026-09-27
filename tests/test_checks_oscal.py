"""OSCAL assessment-results output validates against the vendored NIST schema."""
from __future__ import annotations

import hashlib
import json

import pytest
from _checks_util import run

from membrane.checks import oscal


@pytest.fixture(scope="module")
def schema():
    return oscal.load_schema()


def test_vendored_schema_hash():
    assert hashlib.sha256(oscal.SCHEMA_PATH.read_bytes()).hexdigest() == oscal.SCHEMA_SHA256
    raw = json.loads(oscal.SCHEMA_PATH.read_text())
    assert raw["$id"] == "http://csrc.nist.gov/ns/oscal/1.1.3/oscal-ar-schema.json"


def test_live_run_output_is_valid(tmp_path, schema):
    _, res, out = run(tmp_path)
    doc = json.loads((out / "assessment-results.oscal.json").read_text())
    assert oscal.validate(doc, schema) == []
    ar = doc["assessment-results"]
    assert ar["metadata"]["oscal-version"] == "1.1.3"
    assert ar["import-ap"]["href"] == oscal.PLACEHOLDER_AP
    result = ar["results"][0]
    assert len(result["observations"]) == len(res["checks"])
    n_controls = sum(len(v) for v in res["controls"].values())
    assert len(result["findings"]) == n_controls


def test_demo_run_output_is_valid_and_marked(tmp_path, schema):
    _, res, out = run(tmp_path, allow_nonlive=True)
    doc = json.loads((out / "assessment-results.oscal.json").read_text())
    assert oscal.validate(doc, schema) == []
    props = {p["name"]: p["value"] for p in doc["assessment-results"]["metadata"]["props"]}
    assert props["demo"] == "true"
    assert props["results-json-sha256"] == hashlib.sha256((out / "results.json").read_bytes()).hexdigest()


def test_status_mapping_and_targets(tmp_path):
    _, res, out = run(tmp_path)
    doc = json.loads((out / "assessment-results.oscal.json").read_text())
    findings = doc["assessment-results"]["results"][0]["findings"]
    rollup = {(fw, r["control_id"]): r["status"] for fw, rows in res["controls"].items() for r in rows}
    seen = 0
    for f in findings:
        props = {p["name"]: p["value"] for p in f["props"]}
        fw = props["framework"]
        t = f["target"]
        if fw == "nist_800_53":
            assert t["type"] == "statement-id" and t["target-id"].endswith("_smt")
            cid = t["title"].split()[-1]
        else:
            assert t["type"] == "objective-id"
            cid = t["target-id"]
        word = rollup[(fw, cid)]
        assert props["membrane-control-status"] == word
        assert t["status"]["state"] == ("satisfied" if word == "MET" else "not-satisfied")
        seen += 1
    assert seen == len(rollup)
    targets = {f["target"]["target-id"] for f in findings}
    assert "cm-8.3_smt" in targets and "ia-5.7_smt" in targets and "AAT-39.13_A01" in targets


def test_relevant_evidence_carries_payload_hashes(tmp_path):
    _, res, out = run(tmp_path)
    doc = json.loads((out / "assessment-results.oscal.json").read_text())
    hashes = {i["id"]: i["payload_sha256"] for i in res["inputs"]}
    obs = doc["assessment-results"]["results"][0]["observations"]
    n = 0
    for o in obs:
        for ev in o.get("relevant-evidence", []):
            props = {p["name"]: p["value"] for p in ev["props"]}
            assert hashes[props["evidence-record-id"]] == props["payload-sha256"]
            n += 1
    assert n > 0


def test_validator_rejects_bad_document(tmp_path, schema):
    _, _, out = run(tmp_path)
    doc = json.loads((out / "assessment-results.oscal.json").read_text())
    doc["assessment-results"]["results"][0]["findings"][0]["target"]["status"]["state"] = "MET"
    assert oscal.validate(doc, schema)
    doc = json.loads((out / "assessment-results.oscal.json").read_text())
    del doc["assessment-results"]["import-ap"]
    assert oscal.validate(doc, schema)
