"""The engine fails closed on any evidence integrity error (exit 2, no output)."""
from __future__ import annotations

import io
import json

from _checks_util import REGISTRY, fixture_sets, run, write_sets

from membrane.checks import execute


def test_tampered_payload_exits_2_and_writes_nothing(tmp_path):
    sets = fixture_sets()
    sets["secret_scan"][0]["payload"]["findings"][0]["in_vault"] = True  # no rehash
    code, res, out = run(tmp_path, sets)
    assert code == 2
    assert res is None
    assert not (out / "assessment-results.oscal.json").exists()


def test_tampered_line_in_file(tmp_path):
    ev = write_sets(tmp_path / "ev", fixture_sets())
    path = ev / "tool_exec.jsonl"
    lines = path.read_text().splitlines()
    rec = json.loads(lines[0])
    rec["payload"]["result"] = "error"
    lines[0] = json.dumps(rec)
    path.write_text("\n".join(lines) + "\n")
    code, res, _ = run(tmp_path, evidence=[str(ev)])
    assert code == 2 and res is None


def test_envelope_schema_error(tmp_path):
    sets = fixture_sets()
    sets["inventory"][0]["mode"] = "production"
    code, res, _ = run(tmp_path, sets)
    assert code == 2


def test_same_id_different_content_across_dirs(tmp_path):
    a = write_sets(tmp_path / "a", fixture_sets())
    sets = fixture_sets()
    sets["canary"][0]["payload"]["run_id"] = "different"
    from _checks_util import rehash
    rehash(sets["canary"][0])
    b = write_sets(tmp_path / "b", {"canary": sets["canary"]})
    code, _, _ = run(tmp_path, evidence=[str(a), str(b)])
    assert code == 2


def test_same_record_in_two_dirs_is_deduplicated(tmp_path):
    a = write_sets(tmp_path / "a", fixture_sets())
    b = write_sets(tmp_path / "b", fixture_sets())
    code, res, _ = run(tmp_path, evidence=[str(a), str(b)])
    assert code == 0
    code1, res1, _ = run(tmp_path, evidence=[str(a)], name="single")
    assert [c["status"] for c in res["checks"]] == [c["status"] for c in res1["checks"]]
    assert len(res["inputs"]) == len(res1["inputs"])


def test_missing_evidence_dir_is_input_error(tmp_path):
    code, _, _ = run(tmp_path, evidence=[str(tmp_path / "nope")])
    assert code == 2


def test_bad_now_is_input_error(tmp_path):
    code = execute(evidence=[str(tmp_path)], registry=str(REGISTRY), out=str(tmp_path / "o"),
                   now="yesterday", emit_record=False, stream=io.StringIO())
    assert code == 2


def test_contract_shape_error_is_input_error(tmp_path):
    sets = fixture_sets()
    del sets["egress_flow"][0]["payload"]["flows"][0]["verdict"]
    from _checks_util import rehash
    rehash(sets["egress_flow"][0])
    code, _, _ = run(tmp_path, sets)
    assert code == 2
