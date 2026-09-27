"""Same inputs and the same --now give byte-identical output. Fixture builders are repeatable."""
from __future__ import annotations

import importlib.util
import json

from _checks_util import BUILDER, EVIDENCE, fixture_sets, run, write_sets

from membrane.manifest import REPO_ROOT

OUTPUTS = ("results.json", "assessment-results.oscal.json", "poam-candidates.json", "report.md")


def _ev(tmp_path):
    return [str(write_sets(tmp_path / "ev", fixture_sets()))]


def test_two_runs_are_identical(tmp_path):
    ev = _ev(tmp_path)
    _, _, a = run(tmp_path, name="a", evidence=ev)
    _, _, b = run(tmp_path, name="b", evidence=ev)
    for name in OUTPUTS:
        assert (a / name).read_bytes() == (b / name).read_bytes(), name


def test_demo_runs_are_identical(tmp_path):
    ev = _ev(tmp_path)
    _, _, a = run(tmp_path, name="a", allow_nonlive=True, evidence=ev)
    _, _, b = run(tmp_path, name="b", allow_nonlive=True, evidence=ev)
    for name in OUTPUTS:
        assert (a / name).read_bytes() == (b / name).read_bytes(), name


def test_now_changes_run_id(tmp_path):
    _, r1, _ = run(tmp_path, name="a")
    _, r2, _ = run(tmp_path, name="b", now="2026-09-27T13:00:01Z")
    assert r1["run"]["run_id"] != r2["run"]["run_id"]


def test_test_fixture_builder_matches_committed_files(tmp_path):
    BUILDER.write_all(BUILDER.build(), tmp_path)
    for path in sorted(EVIDENCE.glob("*.jsonl")):
        assert (tmp_path / path.name).read_text() == path.read_text(), path.name


def test_repo_fixture_builder_matches_committed_files(tmp_path):
    spec = importlib.util.spec_from_file_location("build_fixtures", REPO_ROOT / "fixtures" / "build_fixtures.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    for kind, recs in mod.build().items():
        path = mod.write(kind, recs, tmp_path)
        committed = REPO_ROOT / "fixtures" / "evidence" / path.name
        assert path.read_text() == committed.read_text(), (
            f"{path.name} differs; rerun python fixtures/build_fixtures.py (registry changed?)")
        for line in path.read_text().splitlines():
            assert json.loads(line)["mode"] == "fixture"
