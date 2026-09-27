"""Shared helpers for tests/test_checks_*.py."""
from __future__ import annotations

import copy
import importlib.util
import io
import json
from pathlib import Path

from membrane.checks import execute
from membrane.manifest import canonical_json, sha256_hex

HERE = Path(__file__).resolve().parent
FIX = HERE / "fixtures" / "checks"
REGISTRY = FIX / "registry"
EVIDENCE = FIX / "evidence"
NOW = "2026-09-27T13:00:00Z"


def _load_builder():
    spec = importlib.util.spec_from_file_location("checks_fixture_build", FIX / "build.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


BUILDER = _load_builder()


def fixture_sets() -> dict[str, list[dict]]:
    """Fresh deep copy of the test fixture set, read from the committed JSONL files."""
    out: dict[str, list[dict]] = {}
    for path in sorted(EVIDENCE.glob("*.jsonl")):
        out[path.stem] = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    return copy.deepcopy(out)


def rehash(rec: dict) -> dict:
    rec["payload_sha256"] = sha256_hex(canonical_json(rec["payload"]))
    return rec


def write_sets(directory: Path, sets: dict[str, list[dict]]) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    for kind, recs in sets.items():
        (directory / f"{kind}.jsonl").write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in recs))
    return directory


def run(tmp: Path, sets: dict | None = None, *, now: str = NOW, allow_nonlive: bool = False,
        evidence: list[str] | None = None, name: str = "run") -> tuple[int, dict | None, Path]:
    out = tmp / f"{name}-out"
    if evidence is None:
        ev = write_sets(tmp / f"{name}-ev", sets if sets is not None else fixture_sets())
        evidence = [str(ev)]
    code = execute(allow_nonlive=allow_nonlive, evidence=evidence, registry=str(REGISTRY), out=str(out),
                   now=now, emit_record=False, stream=io.StringIO())
    res = json.loads((out / "results.json").read_text()) if (out / "results.json").exists() else None
    return code, res, out


def check(results: dict, check_id: str) -> dict:
    return next(c for c in results["checks"] if c["id"] == check_id)
