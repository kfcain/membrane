"""membrane checks: run the check catalog over evidence and write assessment output.

Commands:
  membrane checks run [--allow-nonlive] [--evidence DIR ...] [--registry DIR]
                      [--out out/assessment] [--now RFC3339] [--catalog FILE]
  membrane checks doc [--rows rows.json] [--out docs/CONTROLS.md]

Exit codes for `run`: 0 when the run completes (a FAIL result is still exit 0),
2 on an input error (evidence integrity, bad registry, bad catalog, bad --now).
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..evidence import emit, evidence_dir
from ..manifest import REPO_ROOT, ManifestError, load_registry, sha256_hex
from .catalog import CatalogError, load_catalog
from .engine import EvidenceError, load_evidence, rfc3339, run_checks
from .evaluators import parse_time

FIXTURE_DIR = REPO_ROOT / "fixtures" / "evidence"
DEFAULT_OUT = REPO_ROOT / "out" / "assessment"
EXIT_INPUT = 2


def _dump(obj) -> bytes:
    return (json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def execute(*, allow_nonlive: bool = False, evidence: list[str] | None = None, registry: str | None = None,
            out: str | None = None, now: str | None = None, catalog: str | None = None,
            emit_record: bool = True, stream=None) -> int:
    from . import oscal, report  # local import keeps `membrane --help` fast

    stream = stream or sys.stdout
    err = sys.stderr
    try:
        # Round up to the next whole second. Records written earlier in the same
        # second must not count as future records.
        now_dt = parse_time(now) if now else (datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=1))
    except ValueError as exc:
        print(f"error: --now: {exc}", file=err)
        return EXIT_INPUT
    if evidence:
        dirs = [Path(d) for d in evidence]
    else:
        dirs = [d for d in [evidence_dir()] if Path(d).is_dir()]
        if allow_nonlive:
            dirs.append(FIXTURE_DIR)
    registry_dir = Path(registry) if registry else REPO_ROOT / "registry" / "agents"
    try:
        cat = load_catalog(Path(catalog) if catalog else None)
        reg = load_registry(registry_dir)
        loaded = load_evidence(dirs)
    except (CatalogError, ManifestError, EvidenceError, OSError) as exc:
        print(f"error: {exc}", file=err)
        print("error: the run stopped. No output was written.", file=err)
        return EXIT_INPUT

    try:
        results = run_checks(cat, loaded, reg, now_dt, allow_nonlive, dirs, registry_dir)
    except EvidenceError as exc:
        print(f"error: {exc}", file=err)
        print("error: the run stopped. No output was written.", file=err)
        return EXIT_INPUT

    results_bytes = _dump(results)
    results_sha = sha256_hex(results_bytes)
    oscal_doc = oscal.build(results, results_sha)
    oscal_bytes = _dump(oscal_doc)
    poam = report.poam_candidates(results, cat)
    md = report.render_markdown(results, results_sha)

    out_dir = Path(out) if out else DEFAULT_OUT
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "results.json": results_bytes,
        "assessment-results.oscal.json": oscal_bytes,
        "poam-candidates.json": _dump(poam),
        "report.md": md.encode("utf-8"),
    }
    for name, data in paths.items():
        (out_dir / name).write_bytes(data)

    if results["demo"]:
        print("=" * 78, file=stream)
        print(results["banner"], file=stream)
        print("=" * 78, file=stream)
    for c in results["checks"]:
        extra = f"  ({len(c['offending'])} offending)" if c["offending"] else ""
        print(f"{c['id']:<11} {c['status']:<11} {c['title']}{extra}", file=stream)
    for fw, counts in results["summary"]["controls"].items():
        print(f"controls {fw}: MET {counts['MET']}, PARTIAL {counts['PARTIAL']}, NOT MET {counts['NOT MET']}",
              file=stream)
    for name in paths:
        print(f"wrote {out_dir / name}", file=stream)

    if emit_record:
        payload = {
            "run_id": results["run"]["run_id"],
            "assessed_at": results["run"]["assessed_at"],
            "demo": results["demo"],
            "results_sha256": results_sha,
            "oscal_sha256": sha256_hex(oscal_bytes),
            "statuses": {c["id"]: c["status"] for c in results["checks"]},
            "input_record_count": len(results["inputs"]),
        }
        rec = emit("check_result", "membrane.checks", payload,
                   mode="simulated" if allow_nonlive else "live")
        print(f"wrote evidence {Path(evidence_dir()) / 'check_result.jsonl'} (record {rec['id']})", file=stream)
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    return execute(allow_nonlive=args.allow_nonlive, evidence=args.evidence, registry=args.registry,
                   out=args.out, now=args.now, catalog=args.catalog, emit_record=not args.no_emit)


def _cmd_doc(args: argparse.Namespace) -> int:
    from .doc import write_doc
    try:
        path = write_doc(Path(args.catalog) if args.catalog else None,
                         Path(args.rows) if args.rows else None,
                         Path(args.out) if args.out else None)
    except (CatalogError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INPUT
    print(f"wrote {path}")
    return 0


def register(sub) -> None:
    p = sub.add_parser("checks", help="Run evidence checks and write assessment output.")
    csub = p.add_subparsers(dest="checks_command", required=True)

    r = csub.add_parser("run", help="Evaluate every check in controls/checks.yaml.")
    r.add_argument("--allow-nonlive", action="store_true",
                   help="Count fixture and simulated records. Marks the output as a demonstration.")
    r.add_argument("--evidence", action="append", metavar="DIR",
                   help="Evidence directory. Repeat for more. Default: MEMBRANE_EVIDENCE_DIR, "
                        "plus fixtures/evidence with --allow-nonlive.")
    r.add_argument("--registry", metavar="DIR", help="Agent registry directory. Default: registry/agents.")
    r.add_argument("--out", metavar="DIR", help="Output directory. Default: out/assessment.")
    r.add_argument("--now", metavar="RFC3339", help="Assessment time. Use for repeatable runs.")
    r.add_argument("--catalog", metavar="FILE", help="Check catalog. Default: controls/checks.yaml.")
    r.add_argument("--no-emit", action="store_true", help="Do not write a check_result evidence record.")
    r.set_defaults(func=_cmd_run)

    d = csub.add_parser("doc", help="Generate docs/CONTROLS.md from the catalog and SCF rows.json.")
    d.add_argument("--catalog", metavar="FILE")
    d.add_argument("--rows", metavar="FILE", help="SCF rows.json. Default: MEMBRANE_SCF_ROWS or Beacon's pin.")
    d.add_argument("--out", metavar="FILE")
    d.set_defaults(func=_cmd_doc)


__all__ = ["register", "execute", "rfc3339"]
