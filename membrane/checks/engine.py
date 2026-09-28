"""Check engine: evidence records in, check results and control rollups out.

Status logic follows docs/CONTRACTS.md section 7. The order is fixed:

1. NO_EVIDENCE  a needed kind has no record at or before --now.
2. INELIGIBLE   a needed kind has records, but none is eligible. Only live
                records are eligible unless the run passes --allow-nonlive.
3. STALE        the newest eligible record of a needed kind is older than
                max_age_hours.
4. PASS / FAIL  the evaluator lists offending items. Zero items is PASS.

Records with collected_at after --now do not exist for the run. The engine
lists them under ignored_future_records.

Integrity: every record passes membrane.evidence.read_all (payload hash and
record hash) and the evidence-record.v1 envelope schema. The same record id
with two different record hashes, in any dir, is an error. Any error stops the run.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jsonschema

from ..evidence import read_all
from ..manifest import REPO_ROOT, canonical_json, sha256_hex
from .catalog import Catalog, Check
from .evaluators import EVALUATORS, EvalContext, parse_time

ENGINE_VERSION = "0.1.0"
ENVELOPE_SCHEMA = REPO_ROOT / "schema" / "evidence-record.v1.schema.json"
RUN_NAMESPACE = uuid.UUID("6f1c2d4e-9a7b-5c3d-8e2f-1a2b3c4d5e6f")

STATUSES = ("PASS", "FAIL", "NO_EVIDENCE", "STALE", "INELIGIBLE")
CONTROL_STATUSES = ("MET", "PARTIAL", "NOT MET")
ELIGIBLE_LIVE = {"live"}
NONLIVE = {"fixture", "simulated"}


class EvidenceError(Exception):
    """Evidence failed an integrity or shape check. The run fails closed."""


@dataclass
class LoadedRecord:
    record: dict
    source_file: str


def rfc3339(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def load_evidence(dirs: list[Path]) -> list[LoadedRecord]:
    """Read every record from every dir. Fail closed on any integrity error."""
    validator = jsonschema.Draft202012Validator(
        json.loads(ENVELOPE_SCHEMA.read_text()), format_checker=jsonschema.FormatChecker())
    by_id: dict[str, LoadedRecord] = {}
    for d in dirs:
        d = Path(d)
        if not d.is_dir():
            raise EvidenceError(f"evidence directory not found: {d}")
        try:
            records = list(read_all(d))
        except (ValueError, KeyError, json.JSONDecodeError) as exc:
            raise EvidenceError(f"{d}: {exc}") from exc
        for rec in records:
            errors = sorted(validator.iter_errors(rec), key=lambda e: list(e.path))
            if errors:
                e = errors[0]
                raise EvidenceError(f"{d}: record {rec.get('id')}: envelope schema: "
                                    f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}")
            try:
                parse_time(rec["collected_at"])
            except ValueError as exc:
                raise EvidenceError(f"{d}: record {rec['id']}: {exc}") from exc
            prior = by_id.get(rec["id"])
            if prior is not None:
                if prior.record["record_sha256"] != rec["record_sha256"]:
                    raise EvidenceError(f"record id {rec['id']} appears twice with different content")
                continue
            by_id[rec["id"]] = LoadedRecord(rec, str(d))
    return [by_id[k] for k in sorted(by_id)]


def eligible(rec: dict, allow_nonlive: bool) -> bool:
    return rec["mode"] in ELIGIBLE_LIVE or (allow_nonlive and rec["mode"] in NONLIVE)


def evaluate_check(check: Check, records: list[dict], registry: dict, now: datetime,
                   allow_nonlive: bool) -> dict:
    max_age = timedelta(hours=check.max_age_hours)
    by_kind: dict[str, list[dict]] = {k: [] for k in check.all_kinds}
    for r in records:
        if r["kind"] in by_kind:
            by_kind[r["kind"]].append(r)
    elig = {k: [r for r in v if eligible(r, allow_nonlive)] for k, v in by_kind.items()}
    window = {k: [r for r in v if now - parse_time(r["collected_at"]) <= max_age] for k, v in elig.items()}

    newest = {}
    for k in check.evidence_kinds:
        if elig[k]:
            newest[k] = rfc3339(max(parse_time(r["collected_at"]) for r in elig[k]))

    result = {
        "id": check.id, "title": check.title, "question": check.question, "target": check.target,
        "evidence_kinds": list(check.evidence_kinds), "supporting_kinds": list(check.supporting_kinds),
        "max_age_hours": check.max_age_hours,
        "controls": {"nist_800_53": list(check.nist_800_53), "scf_ao": list(check.scf_ao)},
        "status": None, "reason": None, "newest_collected_at": newest,
        "record_counts": {k: {"all": len(by_kind[k]), "eligible": len(elig[k]), "in_window": len(window[k])}
                          for k in check.all_kinds},
        "examined": 0, "offending": [], "record_ids": [],
    }

    missing = [k for k in check.evidence_kinds if not by_kind[k]]
    if missing:
        result["status"], result["reason"] = "NO_EVIDENCE", f"no record of kind {', '.join(missing)}"
        return result
    inelig = [k for k in check.evidence_kinds if not elig[k]]
    if inelig:
        modes = sorted({r["mode"] for k in inelig for r in by_kind[k]})
        result["status"] = "INELIGIBLE"
        result["reason"] = (f"only {'/'.join(modes)} records of kind {', '.join(inelig)}; "
                            "pass --allow-nonlive for a demonstration run")
        result["record_ids"] = sorted(r["id"] for k in inelig for r in by_kind[k])
        return result
    stale = [k for k in check.evidence_kinds if not window[k]]
    if stale:
        result["status"] = "STALE"
        result["reason"] = (f"newest eligible {', '.join(stale)} record is older than {check.max_age_hours:g} h "
                            f"(newest {', '.join(newest[k] for k in stale)})")
        result["record_ids"] = sorted(r["id"] for k in stale for r in elig[k])
        return result

    ctx = EvalContext(now=now, registry=registry, window=window, eligible=elig, all_records=by_kind)
    try:
        outcome = EVALUATORS[check.id](ctx)
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise EvidenceError(f"{check.id}: evidence payload does not match the contract shape: {exc!r}") from exc
    result["examined"] = outcome.examined
    result["offending"] = outcome.offending
    result["record_ids"] = sorted(set(outcome.record_ids))
    if outcome.offending:
        result["status"] = "FAIL"
        result["reason"] = f"{len(outcome.offending)} offending item(s) out of {outcome.examined} examined"
    else:
        result["status"] = "PASS"
        result["reason"] = f"0 offending items out of {outcome.examined} examined"
    if outcome.notes:
        result["reason"] += "; " + "; ".join(outcome.notes)
    return result


def rollup(check_results: list[dict]) -> dict:
    """Per framework, per control: MET when every mapped check is PASS,
    NOT MET when no mapped check is PASS, PARTIAL otherwise."""
    out: dict[str, list[dict]] = {}
    for fw in ("nist_800_53", "scf_ao"):
        table: dict[str, list[dict]] = {}
        for r in check_results:
            for cid in r["controls"][fw]:
                table.setdefault(cid, []).append({"id": r["id"], "status": r["status"]})
        rows = []
        for cid in sorted(table, key=_control_sort_key):
            checks = table[cid]
            passes = sum(1 for c in checks if c["status"] == "PASS")
            status = "MET" if passes == len(checks) else ("NOT MET" if passes == 0 else "PARTIAL")
            rows.append({"control_id": cid, "status": status, "checks": checks})
        out[fw] = rows
    return out


def _control_sort_key(cid: str):
    import re
    parts = re.split(r"(\d+)", cid)
    return [int(p) if p.isdigit() else p for p in parts]


def run_checks(catalog: Catalog, loaded: list[LoadedRecord], registry: dict, now: datetime,
               allow_nonlive: bool, evidence_dirs: list[Path], registry_dir: Path) -> dict:
    future = [lr.record for lr in loaded if parse_time(lr.record["collected_at"]) > now]
    current = [lr for lr in loaded if parse_time(lr.record["collected_at"]) <= now]
    records = [lr.record for lr in current]
    results = [evaluate_check(c, records, registry, now, allow_nonlive) for c in catalog.checks]
    demo = bool(allow_nonlive)
    for r in results:
        r["demo"] = demo

    needed_kinds = {k for c in catalog.checks for k in c.all_kinds}
    inputs = [{
        "id": lr.record["id"], "kind": lr.record["kind"], "mode": lr.record["mode"],
        "source": lr.record["source"], "collected_at": lr.record["collected_at"],
        "agent_id": lr.record["agent_id"], "payload_sha256": lr.record["payload_sha256"],
        "evidence_dir": _rel(lr.source_file),
    } for lr in current if lr.record["kind"] in needed_kinds]

    registry_hashes = {aid: m.sha256 for aid, m in sorted(registry.items())}
    run_seed = canonical_json({"now": rfc3339(now), "allow_nonlive": allow_nonlive,
                               "inputs": [[i["id"], i["payload_sha256"]] for i in inputs],
                               "registry": registry_hashes,
                               "catalog_sha256": sha256_hex(Path(catalog.path).read_bytes())})
    run_id = str(uuid.uuid5(RUN_NAMESPACE, hashlib.sha256(run_seed).hexdigest()))

    findings = []
    for r in results:
        for n, item in enumerate(r["offending"], 1):
            findings.append({"finding_id": f"{r['id']}#{n}", "check_id": r["id"], "status": r["status"], **item})

    counts = {s: sum(1 for r in results if r["status"] == s) for s in STATUSES}
    controls = rollup(results)
    return {
        "schema": "membrane.check-results.v1",
        "run": {
            "run_id": run_id, "engine_version": ENGINE_VERSION, "assessed_at": rfc3339(now),
            "allow_nonlive": allow_nonlive, "demo": demo,
            "evidence_dirs": [_rel(str(d)) for d in evidence_dirs],
            "registry_dir": _rel(str(registry_dir)), "registry_sha256": registry_hashes,
            "catalog": _rel(str(catalog.path)), "catalog_sha256": sha256_hex(Path(catalog.path).read_bytes()),
            "scf_pin": catalog.scf_pin,
        },
        "demo": demo,
        "banner": DEMO_BANNER if demo else None,
        "summary": {
            "checks": counts,
            "controls": {fw: {s: sum(1 for c in rows if c["status"] == s) for s in CONTROL_STATUSES}
                         for fw, rows in controls.items()},
        },
        "checks": results,
        "findings": findings,
        "controls": controls,
        "inputs": inputs,
        "ignored_future_records": sorted(r["id"] for r in future),
        "limitations": LIMITATIONS,
    }


def _rel(path: str) -> str:
    p = Path(path).resolve()
    try:
        return str(p.relative_to(REPO_ROOT))
    except ValueError:
        return str(p)


DEMO_BANNER = ("DEMONSTRATION RUN. This run passed --allow-nonlive. Fixture and simulated records count as "
               "eligible. The output is a demonstration, not an assessment.")

LIMITATIONS = [
    "A check result reports what the evidence records show at the assessment time. It does not show that the records are true.",
    "A PASS covers only the population in the records. A workload, flow, or call that no collector saw is not in the population.",
    "A control status here is a rollup of mapped checks only. It is not an assessor determination and it does not cover the full control.",
    "The SCF and NIST SP 800-53 mappings are membrane's own. Neither the SCF Council nor NIST reviewed them.",
    "Membrane does not seal results. Beacon seals them. Beacon keeps the status word unverified.",
]
