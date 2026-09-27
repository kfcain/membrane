"""Build an OSCAL 1.1.3 assessment-results document from check results.

Mapping:
- One observation per check. relevant-evidence lists each evidence record
  id and payload hash that the check examined.
- One finding per control (NIST SP 800-53 Rev 5 and SCF assessment objective).
  NIST findings target the control statement (statement-id, e.g. cm-8_smt).
  SCF findings target the assessment objective (objective-id, e.g. AAT-07.1_A02).
- MET maps to satisfied. PARTIAL and NOT MET map to not-satisfied. The
  membrane word stays in the prop membrane-control-status.
- import-ap points at a placeholder. Membrane does not write an assessment
  plan. See docs/CONTROLS.md.
"""
from __future__ import annotations

import json
import uuid
from pathlib import Path

import jsonschema

from ..manifest import REPO_ROOT
from .catalog import nist_to_oscal, scf_control_ref

OSCAL_VERSION = "1.1.3"
SCHEMA_PATH = REPO_ROOT / "schema" / "oscal" / "oscal_assessment-results_schema.json"
SCHEMA_SHA256 = "d9e34757f0c12aff61f52b821f0b8f83ba0ba75b3a149a202b08ba82f82bc4c3"
NS = "https://membrane.example.org/ns/oscal"
PLACEHOLDER_AP = "./assessment-plan.placeholder.json"
OSCAL_NAMESPACE = uuid.UUID("0b6f5e0a-3c1d-5e8f-9a4b-7c2d1e0f3a5b")

STATE = {"MET": ("satisfied", "pass"), "PARTIAL": ("not-satisfied", "other"), "NOT MET": ("not-satisfied", "fail")}
FRAMEWORK_TITLE = {"nist_800_53": "NIST SP 800-53 Rev 5", "scf_ao": "SCF 2026.3 assessment objective"}


def _uuid(run_id: str, *parts: str) -> str:
    return str(uuid.uuid5(OSCAL_NAMESPACE, "|".join((run_id,) + parts)))


def _prop(name: str, value, **kw) -> dict:
    p = {"name": name, "ns": NS, "value": str(value)}
    p.update(kw)
    return p


def build(results: dict, results_sha256: str) -> dict:
    run = results["run"]
    rid = run["run_id"]
    demo = results["demo"]
    now = run["assessed_at"]
    inputs = {i["id"]: i for i in results["inputs"]}

    observations = []
    obs_uuid = {}
    for c in results["checks"]:
        ou = _uuid(rid, "observation", c["id"])
        obs_uuid[c["id"]] = ou
        desc = (f"{c['question']} Status {c['status']}. {c['reason']}. Target: {c['target']}")
        o = {
            "uuid": ou,
            "title": f"{c['id']} {c['title']}",
            "description": desc,
            "props": [
                _prop("check-id", c["id"]),
                _prop("check-status", c["status"]),
                _prop("offending-count", len(c["offending"])),
                _prop("examined-count", c["examined"]),
                _prop("demo", "true" if demo else "false"),
            ],
            "methods": ["TEST"],
            "types": ["control-objective"],
            "collected": now,
        }
        evidence = []
        for record_id in c["record_ids"]:
            i = inputs.get(record_id)
            if i is None:
                continue
            evidence.append({
                "href": f"urn:uuid:{record_id}",
                "description": (f"Membrane evidence record {record_id}, kind {i['kind']}, mode {i['mode']}, "
                                f"collected {i['collected_at']}."),
                "props": [
                    _prop("evidence-record-id", record_id),
                    _prop("evidence-kind", i["kind"]),
                    _prop("evidence-mode", i["mode"]),
                    _prop("payload-sha256", i["payload_sha256"]),
                ],
            })
        if evidence:
            o["relevant-evidence"] = evidence
        if c["offending"]:
            o["remarks"] = "Offending items: " + json.dumps(c["offending"], sort_keys=True)
        observations.append(o)

    findings = []
    nist_ids, scf_ids = [], []
    for fw, rows in results["controls"].items():
        for row in rows:
            cid = row["control_id"]
            state, reason = STATE[row["status"]]
            if fw == "nist_800_53":
                oid = nist_to_oscal(cid)
                nist_ids.append(oid)
                target = {"type": "statement-id", "target-id": f"{oid}_smt"}
            else:
                scf_ids.append(cid)
                target = {"type": "objective-id", "target-id": cid}
            check_list = ", ".join(f"{x['id']} {x['status']}" for x in row["checks"])
            target.update({
                "title": f"{FRAMEWORK_TITLE[fw]} {cid}",
                "props": [_prop("membrane-control-status", row["status"])],
                "status": {"state": state, "reason": reason},
            })
            f = {
                "uuid": _uuid(rid, "finding", fw, cid),
                "title": f"{FRAMEWORK_TITLE[fw]} {cid}: {row['status']}",
                "description": (f"Membrane rollup of mapped checks: {check_list}. MET means every mapped check "
                                f"is PASS. NOT MET means no mapped check is PASS. PARTIAL is the rest."),
                "props": [
                    _prop("framework", fw),
                    _prop("membrane-control-status", row["status"]),
                    _prop("demo", "true" if demo else "false"),
                ],
                "target": target,
                "related-observations": [{"observation-uuid": obs_uuid[x["id"]]} for x in row["checks"]],
            }
            if fw == "scf_ao":
                f["props"].append(_prop("scf-control", scf_control_ref(cid)))
            findings.append(f)

    reviewed: dict = {"control-selections": [{
        "description": "NIST SP 800-53 Rev 5 controls that at least one membrane check maps to.",
        "include-controls": [{"control-id": c} for c in nist_ids],
    }]}
    if scf_ids:
        reviewed["control-objective-selections"] = [{
            "description": "SCF 2026.3 assessment objectives that at least one membrane check maps to.",
            "include-objectives": [{"objective-id": a} for a in scf_ids],
        }]

    meta_props = [
        _prop("demo", "true" if demo else "false"),
        _prop("membrane-run-id", rid),
        _prop("results-json-sha256", results_sha256),
        _prop("allow-nonlive", "true" if run["allow_nonlive"] else "false"),
    ]
    result_desc = ("Automated check run by the membrane check engine over evidence records. "
                   "A finding status is a rollup of mapped checks only. It is not an assessor determination.")
    if demo:
        result_desc = results["banner"] + " " + result_desc
    doc = {
        "assessment-results": {
            "uuid": _uuid(rid, "assessment-results"),
            "metadata": {
                "title": "Membrane agent containment check results" + (" (DEMONSTRATION)" if demo else ""),
                "last-modified": now,
                "version": run["engine_version"] + "+" + rid[:8],
                "oscal-version": OSCAL_VERSION,
                "props": meta_props,
                "remarks": " ".join(results["limitations"]),
            },
            "import-ap": {
                "href": PLACEHOLDER_AP,
                "remarks": ("Placeholder. Membrane does not write an assessment plan. "
                            "Replace this href with the assessment plan of the system under assessment."),
            },
            "results": [{
                "uuid": _uuid(rid, "result"),
                "title": "Membrane check run " + rid + (" (DEMONSTRATION)" if demo else ""),
                "description": result_desc,
                "start": now,
                "end": now,
                "props": [_prop("demo", "true" if demo else "false"), _prop("membrane-run-id", rid)],
                "reviewed-controls": reviewed,
                "observations": observations,
                "findings": findings,
            }],
        }
    }
    if not findings:
        del doc["assessment-results"]["results"][0]["findings"]
    return doc


def _fix_patterns(node):
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            if k == "pattern" and isinstance(v, str):
                v = v.replace("\\p{L}", "[^\\W\\d_]").replace("\\p{N}", "\\d")
            out[k] = _fix_patterns(v)
        return out
    if isinstance(node, list):
        return [_fix_patterns(x) for x in node]
    return node


def load_schema(path: Path | None = None) -> dict:
    raw = json.loads(Path(path or SCHEMA_PATH).read_text(encoding="utf-8"))
    return _fix_patterns(raw)


def validate(doc: dict, schema: dict | None = None) -> list[str]:
    """Return a list of schema errors. Empty means valid."""
    schema = schema or load_schema()
    v = jsonschema.Draft7Validator(schema, format_checker=jsonschema.FormatChecker())
    return [f"{'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}"
            for e in sorted(v.iter_errors(doc), key=lambda e: list(e.absolute_path))]
