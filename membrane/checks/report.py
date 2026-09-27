"""POA&M candidates and the Markdown report."""
from __future__ import annotations

import json

CANDIDATE_STATUSES = ("FAIL", "NO_EVIDENCE", "STALE")

WEAKNESS = {
    "FAIL": "The evidence does not meet the target.",
    "NO_EVIDENCE": "No evidence record of a needed kind exists.",
    "STALE": "The newest evidence is older than the freshness limit.",
}
NO_EVIDENCE_REMEDIATION = "Turn on the collector for {kinds} and write its records to the evidence directory, then run the checks again."
STALE_REMEDIATION = "Run the collector for {kinds} at least every {hours:g} hours, then run the checks again."


def poam_candidates(results: dict, catalog) -> dict:
    checks = catalog.by_id()
    items = []
    for c in results["checks"]:
        if c["status"] not in CANDIDATE_STATUSES:
            continue
        chk = checks[c["id"]]
        kinds = ", ".join(c["evidence_kinds"])
        if c["status"] == "FAIL":
            remediation = chk.remediation
        elif c["status"] == "NO_EVIDENCE":
            remediation = NO_EVIDENCE_REMEDIATION.format(kinds=kinds)
        else:
            remediation = STALE_REMEDIATION.format(kinds=kinds, hours=chk.max_age_hours)
        items.append({
            "candidate_id": f"{results['run']['run_id']}:{c['id']}",
            "check_id": c["id"],
            "title": c["title"],
            "check_status": c["status"],
            "weakness": f"{c['id']}: {WEAKNESS[c['status']]} {c['reason']}.",
            "offending_items": c["offending"],
            "controls": c["controls"],
            "suggested_remediation": remediation,
            "source_record_ids": c["record_ids"],
            "detected_at": results["run"]["assessed_at"],
            "demo": results["demo"],
        })
    return {
        "schema": "membrane.poam-candidates.v1",
        "note": ("These items are POA&M candidates. They are not a POA&M. A person must review each item, "
                 "assign an owner and a date, and accept it into the system POA&M."),
        "run_id": results["run"]["run_id"],
        "generated_at": results["run"]["assessed_at"],
        "demo": results["demo"],
        "banner": results["banner"],
        "items": items,
    }


def _cell(v) -> str:
    return str(v).replace("|", "\\|").replace("\n", " ")


def _item_line(item: dict) -> str:
    skip = {"record_id"}
    parts = [f"{k}={_cell(json.dumps(v) if isinstance(v, (list, dict)) else v)}"
             for k, v in item.items() if k not in skip and v is not None]
    return "; ".join(parts) + f" (record {item.get('record_id')})"


def render_markdown(results: dict, results_sha256: str) -> str:
    run = results["run"]
    L: list[str] = []
    L.append("# Membrane check report")
    L.append("")
    if results["demo"]:
        L.append("> **DEMONSTRATION RUN.** This run passed `--allow-nonlive`. Fixture and simulated records count "
                 "as eligible. This report is a demonstration. It is not an assessment.")
        L.append("")
    L.append(f"- Run id: `{run['run_id']}`")
    L.append(f"- Assessment time: `{run['assessed_at']}`")
    L.append(f"- Evidence directories: {', '.join('`' + d + '`' for d in run['evidence_dirs'])}")
    L.append(f"- Input records: {len(results['inputs'])}")
    L.append(f"- results.json SHA-256: `{results_sha256}`")
    L.append("")
    L.append("## Check status counts")
    L.append("")
    counts = results["summary"]["checks"]
    L.append("| PASS | FAIL | NO_EVIDENCE | STALE | INELIGIBLE |")
    L.append("| ---: | ---: | ---: | ---: | ---: |")
    L.append("| " + " | ".join(str(counts[s]) for s in ("PASS", "FAIL", "NO_EVIDENCE", "STALE", "INELIGIBLE")) + " |")
    L.append("")
    L.append("## Checks")
    L.append("")
    L.append("| Check | Title | Status | Offending | Examined | Reason |")
    L.append("| --- | --- | --- | ---: | ---: | --- |")
    for c in results["checks"]:
        L.append(f"| {c['id']} | {_cell(c['title'])} | **{c['status']}** | {len(c['offending'])} | "
                 f"{c['examined']} | {_cell(c['reason'])} |")
    L.append("")
    L.append("## Control rollup")
    L.append("")
    L.append("MET means every mapped check is PASS. NOT MET means no mapped check is PASS. PARTIAL is the rest.")
    L.append("")
    for fw, title in (("nist_800_53", "NIST SP 800-53 Rev 5"), ("scf_ao", "SCF 2026.3 assessment objectives")):
        sc = results["summary"]["controls"][fw]
        L.append(f"### {title}")
        L.append("")
        L.append(f"MET {sc['MET']}, PARTIAL {sc['PARTIAL']}, NOT MET {sc['NOT MET']}.")
        L.append("")
        L.append("| Control | Status | Checks |")
        L.append("| --- | --- | --- |")
        for row in results["controls"][fw]:
            L.append(f"| {row['control_id']} | {row['status']} | "
                     f"{', '.join(x['id'] + ' ' + x['status'] for x in row['checks'])} |")
        L.append("")
    L.append("## Findings")
    L.append("")
    fails = [c for c in results["checks"] if c["offending"]]
    if not fails:
        L.append("No check listed an offending item.")
        L.append("")
    for c in fails:
        L.append(f"### {c['id']} {c['title']}")
        L.append("")
        for item in c["offending"]:
            L.append(f"- {_item_line(item)}")
        L.append("")
    others = [c for c in results["checks"] if c["status"] in ("NO_EVIDENCE", "STALE", "INELIGIBLE")]
    if others:
        L.append("## Checks without a result")
        L.append("")
        for c in others:
            L.append(f"- {c['id']} is {c['status']}: {c['reason']}.")
        L.append("")
    L.append("## Limitations")
    L.append("")
    for s in results["limitations"]:
        L.append(f"- {s}")
    if results["demo"]:
        L.append("- This run is a demonstration. Fixture and simulated records are not observations of a real system.")
    L.append("")
    return "\n".join(L)
