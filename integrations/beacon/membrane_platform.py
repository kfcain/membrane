"""Beacon drop-in platform: membrane check results.

Load with BEACON_PLUGIN_PATH. See integrations/beacon/README.md.

The plugin reads membrane's results.json and returns it to Beacon as one
observation. Beacon seals the payload on its witness chain. The plugin does
not map membrane words to Beacon claim words. The payload status stays
"unverified". A membrane PASS or MET is not a Beacon claim.

Mode:
- "live" only when results.json is not a demonstration run and Beacon did
  not force fixtures.
- "fixture" when results.json is a demonstration run (--allow-nonlive) or
  when Beacon forces fixtures.
- "live_failed" with ok False when a live read fails. The plugin never
  turns a live failure into a fixture.

Environment:
- MEMBRANE_RESULTS_PATH: path to results.json.
  Default: <membrane repo>/out/assessment/results.json.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from beacon.plugins.spec import CollectContext, CollectResult, FetcherSpec

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
DEFAULT_RESULTS = REPO / "out" / "assessment" / "results.json"
CATALOG = REPO / "controls" / "checks.yaml"
CHECK_WORDS = {"PASS", "FAIL", "NO_EVIDENCE", "STALE", "INELIGIBLE"}
CONTROL_WORDS = {"MET", "PARTIAL", "NOT MET"}


def _scf_control_refs() -> tuple[str, ...]:
    """SCF control refs (for example AAT-39.13) from the ao_ids in the catalog.

    The catalog is read as text so that the plugin needs no YAML library.
    """
    refs: set[str] = set()
    try:
        text = CATALOG.read_text(encoding="utf-8")
    except OSError:
        return ("AAT-39",)
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("scf_ao:") and "[" in line:
            inner = line.split("[", 1)[1].split("]", 1)[0]
            for ao in (x.strip() for x in inner.split(",")):
                if "_A" in ao:
                    refs.add(ao.rsplit("_", 1)[0])
    return tuple(sorted(refs)) or ("AAT-39",)


def _results_path() -> Path:
    return Path(os.environ.get("MEMBRANE_RESULTS_PATH") or DEFAULT_RESULTS)


class MembranePlugin:
    spec = FetcherSpec(
        name="membrane.checks",
        version="0.1.0",
        description="Membrane agent containment check results (results.json). Status stays unverified.",
        category="ai-agents",
        scf_targets=_scf_control_refs(),
        tools=(),
    )

    def _fail(self, ctx: CollectContext, fixture: bool, path: Path, error: str) -> CollectResult:
        payload = {"source": "membrane", "status": "unverified", "results_path": str(path), "error": error}
        return CollectResult(
            ok=False,
            mode="fixture" if fixture else "live_failed",
            payload=payload,
            error=error,
            scf_targets=(),
        )

    def collect(self, ctx: CollectContext) -> CollectResult:
        forced_fixture = ctx.live is False or bool(ctx.extra.get("force_fixture") and ctx.live is not True)
        path = _results_path()
        try:
            raw = path.read_bytes()
            results = json.loads(raw)
        except (OSError, ValueError) as exc:
            return self._fail(ctx, forced_fixture, path, f"cannot read results.json: {exc}")
        if not isinstance(results, dict) or results.get("schema") != "membrane.check-results.v1":
            return self._fail(ctx, forced_fixture, path, "results.json schema is not membrane.check-results.v1")
        checks = results.get("checks") or []
        bad = [c.get("id") for c in checks if c.get("status") not in CHECK_WORDS]
        for rows in (results.get("controls") or {}).values():
            bad += [r.get("control_id") for r in rows if r.get("status") not in CONTROL_WORDS]
        if bad:
            return self._fail(ctx, forced_fixture, path, f"unknown status word for {bad}")

        demo = bool(results.get("demo"))
        mode = "fixture" if (demo or forced_fixture) else "live"
        run = results.get("run") or {}
        payload = {
            "source": "membrane",
            "mode": mode,
            "status": "unverified",
            "note": ("Membrane check results. Membrane words (PASS, FAIL, MET, NOT MET) are not Beacon claim "
                     "words. The status stays unverified."),
            "results_path": str(path),
            "results_sha256": hashlib.sha256(raw).hexdigest(),
            "run_id": run.get("run_id"),
            "assessed_at": run.get("assessed_at"),
            "demo": demo,
            "allow_nonlive": bool(run.get("allow_nonlive")),
            "summary": results.get("summary"),
            "checks": [{"id": c.get("id"), "status": c.get("status"), "offending": len(c.get("offending") or []),
                        "examined": c.get("examined"), "record_ids": c.get("record_ids")} for c in checks],
            "controls": {fw: [{"control_id": r.get("control_id"), "status": r.get("status")} for r in rows]
                         for fw, rows in (results.get("controls") or {}).items()},
            "inputs": [{"id": i.get("id"), "kind": i.get("kind"), "mode": i.get("mode"),
                        "payload_sha256": i.get("payload_sha256")} for i in results.get("inputs") or []],
        }
        if ctx.target:
            payload["target"] = ctx.target
        return CollectResult(
            ok=True,
            mode=mode,
            payload=payload,
            scf_targets=(ctx.target,) if ctx.target else self.spec.scf_targets,
        )


PLUGIN = MembranePlugin()
