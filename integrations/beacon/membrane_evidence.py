"""Retain source evidence files in one Beacon custody observation.

The artifact text is source data. It is not a Beacon claim or an assessment.
Install membrane in Beacon's Python environment before loading this plugin.
"""
from __future__ import annotations

from beacon.plugins.spec import CollectContext, CollectResult, FetcherSpec

from membrane.evidence import CustodyError, configured_dirs, snapshot_bundle


class MembraneEvidencePlugin:
    spec = FetcherSpec(
        name="membrane.evidence", version="0.1.0", category="ai-agents",
        description="Retain exact membrane source evidence bytes. Status stays unverified.",
        scf_targets=(), tools=(),
    )

    def collect(self, ctx: CollectContext) -> CollectResult:
        forced_fixture = ctx.live is False or bool(ctx.extra.get("force_fixture") and ctx.live is not True)
        try:
            bundle = snapshot_bundle(configured_dirs())
        except CustodyError as exc:
            mode = "fixture" if forced_fixture else "live_failed"
            return CollectResult(
                ok=False, mode=mode, error=str(exc), scf_targets=(),
                payload={"source": "membrane", "status": "unverified", "mode": mode, "error": str(exc)},
            )
        demo = forced_fixture or bundle["record_modes"] != ["live"]
        mode = "fixture" if demo else "live"
        return CollectResult(
            ok=True, mode=mode, scf_targets=(),
            payload={"source": "membrane", "status": "unverified", "mode": mode,
                     "demo": demo,
                     "note": ("Demonstration source custody. Record modes are retained." if demo else
                              "Source custody only. Record contents are unverified source data."),
                     "bundle": bundle},
        )


PLUGIN = MembraneEvidencePlugin()
