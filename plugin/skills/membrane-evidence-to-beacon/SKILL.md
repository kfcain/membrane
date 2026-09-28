---
name: membrane-evidence-to-beacon
description: Hand off Membrane evidence to a Beacon seal or custody path while preserving lineage. Use when bridging repos; never treat hand-off or seal as a control MET.
---

# Membrane evidence → Beacon

Use this skill when Membrane evidence must move into a Beacon seal or custody path.

Hand-off to a seal is never a **MET** decision. A Beacon seal is custody. It is not a control **MET**.

A Membrane control word **MET**, **PARTIAL**, or **NOT MET** is a rollup of automated checks. It is not an assessor **MET**. The plugins in `integrations/beacon/` keep payload `status` as `unverified`. They do not map Membrane words to Beacon claim words.

A run with `--allow-nonlive` is a demonstration. A demonstration is not an assessment. Beacon records that run as mode `fixture`.

## When

- Membrane validate/checks output must become a Beacon witness input or custody artifact.
- Review needs a clear lineage across Membrane to Beacon (source, scope, time, validation state).
- An agent would paste Membrane success into a Beacon claim word.

## Must

- Use the drop-in plugins in `integrations/beacon/`. `membrane_platform.py` is plugin `membrane.checks` (check `results.json`). `membrane_evidence.py` is plugin `membrane.evidence` (exact source JSONL bytes). Read `integrations/beacon/README.md` before you collect.
- Preserve source identity, scope, timestamps, validation state, and lineage across the hand-off.
- Reject incomplete or unverifiable evidence. Do not fill gaps with inferred product claims.
- Keep Membrane verify labels (canary, fixture, local, `--allow-nonlive` demonstration) visible after hand-off.
- Fail closed when a live read returns `ok: false` or mode `live_failed`. Do not seal a partial bundle.
- After seal, Beacon claim words still require `decide_claim` plus a linked `receipt_id` (see Beacon skill `beacon-decide-claim-gardener` in the Beacon repo). Seal alone stays unverified for program status.

## Forbidden

- Stating a control is **MET** because Membrane handed off or Beacon sealed.
- Treating a Membrane rollup **MET**, **PARTIAL**, or **NOT MET** as an assessor **MET** or as a Beacon claim.
- Treating `make demo`, `scripts/demo.sh`, or `--allow-nonlive` as an assessment.
- Dropping validation failure, unknown check, canary labels, or demonstration mode during transfer.
- Inventing scope hashes, receipt ids, or ownership to complete the bridge.
- Dual-writing program status outside the authoritative system-of-record path.
- Copying files by hand when the documented plugin path can run.

## CLI pointers

Membrane commands from the membrane repo root:

```bash
membrane validate
membrane gen --check
membrane canary run
membrane checks run
```

`membrane checks run` exits 0 when the run completes. A FAIL check is still exit 0. Exit 2 is an input error. Read the results. Do not read exit 0 as a control **MET**.

A demonstration run (not an assessment). `scripts/demo.sh` uses this shape:

```bash
membrane checks run --allow-nonlive --evidence var/evidence --evidence fixtures/evidence
```

If you omit `--evidence`, the engine reads `MEMBRANE_EVIDENCE_DIR` or `var/evidence`. With `--allow-nonlive` and no `--evidence`, it also adds `fixtures/evidence`. If you pass `--evidence`, only those directories are read.

Beacon commands from a Beacon workspace (`beacon init` already done). Point `BEACON_PLUGIN_PATH` at this repo:

```bash
export BEACON_PLUGIN_PATH=/path/to/membrane/integrations/beacon
export MEMBRANE_RESULTS_PATH=/path/to/membrane/out/assessment/results.json
beacon plugins
beacon collect --plugin membrane.checks --fixture
beacon check
```

Use `--fixture` when `results.json` is a demonstration run (`--allow-nonlive`) or when Beacon must force fixtures. For a live results file only, drop `--fixture` and pass `--live`:

```bash
beacon collect --plugin membrane.checks --live
```

Source-byte custody uses `membrane.evidence`. Set `MEMBRANE_EVIDENCE_DIRS` to a JSON list of absolute directories. An empty list, a missing directory, or a directory with no JSONL files fails. Stop writers, or select closed log segments, before collection.

```bash
export MEMBRANE_EVIDENCE_DIRS='["/path/to/membrane/var/evidence"]'
beacon collect --plugin membrane.evidence --live
beacon check
```

If any retained record has mode `fixture` or `simulated`, the observation mode is `fixture` and the text says `Demonstration source custody`. Use `--fixture` for a forced fixture run. Do not call that observation an assessment.

`BEACON_PLUGIN_PATH` may name the directory `integrations/beacon`. Beacon loads every `*.py` file in it that does not start with `_`.

Exact ingest and seal flags follow `integrations/beacon/README.md` and the Beacon repo. Prefer these custody plugins over ad-hoc file copies. A future bridge/verify CLI may live beside this `SKILL.md`.

## Report back

Report Membrane commands and results, Beacon commands and results, preserved lineage fields, plugin name, and Beacon mode (`live`, `fixture`, or `live_failed`). Status word for program/control purposes is **unverified**. State: hand-off and seal are not program **MET**. A seal is custody. A Membrane rollup is not an assessor **MET**. A demonstration is not an assessment.
