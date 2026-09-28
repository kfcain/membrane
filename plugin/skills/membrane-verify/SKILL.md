---
name: membrane-verify
description: Run Membrane verification via validate, gen --check, canary run, and checks run. Use when confirming Membrane workflow health without treating verify success as a control MET.
---

# Membrane verify

Use this skill when the task is to verify Membrane configs, generated artifacts, canaries, or check suites.

Verify success is workflow health. It is not a program control **MET**.

A Membrane control word **MET**, **PARTIAL**, or **NOT MET** is a rollup of automated checks. It is not an assessor **MET**.

A run with `--allow-nonlive` is a demonstration. A demonstration is not an assessment. `make demo` and `scripts/demo.sh` pass `--allow-nonlive`.

## When

- A change needs `validate`, codegen drift check, canary, or checks as comparable evidence.
- CI or review must record the exact Membrane commands and outcomes.
- Fixture, local, or canary output must stay labeled and fail-closed.

## Must

- Run the Membrane CLI entry points for the task. Capture command, scope/target, exit code, and failure reason.
- Fail closed on validation errors, generated drift, missing inputs, or an unknown check result.
- Label canary, fixture, and local outputs as such. Do not call them production evidence.
- Label a run that passes `--allow-nonlive` as a demonstration. Do not call it an assessment.
- Treat check status words (PASS, FAIL, NO_EVIDENCE, STALE, INELIGIBLE) and control rollups (MET, PARTIAL, NOT MET) as Membrane words only. They are not an assessor determination.
- Keep verify separate from tier admission and from Beacon seal/claim paths. The Beacon handoff is `integrations/beacon/`. A seal is custody. It is not a control **MET**.

## Forbidden

- Claiming a control is **MET** because validate, gen --check, canary, or checks exited 0.
- Treating a Membrane rollup **MET**, **PARTIAL**, or **NOT MET** as an assessor **MET**.
- Treating `make demo`, `scripts/demo.sh`, or `--allow-nonlive` as an assessment.
- Promoting canary success to a control assertion or program status.
- Inventing inputs, tiers, or evidence to force a green verify.
- Skipping a failed check and reporting partial success as full verify.

## CLI pointers

Commands from the repo root. Flags match `membrane --help` in this repo.

```bash
membrane validate
membrane gen --check
membrane canary run
membrane checks run
```

`membrane checks run` exits 0 when the run completes. A FAIL check is still exit 0. Exit 2 is an input error (evidence integrity, bad registry, bad catalog, or bad `--now`). Read the check results. Do not read exit 0 as every check PASS.

A demonstration run (not an assessment). `scripts/demo.sh` uses this shape:

```bash
membrane checks run --allow-nonlive --evidence var/evidence --evidence fixtures/evidence
```

If you omit `--evidence`, the engine reads `MEMBRANE_EVIDENCE_DIR` or `var/evidence`. With `--allow-nonlive` and no `--evidence`, it also adds `fixtures/evidence`. If you pass `--evidence`, only those directories are read. The report banner and OSCAL props mark a `--allow-nonlive` run as a demonstration.

Exact subcommand flags follow this repo. Later, this skill directory may hold a thin verify CLI beside `SKILL.md`.

## Report back

Report commands, targets, exit codes, and whether output was fixture, canary, local, or `--allow-nonlive` demonstration. Status for program/control purposes remains **unverified** unless a separate authoritative assessment path says otherwise. Verify is not program **MET**. A Membrane rollup is not an assessor **MET**.
