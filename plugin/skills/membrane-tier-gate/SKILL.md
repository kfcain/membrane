---
name: membrane-tier-gate
description: Make the Membrane tier explicit before a workflow advances. Use when tier, ownership, or admission is unclear; fail closed rather than inferring a stronger tier or MET.
---

# Membrane tier gate

Use this skill before a Membrane workflow advances across tier boundaries.

Tier admission is not a control assessment and not program **MET**.

A Membrane control word **MET**, **PARTIAL**, or **NOT MET** is a rollup of automated checks. It is not an assessor **MET**. It is not a tier admit.

## When

- A workflow, deploy, or evidence path depends on an applicable Membrane tier.
- Tier inputs or ownership are missing, conflicting, or inferred from environment alone.
- An agent would silently select a stronger tier to unblock progress.

## Must

- Make the applicable tier explicit before advance. Require tier inputs and ownership to be present.
- Read the tier from the agent manifest. In this repo the field is `spec.tier` on files in `registry/agents/`. Tiers are integers 1 to 4. See README "Agent tiers" and `policy/README.md`.
- Block promotion when tier data is unknown or conflicting. Prefer a deterministic deny/review path.
- Keep tier admission separate from control assessment, Beacon seals, and final **MET** status. A Beacon seal (`integrations/beacon/`) is custody. It is not a control **MET**.
- Record the tier id, source of ownership, and admit/deny decision for review.
- Stop when you cannot name the tier from the manifest. Do not infer it from the environment, the image, or a green check run.

## Forbidden

- Inferring a stronger tier to pass a gate.
- Treating tier admit as a control **MET** or as Beacon claim permission.
- Treating a Membrane rollup **MET**, **PARTIAL**, or **NOT MET** as an assessor **MET** or as tier admission.
- Treating `make demo` or `--allow-nonlive` as an assessment or as a tier admit.
- Filling missing ownership with guessed product or account claims.
- Soft language that collapses tier gate and assessment into one state.

## CLI pointers

This repo has no admit subcommand. The CI tier gate is `policy/ci` (conftest). It reads the manifests. It does not assign a tier.

```bash
membrane validate
membrane list
membrane checks run
membrane gen --check
```

`membrane validate` checks each manifest against the schema. `membrane list` prints tier, status, and manifest hash. Neither command admits a stronger tier.

`membrane checks run` exits 0 when the run completes. A FAIL check is still exit 0. A control rollup is not an assessor **MET**.

A run with `--allow-nonlive` is a demonstration. It is not an assessment and not a tier admit.

Use repo-documented tier rules in `policy/ci`. Stop when the tier cannot be named. A future verify/admit CLI may live beside this `SKILL.md`.

## Report back

Report tier id (or "unknown"), ownership source, admit or deny, and commands run. On deny or unknown, stop. State: tier gate is not program **MET**. A Membrane rollup is not an assessor **MET**.
