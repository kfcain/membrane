# Beacon drop-in: membrane check results

`membrane_platform.py` is a Beacon drop-in platform plugin. It follows `docs/PLUGINS.md` and `examples/echo_platform.py` in the Beacon repo. It exports `PLUGIN` with a `FetcherSpec` and a `collect(ctx)` method.

The plugin reads membrane's `results.json` and returns one observation. Beacon seals that payload on its witness chain and writes a checkpoint.

## What the plugin does not do

- It does not map membrane words to Beacon claim words. The payload `status` is always `unverified`.
- A membrane PASS or MET is not a Beacon claim. Only Beacon `decide_claim` with a linked receipt can permit a claim word.
- It does not run the checks. Run `membrane checks run` first.

## Mode

| Condition | Beacon mode | ok |
| --- | --- | --- |
| `results.json` is a normal run and Beacon did not force fixtures | `live` | true |
| `results.json` is a demonstration run (`--allow-nonlive`) | `fixture` | true |
| Beacon forces fixtures (`--fixture`) | `fixture` | true |
| Live read fails (file missing, bad JSON, unknown status word) | `live_failed` | false |
| Forced-fixture read fails | `fixture` | false |

A failed read seals no SCF target (`scf_targets` is empty).

## SCF targets

`spec.scf_targets` lists the SCF 2026.3 control refs that the membrane catalog maps to (for example `AAT-39.13`). The plugin reads them from `controls/checks.yaml`. `beacon collect --target <id>` selects this plugin when the id overlaps one of them. The seal names the targets. It does not state that a control is met.

## Commands

From the membrane repo root:

```bash
membrane checks run --allow-nonlive --now 2026-09-27T13:00:00Z --evidence fixtures/evidence
```

From a Beacon workspace (any directory where you ran `beacon init`):

```bash
export BEACON_PLUGIN_PATH=/path/to/membrane/integrations/beacon/membrane_platform.py
export MEMBRANE_RESULTS_PATH=/path/to/membrane/out/assessment/results.json
beacon plugins
beacon collect --plugin membrane.checks --fixture
beacon check
```

For a run over live evidence only (no `--allow-nonlive`), drop `--fixture`:

```bash
beacon collect --plugin membrane.checks --live
```

`BEACON_PLUGIN_PATH` can also name the directory `integrations/beacon`. Beacon loads every `*.py` file in it that does not start with `_`.

## Test record

Tested on 2026-09-27 with Beacon installed in a throwaway venv (`uv pip install -e .` from the Beacon repo, Python 3.11):

- `beacon init`, then `beacon collect --plugin membrane.checks --fixture` over a demonstration `results.json`: ok true, mode `fixture`, sealed with a checkpoint.
- `beacon check`: ok true, every record covered by a checkpoint.
- `beacon collect --plugin membrane.checks --live` with a missing `results.json`: ok false, mode `live_failed`, no SCF target.
