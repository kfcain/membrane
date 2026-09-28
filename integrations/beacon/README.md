# Beacon drop-ins: check results and source evidence

`membrane_platform.py` is a Beacon drop-in platform plugin. It follows `docs/PLUGINS.md` and `examples/echo_platform.py` in the Beacon repo. It exports `PLUGIN` with a `FetcherSpec` and a `collect(ctx)` method.

The plugin reads membrane's `results.json` and returns one observation. Beacon seals that payload on its witness chain and writes a checkpoint.

`membrane_evidence.py` adds the `membrane.evidence` plugin. It reads every top-level `*.jsonl` file in the selected directories. It retains the exact UTF-8 bytes, file hashes, and record hashes in one Beacon observation. Both plugins keep status `unverified`.

## Source evidence custody

Install membrane in the same Python environment as Beacon. Stop evidence writers, or select closed log segments, before collection. Select all source directories that you need to retain. The plugin does not infer paths from `results.json`.

```bash
pip install -e /path/to/membrane
export BEACON_PLUGIN_PATH=/path/to/membrane/integrations/beacon
export MEMBRANE_EVIDENCE_DIRS='["/path/to/membrane/var/evidence", "/path/to/membrane/fixtures/evidence"]'
beacon collect --plugin membrane.evidence --fixture
beacon check
```

`MEMBRANE_EVIDENCE_DIRS` is a JSON list of absolute directory paths. If it is absent, the plugin uses `MEMBRANE_EVIDENCE_DIR`, or membrane's default `var/evidence`. An empty or invalid list fails. A missing directory or a directory with no JSONL files fails.

For live source files, use `--live`. If any retained record has mode `fixture` or `simulated`, the observation has mode `fixture` and says `Demonstration source custody`. A forced fixture run also has this mode. The raw record modes stay unchanged. A failed live read returns `ok: false`, `mode: live_failed`, and no partial bundle. A failed forced fixture read returns `ok: false`, `mode: fixture`.

Source custody always has an empty SCF target list, even when a caller supplies a target. Collection retains data. It does not assess a control. Continue to use `membrane.checks` for the check summary.

The bundle contains at most 256 files and 16 MiB of source bytes. Collection fails on a limit, invalid envelope, hash mismatch, conflicting record id, duplicate JSON key, missing final newline, or empty file. It also rejects symlinks and special files. It checks for file replacement, append, and file-set changes during collection. It does not lock source writers or provide a filesystem transaction.

Beacon retains each file under `bundle.artifacts[].content_utf8`. UTF-8 encoding of that string restores the source bytes, including CRLF line endings. Compare the bytes with the artifact's `sha256` and `size_bytes`. The `records` list gives each record's id, kind, mode, payload hash, and full record hash. Beacon's witness signature and checkpoint cover the whole bundle. `beacon check` checks that retained payload against the witness chain.

The source content remains unverified data. It can contain personal data, tool arguments, or claim words from a source system. Custody does not interpret those words or authorize a claim. Keep the Beacon workspace under the same access controls as the source evidence. No new network upload occurs in this plugin. Beacon's configured storage still applies.

This is an explicit snapshot. New writes need another collection. Files deleted before collection cannot be detected. Separate `membrane.checks` and `membrane.evidence` observations do not yet have an automatic receipt link. Use a closed source snapshot for both operations when the assessed bytes must match the retained bytes.

## Check results plugin

- It does not map membrane words to Beacon claim words. The payload `status` is always `unverified`. Control rollups appear as neutral tokens: `rollup_all_pass` (MET), `rollup_some_pass` (PARTIAL), `rollup_none_pass` (NOT MET). Beacon's claim-word guard is case-sensitive, and a lower-cased "NOT MET" would contain " met".
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
