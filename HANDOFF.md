# Handoff

This file lets any capable coding model or engineer continue work on membrane without the original conversation. Read it first. Then read the files it names. Do not rely on memory of earlier sessions.

Last update: 2026-10-06. Owner: kfcain.

## 1. What membrane is

Membrane is a reference for AI agent containment. One manifest per agent is the source of truth. Policy gates (CI, admission, runtime) prevent actions. Each gate decision becomes an evidence record. A check engine turns evidence into check results, control rollups (MET, PARTIAL, NOT MET), and OSCAL assessment results. Beacon (`github.com/kfcain/beacon`) seals the results for custody.

Read in this order:

1. `README.md`: purpose, tiers, commands.
2. `LIMITS.md`: what the reference does not prove.
3. `docs/CONTRACTS.md`: the binding interfaces. Change code to fit the contract, or change the contract on purpose in the same commit.
4. `docs/ARCHITECTURE.md`: diagrams and the tool-call sequence.
5. `policy/README.md`: every policy rule and how to test it.
6. `docs/PATH-TO-MET.md`: the work plan for multi-agent controls (items M-01 to M-14).
7. `docs/research/rogue-agent-field-notes.md`: the research behind that plan. It is a snapshot of a live doc. The file header has the link.

## 2. State at handoff

| Area | State |
| --- | --- |
| Manifest schema and example registry (5 agents) | Done |
| CI policy (conftest), runtime authz (OPA), admission (Kyverno and Rego) | Done. 187 Rego tests, 108 Kyverno rows |
| Generators and drift check | Done. Network and admission config tested on kind. SPIRE entries remain untested |
| Reference gateway, approvals, canary, response playbook, kill drill | Done. Dev HMAC identity. Mock default plus bounded live directory backend on `codex/multi-agent-next-steps` |
| Check engine, OSCAL 1.1.3 output, POA&M candidates, report | Done. OSCAL validates against the vendored NIST schema |
| Beacon plugins | Done. Check summaries plus exact source JSONL bytes. Local witness sealing, checkpoints, byte recovery, and detection of edits tested |
| GitHub Actions CI | Green on `main` |
| Multi-agent controls | IN PROGRESS. `docs/PATH-TO-MET.md` lists 14 items in 4 phases. M-02 has a tested read-only adapter pending merge. Control rows stay at 1 MET, 5 PARTIAL, and 6 NOT MET |
| Independent cold review | `docs/review/REVIEW-2026-09-27.md`: 26 findings. 26 FIXED, 0 OPEN, 0 WONTFIX. One commit per finding (`Fix R-NN: ...`), each with a test. R-03 has a second commit that restored a green state |

## 3. Environment setup

```sh
python3 -m pip install -e '.[dev]'
# Tools on PATH (versions used in CI):
#   opa v1.4.2, conftest 0.59.0, kyverno CLI v1.14.1
make test     # all policy and Python tests, plus the drift check
make demo     # end-to-end run; writes out/assessment/
```

For the SCF tests, clone `kfcain/beacon` and set `MEMBRANE_SCF_ROWS` to `<beacon>/beacon/scf/objectives/rows.json`. Without it, those tests skip.

For source custody integration tests, install Beacon in the same environment: `python3 -m pip install -e /path/to/beacon`. Set `MEMBRANE_REQUIRE_BEACON_TESTS=1` to fail if Beacon is missing. CI installs Beacon and sets this flag.

## 4. Rules that apply to all work

These are the owner's rules. Keep them.

- **Prose style.** Write all prose in ASD-STE100 Simplified Technical English: short sentences, active voice, one idea per sentence, no em-dashes.
- **Status words.** Checks use PASS, FAIL, NO_EVIDENCE, STALE, INELIGIBLE. Controls use MET, PARTIAL, NOT MET. Never write "in place", "compliant", "evidenced", or "proven".
- **Fail closed.** An error, a missing field, or an unknown value must deny or give a non-PASS result. Never the reverse.
- **No invented ids.** Every SCF id must exist in Beacon's pinned `rows.json`. Every NIST SP 800-53 id must exist in Rev 5. If you cannot verify an id, leave it out.
- **Non-live evidence.** Fixture or simulated evidence counts only with `--allow-nonlive`, and that output must say "demonstration".
- **Honest limits.** When you add a limitation or remove one, update `LIMITS.md`.
- **Contracts.** When you change an interface, update `docs/CONTRACTS.md` in the same commit.
- **Commits.** Keep `make test` green before each commit. Use small commits with clear messages.

## 5. How to continue a review

1. Open the newest file in `docs/review/`. Each finding has an id, a severity, the evidence, a suggested fix, and a status: OPEN, FIXED, or WONTFIX.
2. Work on OPEN findings from the most severe down. For each fix:
   - add a test that fails before the fix
   - make the fix
   - run `make test`
   - set the status to FIXED and name the commit
3. If the review file has "INCOMPLETE" in its header, the review stopped early. Finish the unchecked items in its checklist first.

## 6. Open next steps (after the review)

### 6.0 Work split (set 2026-09-28)

Two agents work in parallel. Each one owns its files. Do not edit files that the other agent owns. If you must change a shared file, make a small, separate commit and say why in the message.

| Item | Owner | Branch | Files the owner changes | State |
| --- | --- | --- | --- | --- |
| 4. Source evidence custody | **Codex** | `codex/source-evidence-custody` (merged) | `integrations/beacon/`, `membrane/evidence.py` (sealing hooks only), custody tests, `LIMITS.md` custody section, `docs/CONTRACTS.md` custody text | DONE. PR #1, merge `d95b6a0ff889dbcb84d6e2a9b703caa4acddf02a`. GitHub CI run 36425955426 passed. Local `make test`: 260 Python tests, 187 Rego tests, 108 Kyverno rows, drift check OK. The 31 custody tests include the actual Beacon witness path. |
| 1. Live cluster validation | **Claude** | `claude/live-cluster` (merged) | `.github/workflows/live-cluster.yml`, `scripts/live/`, `tests/live/`, `LIMITS.md` cluster lines, this table | DONE. 17 of 17 live probes pass on kind + Cilium 1.17.4 + Kyverno (GitHub run 36387979570). Runs on GitHub-hosted runners only, because neither sandbox can pull the kind node image. It found one real defect: Cilium must answer `nameError` (see LIMITS.md). |
| 3. Real tool backend | **Codex** | `codex/multi-agent-next-steps` | `membrane/gateway/`, `tests/test_real_backend.py`, backend contract and limits | IMPLEMENTED, pending review and merge. Read-only local `kb.search` writes live evidence. AGT-AU-01 counts it without the nonlive flag. Local `make test`: 297 Python tests, 187 Rego tests, 108 Kyverno rows, drift check OK. `make demo` passed. Store and memory writes remain open. |
| 2. SPIFFE identity | Unassigned | | | Can reuse the item 1 kind cluster. It is M-01 in `docs/PATH-TO-MET.md`, so it now blocks multi-agent work |
| 5. Multi-agent controls (M-01 to M-14) | Per item | | Per item in `docs/PATH-TO-MET.md` section 4 | IN PROGRESS. Items 2 and 3 above are M-01 and M-02 |

Rules for this split:

- **Custody belongs to Codex.** Claude does not implement custody, and does not change `integrations/beacon/` or the sealing parts of `membrane/evidence.py`.
- **Evidence API is frozen.** The live-cluster work writes evidence only through the existing `membrane.evidence.emit()` API. If Codex changes that API, Codex keeps it backward compatible, or updates `scripts/live/` in the same commit.
- **Shared files.** Both agents may need `LIMITS.md` and `docs/CONTRACTS.md`. Edit only your own section. Rebase on `main` before you push.
- **Status.** When an item finishes, the owner sets its state here to DONE and names the merge commit.

### 6.1 Item details

Item 5 has its own plan in `docs/PATH-TO-MET.md`. Each M item names its files, its evidence record, its proposed check, and its test for done. Set the item state in that file, not here. Start with M-05, M-09, M-11, or M-13. They do not need SPIFFE or the real tool backend.


1. **Kind cluster test.** DONE, see the table above and `scripts/live/`. Follow-ups: let `membrane checks run` read the live canary record from the workflow artifact, and add SPIRE to the same cluster for item 2. Original scope: Run a kind cluster with Cilium. Apply `out/generated/k8s/*` and `policy/admission/kyverno/*`. Then run the egress canary probes, which are listed as not run today. Add a DNS probe: an agent with a Cilium policy must fail to resolve a name outside its egress list (R-23). Also apply the admission policies and try the R-15 test pod (wrong namespace, service account, tier, and image digest) against the live webhook.
2. **Identity.** Replace the dev HMAC identity with SPIFFE SVIDs over mTLS. The token fields already match the SPIFFE ID shape.
3. **Real tool backend.** Add a real tool backend adapter that writes `tool_exec` records with mode `live`.
4. **Custody.** DONE. `beacon collect --plugin membrane.evidence` retains every top-level JSONL file from the selected source directories. It verifies envelopes and hashes, retains exact file bytes, and preserves record modes. Read `integrations/beacon/README.md` and `docs/CONTRACTS.md` section 9. Follow-ups: link source and assessment receipts automatically, schedule collection of closed log segments, and test remote custody. The snapshot does not lock writers or detect data omitted before collection.

## 7. Prompt to start a new model

Paste this into the new session together with repo access. For multi-agent work, use the second prompt.

> You are continuing work on the repo kfcain/membrane. Read HANDOFF.md, then README.md, LIMITS.md, docs/CONTRACTS.md, and the newest file in docs/review/. Follow every rule in HANDOFF.md section 4. Set up the environment per section 3 and run `make test` to confirm a green baseline before you change anything. Then work the OPEN review findings from most to least severe, one commit per finding, each with a test. Report what you fixed, what you did not fix, and why.

> You are continuing work on the repo kfcain/membrane. Read HANDOFF.md, then README.md, LIMITS.md, docs/CONTRACTS.md, docs/PATH-TO-MET.md, and docs/research/rogue-agent-field-notes.md. Follow every rule in HANDOFF.md section 4. Set up the environment per section 3 and run `make test` to confirm a green baseline. Then pick the first PLANNED item in docs/PATH-TO-MET.md that has no unmet prerequisite. For that item, deliver the gate, the evidence record, the check, and the tests. Update CONTRACTS.md and LIMITS.md in the same commit. Set the item state in docs/PATH-TO-MET.md. Report what you finished, what you did not finish, and why.
