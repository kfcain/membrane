# Handoff

This file lets any capable coding model or engineer continue work on membrane without the original conversation. Read it first. Then read the files it names. Do not rely on memory of earlier sessions.

Last update: 2026-09-27. Owner: kfcain.

## 1. What membrane is

Membrane is a reference for AI agent containment. One manifest per agent is the source of truth. Policy gates (CI, admission, runtime) prevent actions. Each gate decision becomes an evidence record. A check engine turns evidence into check results, control rollups (MET, PARTIAL, NOT MET), and OSCAL assessment results. Beacon (`github.com/kfcain/beacon`) seals the results for custody.

Read in this order:

1. `README.md`: purpose, tiers, commands.
2. `LIMITS.md`: what the reference does not prove.
3. `docs/CONTRACTS.md`: the binding interfaces. Change code to fit the contract, or change the contract on purpose in the same commit.
4. `docs/ARCHITECTURE.md`: diagrams and the tool-call sequence.
5. `policy/README.md`: every policy rule and how to test it.

## 2. State at handoff

| Area | State |
| --- | --- |
| Manifest schema and example registry (5 agents) | Done |
| CI policy (conftest), runtime authz (OPA), admission (Kyverno and Rego) | Done. 184 Rego tests, 108 Kyverno rows |
| Generators and drift check | Done. Not applied to a real cluster |
| Reference gateway, approvals, canary, response playbook, kill drill | Done. Dev HMAC identity, mock tool backend |
| Check engine, OSCAL 1.1.3 output, POA&M candidates, report | Done. OSCAL validates against the vendored NIST schema |
| Beacon plugin | Done. Tested against a local Beacon install |
| GitHub Actions CI | Green on `main` |
| Independent cold review | See `docs/review/`. Findings may be open |

## 3. Environment setup

```sh
python3 -m pip install -e '.[dev]'
# Tools on PATH (versions used in CI):
#   opa v1.4.2, conftest 0.59.0, kyverno CLI v1.14.1
make test     # all policy and Python tests, plus the drift check
make demo     # end-to-end run; writes out/assessment/
```

For the SCF tests, clone `kfcain/beacon` and set `MEMBRANE_SCF_ROWS` to `<beacon>/beacon/scf/objectives/rows.json`. Without it, those tests skip.

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

1. **Kind cluster test.** Run a kind cluster with Cilium. Apply `out/generated/k8s/*` and `policy/admission/kyverno/*`. Then run the egress canary probes, which are listed as not run today.
2. **Identity.** Replace the dev HMAC identity with SPIFFE SVIDs over mTLS. The token fields already match the SPIFFE ID shape.
3. **Real tool backend.** Add a real tool backend adapter that writes `tool_exec` records with mode `live`.
4. **Custody.** Seal every evidence file, not only the check results, through the Beacon plugin.

## 7. Prompt to start a new model

Paste this into the new session together with repo access:

> You are continuing work on the repo kfcain/membrane. Read HANDOFF.md, then README.md, LIMITS.md, docs/CONTRACTS.md, and the newest file in docs/review/. Follow every rule in HANDOFF.md section 4. Set up the environment per section 3 and run `make test` to confirm a green baseline before you change anything. Then work the OPEN review findings from most to least severe, one commit per finding, each with a test. Report what you fixed, what you did not fix, and why.
