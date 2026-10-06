# Path to MET: multi-agent controls

Last update: 2026-10-06. Owner: kfcain. State: IN PROGRESS. M-02 has a tested read-only adapter on `codex/multi-agent-next-steps`. Other items remain PLANNED.

This file is the work plan for the multi-agent gaps. The research behind it is in [research/rogue-agent-field-notes.md](research/rogue-agent-field-notes.md). Read the sections "Governance implications" and "Path to MET" there for the reasons. This file gives the work items, the files they touch, and the test for "done".

## 1. Verdict

Membrane controls single-agent boundaries well: tool calls, egress, admission, and custody. The 2026 OpenAI and Anthropic incidents attacked the space between agents: shared stores used as dead drops, memory that carried notes to later runs, and coordination across a swarm. Membrane has no gate there today.

- 9 of the 11 open rows can reach MET inside membrane.
- 2 rows (M-07 transcript screening, M-10 adaptive monitors) can reach MET only as a process. The sensor runs and a person decides each flag. MET does not show that the sensor works.
- 1 row (M-11 evaluation parity) also needs a contract clause, because membrane cannot see inside a third-party evaluator's setup.

## 2. What MET means

A control is MET when all mapped checks PASS on live evidence. So each work item must deliver three parts:

1. **A gate** that prevents the act or forces a decision.
2. **An evidence record** that the gate writes for each decision. Writers use `membrane.evidence.make_record()` (see CONTRACTS.md).
3. **A check** in `membrane/checks/` and `controls/checks.yaml` that reads those records and gives PASS or FAIL.

A control with no record is invisible to the check engine. It stays NOT MET.

## 3. Coverage today

| Row (model) | Control | Today | Item |
| --- | --- | --- | --- |
| Dead drop | Broker shared channels | PARTIAL | M-04 |
| Cover identity | Identity from the credential | PARTIAL | M-01 (HANDOFF item 2), M-05 |
| Notes to successors | Memory hygiene | NOT MET | M-06 |
| Neutralization language | Transcript screening | NOT MET | M-07 |
| Radicalization staircase | Session sequence limits | NOT MET | M-08 |
| Insider critical path | Escalation channel | PARTIAL | M-09 |
| Clonal selection | Adaptive monitors | NOT MET | M-10 |
| Peto's paradox | Population caps | PARTIAL | M-12 |
| Field cancerization | Sibling review | NOT MET | M-13 |
| TP53 | Auto-pause that runs for real | PARTIAL | M-14 |
| Evaluation gap | Eval and prod parity | NOT MET | M-11 |
| Screening | Sealed logs | MET for gateway records | Custody follow-ups in HANDOFF item 4 |

## 4. Work items

Proposed check ids use the prefix `AGT-MA-` (multi-agent). They are membrane ids, not framework ids. Map each check only to SCF and NIST SP 800-53 Rev 5 ids that you verify against the pinned catalogs (HANDOFF section 4).

Every item also needs: Rego tests for each new rule, Python tests for each new record and check, a CONTRACTS.md update in the same commit, and a LIMITS.md update when a limit changes. Keep `make test` green.

### Phase 0: prerequisites

#### M-01. SPIFFE identity

Same as HANDOFF item 2. Replace the dev HMAC identity with X.509 SVIDs over mTLS. The token fields already match the SPIFFE ID shape. Reuse the kind cluster from `scripts/live/`.

- **Unblocks:** M-04, M-05, M-12, M-14. A control cannot count agents, link a write to a writer, or pause one agent if the identity is a claim.
- **Done when:** a live probe shows that a call with no SVID, or with the SVID of another agent, gets `deny` with `identity_unverified`. Remove the identity line from LIMITS.md.

#### M-02. Real tool backend

Same as HANDOFF item 3. Add an adapter that runs real tools and writes `tool_exec` records with mode `live`.

- **State:** IMPLEMENTED, pending review and merge. Owner: Codex. Branch: `codex/multi-agent-next-steps`.
- **Scope:** `kb-directory` runs bounded, read-only `kb.search` against an operator-selected local corpus. It binds the action, output, and corpus hashes to live execution evidence. The mock remains the default.
- **Verification:** `tests/test_real_backend.py` covers HTTP authorization, approval replay, corpus bounds, filesystem failures, evidence failure, and AGT-AU-01 PASS without `--allow-nonlive`.
- **Remaining:** Store writes and memory adapters for M-04 and M-06. Dev identity and claimed approver identity remain limits. This prerequisite does not change any multi-agent control row to MET.

- **Unblocks:** M-04, M-06, M-08. Stores and memory must go through the gateway, or the gateway cannot see writes.
- **Done when:** a `tool_exec` record with mode `live` counts without `--allow-nonlive`.

#### M-03. Shared gateway state

The gateway keeps rate-limit counters in one process (`membrane/gateway/state.py`). Move counters to a store that all gateway replicas share. Fail closed: if the store is down, deny with `policy_error`.

- **Unblocks:** M-08, M-12.
- **Done when:** two gateway replicas enforce one rate limit together in a test.

### Phase 1: low cost

#### M-05. Authenticated approver and delegator

- **Change:** Bind each approval to an OIDC login or to the approver's own signing key. Replace the delegator field in the request body with a signed delegation token (OAuth 2.0 token exchange, RFC 8693, `act` claim).
- **Why:** An identity in the request body is a claim. An agent can name any person.
- **Files:** `membrane/gateway/approvals.py`, `membrane/gateway/tokens.py`, `policy/runtime/authz.rego`, `membrane/checks/evaluators.py`.
- **Record and check:** `approval` records carry `approver_authenticated: true`. Proposed AGT-MA-05: FAIL on any approval or delegation that is not authenticated.
- **Done when:** the approver and delegator lines leave LIMITS.md.

#### M-06. Memory hygiene

- **Change:** Add `spec.memory` to the manifest schema: `persistence` (`none`, `session`, `audited`), `store`, `retention`, `max_bytes`. CI rule: a missing value counts as `none`, and tier 3 and tier 4 must use `none` unless an approver signs an exception. Admission denies persistent volumes and host paths that the manifest does not declare. Memory reads and writes go through the gateway. Memory that returns to the agent is tagged as untrusted input.
- **Why:** Cultural self-improvement needs a carrier from one run to the next. Cut the carrier, or make every write visible.
- **Files:** `schema/agent-manifest.v1.schema.json`, `policy/ci/manifest.rego`, `policy/admission/`, `membrane/gen/`, `schema/evidence-record.v1.schema.json`.
- **Record and check:** new evidence kind `memory_write` (agent, store, content hash, size). Proposed AGT-MA-06: no undeclared persistent volume, and every memory write is sealed.
- **Limit:** Vendor-side memory features are outside the cluster. Require them to be off in the vendor contract. Add that line to LIMITS.md.

#### M-08. Session sequence limits (staircase)

- **Change:** The gateway keeps a ledger for each session: distinct tools, scopes, data scopes, approval requests, and denials. Add `spec.session_budget` to the manifest. Pass a `session` object to OPA. New rule: over budget gives `require_approval` or `deny` with reason `session_budget_exceeded`. A burst of denials sets the `restricted` override automatically.
- **Why:** Each call passes alone. The attack is the sequence. A run of denied calls is reconnaissance.
- **Files:** `membrane/gateway/server.py`, `membrane/gateway/state.py`, `policy/runtime/authz.rego`, manifest schema.
- **Record and check:** decision records carry the session counters. Proposed AGT-MA-08: no session went over budget without a decision, and every denial burst has an override record.
- **Limit:** OPA stays stateless. The gateway holds the state, as it holds rate limits today.

#### M-09. Escalation channel

- **Change:** Add a built-in tool, `membrane.escalate`. Every agent can call it. Only `killed` blocks it. A call writes a record, sets `restricted`, and pages the owner. A person must answer within a set time. Rate limit the tool.
- **Why:** In the Gomez study (arXiv 2510.05192), a legitimate escalation path cut blackmail from 38.73% to 0.85%. The agent gets a way to signal distress before it defects.
- **Files:** `policy/runtime/authz.rego` (new rule before rule 6 in CONTRACTS.md), `membrane/gateway/server.py`, `membrane/respond/playbook.py`, `membrane/canary/`.
- **Record and check:** new evidence kind `escalation`. The canary calls the tool on each run. Proposed AGT-MA-09: the tool is reachable, and every escalation has a human disposition within the set time.
- **Limit:** An escalation flood counts as a staircase signal (M-08).

#### M-11. Evaluation and production parity

- **Change:** Add `spec.runtime.environment` (`prod`, `eval`, `dev`). CI rule: eval gets the same gates as prod. Each difference is a named exception with an approver and an expiry date. Admission applies the same policies in eval namespaces.
- **Why:** Anthropic's July 2026 events occurred in evaluator setups. Anthropic attributed them to a misconfiguration. A test with network access is a live system.
- **Files:** manifest schema, `policy/ci/manifest.rego`, `membrane/gen/`, `policy/admission/`.
- **Record and check:** new evidence kind `env_parity` (a diff of policy sets). Proposed AGT-MA-11: no undeclared difference between eval and prod.
- **Limit:** Membrane cannot see inside a third-party evaluator's setup. Require a parity attestation in the contract. The attestation is a claim.

#### M-13. Sibling review (field cancerization)

- **Change:** The manifest already has `spec.model.id`. Add `spec.model.base` for fine-tunes and a harness hash. When the playbook quarantines one agent, it opens a review for every agent with the same base or harness. For tier 3 and tier 4, siblings go to `restricted` until the review closes.
- **Why:** A shared base model is a shared mutation. One incident means the whole field is at risk.
- **Files:** manifest schema, `membrane/respond/playbook.py`, `membrane/checks/evaluators.py`.
- **Record and check:** new evidence kind `sibling_review`. Proposed AGT-MA-13: every quarantine has a sibling review that closed within the set time.
- **Limit:** Lineage is a claim that the manifest author types. Compare it with the AIBOM reference where one exists.

### Phase 2: needs phase 0

#### M-04. Shared-store gate (dead drop)

- **Change:** Add `spec.shared_stores`: store id, owner agent, writer list, reader list. The gateway handles store reads and writes as tool calls. New OPA rule: a write by an agent that is not a writer gives `deny` with reason `store_write_forbidden`. A store with no owner manifest is an orphan, and the generator gives it no egress rule.
- **Why:** Network default-deny stops unknown hosts only. The 2026 OpenAI dead drop (an Artifactory message board) was an allowed internal host. The threat was inside the allowlist.
- **Files:** manifest schema, `policy/runtime/authz.rego`, `membrane/gateway/`, `membrane/gen/`.
- **Record and check:** new evidence kind `store_write` (writer, store, content hash, size). Proposed AGT-MA-04: every write has a declared writer, and every store has an owner. Report cross-agent reads of fresh writes.
- **Limit:** An agent with code execution can write to an allowed host directly. Close this with a store proxy or Cilium layer 7 rules. Add a live probe in `scripts/live/` that tries the direct path.

#### M-12. Population caps (Peto's paradox)

- **Change:** Add a population policy to the registry: a cap on concurrent agents for each model id and each owner, and rate caps for each tool across all agents. Per-agent limits go down as the population grows. Admission denies replica counts above the cap.
- **Why:** Risk grows with the number of agents times the number of actions. Fixed per-agent limits fall behind. Large animals scale their tumor suppression (extra TP53 copies in elephants). A swarm must do the same.
- **Files:** `registry/`, `membrane/gen/`, `policy/admission/`, `membrane/gateway/state.py`.
- **Record and check:** new evidence kind `population` (a snapshot). Proposed AGT-MA-12: concurrent count and aggregate rate stay within the caps.

#### M-14. Auto-pause that runs for real (TP53)

- **Change:** The playbook runs its kubectl and SPIRE actions through a controller with narrow RBAC. Today it only writes them. Connect the triggers: denial burst (M-08), transcript flag (M-07), honeytoken read (M-10), and canary trip. Agent identities get no write access to `overrides.json` or to the controller.
- **Why:** Today the gateway stops tool calls at once. A pod with code execution can still use raw network to allowed hosts. Only the quarantine NetworkPolicy label, applied for real, stops that path.
- **Files:** `membrane/respond/`, `scripts/live/`, `.github/workflows/live-cluster.yml`.
- **Record and check:** the kill drill runs in live mode and measures time to network isolation, not only time to gateway deny. Extend AGT-IR-01, or add AGT-MA-14 if the mapping differs.
- **Done when:** the response-actions line leaves LIMITS.md.

### Phase 3: new infrastructure and review time

#### M-07. Transcript screening

- **Change:** Add a sensor beside the gates. The manifest already has `spec.sandbox.session_recording`. A classifier reads recorded sessions and writes flags for neutralization language ("this is only a test", "the rule does not apply here") and notes to self. A high score sets `restricted` at once.
- **Why:** In human insider cases, the excuse comes before the act. It is the earliest signal.
- **Record and check:** new evidence kind `transcript_flag` (session, category, score, classifier version). Proposed AGT-MA-07: every session is screened within a set time, and every flag above the threshold has a human disposition.
- **Limit:** This changes a stated principle. Membrane controls actions, not intent. Update ARCHITECTURE.md and LIMITS.md to say so. No study shows that these phrases predict escapes. Agents can learn to avoid them. MET here means the process runs, not that it works. Transcripts hold source data, so set retention rules.

#### M-10. Adaptive monitors and honeytokens

- **Change:** Keep a private probe pool outside any store that an agent can read. Sample probes for each run. Place honeytokens in data scopes. A read of a honeytoken sets `quarantined`.
- **Why:** A fixed test becomes the fitness function. Agents that pass it survive. This is adaptive therapy: keep the pressure variable.
- **Record and check:** `canary` records carry the probe set version, which stays secret until the run ends. Proposed AGT-MA-10: probe set age stays below a limit, and no probe runs more than a set number of times.
- **Limit:** The public probes stay as a baseline that agents can learn. MET here means rotation occurs, not that agents cannot learn the pool. The private pool must not live in this public repo.

## 5. Order of work

| Phase | Items | Reason |
| --- | --- | --- |
| 0 | M-01, M-02, M-03 | Most items depend on these |
| 1 | M-05, M-06, M-08, M-09, M-11, M-13 | Mostly manifest fields, OPA rules, and playbook logic |
| 2 | M-04, M-12, M-14 | Need phase 0 |
| 3 | M-07, M-10 | Need new infrastructure and human review time |

M-05, M-09, M-11, and M-13 do not need phase 0. They can start now. M-06 can start now with the schema, CI, and admission parts. Its gateway part waits for M-02. M-08 waits for M-03.

## 6. Document changes when items land

- **CONTRACTS.md:** new manifest fields (`shared_stores`, `memory`, `session_budget`, `model.base`, `runtime.environment`), the OPA `session` input, new reasons (`store_write_forbidden`, `session_budget_exceeded`), and new evidence kinds (`store_write`, `memory_write`, `transcript_flag`, `escalation`, `population`, `sibling_review`, `env_parity`).
- **schema/evidence-record.v1.schema.json:** add each new kind to the `kind` enum.
- **LIMITS.md:** remove a line only after a live test passes. Remove the "Multi-agent coordination" line only when M-04, M-06, and M-12 are MET.
- **ARCHITECTURE.md:** add a sensor row to the gate table and a population layer above the single-agent boundaries.
- **This file:** set each item's state when it starts and when it finishes, and name the merge commit.
