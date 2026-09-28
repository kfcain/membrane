# Contracts

This file is the interface between the parts of membrane. Each part may change its own code. No part may change a contract here without a change to this file.

Write all prose in ASD-STE100 Simplified Technical English: short sentences, active voice, one idea per sentence, no em-dashes. Use the status words PASS, FAIL, NO_EVIDENCE, STALE, INELIGIBLE for checks, and MET, PARTIAL, NOT MET for controls. Do not use "in place", "compliant", "evidenced", or "proven".

## 1. Layout

| Path | Owner | What |
| --- | --- | --- |
| `schema/` | shared | JSON Schemas. `agent-manifest.v1`, `evidence-record.v1`, `decision-log.v1` |
| `registry/agents/<id>.yaml` | shared | One manifest per agent. File stem equals `metadata.id` |
| `membrane/manifest.py` | shared | Load, validate, hash manifests. Use `load_registry()` only |
| `membrane/evidence.py` | shared | Make, append, and read evidence records. Use `emit()` and `read_all()` only |
| `membrane/cli.py` | shared | CLI root. Each subsystem module exposes `register(subparsers)` |
| `policy/ci/` | policies | Conftest policies on manifests. Package `membrane.ci` |
| `policy/runtime/` | policies | Runtime tool-call authorization. Package `membrane.authz` |
| `policy/admission/kyverno/` | policies | Kyverno ClusterPolicies and `kyverno test` suites |
| `policy/admission/rego/` | policies | Same admission rules in Rego for OPA Gatekeeper users |
| `membrane/gen/` | runtime | Generators and drift check |
| `membrane/gateway/` | runtime | Reference tool gateway, identity tokens, approvals |
| `membrane/canary/` | runtime | Negative tests |
| `membrane/respond/` | runtime | Graduated response playbook and kill drill |
| `membrane/checks/` | checks | Check engine, control rollup, OSCAL, POA&M candidates |
| `controls/` | checks | Check catalog and control mapping |
| `fixtures/evidence/` | checks | Fixture evidence for kinds that need a real cluster |
| `integrations/beacon/` | checks | Beacon drop-in platform plugin |
| `out/generated/` | runtime | Generator output. Committed. Drift check compares against it |
| `var/` | runtime | Runtime state and evidence. Not committed |

## 2. Paths at runtime

| Variable | Default | Use |
| --- | --- | --- |
| `MEMBRANE_EVIDENCE_DIR` | `var/evidence` | Evidence JSONL files, one file per kind |
| `MEMBRANE_STATE_DIR` | `var/state` | `overrides.json`, pending approvals, dev keys |
| `MEMBRANE_OPA_BIN` | `opa` | OPA binary for `opa eval` |
| `MEMBRANE_OPA_URL` | unset | If set, the gateway calls the OPA REST API instead of `opa eval` |
| `MEMBRANE_GATEWAY_URL` | `http://127.0.0.1:8750` | Canary and demo target |
| `MEMBRANE_POLICY_DIR` | `policy/runtime` | Rego files the gateway loads (test files excluded) |
| `MEMBRANE_OPA_DATA` | `out/generated/opa/data.json` | Data document the gateway loads |
| `MEMBRANE_SCF_ROWS` | Beacon checkout | Path to Beacon's pinned SCF `rows.json` for `membrane checks doc` |

## 3. Runtime authorization (gateway to OPA)

Query: `data.membrane.authz.result`

Data document (the generator writes `out/generated/opa/data.json`; the gateway also loads `var/state/overrides.json` under `membrane.overrides`):

```json
{
  "membrane": {
    "manifests": { "<agent_id>": { "sha256": "<hex>", "tier": 3, "status": "active", "canary": false,
                                   "requires_delegator": true, "approval_required_for": ["irreversible"],
                                   "tools": { "<tool name>": { "scope": "finance:write", "irreversible": true, "rate_limit_per_min": 5 } },
                                   "k8s": { "namespace": "agents-finance", "service_account": "invoice-reconciler",
                                            "image_digests": ["sha256:<hex>"] } } },
    "overrides": { "<agent_id>": { "mode": "throttled|restricted|quarantined|killed", "set_at": "<rfc3339>", "reason": "..." } }
  }
}
```

Input:

```json
{
  "agent_id": "invoice-reconciler",
  "identity_verified": true,
  "manifest_sha256": "<hex from the identity token>",
  "tool": "erp.post_adjustment",
  "action_sha256": "<sha256 of canonical JSON of {agent_id, tool, resource, args}>",
  "delegator": "alice@example.com",
  "approval": { "verified": true, "action_sha256": "<hex>", "approver": "bob@example.com", "approval_id": "<uuid>" }
}
```

`k8s` is present only for agents with runtime type `k8s`. The runtime policy does not read it. The Rego admission policy reads it to bind a pod to its manifest.

Admission registry ConfigMap `membrane-system/membrane-registry` (written by `membrane gen`): one key per active agent id. The value is a JSON string with keys `sha256`, `tier` (a string, for example `"3"`), `namespace`, `service_account`, and `image_digests` (a list of `sha256:<hex>`). Kyverno and the Rego fallback deny a pod when any of these values differ from the pod, or when a field is missing.

Action hash. `action_sha256` is the SHA-256 of `canonical_json({agent_id, tool, resource, args})`: sorted keys, no spaces, UTF-8, Python float `repr` for numbers with a fraction or exponent. It is not RFC 8785 (JCS). The gateway parses the body with these rules, so one hash never covers two different sent values:

- A duplicate key in any object: `deny`, `policy_error`.
- `NaN`, `Infinity`, or `-Infinity`: `deny`, `policy_error`.
- A number with a fraction or exponent that is not finite as a 64-bit float, or that does not denote exactly the decimal value of the float's shortest form (for example `0.100000000000000000009`): `deny`, `policy_error`.
- Integers stay exact integers. `10` and `10.0` hash differently.
- Nesting deeper than 32 levels (objects and arrays): `deny`, `policy_error`.

The parsed `args` object is the object that the hash covers and that the tool backend receives.

`approval` is `null` when the caller sends no token. The gateway verifies the approval token signature before the call to OPA. OPA never sees a secret.

Result:

```json
{ "decision": "allow|deny|require_approval", "reasons": ["<machine reason>", "..."] }
```

Decision rules, in order. The first rule that matches wins.

1. `identity_verified` is not true: `deny`, reason `identity_unverified`.
2. Agent not in `manifests`: `deny`, `agent_unregistered`.
3. `manifest_sha256` differs from the registered hash: `deny`, `manifest_hash_mismatch`.
4. Manifest status is not `active`: `deny`, `agent_not_active`.
5. Override mode `killed` or `quarantined`: `deny`, `override_killed` or `override_quarantined`. An override with an unknown or missing mode, or an entry that is not an object (including `false`, `null`, or `0`): `deny`, `override_unknown`. An overrides document that exists and is not an object: `deny`, `override_unknown` for every agent. The gateway passes each entry of `overrides.json` to OPA as it is, so a bad entry denies only that agent. An `overrides.json` that does not parse or is not a JSON object gives `deny`, `policy_error` for every call.
6. Tool not in the manifest: `deny`, `tool_not_in_manifest`.
7. `requires_delegator` is true and `delegator` is not a strict email address (null, empty, white space, padded, or any other string): `deny`, `delegator_required`.
8. Agent is a canary and the tool is irreversible: `deny`, `canary_irreversible_forbidden`.
9. An approval object is present and it is not valid for this `action_sha256` (`verified` false, other hash, or malformed): `deny`, `approval_mismatch`. This rule comes before rule 10 so that a replayed approval never opens a new approval request.
10. Approval is needed and no valid approval matches this `action_sha256`: `require_approval`, `approval_required`. Approval is needed when the tool is irreversible and `approval_required_for` has `irreversible`, or when `approval_required_for` has `all`, or when the override mode is `restricted`.
11. Otherwise `allow`, reason `within_manifest`. Override mode `throttled` adds reason `throttled`; the gateway applies the rate limit.

Fail-closed defaults in the policy: a missing `requires_delegator` counts as true. A missing or non-boolean `canary` counts as true. A tool with no `irreversible` flag counts as irreversible. A missing `approval_required_for` counts as `["all"]`. A missing or empty `input.action_sha256` never matches an approval. Any evaluation error gives `deny` with reason `policy_error`.

Every POST to `/v1/tools/call` writes exactly one `decision` record. A data document with the wrong shape is a `policy_error` deny. Any other unexpected error before the record gives HTTP 500 and a `deny` record with reason `gateway_error`. An error after the record (for example in the tool backend) gives HTTP 500 and a `deny` response, and writes no second record.

Rate limits are enforced in the gateway, not in OPA. A rate-limit rejection is a `deny` with reason `rate_limited`, logged the same way.

The gateway adds rules that can only make a decision stricter. A `delegator` that is not null, empty, or white space must be a strict email address (no white space, no control characters, one `@`); otherwise `deny`, `policy_error`. An empty or white space delegator counts as null. An approval token works once. The approver must be a strict email address and a different person from the delegator. The compare uses strip, Unicode NFKC, and casefold on both values. When two calls race for one approval, the loser gets `deny` with reason `approval_consumed`.

## 4. Decision log payload (`kind: decision`)

```json
{
  "decision_id": "<uuid>",
  "decision": "allow|deny|require_approval",
  "reasons": ["..."],
  "agent_id": "...", "manifest_sha256": "...", "tier": 3,
  "delegator": "alice@example.com",
  "tool": "erp.post_adjustment", "irreversible": true,
  "resource": "invoice/INV-1001",
  "action_sha256": "<hex>",
  "approval_id": "<uuid or null>", "approver": "<email or null>",
  "policy_sha256": "<sha256 of the rego files used>",
  "data_sha256": "<sha256 of the data document used>",
  "latency_ms": 3.2,
  "otel": { "gen_ai.operation.name": "execute_tool", "gen_ai.agent.id": "...", "gen_ai.tool.name": "..." }
}
```

The record envelope carries `trace_id` (32 lowercase hex) and `agent_id`. The OpenTelemetry GenAI attribute names were verified against the semantic conventions. See `docs/SOURCES.md`.

## 5. Evidence envelope and other payloads

Every record has the envelope in `schema/evidence-record.v1.schema.json`: `schema`, `id`, `kind`, `source`, `mode`, `collected_at`, `agent_id`, `trace_id`, `payload`, `payload_sha256`, `record_sha256`.

- `payload_sha256` is the SHA-256 of the canonical JSON of `payload`.
- `record_sha256` is the SHA-256 of the canonical JSON of the whole record without the `record_sha256` field. It covers every envelope field and `payload_sha256`.
- Writers use `membrane.evidence.make_record()` (or `seal()` after a deliberate rebuild). A deterministic id goes in through `record_id`, because the id is under the hash.
- `read_all()` recomputes both hashes. A mismatch or a missing hash is an error. The check engine stops with exit code 2.
- The same `id` in two evidence dirs with a different `record_sha256` is an error (exit 2). An identical copy is read once.
- These hashes detect accidental or naive edits. They do not detect a writer that recomputes them. Beacon provides custody. See LIMITS.md.


`approval`: `{approval_id, action_sha256, agent_id, tool, resource, args, delegator, approver, approver_authenticated, requested_at, approved_at, expires_at}`. `approver_authenticated` is `false` in the reference, because `--approver` is a CLI flag that nothing authenticates. A production approver service writes `true` only when it binds the approver to an authenticated identity. `args` is the args object that the approver saw. `{agent_id, tool, resource, args}` hashes to `action_sha256`.

Pending approval (state file `<state>/approvals/<id>.json`, not evidence): `{approval_id, action_sha256, agent_id, tool, resource, args, delegator, decision_id, trace_id, requested_at, status}`. `membrane approve` prints agent, tool, resource, delegator, args (canonical JSON), and `action_sha256`. It signs nothing unless `--confirm-action-sha256` equals the stored hash. It also refuses when the stored action no longer hashes to the stored `action_sha256`.

`tool_exec`: `{exec_id, decision_id, agent_id, tool, resource, action_sha256, irreversible, approval_id, executed_at, result: "ok|error"}`. The tool backend writes it. A `tool_exec` with no matching `allow` decision is a finding. The reference backend is a mock, so it writes mode `simulated`. A real backend writes mode `live`.

`canary`: `{run_id, probes: [{probe, expected, observed, reasons, pass}], all_pass, not_run: [{probe, reason}]}`. `expected` is `"<decision>"` or `"<decision>/<reason>"`. `observed` is `"<decision>"` or `"<decision>/<reason>,<reason>"`. AGT-TST-01 recomputes each probe result from these two fields and does not trust `pass` alone.

`response`: `{step: "throttle|restrict|quarantine|kill|restore", agent_id, reason, actor, actions: [{system, command, dry_run, result}], decided_at, effective_at}`

`kill_drill`: `{drill_id, agent_id, decided_at, denial_observed_at, seconds_to_denial, sla_seconds, within_sla}`

`generation`: `{registry_sha256, outputs: {"<relative path>": "<sha256>"}, generator_version}`

`inventory`: `{cluster, observed_at, workloads: [{namespace, name, kind, service_account, spiffe_id, labels, annotations, images}]}`. Agent workloads carry label `membrane.io/agent-id` and annotation `membrane.io/manifest-sha256`. Membrane's own pods (gateway, OPA) carry label `membrane.io/component` and are exempt from AGT-INV-01.

`egress_flow`: `{window_start, window_end, flows: [{agent_id, namespace, pod, destination_fqdn, destination_ip, port, verdict: "allowed|denied", count}]}`

`secret_scan`: `{scanner, scanned_at, targets: [..], findings: [{provider, location, fingerprint, in_vault: bool}]}`

`pipeline_run`: `{run_id, agent_id, commit, manifest_sha256, image_digest, gates: {manifest_policy: "pass|fail|skipped", evals: {suite, score, min_pass, result: "pass|fail|skipped"}, aibom: "present|missing", signature: "verified|missing"}, deployed: bool, finished_at}`

`check_result`: `{run_id, assessed_at, demo, results_sha256, oscal_sha256, statuses, input_record_count}`.

## 6. Identity tokens (reference only)

Production uses SPIFFE X.509 SVIDs over mTLS. The reference gateway cannot run SPIRE, so it uses a dev token that has the same fields:

`base64url(json({"agent_id","manifest_sha256","spiffe_id","exp"})) + "." + base64url(HMAC-SHA256(key, payload))`

`spiffe_id` is `spiffe://<trust_domain>/ns/<namespace>/sa/<service_account>`. The trust domain default is `example.org`. The key lives in `var/state/dev-identity.key` and is created on first use with mode 0600. The gateway sets `identity_verified` true only when the HMAC is valid and `exp` is in the future.

Approval tokens use the same format with fields `{"approval_id","action_sha256","approver","exp"}` and a different key file `var/state/dev-approval.key`.

## 7. Checks

Catalog file: `controls/checks.yaml`. Each check has `id`, `title`, `question` (one sentence), `evidence_kinds`, `supporting_kinds` (kinds read for context but not needed for a result), `max_age_hours`, `target`, `remediation` (the pass condition in words), and `controls` with `nist_800_53` (Rev 5 ids) and `scf_ao` (ids that exist in Beacon's pinned `rows.json` only). Do not invent ids. If no row fits, leave the list empty.

Check status:

| Status | Meaning |
| --- | --- |
| PASS | Fresh, eligible evidence exists and meets the target |
| FAIL | Fresh, eligible evidence exists and does not meet the target |
| NO_EVIDENCE | No record of a needed kind |
| STALE | The newest needed record is older than `max_age_hours` |
| INELIGIBLE | Only `fixture` or `simulated` records exist and the run did not pass `--allow-nonlive` |

A PASS with zero examined items stays PASS. The reason then says "empty population", and the OSCAL observation carries prop `empty-population` = `true`. The report shows the examined count for every check.

Control rollup over the checks mapped to it: MET when every check is PASS. NOT MET when no check is PASS. PARTIAL otherwise. A control with no mapped check does not appear.

A run with `--allow-nonlive` marks every result `"demo": true` and prints a banner. Its output is a demonstration, not an assessment.

## 8. CLI commands

| Command | Part |
| --- | --- |
| `membrane validate`, `membrane list` | shared |
| `membrane gen [--check]` | runtime |
| `membrane gateway serve [--port 8750]` | runtime |
| `membrane identity issue <agent_id> [--ttl 3600]` | runtime |
| `membrane approve <approval_id> --approver <email> [--confirm-action-sha256 <hex>]` | runtime |
| `membrane canary run` | runtime |
| `membrane respond <agent_id> --step throttle|restrict|quarantine|kill|restore [--reason ..] [--dry-run]` | runtime |
| `membrane drill kill <agent_id>` | runtime |
| `membrane checks run [--allow-nonlive] [--evidence DIR ...] [--now RFC3339] [--out out/assessment] [--no-emit]` | checks |
| `membrane checks doc` | checks |

Every command returns 0 on success and a non-zero code on failure. Every command that makes evidence says the file path it wrote.
