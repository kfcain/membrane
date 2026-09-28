# Policy

This folder holds the four policy gates of membrane. Each gate reads the agent manifests or data built from them. Each gate fails closed. A missing or malformed field causes a deny.

| Gate | Folder | Engine | Checks |
| --- | --- | --- | --- |
| CI | `ci/` | conftest (Rego, package `membrane.ci`) | One manifest before merge and deploy |
| Runtime | `runtime/` | OPA (package `membrane.authz`) | One tool call at the gateway |
| Admission (Kyverno) | `admission/kyverno/` | Kyverno ClusterPolicy | Pods and Deployments at the Kubernetes API |
| Admission (Rego) | `admission/rego/` | OPA or Gatekeeper (package `membrane.admission`) | The same admission rules for OPA users |

Run all tests from the repo root:

```sh
opa check --strict policy/
opa test policy/ --ignore '*.yaml' -v
policy/ci/check.sh
policy/admission/kyverno/check.sh
python -m pytest tests/test_policies.py
```

`opa test` needs `--ignore '*.yaml'`. OPA loads YAML files as data. The YAML files here are conftest inputs and Kyverno documents. They are not OPA data.

## CI gate (`ci/`)

Input: one manifest file. Output: `deny` (fails the gate) and `warn` (does not fail the gate).

```sh
conftest test --policy policy/ci --namespace membrane.ci registry/agents/*.yaml
```

Rules for all tiers:

- `apiVersion` is `membrane/v1` and `kind` is `AgentManifest`.
- `spec.tier` is an integer from 1 to 4. `spec.status` is `active`, `suspended`, or `retired`.
- `spec.model.pinned` is true.
- Each tool name occurs one time. Each tool has a boolean `irreversible` flag.
- For `runtime.type: k8s`: `namespace` is set, `service_account` is set and is not `default`, and `image` ends in `@sha256:` and 64 lowercase hex characters.

Rules by tier:

| Tier | Rules |
| --- | --- |
| 1 | No tool scope ends in `:write` or `:admin`. No irreversible tool. `egress` is empty. |
| 2 and above | `evals` with `min_pass` at or above 0.90 (tier 2), 0.95 (tier 3), 0.97 (tier 4). `aibom` with `format` and `ref`. Each tool has `rate_limit_per_min`. |
| 3 and above | No `egress` entry contains `*`. Each entry is a lowercase FQDN. An empty list is allowed. If a tool is irreversible, `approval.required_for` contains `irreversible` or `all`. `delegation.requires_delegator` is true. |
| 4 | `sandbox` has `isolated: true`, `standing_credentials: false`, `session_recording: true`. `redteam` has `ref` and a valid `date` that is not in the future. `promotion.approvers` has 2 or more distinct entries after trim and lower-case. Each entry is a plain ASCII email address. No approver is the owner. The list is a claim; see LIMITS.md. |
| Canary | No irreversible tool. `approval.required_for` contains `all`. Tier is 2. |

Warnings: a tier 4 red team older than 180 days, an `:admin` scope at tier 2 and above, a wildcard egress entry at tier 2, a `lambda` or `saas` runtime, and an agent with no tools. The red team age uses `time.now_ns()`. The unit tests replace the clock with a fixed value.

The CI gate does not check that the file name equals `metadata.id`. `membrane/manifest.py` checks that.

Tests:

- `ci/manifest_test.rego`: unit tests for each rule, with good and bad inputs.
- `ci/testdata/bad/*.yaml`: one bad manifest per rule. Line 2 of each file names the expected deny message.
- `ci/check.sh`: conftest must pass all of `registry/agents/*.yaml`. It must fail each bad file with its expected message.

## Runtime gate (`runtime/authz.rego`)

Query: `data.membrane.authz.result`. The rules follow `docs/CONTRACTS.md` section 3. The policy builds the list of rules in contract order. It keeps the rules that match and returns the first. Each match flag is true or false, never undefined. Thus a missing field cannot remove a rule from the list. If evaluation fails, the default result is `deny` with reason `policy_error`.

The policy closes these gaps in the contract. Each choice denies or asks for approval:

| Case | Result |
| --- | --- |
| An override entry has a mode that is not one of the four modes, or has no mode | Rule 5 slot: `deny`, reason `override_unknown` |
| The manifest entry has no `requires_delegator` flag | The policy treats the flag as true |
| The tool entry has no `irreversible` flag | The policy treats the tool as irreversible |
| The manifest entry has no `approval_required_for` list | The policy treats the list as `["all"]` |
| `input.action_sha256` is missing or empty | No approval can match it |
| `delegator` is only white space | The policy treats it as empty |

`runtime/testdata/data.json` has the contract data shape, built from `registry/agents/`. `tests/test_policies.py` fails if it does not match the registry. To try one request:

```sh
opa eval -d policy/runtime/authz.rego -d policy/runtime/testdata/data.json -I 'data.membrane.authz.result' < request.json
```

Tests: `runtime/authz_test.rego` has a test for each rule and for the order between rules. Examples: a killed agent with a valid approval gets `deny`. A `restricted` override makes a reversible tool need approval. A bad or replayed approval gets `deny` with `approval_mismatch`, even on a tool that needs approval. It never opens a new approval request. A canary call to an irreversible tool gets `deny` even with a valid approval.

## Admission gate, Kyverno (`admission/kyverno/`)

Two ClusterPolicies. Each rule uses `validate.failureAction: Enforce`. Kyverno 1.13 and later deprecate `spec.validationFailureAction`, so the policies do not use it. Autogen is off. The Deployment rules are explicit.

`membrane-agent-workloads` applies to Pods with the label `membrane.io/agent-id`. It also applies to Deployments whose pod template has that label.

| Rule (Pod and Deployment) | Check |
| --- | --- |
| `*-manifest-sha256` | Annotation `membrane.io/manifest-sha256` is 64 lowercase hex characters |
| `*-tier-label` | Label `membrane.io/tier` is `1`, `2`, `3`, or `4` |
| `*-image-digest` | Each container, init container, and ephemeral container image ends in `@sha256:` and 64 hex characters |
| `*-service-account` | `serviceAccountName` is set and is not `default` |
| `*-no-token-automount-tier3` | Tier 3 and 4: `automountServiceAccountToken` is `false`. The rule applies when the tier label is 3 or 4, or when the registered tier is 3 or 4 |
| `*-registered` | ConfigMap `membrane-system/membrane-registry` has a key equal to the agent id. The value binds the pod: the manifest hash equals the annotation, the namespace equals the pod namespace, the service account equals `serviceAccountName`, and the tier equals the `membrane.io/tier` label |
| `*-image-registered` | The digest of each container image (Pods: containers, init containers, and ephemeral containers; Deployments: containers and init containers) is in the registered `image_digests` list. The digest decides, not the registry host |

Registry ConfigMap layout. `membrane gen` writes one key per active agent. The value is a JSON string: `{"image_digests": ["sha256:<hex>"], "namespace": "...", "service_account": "...", "sha256": "<manifest hash>", "tier": "3"}`. A missing field denies. A value in the old layout (a bare hash) denies, because it does not parse as a JSON object.

`membrane-unregistered-agents` denies Pods and Deployments without the `membrane.io/agent-id` label in a namespace with label `membrane.io/agent-namespace: "true"`.

The rules select agent workloads with preconditions, not with a `match` selector. A precondition miss gives a `skip` result, and `kyverno test` can check it. If the ConfigMap is not present, Kyverno cannot load the rule context. The rule then gives an error, and the webhook failure policy decides. Set the webhook failure policy to `Fail`.

Tests: `admission/kyverno/tests/` has `kyverno-test.yaml`, `resources.yaml` (45 resources), and `values.yaml`. The values file supplies the ConfigMap data and the namespace labels, because the CLI has no cluster. After a registry change, run `membrane gen` and then `python scripts/sync_kyverno_values.py`. A pytest check fails when the mock and the generated ConfigMap differ.

```sh
policy/admission/kyverno/check.sh
```

Use `check.sh`, not only `kyverno test`. Kyverno CLI 1.14.1 counts a row that wants `fail` and gets `pass` as a pass. The row reason still shows `Want fail, got pass`. `check.sh` fails on any such row. The CLI also accepts any expectation for a resource that a `match` block excludes. For this reason the suite has no expectation for a Pod outside the agent namespaces in `membrane-unregistered-agents`. The Rego unit tests check that case.

## Admission gate, Rego (`admission/rego/`)

Package `membrane.admission`. Output: `deny` (set of messages), `violation` (set of `{"msg": ...}` for Gatekeeper), and `allowed`.

Input can have three shapes. The policy finds the object in `input.request.object` (AdmissionReview), then `input.review.object` (Gatekeeper), then `input` (a plain object). It checks Pods and the pod template of Deployments, StatefulSets, DaemonSets, ReplicaSets, Jobs, and CronJobs. It skips `DELETE` requests.

Registry data comes from `data.membrane.manifests` (the generated `data.json`): `sha256`, `tier`, and `k8s.namespace`, `k8s.service_account`, `k8s.image_digests`. If that is absent, the policy reads the synced ConfigMap `membrane-system/membrane-registry` from `data.inventory` and parses each value as JSON. Both sources give the full binding, so Gatekeeper users get the tier, namespace, service account, and image rules too. Namespace labels come from `data.inventory.cluster.v1.Namespace` (Gatekeeper sync) or `data.kubernetes.namespaces` (kube-mgmt).

The rules are the Kyverno rules, plus one: an agent workload must have at least one container. The Rego policy also checks the image digests of every controller kind it reads, not only Pods and Deployments.

Gatekeeper users wrap `violation` in a ConstraintTemplate. Gatekeeper gives the policy only `data.inventory`. Sync Namespaces and the `membrane-registry` ConfigMap into the inventory.

Tests: `admission/rego/admission_test.rego`.

## NIST SP 800-53 Rev 5 support

Each gate supports the controls below. A gate makes evidence for a control. It does not meet the control alone. The checks part rolls results up to MET, PARTIAL, or NOT MET.

| Gate | Rule group | Controls |
| --- | --- | --- |
| CI | Manifest review before deploy | CM-3, CM-5 |
| CI | Tier scope limits, tier 1 read only | AC-6, CM-7 |
| CI | Evals by tier | SA-11 |
| CI | Red team at tier 4 | CA-8(2) |
| CI | Digest pinning, AIBOM, pinned model | CM-6, SR-3 |
| CI | Egress FQDN list at tier 3 and above | SC-7 |
| CI | Two promotion approvers, not the owner | AC-5, CM-3 |
| Runtime | Identity check, manifest hash check | IA-9 |
| Runtime | Tool must be in the manifest, delegator, overrides | AC-3, AC-6 |
| Runtime | Human approval for irreversible tools | AC-3(2) |
| Admission | Registered agents only, unregistered workloads denied | CM-7(5), CM-8 |
| Admission | Digest pinning, manifest hash match | CM-5, SR-3 |
| Admission | Dedicated service account, no token at tier 3 and above | AC-6 |
