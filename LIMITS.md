# Limits

Membrane is a reference. It shows a design and gives working parts that you can test on a laptop. It is not ready for production as it is. This file says what membrane does not do.

## What the reference parts do not prove

- **Identity.** The gateway uses a dev HMAC token that has the same fields as a SPIFFE ID. It is not SPIFFE. Production must use X.509 SVIDs over mTLS from SPIRE or a cloud workload identity.
- **Approver identity.** `membrane approve --approver <email>` takes the approver from a CLI flag. Nothing authenticates it. Any person who can run the command and read the state directory can name any approver. The `approval` record says `approver_authenticated: false`. Production must bind the approver to an authenticated identity, for example an OIDC login or an approval signed with the approver's own key.
- **Gateway capacity.** The reference gateway uses one thread per connection with no cap on the thread count. A read that stalls for 10 seconds gets a deny. A flood of connections can still exhaust the host. Put a real proxy with connection limits in front of it.
- **Shared rate state.** The default limiter is per process. `--rate-limit-db` shares a persistent budget across processes on one trusted local filesystem. Each process must select the same initialized SQLite file. A state failure denies and does not fall back. SQLite here is not a cross-host store. NFS, replicated storage, shared identity, and shared approval deployment are not covered. Operators control initialization and file access. Restoring an old database or moving the host clock forward can change the effective window.
- **Tool execution.** The default backend is a mock. It writes `tool_exec` records with mode `simulated`. The optional `kb-directory` backend reads real local files and writes mode `live`. It supports only read-only `kb.search` on `kb.public-internal`. It does not execute store writes, remote tools, or memory updates. Those adapters remain work for M-04 and M-06. Live execution does not change the dev identity and approval limits.
- **Directory corpus.** An operator selects the corpus at startup. Use a private local directory with stable files. The backend rejects symlinks, hard-linked documents, special files, invalid UTF-8, changed files, and inputs over its bounds. It checks file metadata before and after reads. It does not lock writers or give an atomic filesystem snapshot. It does not detect semantic prompt injection in documents. Returned excerpts are untrusted data. Do not use an untrusted mount that can stall filesystem calls.
- **Cluster config.** The `live-cluster` workflow applies the generated NetworkPolicies, Cilium policies, registry ConfigMap, and Kyverno policies to a kind cluster with Cilium and Kyverno, and runs 17 admission and egress probes. That is one cluster type at one time. Generated SPIRE entries have not been applied to a SPIRE server. See [docs/SOURCES.md](docs/SOURCES.md).
- **Admission image list.** The manifest has one `runtime.image`. Admission allows only that image digest in every container of an agent pod. A pod with a sidecar or an init image that the manifest does not name is denied. The schema has no field for more images yet.
- **Action hash encoding.** The action hash uses membrane's own canonical JSON (Python float `repr`), not RFC 8785 (JCS). The gateway rejects inexact and non-finite numbers, so the hash binds the exact value sent. A backend in another language must reproduce this encoding to check a hash.
- **Tier 4 promotion approvers.** The CI gate checks that `spec.promotion.approvers` lists at least two distinct plain email addresses and that none is the owner. The compare trims white space and ignores case. The list is a claim that the manifest author types. No gate checks that the named people approved the change. In production, check the list against pull request review records (for example CODEOWNERS approvals) and record the result in `pipeline_run`.
- **Delegator.** The agent sends the delegator in the request body. Nothing authenticates it. AGT-AC-02 shows only that a delegator was named. It maps to AC-3 only, not to IA-2 or to SCF objectives that need an authenticated identity.
- **DNS for agents with no egress list.** An agent with an empty egress list has no Cilium policy. Its plain NetworkPolicy allows DNS to kube-dns at layer 4. It can look up any name, and a DNS lookup can carry data out. Agents with an egress list get DNS only through the Cilium DNS proxy.
- **Cluster requirement for Cilium DNS.** Set the Cilium Helm value `dnsProxy.dnsRejectResponseCode=nameError`. A pod resolver tries each search-list name first (`ndots:5`, and the node may add its own search domains). With the Cilium default `refused`, the resolver stops at the first refused name, and an allowed FQDN never resolves. The live kind run found this. `scripts/live/run.sh` sets the value.
- **Egress probes.** `membrane canary run` cannot send pod egress, so it lists the egress probes as not run. The `live-cluster` workflow runs them in real pods on kind and writes a `canary` record with mode `live`. The check engine does not read that record yet; it stays in the workflow artifact.
- **Response actions.** The playbook writes the kubectl and spire-server commands it would run. It does not run them. The overrides file does take effect at the gateway at once.
- **Fixture evidence.** Inventory, egress flow, secret scan, and pipeline evidence in the demo are fixtures with planted problems. They are not observations of a real system.

## What the check results do not mean

- A check result reports what the evidence records show at the assessment time. It does not show that the records are true.
- A PASS covers only the population in the records. A workload, flow, or call that no collector saw is not in the population.
- A control status is a rollup of mapped checks only. It is not an assessor determination. It does not cover the whole control.
- The NIST SP 800-53 and SCF mappings are membrane's own. Neither NIST nor the SCF Council reviewed them. ISO/IEC 42001 is not mapped, because its Annex A text is not public.
- A run with `--allow-nonlive` is a demonstration. Its output says so in a banner and in the OSCAL props.
- OSCAL output points `import-ap` at a placeholder assessment plan. A real assessment needs a real plan.

## What membrane cannot see

- Gates control actions, not intent. An agent can do harm inside its permissions. Tiers and approvals reduce this risk. They do not remove it.
- An agent that can run code can bypass the tool gateway with raw network calls. The network default-deny is the backstop. Do not rely on one layer.
- **Multi-agent coordination.** Every gate decides for one agent and one call. No gate inspects writes to stores that other agents read, memory that persists between runs, the sequence of calls in a session, or the total size of a swarm. Agents can coordinate through allowed hosts. The work plan is [docs/PATH-TO-MET.md](docs/PATH-TO-MET.md).
- Vendor SaaS agents (for example Microsoft Copilot or Salesforce Agentforce) run outside your cluster. Membrane cannot put a gate inside them. Use the vendor's admin APIs and audit logs, and require per-action log export in the contract.

## Custody

Membrane writes append-only JSONL files. Each record carries two hashes: `payload_sha256` over the payload and `record_sha256` over the whole record, envelope included. The reader checks both and stops on a mismatch or a missing hash. These hashes detect an accidental edit or a naive edit that does not recompute them. They do not detect a writer that recomputes the hashes. Such a writer can change `mode`, `collected_at`, or any other field without detection before custody. Beacon provides signed witness records and checkpoints. Use `membrane.checks` for results and `membrane.evidence` for exact source file bytes. Both plugins are in `integrations/beacon/`. The Beacon status word stays unverified.

Source custody is an explicit snapshot of the selected directories. It retains at most 256 top-level JSONL files and 16 MiB of source bytes. It rejects invalid, incomplete, empty, or changed inputs. It rejects symlinks and special files. It does not lock writers. Stop writers, or select closed log segments, for a stable capture. Files omitted or deleted before collection are outside its view. New writes need another collection.

The source bundle includes original tool arguments and other source data. Custody does not redact that data or assess its truth. Fixture and simulated record modes remain unchanged and make the bundle a demonstration. The raw file content is data, not a Beacon claim. A source bundle and a check result have separate receipts. No automatic link checks that both used the same snapshot yet. Local Beacon testing covers signing, checkpoint verification, byte recovery, and detection of edits after sealing. It does not test an independent witness service or remote Object Lock storage.
