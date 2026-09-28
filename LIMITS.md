# Limits

Membrane is a reference. It shows a design and gives working parts that you can test on a laptop. It is not ready for production as it is. This file says what membrane does not do.

## What the reference parts do not prove

- **Identity.** The gateway uses a dev HMAC token that has the same fields as a SPIFFE ID. It is not SPIFFE. Production must use X.509 SVIDs over mTLS from SPIRE or a cloud workload identity.
- **Tool execution.** The tool backend is a mock. It executes nothing. It writes `tool_exec` records with mode `simulated`. A check that needs `tool_exec` is INELIGIBLE unless the run passes `--allow-nonlive`.
- **Cluster config.** No generated NetworkPolicy, Cilium policy, SPIRE entry, or Kyverno policy has been applied to a real cluster. The formats were checked against upstream documentation and source. See [docs/SOURCES.md](docs/SOURCES.md).
- **Egress probes.** The canary cannot send pod egress. It lists the egress probes as not run. It does not report them as passed.
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
- Vendor SaaS agents (for example Microsoft Copilot or Salesforce Agentforce) run outside your cluster. Membrane cannot put a gate inside them. Use the vendor's admin APIs and audit logs, and require per-action log export in the contract.

## Custody

Membrane writes append-only JSONL files. Each record carries two hashes: `payload_sha256` over the payload and `record_sha256` over the whole record, envelope included. The reader checks both and stops on a mismatch or a missing hash. These hashes detect an accidental edit or a naive edit that does not recompute them. They do not detect a writer that recomputes the hashes. Such a writer can change `mode`, `collected_at`, or any other field without detection. Beacon provides custody: signed witness records, checkpoints, and fail-closed claim words. Send membrane results to Beacon with the plugin in `integrations/beacon/`. The Beacon status word stays unverified.
