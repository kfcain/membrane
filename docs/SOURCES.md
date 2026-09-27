# Sources

This file lists the external sources that membrane uses. The first part lists the external formats that the runtime part uses. Each entry names the source and what we checked. We checked every source on 2026-09-27.

## OpenTelemetry GenAI semantic conventions

The GenAI conventions moved out of the core semantic conventions repository. The old page at https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-spans/ now says: "GenAI semantic conventions have moved to the OpenTelemetry GenAI semantic conventions repository".

Current sources:

- Repository: https://github.com/open-telemetry/semantic-conventions-genai
- Attribute registry: https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/registry/attributes/gen-ai.md
- Spans, section "Execute tool span": https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/gen-ai-spans.md#execute-tool-span

What we checked:

| Attribute in `otel` | Registry entry | Execute tool span | Our value |
| --- | --- | --- | --- |
| `gen_ai.operation.name` | Yes. `execute_tool` is a well-known value ("Execute a tool") | Required. The span says it SHOULD be `execute_tool` | `execute_tool` |
| `gen_ai.tool.name` | Yes | Required | The tool name from the request |
| `gen_ai.tool.call.id` | Yes | Recommended, if available | The gateway `decision_id` |
| `gen_ai.agent.name` | Yes | Conditionally required, when applicable | The manifest `metadata.id` |
| `gen_ai.agent.id` | Yes. "The unique and stable identifier of the GenAI hosted agent resource" | Not listed on the execute tool span | The manifest `metadata.id` |

Notes:

- Every GenAI attribute has stability "Development". Names can change. Check again before a release.
- The span name SHOULD be `execute_tool {gen_ai.tool.name}` and the span kind SHOULD be `INTERNAL`. The gateway writes attributes to evidence. It does not export spans.
- `gen_ai.agent.id` is not on the execute tool span. The registry defines it for hosted agent resources and says in-memory instance ids are NOT RECOMMENDED. The manifest id is a stable registry id, so we use it. A strict consumer can ignore it on tool spans.
- `gen_ai.tool.type` (`function`, `extension`, `datastore`) is recommended. We do not set it because the manifest does not declare a tool type.
- We do not set `error.type`. A deny is a policy outcome, not a tool error. The decision and reasons carry it.

## W3C Trace Context

- https://www.w3.org/TR/trace-context/#traceparent-header
- Spec source: https://github.com/w3c/trace-context/blob/main/spec/20-http_request_header_format.md
- Format `version-traceid-parentid-flags`, lowercase hex, 2-32-16-2. An all zero trace id or parent id is invalid. Version `ff` is invalid. Vendors MUST ignore a header with non-lowercase hex.
- The gateway takes the trace id from a valid `traceparent`. Otherwise it makes a new random 32 hex trace id. It returns a `traceparent` header with the same trace id and a new parent id.

## SPIRE registration entries (`spire-server entry create -data`)

- Flag definition: https://github.com/spiffe/spire/blob/main/cmd/spire-server/cli/entry/create.go ("Path to a file containing registration JSON").
- Parser: https://github.com/spiffe/spire/blob/main/cmd/spire-server/cli/entry/util.go (`parseEntryJSON` unmarshals into `common.RegistrationEntries`).
- Field names: https://github.com/spiffe/spire/blob/main/proto/spire/common/common.proto (`RegistrationEntry`: `selectors`, `parent_id`, `spiffe_id`, `x509_svid_ttl`, `jwt_svid_ttl`, `hint`, and others).
- Example file: https://github.com/spiffe/spire/blob/main/test/fixture/registration/good.json (top level `entries`, selectors as `{"type", "value"}`).
- k8s selectors: https://github.com/spiffe/spire/blob/main/doc/plugin_agent_workloadattestor_k8s.md (`k8s:ns`, `k8s:sa`). In JSON the type is `k8s` and the value is `ns:<namespace>` or `sa:<service account>`.
- PSAT agent ids and node alias selectors: https://github.com/spiffe/spire/blob/main/doc/plugin_server_nodeattestor_k8s_psat.md (agent id `spiffe://<trust_domain>/spire/agent/k8s_psat/<cluster>/<node UID>`, selector `k8s_psat:cluster:<name>`).

The default parent id `spiffe://example.org/spire/agent/k8s_psat/membrane` is a node alias. It is not a real agent id. The operator creates it with `spire-server entry create -node -spiffeID spiffe://example.org/spire/agent/k8s_psat/membrane -selector k8s_psat:cluster:<cluster>`. `membrane gen --parent-id` changes it.

## Cilium FQDN egress policy

- Layer 3 policy, DNS based section: https://github.com/cilium/cilium/blob/main/Documentation/security/policy/layer3.rst. It says Cilium needs "an L7 policy allowing DNS requests (`rules.dns` YAML block)" so that the DNS proxy can map names to IPs. It also says a `toFQDNs` rule cannot hold other L3 selectors such as `toEndpoints`.
- Examples: https://github.com/cilium/cilium/blob/main/examples/kubernetes-dns/dns-matchname.yaml and https://github.com/cilium/cilium/blob/main/examples/policies/l7/dns/dns.yaml (DNS rule to `k8s:io.kubernetes.pod.namespace: kube-system` and `k8s:k8s-app: kube-dns`, port 53 protocol ANY, `rules.dns` with `matchPattern` or `matchName`).
- `endpointSelector` with `matchExpressions`: https://github.com/cilium/cilium/blob/main/Documentation/security/policy/intro.rst (example with `operator: NotIn`).
- DNS proxy guide: https://github.com/cilium/cilium/blob/main/Documentation/security/dns.rst

Our DNS rule lists each allowed FQDN as a `matchPattern` with no wildcard. The proxy then answers only lookups for allowed names. The upstream examples use `matchPattern: "*"`, which permits every lookup.

Kubernetes NetworkPolicy and CiliumNetworkPolicy allows add together. The plain NetworkPolicy allows only DNS. The Cilium policy adds the FQDN allows on TCP 443. Without Cilium only the plain policy applies, so FQDN egress fails closed.

## Kubernetes NetworkPolicy

- https://kubernetes.io/docs/concepts/services-networking/network-policies/
- Source: https://github.com/kubernetes/website/blob/main/content/en/docs/concepts/services-networking/network-policies.md
- "Network policies do not conflict; they are additive." The allowed connections are the union of all policies that select the pod.
- "The Kubernetes control plane sets an immutable label `kubernetes.io/metadata.name` on all namespaces". The namespace selector uses it.
- Because policies only add allows, the agent policies exclude pods with `membrane.io/quarantine=true`. The quarantine policy then selects those pods alone. It has no rules, so all ingress and egress deny.

## Open Policy Agent

- Local binary: `opa` 1.4.2 (Rego v1). `opa eval --format=json --stdin-input -d <files> <query>`.
- REST: `PUT /v1/data/<path>` ("Create or Overwrite a Document") and `POST /v1/data/<path>` with `{"input": ...}` ("Get a Document (with Input)"). https://www.openpolicyagent.org/docs/rest-api, source https://github.com/open-policy-agent/opa/blob/main/docs/docs/rest-api.md. We ran the REST path against a local `opa run --server` (1.4.2) with policy/runtime/authz.rego. It gave the same results as `opa eval` for an allow and for a killed override. The gateway PUTs each data leaf (`membrane/manifests`, `membrane/overrides`) and never `membrane` itself, because that path holds the policy package.

## Policy formats

- Kyverno CLI test, release 1.14: https://release-1-14-0.kyverno.io/docs/kyverno-cli/usage/test/
- Kyverno validate rules and the `failureAction` field: https://kyverno.io/docs/policy-types/cluster-policy/validate/
- OPA policy language and `opa test`: https://www.openpolicyagent.org/docs/policy-language and https://www.openpolicyagent.org/docs/policy-testing
- Conftest: https://www.conftest.dev/

## Assessment output

- OSCAL 1.1.3 assessment-results JSON schema, vendored under `schema/oscal/` with its SHA-256: https://github.com/usnistgov/OSCAL/releases/tag/v1.1.3
- NIST SP 800-53 Rev 5 OSCAL catalog, used to check control and statement ids: https://github.com/usnistgov/oscal-content
- Secure Controls Framework 2026.3 assessment objectives, read from the Beacon pin (`beacon/scf/objectives/rows.json`, workbook SHA-256 `5a89bf2d3c106a9a87d4b6e3d62dd3e147d0e960d4c07473045a10aa8a7df697`). Membrane does not vendor SCF content.

## Threat and governance references

These sources shaped the design. Membrane does not claim conformance to any of them.

- NIST CAISI AI Agent Standards Initiative: https://www.nist.gov/news-events/news/2026/02/announcing-ai-agent-standards-initiative-interoperable-and-secure
- NCCoE concept paper, "Accelerating the Adoption of Software and AI Agent Identity and Authorization" (summary): https://labs.cloudsecurityalliance.org/research/csa-research-note-nist-ai-agent-standards-20260416-csa-style/
- NIST SP 800-53 control overlays for securing AI systems (COSAiS): https://csrc.nist.gov/projects/cosais
- OWASP Top 10 for Agentic Applications 2026: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- OWASP MCP Top 10: https://owasp.org/www-project-mcp-top-10/
- CSA AI Controls Matrix v1.1: https://cloudsecurityalliance.org/artifacts/ai-controls-matrix-v1-1
- AIUC-1: https://www.aiuc-1.com/
- CycloneDX ML-BOM: https://cyclonedx.org/capabilities/mlbom/
