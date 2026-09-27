package membrane.admission_test

import rego.v1

import data.membrane.admission

sha_kb := "0f6620a7dddf9d7bb1e67bd79d5ec2184c11a49543e2f0305bf5fe8c19efa35c"

sha_inv := "4cc66320962fcb4d949a49a77acbdf20cf0506ecfd5d9b9d750b7b60361b3a18"

digest := "@sha256:1111111111111111111111111111111111111111111111111111111111111111"

manifests := {
	"kb-reader": {"sha256": sha_kb, "tier": 1},
	"invoice-reconciler": {"sha256": sha_inv, "tier": 3},
}

namespaces := {
	"agents": {"metadata": {"name": "agents", "labels": {"membrane.io/agent-namespace": "true"}}},
	"web": {"metadata": {"name": "web", "labels": {"team": "web"}}},
}

kb_pod := {
	"apiVersion": "v1",
	"kind": "Pod",
	"metadata": {
		"name": "kb-reader-0",
		"namespace": "agents",
		"labels": {"membrane.io/agent-id": "kb-reader", "membrane.io/tier": "1"},
		"annotations": {"membrane.io/manifest-sha256": sha_kb},
	},
	"spec": {
		"serviceAccountName": "kb-reader",
		"containers": [{"name": "agent", "image": concat("", ["registry.example.com/agents/kb-reader", digest])}],
	},
}

inv_pod := json.patch(kb_pod, [
	{"op": "replace", "path": "/metadata/name", "value": "inv-0"},
	{"op": "replace", "path": "/metadata/labels/membrane.io~1agent-id", "value": "invoice-reconciler"},
	{"op": "replace", "path": "/metadata/labels/membrane.io~1tier", "value": "3"},
	{"op": "replace", "path": "/metadata/annotations/membrane.io~1manifest-sha256", "value": sha_inv},
	{"op": "replace", "path": "/spec/serviceAccountName", "value": "invoice-reconciler"},
	{"op": "add", "path": "/spec/automountServiceAccountToken", "value": false},
])

inv_deploy := {
	"apiVersion": "apps/v1",
	"kind": "Deployment",
	"metadata": {"name": "invoice-reconciler", "namespace": "agents"},
	"spec": {
		"selector": {"matchLabels": {"app": "inv"}},
		"template": {"metadata": inv_pod.metadata, "spec": inv_pod.spec},
	},
}

plain_pod := {
	"apiVersion": "v1",
	"kind": "Pod",
	"metadata": {"name": "nginx", "namespace": "agents", "labels": {"app": "nginx"}},
	"spec": {"containers": [{"name": "nginx", "image": "nginx:latest"}]},
}

review(obj) := {"apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview", "request": {"operation": "CREATE", "namespace": obj.metadata.namespace, "object": obj}}

denies(obj) := d if {
	d := admission.deny with input as obj
		with data.membrane.manifests as manifests
		with data.inventory.cluster.v1.Namespace as namespaces
}

has(obj, fragment) if {
	some m in denies(obj)
	contains(m, fragment)
}

p(ops) := json.patch(kb_pod, ops)

# ---- good -----------------------------------------------------------------

test_good_pod_plain if count(denies(kb_pod)) == 0

test_good_pod_admission_review if count(denies(review(kb_pod))) == 0

test_good_pod_gatekeeper_review if count(denies({"review": {"operation": "CREATE", "object": kb_pod}})) == 0

test_good_tier3_pod if count(denies(inv_pod)) == 0

test_good_deployment if count(denies(inv_deploy)) == 0

test_good_allowed_flag if {
	admission.allowed with input as kb_pod with data.membrane.manifests as manifests
}

test_delete_is_out_of_scope if {
	req := {"request": {"operation": "DELETE", "namespace": "agents", "object": plain_pod}}
	count(denies(req)) == 0
}

test_non_workload_kind_ignored if {
	count(denies({"kind": "ConfigMap", "metadata": {"name": "x", "namespace": "agents"}})) == 0
}

test_plain_pod_in_other_namespace_allowed if {
	count(denies(json.patch(plain_pod, [{"op": "replace", "path": "/metadata/namespace", "value": "web"}]))) == 0
}

# ---- manifest hash annotation ---------------------------------------------

test_missing_sha if has(p([{"op": "remove", "path": "/metadata/annotations"}]), "64 lowercase hex")

test_short_sha if has(p([{"op": "replace", "path": "/metadata/annotations/membrane.io~1manifest-sha256", "value": "abc"}]), "64 lowercase hex")

test_upper_sha if has(p([{"op": "replace", "path": "/metadata/annotations/membrane.io~1manifest-sha256", "value": upper(sha_kb)}]), "64 lowercase hex")

# ---- tier label -----------------------------------------------------------

test_missing_tier if has(p([{"op": "remove", "path": "/metadata/labels/membrane.io~1tier"}]), "value from 1 to 4")

test_tier_5 if has(p([{"op": "replace", "path": "/metadata/labels/membrane.io~1tier", "value": "5"}]), "value from 1 to 4")

test_tier_mismatch_registry if {
	has(p([{"op": "replace", "path": "/metadata/labels/membrane.io~1tier", "value": "2"}]), "does not match the registered tier 1")
}

# ---- images ---------------------------------------------------------------

test_tag_image if has(p([{"op": "replace", "path": "/spec/containers/0/image", "value": "r/kb:1.0"}]), "must be pinned by @sha256")

test_short_digest if has(p([{"op": "replace", "path": "/spec/containers/0/image", "value": "r/kb@sha256:abc"}]), "must be pinned by @sha256")

test_init_container_tag if {
	has(p([{"op": "add", "path": "/spec/initContainers", "value": [{"name": "init", "image": "busybox:latest"}]}]), "container \"init\"")
}

test_ephemeral_container_tag if {
	has(p([{"op": "add", "path": "/spec/ephemeralContainers", "value": [{"name": "dbg", "image": "busybox"}]}]), "container \"dbg\"")
}

test_no_containers if has(p([{"op": "replace", "path": "/spec/containers", "value": []}]), "at least one container")

# ---- service account ------------------------------------------------------

test_default_sa if has(p([{"op": "replace", "path": "/spec/serviceAccountName", "value": "default"}]), "serviceAccountName")

test_missing_sa if has(p([{"op": "remove", "path": "/spec/serviceAccountName"}]), "serviceAccountName")

# ---- token automount ------------------------------------------------------

test_tier3_automount_unset if {
	has(json.patch(inv_pod, [{"op": "remove", "path": "/spec/automountServiceAccountToken"}]), "automountServiceAccountToken")
}

test_tier3_automount_true if {
	has(json.patch(inv_pod, [{"op": "replace", "path": "/spec/automountServiceAccountToken", "value": true}]), "automountServiceAccountToken")
}

test_tier1_automount_unset_ok if not has(kb_pod, "automountServiceAccountToken")

test_deployment_automount_unset if {
	has(json.patch(inv_deploy, [{"op": "remove", "path": "/spec/template/spec/automountServiceAccountToken"}]), "automountServiceAccountToken")
}

# ---- registry -------------------------------------------------------------

test_unregistered_agent if {
	has(p([{"op": "replace", "path": "/metadata/labels/membrane.io~1agent-id", "value": "shadow"}]), "not in the membrane registry")
}

test_hash_mismatch if {
	has(p([{"op": "replace", "path": "/metadata/annotations/membrane.io~1manifest-sha256", "value": sha_inv}]), "does not match the registered manifest hash")
}

test_no_registry_data_denies if {
	d := admission.deny with input as kb_pod with data.membrane.manifests as null
	some m in d
	contains(m, "not in the membrane registry")
}

test_gatekeeper_configmap_registry if {
	cm := {"membrane-system": {"v1": {"ConfigMap": {"membrane-registry": {"data": {"kb-reader": sha_kb}}}}}}
	d := admission.deny with input as {"review": {"operation": "CREATE", "object": kb_pod}} with data.inventory.namespace as cm
	count(d) == 0
}

test_gatekeeper_configmap_mismatch if {
	cm := {"membrane-system": {"v1": {"ConfigMap": {"membrane-registry": {"data": {"kb-reader": sha_inv}}}}}}
	d := admission.deny with input as kb_pod with data.inventory.namespace as cm
	some m in d
	contains(m, "does not match the registered manifest hash")
}

test_deployment_unregistered if {
	has(json.patch(inv_deploy, [{"op": "replace", "path": "/spec/template/metadata/labels/membrane.io~1agent-id", "value": "shadow"}]), "not in the membrane registry")
}

test_cronjob_checked if {
	cj := {
		"kind": "CronJob",
		"metadata": {"name": "cj", "namespace": "agents"},
		"spec": {"jobTemplate": {"spec": {"template": {"metadata": kb_pod.metadata, "spec": {"serviceAccountName": "default", "containers": kb_pod.spec.containers}}}}},
	}
	has(cj, "serviceAccountName")
}

# ---- unregistered workloads in agent namespaces ---------------------------

test_plain_pod_in_agent_namespace_denied if has(plain_pod, "is an agent namespace")

test_plain_pod_in_agent_namespace_review_denied if has(review(plain_pod), "is an agent namespace")

test_plain_deployment_in_agent_namespace_denied if {
	d := json.patch(inv_deploy, [{"op": "remove", "path": "/spec/template/metadata/labels/membrane.io~1agent-id"}])
	has(d, "is an agent namespace")
}

test_kube_mgmt_namespace_source if {
	d := admission.deny with input as plain_pod with data.kubernetes.namespaces as namespaces
	some m in d
	contains(m, "is an agent namespace")
}

test_violation_shape if {
	v := admission.violation with input as plain_pod
		with data.membrane.manifests as manifests
		with data.inventory.cluster.v1.Namespace as namespaces
	some x in v
	contains(x.msg, "is an agent namespace")
}
