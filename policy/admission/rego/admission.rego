# Membrane admission rules in Rego, for OPA and Gatekeeper users.
# The rules match policy/admission/kyverno. Both bind a pod to its manifest:
# the hash annotation, the namespace, the service account, the tier label, and
# the image digest of every container (containers, initContainers, and
# ephemeralContainers) must equal the registry values.
#
# Input. The policy accepts three shapes:
#   1. An AdmissionReview:           input.request.object  (OPA kube-mgmt, plain webhooks)
#   2. A Gatekeeper review:          input.review.object
#   3. A plain Kubernetes object:    input  (conftest, CI, unit tests)
#
# Supported kinds: Pod, Deployment, StatefulSet, DaemonSet, ReplicaSet, Job, CronJob.
# The policy checks the pod template for controllers.
#
# Registry. The policy reads data.membrane.manifests (the generated data.json):
# sha256, tier, and k8s.{namespace, service_account, image_digests}. If that is
# absent, it reads the synced ConfigMap membrane-system/membrane-registry from
# data.inventory (Gatekeeper sync). Each ConfigMap value is a JSON string with
# sha256, tier, namespace, service_account, and image_digests. With neither,
# every agent is unregistered. A missing binding field denies (fail closed).
#
# Namespace labels. The policy reads them from data.inventory.cluster.v1.Namespace
# (Gatekeeper sync) or data.kubernetes.namespaces (kube-mgmt replication).
#
# Output: deny (set of strings) and violation (set of {"msg": ...}) for Gatekeeper.
package membrane.admission

import rego.v1

agent_label := "membrane.io/agent-id"

tier_label := "membrane.io/tier"

sha_annotation := "membrane.io/manifest-sha256"

agent_ns_label := "membrane.io/agent-namespace"

valid_tiers := {"1", "2", "3", "4"}

# ---------------------------------------------------------------------------
# Input normalization
# ---------------------------------------------------------------------------

object_under_review := o if {
	o := input.request.object
	is_object(o)
} else := o if {
	o := input.review.object
	is_object(o)
} else := input

operation := op if {
	op := input.request.operation
} else := op if {
	op := input.review.operation
} else := "CREATE"

namespace := ns if {
	ns := object_under_review.metadata.namespace
	is_string(ns)
} else := ns if {
	ns := input.request.namespace
	is_string(ns)
} else := ns if {
	ns := input.review.namespace
	is_string(ns)
} else := ""

kind := object.get(object_under_review, "kind", "")

controller_kinds := {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"}

# The pod template: metadata and spec that the pods will run with.
pod_meta := m if {
	kind == "Pod"
	m := object.get(object_under_review, "metadata", {})
} else := m if {
	kind in controller_kinds
	m := object.get(object_under_review, ["spec", "template", "metadata"], {})
} else := m if {
	kind == "CronJob"
	m := object.get(object_under_review, ["spec", "jobTemplate", "spec", "template", "metadata"], {})
}

pod_spec := s if {
	kind == "Pod"
	s := object.get(object_under_review, "spec", {})
} else := s if {
	kind in controller_kinds
	s := object.get(object_under_review, ["spec", "template", "spec"], {})
} else := s if {
	kind == "CronJob"
	s := object.get(object_under_review, ["spec", "jobTemplate", "spec", "template", "spec"], {})
}

in_scope if {
	operation != "DELETE"
	pod_meta
}

labels := object.get(pod_meta, "labels", {})

annotations := object.get(pod_meta, "annotations", {})

agent_id := object.get(labels, agent_label, "")

is_agent if {
	in_scope
	is_string(agent_id)
	agent_id != ""
}

name := object.get(object.get(object_under_review, "metadata", {}), "name", "<unnamed>")

subject := sprintf("%s %s/%s", [kind, namespace, name])

tier := object.get(labels, tier_label, "")

manifest_sha := object.get(annotations, sha_annotation, "")

# ---------------------------------------------------------------------------
# Registry and namespace data
# ---------------------------------------------------------------------------

# binding(id): {sha256, tier (string), namespace, service_account, image_digests}.
binding(id) := b if {
	m := data.membrane.manifests[id]
	is_object(m)
	k := object.get(m, "k8s", {})
	b := {
		"sha256": object.get(m, "sha256", null),
		"tier": sprintf("%v", [object.get(m, "tier", "")]),
		"namespace": object.get(k, "namespace", null),
		"service_account": object.get(k, "service_account", null),
		"image_digests": object.get(k, "image_digests", []),
	}
} else := b if {
	not data.membrane.manifests
	raw := data.inventory.namespace["membrane-system"].v1.ConfigMap["membrane-registry"].data[id]
	is_string(raw)
	e := json.unmarshal(raw)
	is_object(e)
	b := {
		"sha256": object.get(e, "sha256", null),
		"tier": object.get(e, "tier", null),
		"namespace": object.get(e, "namespace", null),
		"service_account": object.get(e, "service_account", null),
		"image_digests": object.get(e, "image_digests", []),
	}
}

registered_sha(id) := sha if {
	sha := binding(id).sha256
	is_string(sha)
	sha != ""
}

namespace_labels := l if {
	l := data.inventory.cluster.v1.Namespace[namespace].metadata.labels
} else := l if {
	l := data.kubernetes.namespaces[namespace].metadata.labels
} else := {}

agent_namespace if namespace_labels[agent_ns_label] == "true"

# ---------------------------------------------------------------------------
# Rules for agent workloads
# ---------------------------------------------------------------------------

deny contains sprintf("%s: agent workloads need annotation %s with 64 lowercase hex characters", [subject, sha_annotation]) if {
	is_agent
	not regex.match(`^[a-f0-9]{64}$`, sprintf("%v", [manifest_sha]))
}

deny contains sprintf("%s: agent workloads need label %s with a value from 1 to 4", [subject, tier_label]) if {
	is_agent
	not tier in valid_tiers
}

containers contains c if {
	some field in ["ephemeralContainers", "initContainers", "containers"]
	some c in object.get(pod_spec, field, [])
}

deny contains sprintf("%s: container %q image %q must be pinned by @sha256 digest (64 hex)", [subject, object.get(c, "name", "<unnamed>"), image]) if {
	is_agent
	some c in containers
	image := object.get(c, "image", "")
	not regex.match(`@sha256:[a-f0-9]{64}$`, sprintf("%v", [image]))
}

deny contains sprintf("%s: agent workloads need at least one container", [subject]) if {
	is_agent
	count(containers) == 0
}

deny contains sprintf("%s: serviceAccountName must name a dedicated account, not empty and not default", [subject]) if {
	is_agent
	object.get(pod_spec, "serviceAccountName", "") in {"", "default"}
}

# The automount rule applies when the tier label or the registered tier is 3 or 4.
deny contains sprintf("%s: tier %s agents must set automountServiceAccountToken to false", [subject, t]) if {
	is_agent
	some t in {tier, registered_tier_string(agent_id)}
	t in {"3", "4"}
	object.get(pod_spec, "automountServiceAccountToken", null) != false
}

registered_tier_string(id) := t if {
	t := binding(id).tier
	is_string(t)
} else := ""

deny contains sprintf("%s: agent %q is not in the membrane registry", [subject, agent_id]) if {
	is_agent
	not registered_sha(agent_id)
}

deny contains sprintf("%s: annotation %s does not match the registered manifest hash for %q", [subject, sha_annotation, agent_id]) if {
	is_agent
	sha := registered_sha(agent_id)
	manifest_sha != sha
}

deny contains sprintf("%s: label %s=%s does not match the registered tier %v for %q", [subject, tier_label, tier, want, agent_id]) if {
	is_agent
	registered_sha(agent_id)
	want := binding(agent_id).tier
	tier != want
}

deny contains sprintf("%s: namespace %q does not match the registered namespace %v for %q", [subject, namespace, want, agent_id]) if {
	is_agent
	registered_sha(agent_id)
	want := binding(agent_id).namespace
	namespace != want
}

deny contains sprintf("%s: serviceAccountName %q does not match the registered service account %v for %q", [subject, sa, want, agent_id]) if {
	is_agent
	registered_sha(agent_id)
	want := binding(agent_id).service_account
	sa := object.get(pod_spec, "serviceAccountName", "")
	sa != want
}

image_digest(image) := d if {
	is_string(image)
	parts := regex.find_all_string_submatch_n(`@(sha256:[a-f0-9]{64})$`, image, 1)
	count(parts) == 1
	d := parts[0][1]
} else := ""

deny contains sprintf("%s: container %q image %q is not a registered image digest for %q", [subject, object.get(c, "name", "<unnamed>"), image, agent_id]) if {
	is_agent
	registered_sha(agent_id)
	allowed_digests := binding(agent_id).image_digests
	some c in containers
	image := object.get(c, "image", "")
	not image_digest(image) in registered_digest_set(allowed_digests)
}

registered_digest_set(l) := {d | some d in l; is_string(d); d != ""} if is_array(l)

else := set()

# ---------------------------------------------------------------------------
# Unregistered agent workloads in agent namespaces
# ---------------------------------------------------------------------------

deny contains sprintf("%s: namespace %s is an agent namespace; workloads here need label %s", [subject, namespace, agent_label]) if {
	in_scope
	agent_namespace
	not is_agent
}

# Gatekeeper shape.
violation contains {"msg": msg} if some msg in deny

default allowed := false

allowed if count(deny) == 0
