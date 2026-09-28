# Membrane runtime authorization. The gateway asks this policy before every tool call.
#
# Query: data.membrane.authz.result
# Data:  data.membrane.manifests (generated), data.membrane.overrides (optional)
# Output: {"decision": "allow" | "deny" | "require_approval", "reasons": [...]}
#
# This file implements docs/CONTRACTS.md section 3. The rules are ordered.
# The first rule that matches wins. The policy builds the full ordered list of
# rules, keeps the ones that match, and returns the first. Each match flag is a
# total boolean (default false), so a missing field never removes a rule from
# the list. A policy error returns deny.
package membrane.authz

import rego.v1

# Fail closed. This value applies only if the ordered evaluation below is undefined.
default result := {"decision": "deny", "reasons": ["policy_error"]}

result := {"decision": first.decision, "reasons": first.reasons} if {
	matched := [r | some r in ordered_rules; r.match == true]
	first := matched[0]
}

# ---------------------------------------------------------------------------
# The ordered rule list. Order here is the contract order. Do not reorder.
# ---------------------------------------------------------------------------

ordered_rules := [
	# 1
	{"match": identity_unverified, "decision": "deny", "reasons": ["identity_unverified"]},
	# 2
	{"match": agent_unregistered, "decision": "deny", "reasons": ["agent_unregistered"]},
	# 3
	{"match": manifest_hash_mismatch, "decision": "deny", "reasons": ["manifest_hash_mismatch"]},
	# 4
	{"match": agent_not_active, "decision": "deny", "reasons": ["agent_not_active"]},
	# 5
	{"match": override_killed, "decision": "deny", "reasons": ["override_killed"]},
	{"match": override_quarantined, "decision": "deny", "reasons": ["override_quarantined"]},
	{"match": override_unknown, "decision": "deny", "reasons": ["override_unknown"]},
	# 6
	{"match": tool_not_in_manifest, "decision": "deny", "reasons": ["tool_not_in_manifest"]},
	# 7
	{"match": delegator_required, "decision": "deny", "reasons": ["delegator_required"]},
	# 8
	{"match": canary_irreversible, "decision": "deny", "reasons": ["canary_irreversible_forbidden"]},
	# 9. A presented approval that does not match denies. It must not
	# fall through to a fresh approval request (replay protection).
	{"match": approval_mismatch, "decision": "deny", "reasons": ["approval_mismatch"]},
	# 10
	{"match": approval_required, "decision": "require_approval", "reasons": ["approval_required"]},
	# 11
	{"match": true, "decision": "allow", "reasons": allow_reasons},
]

# ---------------------------------------------------------------------------
# Inputs and data, read defensively
# ---------------------------------------------------------------------------

manifests := m if {
	m := data.membrane.manifests
	is_object(m)
} else := {}

overrides := o if {
	o := data.membrane.overrides
	is_object(o)
} else := {}

agent_id := id if {
	id := input.agent_id
	is_string(id)
} else := ""

tool_name := t if {
	t := input.tool
	is_string(t)
} else := ""

manifest := manifests[agent_id]

tool := manifest.tools[tool_name]

valid_modes := {"throttled", "restricted", "quarantined", "killed"}

# "none" means the data has no override for this agent. An entry with no
# mode string gets "<invalid>", which rule 5 denies as override_unknown.
override_mode := mode if {
	entry := overrides[agent_id]
	mode := object.get(entry, "mode", "<invalid>")
	is_string(mode)
} else := "<invalid>" if {
	# Present with any value, even false, null, or 0.
	agent_id in object.keys(overrides)
} else := "<invalid>" if {
	overrides_malformed
} else := "none"

# An overrides document that exists and is not an object denies every agent.
overrides_malformed if {
	o := data.membrane.overrides
	not is_object(o)
}

# The same strict form as the gateway: one "@", a dot in the domain, no white
# space, and no control characters.
delegator_email(s) if {
	is_string(s)
	regex.match(`^[^@\s\x00-\x1f\x7f]+@[^@\s\x00-\x1f\x7f]+\.[^@\s\x00-\x1f\x7f]+$`, s)
}

non_empty_string(s) if {
	is_string(s)
	trim_space(s) != ""
}

# ---------------------------------------------------------------------------
# Match flags. Each one is total: true or false, never undefined.
# ---------------------------------------------------------------------------

# Rule 1
default identity_unverified := true

identity_unverified := false if input.identity_verified == true

# Rule 2
default agent_unregistered := true

agent_unregistered := false if is_object(manifest)

# Rule 3
default manifest_hash_mismatch := true

manifest_hash_mismatch := false if {
	non_empty_string(manifest.sha256)
	input.manifest_sha256 == manifest.sha256
}

# Rule 4
default agent_not_active := true

agent_not_active := false if manifest.status == "active"

# Rule 5
default override_killed := false

override_killed if override_mode == "killed"

default override_quarantined := false

override_quarantined if override_mode == "quarantined"

# Rule 5 (extension). An override entry whose mode is not one of the four known modes is
# corrupt state. Fail closed with its own reason.
default override_unknown := false

override_unknown if {
	override_mode != "none"
	not override_mode in valid_modes
}

# Rule 6
default tool_not_in_manifest := true

tool_not_in_manifest := false if is_object(tool)

# Rule 7. Fail closed: a manifest entry with no boolean flag requires a delegator.
default requires_delegator := true

requires_delegator := false if manifest.requires_delegator == false

default delegator_required := false

delegator_required if {
	requires_delegator
	not delegator_email(object.get(input, "delegator", null))
}

# Tool irreversibility. Fail closed: no boolean flag means irreversible.
default tool_irreversible := true

tool_irreversible := false if tool.irreversible == false

# Rule 8
default canary_irreversible := false

canary_irreversible if {
	is_canary
	tool_irreversible
}

# Fail closed: only an explicit boolean false makes an agent a non-canary.
is_canary if not manifest.canary == false

# Rule 10. Fail closed: no approval_required_for list means approval for all.
approval_required_for := r if {
	r := manifest.approval_required_for
	is_array(r)
} else := ["all"]

default approval_needed := false

approval_needed if {
	tool_irreversible
	"irreversible" in approval_required_for
}

approval_needed if "all" in approval_required_for

approval_needed if override_mode == "restricted"

approval_present if {
	"approval" in object.keys(input)
	input.approval != null
}

default approval_valid := false

approval_valid if {
	is_object(input.approval)
	input.approval.verified == true
	non_empty_string(input.action_sha256)
	input.approval.action_sha256 == input.action_sha256
}

default approval_required := false

approval_required if {
	approval_needed
	not approval_valid
}

# Rule 9. Applies whenever an approval is present and not valid.
default approval_mismatch := false

approval_mismatch if {
	approval_present
	not approval_valid
}

# Rule 11
allow_reasons := ["within_manifest", "throttled"] if override_mode == "throttled"

else := ["within_manifest"]
