# Membrane CI gate. Conftest policies over one agent manifest (YAML input).
#
# Run: conftest test --policy policy/ci --namespace membrane.ci registry/agents/*.yaml
#
# The schema checks shape. This policy checks tier rules. It fails closed:
# a missing or malformed field is a deny, not a skip.
package membrane.ci

import rego.v1

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

valid_statuses := {"active", "suspended", "retired"}

valid_tiers := {1, 2, 3, 4}

# Minimum eval pass rate by tier. Tier 1 needs no evals.
min_eval_pass := {2: 0.90, 3: 0.95, 4: 0.97}

digest_pattern := `@sha256:[a-f0-9]{64}$`

# Lowercase FQDN with at least two labels. No wildcards, no ports, no schemes.
fqdn_pattern := `^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`

# A red team result older than this raises a warning at tier 4.
redteam_warn_age_days := 180

ns_per_day := ((24 * 60) * 60) * 1000000000

# ---------------------------------------------------------------------------
# Safe accessors. Each returns a typed default so rules stay defined.
# ---------------------------------------------------------------------------

metadata := m if {
	m := input.metadata
	is_object(m)
} else := {}

spec := s if {
	s := input.spec
	is_object(s)
} else := {}

agent_id := id if {
	id := metadata.id
	is_string(id)
} else := "<unknown>"

owner := o if {
	o := metadata.owner
	is_string(o)
} else := ""

tier := t if {
	t := spec.tier
	t in valid_tiers
} else := 0

runtime := r if {
	r := spec.runtime
	is_object(r)
} else := {}

tools := t if {
	t := spec.tools
	is_array(t)
} else := []

egress := e if {
	e := spec.egress
	is_array(e)
} else := []

approval_required_for := r if {
	r := spec.approval.required_for
	is_array(r)
} else := []

canary if spec.canary == true

tool_name(t) := n if {
	n := t.name
	is_string(n)
} else := "<unnamed>"

irreversible(t) if t.irreversible == true

# Fail closed: a tool with no boolean irreversible flag counts as irreversible.
irreversible(t) if not is_boolean(object.get(t, "irreversible", null))

any_irreversible if {
	some t in tools
	irreversible(t)
}

non_empty_string(s) if {
	is_string(s)
	trim_space(s) != ""
}

# ---------------------------------------------------------------------------
# Document shape (all tiers)
# ---------------------------------------------------------------------------

deny contains "manifest: apiVersion must be membrane/v1" if input.apiVersion != "membrane/v1"

deny contains "manifest: apiVersion must be membrane/v1" if not input.apiVersion

deny contains "manifest: kind must be AgentManifest" if input.kind != "AgentManifest"

deny contains "manifest: kind must be AgentManifest" if not input.kind

deny contains "manifest: metadata.id must be a non-empty string" if not non_empty_string(object.get(metadata, "id", null))

deny contains sprintf("%s: metadata.owner must be a non-empty string", [agent_id]) if not non_empty_string(object.get(metadata, "owner", null))

deny contains sprintf("%s: spec.tier must be an integer from 1 to 4", [agent_id]) if tier == 0

deny contains sprintf("%s: spec.status must be one of active, suspended, retired", [agent_id]) if {
	not object.get(spec, "status", null) in valid_statuses
}

deny contains sprintf("%s: spec.tools must be a list", [agent_id]) if not is_array(object.get(spec, "tools", null))

deny contains sprintf("%s: spec.egress must be a list", [agent_id]) if not is_array(object.get(spec, "egress", null))

deny contains sprintf("%s: spec.approval.required_for must be a list", [agent_id]) if {
	not is_array(object.get(object.get(spec, "approval", {}), "required_for", null))
}

deny contains sprintf("%s: tool name %q appears more than once", [agent_id, name]) if {
	some name in {tool_name(t) | some t in tools}
	count([t | some t in tools; tool_name(t) == name]) > 1
}

deny contains sprintf("%s: tool %q has no boolean irreversible flag", [agent_id, tool_name(t)]) if {
	some t in tools
	not is_boolean(object.get(t, "irreversible", null))
}

deny contains sprintf("%s: tool %q has no scope string", [agent_id, tool_name(t)]) if {
	some t in tools
	not is_string(object.get(t, "scope", null))
}

# ---------------------------------------------------------------------------
# Model and runtime (all tiers)
# ---------------------------------------------------------------------------

deny contains sprintf("%s: spec.model.pinned must be true", [agent_id]) if {
	object.get(object.get(spec, "model", {}), "pinned", false) != true
}

# A pin needs a versioned model id: a date (8 digits, or YYYY-MM-DD), a -vN
# suffix, or an @version suffix. A floating alias is not a pin. Provider none
# (no model) is exempt.
versioned_model_id(id) if {
	is_string(id)
	regex.match(`(\d{8}|\d{4}-\d{2}-\d{2}|-v\d+(:\d+)?$|@[0-9A-Za-z._-]+$)`, id)
}

deny contains sprintf("%s: spec.model.pinned is true, so spec.model.id %v must be a versioned model id (date, -vN, or @version), not an alias", [agent_id, model_id]) if {
	m := object.get(spec, "model", {})
	object.get(m, "pinned", false) == true
	object.get(m, "provider", "") != "none"
	model_id := object.get(m, "id", null)
	not versioned_model_id(model_id)
}

deny contains sprintf("%s: spec.runtime.type must be set", [agent_id]) if not runtime.type

deny contains sprintf("%s: k8s runtime needs spec.runtime.namespace", [agent_id]) if {
	runtime.type == "k8s"
	not non_empty_string(object.get(runtime, "namespace", null))
}

deny contains sprintf("%s: k8s runtime needs spec.runtime.service_account", [agent_id]) if {
	runtime.type == "k8s"
	not non_empty_string(object.get(runtime, "service_account", null))
}

deny contains sprintf("%s: k8s runtime must not use the default service account", [agent_id]) if {
	runtime.type == "k8s"
	runtime.service_account == "default"
}

deny contains sprintf("%s: k8s runtime image must be pinned by @sha256 digest (64 hex)", [agent_id]) if {
	runtime.type == "k8s"
	not regex.match(digest_pattern, object.get(runtime, "image", ""))
}

# ---------------------------------------------------------------------------
# Tier 1: read only, no egress
# ---------------------------------------------------------------------------

deny contains sprintf("%s: tier 1 tool %q must not have scope %q (write or admin)", [agent_id, tool_name(t), t.scope]) if {
	tier == 1
	some t in tools
	is_string(t.scope)
	regex.match(`:(write|admin)$`, t.scope)
}

deny contains sprintf("%s: tier 1 tool %q must not be irreversible", [agent_id, tool_name(t)]) if {
	tier == 1
	some t in tools
	irreversible(t)
}

deny contains sprintf("%s: tier 1 agents must have empty egress", [agent_id]) if {
	tier == 1
	count(egress) > 0
}

# ---------------------------------------------------------------------------
# Tier 2 and above: evals, AIBOM, rate limits
# ---------------------------------------------------------------------------

deny contains sprintf("%s: tier %d needs spec.evals", [agent_id, tier]) if {
	tier >= 2
	not is_object(object.get(spec, "evals", null))
}

deny contains sprintf("%s: tier %d needs evals.min_pass >= %v (got %v)", [agent_id, tier, min_eval_pass[tier], got]) if {
	tier >= 2
	is_object(spec.evals)
	got := object.get(spec.evals, "min_pass", null)
	not eval_threshold_met(got)
}

eval_threshold_met(got) if {
	is_number(got)
	got >= min_eval_pass[tier]
}

deny contains sprintf("%s: tier %d needs evals.suite", [agent_id, tier]) if {
	tier >= 2
	is_object(spec.evals)
	not non_empty_string(object.get(spec.evals, "suite", null))
}

deny contains sprintf("%s: tier %d needs spec.aibom with format and ref", [agent_id, tier]) if {
	tier >= 2
	not aibom_present
}

aibom_present if {
	is_object(spec.aibom)
	non_empty_string(object.get(spec.aibom, "format", null))
	non_empty_string(object.get(spec.aibom, "ref", null))
}

deny contains sprintf("%s: tier %d tool %q needs rate_limit_per_min", [agent_id, tier, tool_name(t)]) if {
	tier >= 2
	some t in tools
	not rate_limited(t)
}

rate_limited(t) if {
	is_number(t.rate_limit_per_min)
	t.rate_limit_per_min >= 1
}

# ---------------------------------------------------------------------------
# Tier 3 and above: egress, approvals, delegation
# ---------------------------------------------------------------------------

deny contains sprintf("%s: tier %d egress entry %q must not contain a wildcard", [agent_id, tier, e]) if {
	tier >= 3
	some e in egress
	contains(sprintf("%v", [e]), "*")
}

deny contains sprintf("%s: tier %d egress entry %v must be a lowercase FQDN", [agent_id, tier, e]) if {
	tier >= 3
	some e in egress
	not fqdn(e)
}

fqdn(e) if {
	is_string(e)
	count(e) <= 253
	regex.match(fqdn_pattern, e)
}

deny contains sprintf("%s: tier %d has irreversible tools, so approval.required_for must contain irreversible or all", [agent_id, tier]) if {
	tier >= 3
	any_irreversible
	not "irreversible" in approval_required_for
	not "all" in approval_required_for
}

deny contains sprintf("%s: tier %d needs delegation.requires_delegator true", [agent_id, tier]) if {
	tier >= 3
	object.get(object.get(spec, "delegation", {}), "requires_delegator", false) != true
}

# ---------------------------------------------------------------------------
# Tier 4: sandbox, red team, two-person promotion
# ---------------------------------------------------------------------------

deny contains sprintf("%s: tier 4 needs spec.sandbox", [agent_id]) if {
	tier == 4
	not is_object(object.get(spec, "sandbox", null))
}

deny contains sprintf("%s: tier 4 sandbox.isolated must be true", [agent_id]) if {
	tier == 4
	is_object(spec.sandbox)
	object.get(spec.sandbox, "isolated", false) != true
}

deny contains sprintf("%s: tier 4 sandbox.standing_credentials must be false", [agent_id]) if {
	tier == 4
	is_object(spec.sandbox)
	object.get(spec.sandbox, "standing_credentials", true) != false
}

deny contains sprintf("%s: tier 4 sandbox.session_recording must be true", [agent_id]) if {
	tier == 4
	is_object(spec.sandbox)
	object.get(spec.sandbox, "session_recording", false) != true
}

deny contains sprintf("%s: tier 4 needs spec.redteam with ref and date", [agent_id]) if {
	tier == 4
	not redteam_present
}

redteam_present if {
	is_object(spec.redteam)
	non_empty_string(object.get(spec.redteam, "ref", null))
	non_empty_string(object.get(spec.redteam, "date", null))
}

deny contains sprintf("%s: tier 4 redteam.date %q is not a valid YYYY-MM-DD date", [agent_id, spec.redteam.date]) if {
	tier == 4
	redteam_present
	not redteam_ns
}

# Nanoseconds since the epoch at midnight UTC on the red team date.
# The date is range-checked first, so time.parse_rfc3339_ns never raises a
# builtin error (conftest verify runs with strict builtin errors).
redteam_ns := ns if {
	valid_date(spec.redteam.date)
	ns := time.parse_rfc3339_ns(concat("", [spec.redteam.date, "T00:00:00Z"]))
}

valid_date(s) if {
	is_string(s)
	regex.match(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`, s)
	parts := split(s, "-")
	y := to_number(parts[0])
	m := to_number(parts[1])
	d := to_number(parts[2])
	m >= 1
	m <= 12
	d >= 1
	d <= days_in_month(y, m)
}

days_in_month(_, m) := 31 if m in {1, 3, 5, 7, 8, 10, 12}

days_in_month(_, m) := 30 if m in {4, 6, 9, 11}

days_in_month(y, 2) := 29 if leap_year(y)

days_in_month(y, 2) := 28 if not leap_year(y)

leap_year(y) if {
	y % 4 == 0
	y % 100 != 0
}

leap_year(y) if y % 400 == 0

promotion_approvers := a if {
	a := spec.promotion.approvers
	is_array(a)
} else := []

# One person, one entry: trim white space and lower-case before the distinct
# count and the owner compare. Each entry must be a plain ASCII email address.
norm_person(a) := lower(trim_space(a))

plain_email(a) if {
	is_string(a)
	regex.match(`^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$`, trim_space(a))
}

distinct_approvers := {norm_person(a) | some a in promotion_approvers; is_string(a)}

deny contains sprintf("%s: tier 4 promotion approver %v must be a plain email address", [agent_id, a]) if {
	tier == 4
	some a in promotion_approvers
	not plain_email(a)
}

deny contains sprintf("%s: tier 4 promotion.approvers needs at least 2 distinct entries (got %d)", [agent_id, count(distinct_approvers)]) if {
	tier == 4
	count(distinct_approvers) < 2
}

deny contains sprintf("%s: tier 4 promotion approver %q must not be the owner", [agent_id, a]) if {
	tier == 4
	some a in distinct_approvers
	a == norm_person(owner)
}

# ---------------------------------------------------------------------------
# Canary agent
# ---------------------------------------------------------------------------

deny contains sprintf("%s: canary tool %q must not be irreversible", [agent_id, tool_name(t)]) if {
	canary
	some t in tools
	irreversible(t)
}

deny contains sprintf("%s: canary approval.required_for must contain all", [agent_id]) if {
	canary
	not "all" in approval_required_for
}

deny contains sprintf("%s: canary must be tier 2 (got %v)", [agent_id, object.get(spec, "tier", null)]) if {
	canary
	tier != 2
}

# ---------------------------------------------------------------------------
# Warnings. Soft issues. They do not fail the gate.
# ---------------------------------------------------------------------------

warn contains sprintf("%s: tier 4 red team is %d days old (limit %d); schedule a new exercise", [agent_id, age, redteam_warn_age_days]) if {
	tier == 4
	age := floor((time.now_ns() - redteam_ns) / ns_per_day)
	age > redteam_warn_age_days
}

deny contains sprintf("%s: tier 4 redteam.date %s is in the future", [agent_id, spec.redteam.date]) if {
	tier == 4
	redteam_ns > time.now_ns()
}

warn contains sprintf("%s: tool %q has admin scope %q; prefer a narrower scope", [agent_id, tool_name(t), t.scope]) if {
	tier >= 2
	some t in tools
	is_string(t.scope)
	endswith(t.scope, ":admin")
}

warn contains sprintf("%s: tier 2 egress entry %q contains a wildcard; tier 3 and above forbid this", [agent_id, e]) if {
	tier == 2
	some e in egress
	contains(sprintf("%v", [e]), "*")
}

warn contains sprintf("%s: runtime type %q is outside Kubernetes admission control; verify controls another way", [agent_id, runtime.type]) if {
	runtime.type in {"lambda", "saas"}
}

warn contains sprintf("%s: tier %d has no tools; confirm the manifest is complete", [agent_id, tier]) if {
	tier >= 1
	count(tools) == 0
}
