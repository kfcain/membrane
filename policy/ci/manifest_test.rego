package membrane.ci_test

import rego.v1

import data.membrane.ci

# 2026-09-27T00:00:00Z in nanoseconds. Tests mock time.now_ns with this value.
now_ns := 1790467200000000000

digest := "@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

base_runtime := {
	"type": "k8s",
	"namespace": "agents",
	"service_account": "agent-sa",
	"image": concat("", ["registry.example.com/a", digest]),
}

tier1 := {
	"apiVersion": "membrane/v1",
	"kind": "AgentManifest",
	"metadata": {"id": "t1", "owner": "owner@example.com", "description": "d"},
	"spec": {
		"tier": 1,
		"status": "active",
		"runtime": base_runtime,
		"model": {"provider": "p", "id": "m", "pinned": true},
		"delegation": {"requires_delegator": true},
		"tools": [{"name": "kb.search", "scope": "kb:read", "irreversible": false}],
		"egress": [],
		"data_scopes": [],
		"approval": {"required_for": []},
	},
}

tier2 := json.patch(tier1, [
	{"op": "replace", "path": "/spec/tier", "value": 2},
	{"op": "replace", "path": "/spec/tools", "value": [
		{"name": "t.read", "scope": "t:read", "irreversible": false, "rate_limit_per_min": 60},
		{"name": "t.write", "scope": "t:write", "irreversible": false, "rate_limit_per_min": 10},
	]},
	{"op": "add", "path": "/spec/evals", "value": {"suite": "s", "min_pass": 0.9}},
	{"op": "add", "path": "/spec/aibom", "value": {"format": "cyclonedx-1.6", "ref": "aibom/x.json"}},
])

tier3 := json.patch(tier2, [
	{"op": "replace", "path": "/spec/tier", "value": 3},
	{"op": "replace", "path": "/spec/evals/min_pass", "value": 0.95},
	{"op": "add", "path": "/spec/tools/-", "value": {"name": "erp.post", "scope": "fin:write", "irreversible": true, "rate_limit_per_min": 5}},
	{"op": "replace", "path": "/spec/egress", "value": ["erp.internal.example.com"]},
	{"op": "replace", "path": "/spec/approval/required_for", "value": ["irreversible"]},
])

tier4 := json.patch(tier3, [
	{"op": "replace", "path": "/spec/tier", "value": 4},
	{"op": "replace", "path": "/spec/evals/min_pass", "value": 0.97},
	{"op": "add", "path": "/spec/sandbox", "value": {"isolated": true, "standing_credentials": false, "session_recording": true}},
	{"op": "add", "path": "/spec/redteam", "value": {"ref": "redteam/x.md", "date": "2026-09-10"}},
	{"op": "add", "path": "/spec/promotion", "value": {"approvers": ["a@example.com", "b@example.com"]}},
])

canary := json.patch(tier2, [
	{"op": "add", "path": "/spec/canary", "value": true},
	{"op": "replace", "path": "/spec/approval/required_for", "value": ["all"]},
])

denies(doc) := d if {
	d := ci.deny with input as doc with time.now_ns as now_ns
}

warns(doc) := w if {
	w := ci.warn with input as doc with time.now_ns as now_ns
}

has_deny(doc, fragment) if {
	some m in denies(doc)
	contains(m, fragment)
}

has_warn(doc, fragment) if {
	some m in warns(doc)
	contains(m, fragment)
}

patched(doc, ops) := json.patch(doc, ops)

# ---- good baselines -------------------------------------------------------

test_good_tier1 if count(denies(tier1)) == 0

test_good_tier2 if count(denies(tier2)) == 0

test_good_tier3 if count(denies(tier3)) == 0

test_good_tier4 if count(denies(tier4)) == 0

test_good_canary if count(denies(canary)) == 0

test_good_tier4_no_warn if count(warns(tier4)) == 0

test_tier3_no_egress_is_allowed if {
	count(denies(patched(tier3, [{"op": "replace", "path": "/spec/egress", "value": []}]))) == 0
}

test_tier3_all_approval_is_enough if {
	count(denies(patched(tier3, [{"op": "replace", "path": "/spec/approval/required_for", "value": ["all"]}]))) == 0
}

test_non_k8s_runtime_skips_k8s_rules if {
	doc := patched(tier1, [{"op": "replace", "path": "/spec/runtime", "value": {"type": "saas", "vendor": "x"}}])
	count(denies(doc)) == 0
	has_warn(doc, "outside Kubernetes admission control")
}

# ---- fail closed on shape -------------------------------------------------

test_empty_input_denied if {
	has_deny({}, "apiVersion must be membrane/v1")
	has_deny({}, "kind must be AgentManifest")
	has_deny({}, "spec.tier must be")
}

test_spec_not_object_denied if has_deny(patched(tier1, [{"op": "replace", "path": "/spec", "value": "x"}]), "spec.tier must be")

test_tier_out_of_range if has_deny(patched(tier1, [{"op": "replace", "path": "/spec/tier", "value": 5}]), "spec.tier must be")

test_tier_string if has_deny(patched(tier1, [{"op": "replace", "path": "/spec/tier", "value": "1"}]), "spec.tier must be")

test_bad_status if has_deny(patched(tier1, [{"op": "replace", "path": "/spec/status", "value": "paused"}]), "spec.status")

test_missing_status if has_deny(patched(tier1, [{"op": "remove", "path": "/spec/status"}]), "spec.status")

test_suspended_and_retired_ok if {
	count(denies(patched(tier1, [{"op": "replace", "path": "/spec/status", "value": "suspended"}]))) == 0
	count(denies(patched(tier1, [{"op": "replace", "path": "/spec/status", "value": "retired"}]))) == 0
}

test_duplicate_tool if {
	has_deny(patched(tier2, [{"op": "add", "path": "/spec/tools/-", "value": tier2.spec.tools[0]}]), "appears more than once")
}

test_missing_irreversible_flag if {
	doc := patched(tier2, [{"op": "remove", "path": "/spec/tools/0/irreversible"}])
	has_deny(doc, "no boolean irreversible flag")
}

test_missing_tools_list if has_deny(patched(tier1, [{"op": "remove", "path": "/spec/tools"}]), "spec.tools must be a list")

# ---- all tiers: model and runtime -----------------------------------------

test_model_unpinned if has_deny(patched(tier1, [{"op": "replace", "path": "/spec/model/pinned", "value": false}]), "model.pinned")

test_model_missing if has_deny(patched(tier1, [{"op": "remove", "path": "/spec/model"}]), "model.pinned")

test_k8s_missing_namespace if has_deny(patched(tier1, [{"op": "remove", "path": "/spec/runtime/namespace"}]), "runtime.namespace")

test_k8s_empty_namespace if has_deny(patched(tier1, [{"op": "replace", "path": "/spec/runtime/namespace", "value": " "}]), "runtime.namespace")

test_k8s_missing_sa if has_deny(patched(tier1, [{"op": "remove", "path": "/spec/runtime/service_account"}]), "runtime.service_account")

test_k8s_default_sa if has_deny(patched(tier1, [{"op": "replace", "path": "/spec/runtime/service_account", "value": "default"}]), "default service account")

test_k8s_tag_image if has_deny(patched(tier1, [{"op": "replace", "path": "/spec/runtime/image", "value": "r/a:latest"}]), "@sha256 digest")

test_k8s_upper_hex_digest if {
	img := "r/a@sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	has_deny(patched(tier1, [{"op": "replace", "path": "/spec/runtime/image", "value": img}]), "@sha256 digest")
}

test_k8s_missing_image if has_deny(patched(tier1, [{"op": "remove", "path": "/spec/runtime/image"}]), "@sha256 digest")

# ---- tier 1 ---------------------------------------------------------------

test_tier1_write_scope if {
	doc := patched(tier1, [{"op": "add", "path": "/spec/tools/-", "value": {"name": "kb.edit", "scope": "kb:write", "irreversible": false}}])
	has_deny(doc, "tier 1 tool \"kb.edit\" must not have scope")
}

test_tier1_admin_scope if {
	doc := patched(tier1, [{"op": "add", "path": "/spec/tools/-", "value": {"name": "kb.adm", "scope": "kb:admin", "irreversible": false}}])
	has_deny(doc, "tier 1 tool \"kb.adm\" must not have scope")
}

test_tier1_irreversible if {
	doc := patched(tier1, [{"op": "replace", "path": "/spec/tools/0/irreversible", "value": true}])
	has_deny(doc, "must not be irreversible")
}

test_tier1_egress if has_deny(patched(tier1, [{"op": "replace", "path": "/spec/egress", "value": ["a.example.com"]}]), "empty egress")

test_tier1_needs_no_evals_or_rate_limits if {
	not has_deny(tier1, "evals")
	not has_deny(tier1, "rate_limit_per_min")
}

# ---- tier 2+ --------------------------------------------------------------

test_tier2_no_evals if has_deny(patched(tier2, [{"op": "remove", "path": "/spec/evals"}]), "needs spec.evals")

test_tier2_eval_threshold if {
	has_deny(patched(tier2, [{"op": "replace", "path": "/spec/evals/min_pass", "value": 0.89}]), "min_pass >= 0.9")
	not has_deny(patched(tier2, [{"op": "replace", "path": "/spec/evals/min_pass", "value": 0.9}]), "min_pass")
}

test_tier3_eval_threshold if {
	has_deny(patched(tier3, [{"op": "replace", "path": "/spec/evals/min_pass", "value": 0.949}]), "min_pass >= 0.95")
	not has_deny(patched(tier3, [{"op": "replace", "path": "/spec/evals/min_pass", "value": 0.95}]), "min_pass")
}

test_tier4_eval_threshold if {
	has_deny(patched(tier4, [{"op": "replace", "path": "/spec/evals/min_pass", "value": 0.969}]), "min_pass >= 0.97")
	not has_deny(patched(tier4, [{"op": "replace", "path": "/spec/evals/min_pass", "value": 0.97}]), "min_pass")
}

test_eval_min_pass_string if has_deny(patched(tier2, [{"op": "replace", "path": "/spec/evals/min_pass", "value": "0.99"}]), "min_pass")

test_eval_missing_suite if has_deny(patched(tier2, [{"op": "remove", "path": "/spec/evals/suite"}]), "evals.suite")

test_tier2_no_aibom if has_deny(patched(tier2, [{"op": "remove", "path": "/spec/aibom"}]), "spec.aibom")

test_tier2_aibom_no_ref if has_deny(patched(tier2, [{"op": "remove", "path": "/spec/aibom/ref"}]), "spec.aibom")

test_tier2_rate_limit if {
	doc := patched(tier2, [{"op": "remove", "path": "/spec/tools/1/rate_limit_per_min"}])
	has_deny(doc, "tool \"t.write\" needs rate_limit_per_min")
}

test_tier2_rate_limit_zero if {
	has_deny(patched(tier2, [{"op": "replace", "path": "/spec/tools/1/rate_limit_per_min", "value": 0}]), "rate_limit_per_min")
}

test_tier2_wildcard_egress_warns_only if {
	doc := patched(tier2, [{"op": "replace", "path": "/spec/egress", "value": ["*.example.com"]}])
	count(denies(doc)) == 0
	has_warn(doc, "contains a wildcard")
}

test_tier2_admin_scope_warns if {
	doc := patched(tier2, [{"op": "replace", "path": "/spec/tools/1/scope", "value": "t:admin"}])
	count(denies(doc)) == 0
	has_warn(doc, "admin scope")
}

# ---- tier 3+ --------------------------------------------------------------

test_tier3_wildcard_egress if {
	has_deny(patched(tier3, [{"op": "add", "path": "/spec/egress/-", "value": "*.example.com"}]), "must not contain a wildcard")
	has_deny(patched(tier3, [{"op": "add", "path": "/spec/egress/-", "value": "*"}]), "must not contain a wildcard")
}

test_tier3_non_fqdn_egress if {
	has_deny(patched(tier3, [{"op": "add", "path": "/spec/egress/-", "value": "https://a.example.com"}]), "lowercase FQDN")
	has_deny(patched(tier3, [{"op": "add", "path": "/spec/egress/-", "value": "localhost"}]), "lowercase FQDN")
	has_deny(patched(tier3, [{"op": "add", "path": "/spec/egress/-", "value": "10.0.0.1"}]), "lowercase FQDN")
	has_deny(patched(tier3, [{"op": "add", "path": "/spec/egress/-", "value": "a.example.com:443"}]), "lowercase FQDN")
	has_deny(patched(tier3, [{"op": "add", "path": "/spec/egress/-", "value": "A.Example.com"}]), "lowercase FQDN")
	has_deny(patched(tier3, [{"op": "add", "path": "/spec/egress/-", "value": 42}]), "lowercase FQDN")
}

test_tier3_irreversible_needs_approval if {
	has_deny(patched(tier3, [{"op": "replace", "path": "/spec/approval/required_for", "value": []}]), "must contain irreversible or all")
}

test_tier3_reversible_only_needs_no_approval if {
	doc := patched(tier3, [
		{"op": "remove", "path": "/spec/tools/2"},
		{"op": "replace", "path": "/spec/approval/required_for", "value": []},
	])
	count(denies(doc)) == 0
}

test_tier3_delegator if {
	has_deny(patched(tier3, [{"op": "replace", "path": "/spec/delegation/requires_delegator", "value": false}]), "requires_delegator")
	has_deny(patched(tier3, [{"op": "remove", "path": "/spec/delegation"}]), "requires_delegator")
}

test_tier2_delegator_optional if {
	count(denies(patched(tier2, [{"op": "replace", "path": "/spec/delegation/requires_delegator", "value": false}]))) == 0
}

# ---- tier 4 ---------------------------------------------------------------

test_tier4_no_sandbox if has_deny(patched(tier4, [{"op": "remove", "path": "/spec/sandbox"}]), "needs spec.sandbox")

test_tier4_sandbox_flags if {
	has_deny(patched(tier4, [{"op": "replace", "path": "/spec/sandbox/isolated", "value": false}]), "isolated must be true")
	has_deny(patched(tier4, [{"op": "replace", "path": "/spec/sandbox/standing_credentials", "value": true}]), "standing_credentials must be false")
	has_deny(patched(tier4, [{"op": "remove", "path": "/spec/sandbox/standing_credentials"}]), "standing_credentials must be false")
	has_deny(patched(tier4, [{"op": "replace", "path": "/spec/sandbox/session_recording", "value": false}]), "session_recording must be true")
}

test_tier4_redteam if {
	has_deny(patched(tier4, [{"op": "remove", "path": "/spec/redteam"}]), "needs spec.redteam")
	has_deny(patched(tier4, [{"op": "remove", "path": "/spec/redteam/ref"}]), "needs spec.redteam")
	has_deny(patched(tier4, [{"op": "replace", "path": "/spec/redteam/date", "value": "2026-02-30"}]), "not a valid YYYY-MM-DD")
	has_deny(patched(tier4, [{"op": "replace", "path": "/spec/redteam/date", "value": "last week"}]), "not a valid YYYY-MM-DD")
}

test_tier4_redteam_stale_warns if {
	doc := patched(tier4, [{"op": "replace", "path": "/spec/redteam/date", "value": "2026-03-01"}])
	count(denies(doc)) == 0
	has_warn(doc, "red team is 210 days old")
}

test_tier4_redteam_at_limit_no_warn if {
	# 180 days before 2026-09-27 is 2026-03-31.
	doc := patched(tier4, [{"op": "replace", "path": "/spec/redteam/date", "value": "2026-03-31"}])
	not has_warn(doc, "red team is")
}

test_tier4_redteam_future_denies if {
	has_deny(patched(tier4, [{"op": "replace", "path": "/spec/redteam/date", "value": "2099-01-01"}]), "in the future")
}

test_tier4_promotion if {
	has_deny(patched(tier4, [{"op": "remove", "path": "/spec/promotion"}]), "at least 2 distinct")
	has_deny(patched(tier4, [{"op": "replace", "path": "/spec/promotion/approvers", "value": ["a@example.com"]}]), "at least 2 distinct")
	has_deny(patched(tier4, [{"op": "replace", "path": "/spec/promotion/approvers", "value": ["a@example.com", "A@example.com"]}]), "at least 2 distinct")
	has_deny(patched(tier4, [{"op": "replace", "path": "/spec/promotion/approvers", "value": ["a@example.com", "owner@example.com"]}]), "must not be the owner")
	has_deny(patched(tier4, [{"op": "replace", "path": "/spec/promotion/approvers", "value": ["a@example.com", "Owner@Example.com"]}]), "must not be the owner")
}

# R-11: white space and case tricks do not make two approvers out of one person.
test_tier4_promotion_normalized if {
	has_deny(patched(tier4, [{"op": "replace", "path": "/spec/promotion/approvers", "value": ["owner@example.com ", " Owner@example.com"]}]), "at least 2 distinct")
	has_deny(patched(tier4, [{"op": "replace", "path": "/spec/promotion/approvers", "value": ["a@example.com", " owner@example.com"]}]), "must not be the owner")
	has_deny(patched(tier4, [{"op": "replace", "path": "/spec/promotion/approvers", "value": ["a@example.com ", " A@example.com"]}]), "at least 2 distinct")
	has_deny(patched(tier4, [{"op": "replace", "path": "/spec/promotion/approvers", "value": ["a@example.com", "b@example"]}]), "must be a plain email address")
	has_deny(patched(tier4, [{"op": "replace", "path": "/spec/promotion/approvers", "value": ["a@example.com", "b @example.com"]}]), "must be a plain email address")
	has_deny(patched(tier4, [{"op": "replace", "path": "/spec/promotion/approvers", "value": ["a@example.com", 5]}]), "must be a plain email address")
	not has_deny(tier4, "must be a plain email address")
}

# ---- canary ---------------------------------------------------------------

test_canary_irreversible if {
	has_deny(patched(canary, [{"op": "replace", "path": "/spec/tools/1/irreversible", "value": true}]), "canary tool \"t.write\" must not be irreversible")
}

test_canary_needs_all if {
	has_deny(patched(canary, [{"op": "replace", "path": "/spec/approval/required_for", "value": ["irreversible"]}]), "must contain all")
}

test_canary_tier if {
	has_deny(patched(canary, [{"op": "replace", "path": "/spec/tier", "value": 1}]), "canary must be tier 2")
	has_deny(patched(canary, [{"op": "replace", "path": "/spec/tier", "value": 3}]), "canary must be tier 2")
}

test_canary_false_is_not_canary if {
	doc := patched(tier2, [{"op": "add", "path": "/spec/canary", "value": false}])
	count(denies(doc)) == 0
}

test_redteam_age_uses_clock if {
	later := now_ns + (200 * ci.ns_per_day)
	msgs := ci.warn with input as tier4 with time.now_ns as later
	some m in msgs
	contains(m, "red team is 217 days old")
}

test_valid_date_edges if {
	ci.valid_date("2024-02-29")
	ci.valid_date("2000-02-29")
	not ci.valid_date("1900-02-29")
	not ci.valid_date("2026-02-29")
	not ci.valid_date("2026-04-31")
	ci.valid_date("2026-12-31")
	not ci.valid_date("2026-00-10")
	not ci.valid_date("2026-9-1")
	not ci.valid_date(20260910)
}
