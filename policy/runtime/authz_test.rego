package membrane.authz_test

import rego.v1

import data.membrane.authz

# Inline fixture in the contract shape. Tests do not depend on registry hashes.
manifests := {
	"invoice-reconciler": {
		"sha256": "h-inv",
		"tier": 3,
		"status": "active",
		"canary": false,
		"requires_delegator": true,
		"approval_required_for": ["irreversible"],
		"tools": {
			"erp.read_invoices": {"scope": "finance:read", "irreversible": false, "rate_limit_per_min": 60},
			"erp.post_adjustment": {"scope": "finance:write", "irreversible": true, "rate_limit_per_min": 5},
		},
	},
	"ticket-triager": {
		"sha256": "h-tri",
		"tier": 2,
		"status": "active",
		"canary": false,
		"requires_delegator": false,
		"approval_required_for": ["irreversible"],
		"tools": {"tickets.route": {"scope": "tickets:write", "irreversible": false, "rate_limit_per_min": 60}},
	},
	"canary": {
		"sha256": "h-can",
		"tier": 2,
		"status": "active",
		"canary": true,
		"requires_delegator": true,
		"approval_required_for": ["all"],
		"tools": {
			"canary.noop": {"scope": "canary:read", "irreversible": false, "rate_limit_per_min": 60},
			# Not allowed by CI. Present here to prove the runtime rule on its own.
			"canary.delete": {"scope": "canary:write", "irreversible": true, "rate_limit_per_min": 1},
		},
	},
	"retired-agent": {
		"sha256": "h-ret",
		"tier": 1,
		"status": "retired",
		"canary": false,
		"requires_delegator": true,
		"approval_required_for": [],
		"tools": {"kb.search": {"scope": "kb:read", "irreversible": false}},
	},
	"sparse-agent": {
		"sha256": "h-sp",
		"status": "active",
		"tools": {"x.do": {"scope": "x:write"}},
	},
}

good_approval := {"verified": true, "action_sha256": "act-1", "approver": "bob@example.com", "approval_id": "ap-1"}

# A valid reversible read by invoice-reconciler.
base := {
	"agent_id": "invoice-reconciler",
	"identity_verified": true,
	"manifest_sha256": "h-inv",
	"tool": "erp.read_invoices",
	"action_sha256": "act-1",
	"delegator": "alice@example.com",
	"approval": null,
}

irrev := object.union(base, {"tool": "erp.post_adjustment"})

triager := object.union(base, {"agent_id": "ticket-triager", "manifest_sha256": "h-tri", "tool": "tickets.route", "delegator": null})

canary_req := object.union(base, {"agent_id": "canary", "manifest_sha256": "h-can", "tool": "canary.noop"})

eval(req) := r if {
	r := authz.result with input as req with data.membrane.manifests as manifests
}

eval_ov(req, ov) := r if {
	r := authz.result with input as req with data.membrane.manifests as manifests with data.membrane.overrides as ov
}

is(r, decision, reasons) if {
	r.decision == decision
	r.reasons == reasons
}

# ---- Rule 1: identity -----------------------------------------------------

test_r1_identity_false if is(eval(object.union(base, {"identity_verified": false})), "deny", ["identity_unverified"])

test_r1_identity_missing if is(eval(object.remove(base, ["identity_verified"])), "deny", ["identity_unverified"])

test_r1_identity_truthy_string if is(eval(object.union(base, {"identity_verified": "true"})), "deny", ["identity_unverified"])

test_r1_beats_unregistered if {
	is(eval(object.union(base, {"identity_verified": false, "agent_id": "nobody"})), "deny", ["identity_unverified"])
}

# ---- Rule 2: registration -------------------------------------------------

test_r2_unregistered if is(eval(object.union(base, {"agent_id": "nobody"})), "deny", ["agent_unregistered"])

test_r2_missing_agent_id if is(eval(object.remove(base, ["agent_id"])), "deny", ["agent_unregistered"])

test_r2_no_data if {
	r := authz.result with input as base with data.membrane.manifests as {}
	is(r, "deny", ["agent_unregistered"])
}

# ---- Rule 3: manifest hash ------------------------------------------------

test_r3_hash_mismatch if is(eval(object.union(base, {"manifest_sha256": "other"})), "deny", ["manifest_hash_mismatch"])

test_r3_hash_missing if is(eval(object.remove(base, ["manifest_sha256"])), "deny", ["manifest_hash_mismatch"])

test_r3_beats_not_active if {
	req := object.union(base, {"agent_id": "retired-agent", "manifest_sha256": "wrong", "tool": "kb.search"})
	is(eval(req), "deny", ["manifest_hash_mismatch"])
}

# ---- Rule 4: status -------------------------------------------------------

test_r4_not_active if {
	req := object.union(base, {"agent_id": "retired-agent", "manifest_sha256": "h-ret", "tool": "kb.search"})
	is(eval(req), "deny", ["agent_not_active"])
}

test_r4_beats_killed if {
	req := object.union(base, {"agent_id": "retired-agent", "manifest_sha256": "h-ret", "tool": "kb.search"})
	is(eval_ov(req, {"retired-agent": {"mode": "killed"}}), "deny", ["agent_not_active"])
}

# ---- Rule 5: overrides ----------------------------------------------------

test_r5_killed if is(eval_ov(base, {"invoice-reconciler": {"mode": "killed"}}), "deny", ["override_killed"])

test_r5_quarantined if is(eval_ov(base, {"invoice-reconciler": {"mode": "quarantined"}}), "deny", ["override_quarantined"])

test_r5_killed_with_valid_approval_denies if {
	req := object.union(irrev, {"approval": good_approval})
	is(eval_ov(req, {"invoice-reconciler": {"mode": "killed", "set_at": "2026-09-27T00:00:00Z", "reason": "drill"}}), "deny", ["override_killed"])
}

test_r5_killed_beats_unknown_tool if {
	req := object.union(base, {"tool": "nope"})
	is(eval_ov(req, {"invoice-reconciler": {"mode": "killed"}}), "deny", ["override_killed"])
}

test_r5_other_agent_override_ignored if {
	is(eval_ov(base, {"ticket-triager": {"mode": "killed"}}), "allow", ["within_manifest"])
}

test_r5_unknown_mode_fails_closed if is(eval_ov(base, {"invoice-reconciler": {"mode": "paused"}}), "deny", ["override_unknown"])

test_r5_missing_mode_fails_closed if is(eval_ov(base, {"invoice-reconciler": {"reason": "x"}}), "deny", ["override_unknown"])

test_r5_non_object_override_fails_closed if is(eval_ov(base, {"invoice-reconciler": "killed"}), "deny", ["override_unknown"])

test_r5_overrides_absent_is_fine if is(eval(base), "allow", ["within_manifest"])

# R-09: an entry that is false, null, or another falsy value still counts as present.
test_r5_false_entry_fails_closed if is(eval_ov(base, {"invoice-reconciler": false}), "deny", ["override_unknown"])

test_r5_null_entry_fails_closed if is(eval_ov(base, {"invoice-reconciler": null}), "deny", ["override_unknown"])

test_r5_zero_entry_fails_closed if is(eval_ov(base, {"invoice-reconciler": 0}), "deny", ["override_unknown"])

# R-09: an overrides document that exists and is not an object denies every agent.
test_r5_overrides_array_fails_closed if is(eval_ov(base, ["x"]), "deny", ["override_unknown"])

test_r5_overrides_string_fails_closed if is(eval_ov(base, "killed"), "deny", ["override_unknown"])

test_r5_overrides_null_fails_closed if is(eval_ov(base, null), "deny", ["override_unknown"])

# ---- Rule 6: tool in manifest ---------------------------------------------

test_r6_unknown_tool if is(eval(object.union(base, {"tool": "erp.delete_vendor"})), "deny", ["tool_not_in_manifest"])

test_r6_missing_tool if is(eval(object.remove(base, ["tool"])), "deny", ["tool_not_in_manifest"])

test_r6_other_agents_tool if is(eval(object.union(base, {"tool": "tickets.route"})), "deny", ["tool_not_in_manifest"])

# ---- Rule 7: delegator ----------------------------------------------------

test_r7_null_delegator if is(eval(object.union(base, {"delegator": null})), "deny", ["delegator_required"])

test_r7_empty_delegator if is(eval(object.union(base, {"delegator": ""})), "deny", ["delegator_required"])

test_r7_blank_delegator if is(eval(object.union(base, {"delegator": "  "})), "deny", ["delegator_required"])

test_r7_missing_delegator if is(eval(object.remove(base, ["delegator"])), "deny", ["delegator_required"])

test_r7_not_required if is(eval(triager), "allow", ["within_manifest"])

test_r7_missing_flag_fails_closed if {
	req := object.union(base, {"agent_id": "sparse-agent", "manifest_sha256": "h-sp", "tool": "x.do", "delegator": null})
	is(eval(req), "deny", ["delegator_required"])
}

# ---- Rule 8: canary -------------------------------------------------------

test_r8_canary_irreversible if {
	is(eval(object.union(canary_req, {"tool": "canary.delete"})), "deny", ["canary_irreversible_forbidden"])
}

test_r8_canary_irreversible_even_with_approval if {
	req := object.union(canary_req, {"tool": "canary.delete", "approval": good_approval})
	is(eval(req), "deny", ["canary_irreversible_forbidden"])
}

test_r8_canary_reversible_needs_approval if is(eval(canary_req), "require_approval", ["approval_required"])

test_r8_canary_reversible_with_approval if {
	is(eval(object.union(canary_req, {"approval": good_approval})), "allow", ["within_manifest"])
}

# ---- Rule 9: approval required --------------------------------------------

test_r9_irreversible_no_approval if is(eval(irrev), "require_approval", ["approval_required"])

test_r9_irreversible_approval_missing_key if is(eval(object.remove(irrev, ["approval"])), "require_approval", ["approval_required"])

test_r9_irreversible_valid_approval if is(eval(object.union(irrev, {"approval": good_approval})), "allow", ["within_manifest"])

test_r9_mismatched_approval_on_needed_tool if {
	req := object.union(irrev, {"approval": object.union(good_approval, {"action_sha256": "act-2"})})
	is(eval(req), "deny", ["approval_mismatch"])
}

test_r9_unverified_approval_on_needed_tool if {
	req := object.union(irrev, {"approval": object.union(good_approval, {"verified": false})})
	is(eval(req), "deny", ["approval_mismatch"])
}

test_r9_missing_action_hash_never_matches if {
	req := object.remove(object.union(irrev, {"approval": object.remove(good_approval, ["action_sha256"])}), ["action_sha256"])
	is(eval(req), "deny", ["approval_mismatch"])
}

test_r9_restricted_makes_reversible_need_approval if {
	is(eval_ov(base, {"invoice-reconciler": {"mode": "restricted"}}), "require_approval", ["approval_required"])
}

test_r9_restricted_with_valid_approval if {
	req := object.union(base, {"approval": good_approval})
	is(eval_ov(req, {"invoice-reconciler": {"mode": "restricted"}}), "allow", ["within_manifest"])
}

test_r9_all_covers_reversible if {
	m := json.patch(manifests, [{"op": "replace", "path": "/ticket-triager/approval_required_for", "value": ["all"]}])
	r := authz.result with input as triager with data.membrane.manifests as m
	is(r, "require_approval", ["approval_required"])
}

test_r9_empty_list_needs_no_approval_for_irreversible if {
	m := json.patch(manifests, [{"op": "replace", "path": "/invoice-reconciler/approval_required_for", "value": []}])
	r := authz.result with input as irrev with data.membrane.manifests as m
	is(r, "allow", ["within_manifest"])
}

test_r9_missing_irreversible_flag_fails_closed if {
	m := json.patch(manifests, [{"op": "add", "path": "/sparse-agent/requires_delegator", "value": false}])
	req := object.union(base, {"agent_id": "sparse-agent", "manifest_sha256": "h-sp", "tool": "x.do"})
	r := authz.result with input as req with data.membrane.manifests as m
	is(r, "require_approval", ["approval_required"])
}

test_mismatch_beats_approval_required if {
	req := object.union(irrev, {"approval": {"verified": false}})
	is(eval(req), "deny", ["approval_mismatch"])
}

# ---- Rule 10: approval mismatch -------------------------------------------

test_r10_mismatch_on_tool_needing_no_approval if {
	req := object.union(base, {"approval": object.union(good_approval, {"action_sha256": "act-2"})})
	is(eval(req), "deny", ["approval_mismatch"])
}

test_r10_unverified_on_tool_needing_no_approval if {
	req := object.union(base, {"approval": object.union(good_approval, {"verified": false})})
	is(eval(req), "deny", ["approval_mismatch"])
}

test_r10_malformed_approval if is(eval(object.union(base, {"approval": "token"})), "deny", ["approval_mismatch"])

test_r10_empty_object_approval if is(eval(object.union(base, {"approval": {}})), "deny", ["approval_mismatch"])

test_r10_valid_approval_on_tool_needing_none if {
	is(eval(object.union(base, {"approval": good_approval})), "allow", ["within_manifest"])
}

# ---- Rule 11: allow -------------------------------------------------------

test_r11_allow if is(eval(base), "allow", ["within_manifest"])

test_r11_throttled if is(eval_ov(base, {"invoice-reconciler": {"mode": "throttled"}}), "allow", ["within_manifest", "throttled"])

test_r11_throttled_still_needs_approval if {
	is(eval_ov(irrev, {"invoice-reconciler": {"mode": "throttled"}}), "require_approval", ["approval_required"])
}

test_r11_throttled_with_approval if {
	req := object.union(irrev, {"approval": good_approval})
	is(eval_ov(req, {"invoice-reconciler": {"mode": "throttled"}}), "allow", ["within_manifest", "throttled"])
}

# ---- Shape of the result --------------------------------------------------

test_result_has_one_decision_and_reasons if {
	r := eval(base)
	object.keys(r) == {"decision", "reasons"}
	is_array(r.reasons)
}

test_empty_input_denied if {
	r := authz.result with input as {} with data.membrane.manifests as manifests
	is(r, "deny", ["identity_unverified"])
}
