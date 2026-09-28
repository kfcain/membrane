"""Pass and fail cases for each check."""
from __future__ import annotations

from _checks_util import check, fixture_sets, rehash, run


def _status(tmp, sets, cid):
    code, res, _ = run(tmp, sets)
    assert code == 0
    return check(res, cid)


def test_fixture_fail_cases(tmp_path):
    code, res, _ = run(tmp_path)
    assert code == 0
    got = {c["id"]: c["status"] for c in res["checks"]}
    assert got == {
        "AGT-INV-01": "FAIL", "AGT-INV-02": "FAIL", "AGT-IAM-01": "FAIL", "AGT-IAM-02": "FAIL",
        "AGT-AU-01": "FAIL", "AGT-AC-01": "FAIL", "AGT-AC-02": "FAIL", "AGT-SC-01": "FAIL",
        "AGT-CM-01": "FAIL", "AGT-TST-01": "PASS", "AGT-IR-01": "PASS",
    }
    assert res["demo"] is False


# ------------------------------------------------------------------ inventory

def _inventory_without(sets, names):
    inv = sets["inventory"][0]
    inv["payload"]["workloads"] = [w for w in inv["payload"]["workloads"] if w["name"] not in names]
    rehash(inv)


def test_inv_01_fail_lists_workloads(tmp_path):
    c = _status(tmp_path, fixture_sets(), "AGT-INV-01")
    assert c["status"] == "FAIL"
    assert {(o["name"], o["reason"]) for o in c["offending"]} == {
        ("ghost-agent", "agent_id_not_registered"), ("shadow-job", "no_agent_id_label_in_agent_namespace")}


def test_inv_01_pass_and_exemptions(tmp_path):
    sets = fixture_sets()
    _inventory_without(sets, {"ghost-agent", "shadow-job"})
    c = _status(tmp_path, sets, "AGT-INV-01")
    # membrane-gateway carries membrane.io/component; coredns is outside agent namespaces.
    assert c["status"] == "PASS"
    assert c["examined"] == 6


def test_inv_02_fail_and_pass(tmp_path):
    c = _status(tmp_path, fixture_sets(), "AGT-INV-02")
    assert c["status"] == "FAIL"
    assert [o["name"] for o in c["offending"]] == ["code-runner"]
    assert c["offending"][0]["reason"] == "manifest_hash_mismatch"

    sets = fixture_sets()
    _inventory_without(sets, {"code-runner"})
    assert _status(tmp_path / "p", sets, "AGT-INV-02")["status"] == "PASS"


def test_inv_02_missing_annotation(tmp_path):
    sets = fixture_sets()
    inv = sets["inventory"][0]
    for w in inv["payload"]["workloads"]:
        if w["name"] == "kb-reader":
            w["annotations"] = {}
    rehash(inv)
    c = _status(tmp_path, sets, "AGT-INV-02")
    assert "manifest_hash_missing" in {o["reason"] for o in c["offending"]}


def test_iam_02_fail_and_pass(tmp_path):
    c = _status(tmp_path, fixture_sets(), "AGT-IAM-02")
    assert c["status"] == "FAIL"
    assert {o["identity_type"] for o in c["offending"]} == {"service_account", "spiffe_id"}
    assert all(o["agent_ids"] == ["ghost-agent", "kb-reader"] for o in c["offending"])

    sets = fixture_sets()
    _inventory_without(sets, {"ghost-agent"})
    assert _status(tmp_path / "p", sets, "AGT-IAM-02")["status"] == "PASS"


# ------------------------------------------------------------------ secrets

def test_iam_01_fail_and_pass(tmp_path):
    c = _status(tmp_path, fixture_sets(), "AGT-IAM-01")
    assert c["status"] == "FAIL"
    assert c["offending"][0]["location"] == "repo-a:app.py:3"

    sets = fixture_sets()
    scan = sets["secret_scan"][0]
    scan["payload"]["findings"] = [f for f in scan["payload"]["findings"] if f["in_vault"]]
    rehash(scan)
    assert _status(tmp_path / "p", sets, "AGT-IAM-01")["status"] == "PASS"


# ------------------------------------------------------------------ gateway

def _drop_execs(sets, keep):
    sets["tool_exec"] = [r for r in sets["tool_exec"] if keep(r)]


def test_au_01_fail_reasons(tmp_path):
    c = _status(tmp_path, fixture_sets(), "AGT-AU-01")
    assert c["status"] == "FAIL"
    assert sorted(o["reason"] for o in c["offending"]) == ["decision_missing", "decision_not_allow"]


def test_au_01_pass(tmp_path):
    sets = fixture_sets()
    allow_ids = {d["payload"]["decision_id"] for d in sets["decision"] if d["payload"]["decision"] == "allow"}
    _drop_execs(sets, lambda r: r["payload"]["decision_id"] in allow_ids)
    assert _status(tmp_path, sets, "AGT-AU-01")["status"] == "PASS"


def test_au_01_decision_mismatch(tmp_path):
    sets = fixture_sets()
    e = next(r for r in sets["tool_exec"] if r["payload"]["tool"] == "kb.search"
             and r["payload"]["decision_id"] in {d["payload"]["decision_id"] for d in sets["decision"]})
    e["payload"]["tool"] = "kb.delete"
    rehash(e)
    c = _status(tmp_path, sets, "AGT-AU-01")
    assert "decision_mismatch" in {o["reason"] for o in c["offending"]}


def test_au_01_ineligible_decision_is_a_finding(tmp_path):
    sets = fixture_sets()
    for d in sets["decision"]:
        d["mode"] = "simulated"
        rehash(d)
    c = _status(tmp_path, sets, "AGT-AU-01")
    assert c["status"] == "FAIL"
    assert "decision_ineligible" in {o["reason"] for o in c["offending"]}


def test_ac_01_fail_reasons(tmp_path):
    c = _status(tmp_path, fixture_sets(), "AGT-AC-01")
    assert c["status"] == "FAIL"
    # kb.delete is not in the kb-reader manifest, so it counts as irreversible (R-17).
    assert sorted((o["tool"], o["reason"]) for o in c["offending"]) == [
        ("email.send_vendor_notice", "approval_missing"), ("erp.post_adjustment", "approval_hash_mismatch"),
        ("kb.delete", "approval_missing"), ("kb.delete", "irreversible_flag_mismatch")]


def test_ac_01_pass(tmp_path):
    sets = fixture_sets()
    bad = {o for o in ("approval_missing", "approval_hash_mismatch")}
    _, res, _ = run(tmp_path / "probe", sets)
    bad_ids = {o["exec_id"] for o in check(res, "AGT-AC-01")["offending"] if o["reason"] in bad}
    _drop_execs(sets, lambda r: r["payload"]["exec_id"] not in bad_ids)
    c = _status(tmp_path, sets, "AGT-AC-01")
    assert c["status"] == "PASS"
    assert c["examined"] == 1


def test_ac_01_expired_approval(tmp_path):
    sets = fixture_sets()
    for a in sets["approval"]:
        a["payload"]["expires_at"] = "2026-09-27T11:00:00.000Z"
        rehash(a)
    c = _status(tmp_path, sets, "AGT-AC-01")
    assert "approval_expired" in {o["reason"] for o in c["offending"]}


def test_ac_02_fail_and_pass(tmp_path):
    c = _status(tmp_path, fixture_sets(), "AGT-AC-02")
    assert c["status"] == "FAIL"
    assert [o["agent_id"] for o in c["offending"]] == ["code-runner"]
    # ticket-triager allows with no delegator do not count: its manifest does not require one.

    sets = fixture_sets()
    for d in sets["decision"]:
        if d["payload"]["agent_id"] == "code-runner":
            d["payload"]["delegator"] = "carol@example.com"
            rehash(d)
    assert _status(tmp_path / "p", sets, "AGT-AC-02")["status"] == "PASS"


# ------------------------------------------------------------------ network

def test_sc_01_fail_and_pass(tmp_path):
    c = _status(tmp_path, fixture_sets(), "AGT-SC-01")
    assert c["status"] == "FAIL"
    assert [o["destination_fqdn"] for o in c["offending"]] == ["pastebin.example.net"]
    assert c["examined"] == 2  # denied flows are not examined

    sets = fixture_sets()
    f = sets["egress_flow"][0]
    f["payload"]["flows"] = [x for x in f["payload"]["flows"] if x["destination_fqdn"] != "pastebin.example.net"]
    rehash(f)
    assert _status(tmp_path / "p", sets, "AGT-SC-01")["status"] == "PASS"


def test_sc_01_unregistered_agent(tmp_path):
    sets = fixture_sets()
    f = sets["egress_flow"][0]
    f["payload"]["flows"][0]["agent_id"] = "shadow-summarizer"
    rehash(f)
    c = _status(tmp_path, sets, "AGT-SC-01")
    assert "agent_unregistered" in {o["reason"] for o in c["offending"]}


# ------------------------------------------------------------------ pipeline

def test_cm_01_fail_and_pass(tmp_path):
    c = _status(tmp_path, fixture_sets(), "AGT-CM-01")
    assert c["status"] == "FAIL"
    assert c["offending"][0]["run_id"] == "run-low"
    assert any(g.startswith("evals_score:") for g in c["offending"][0]["failed_gates"])

    sets = fixture_sets()
    sets["pipeline_run"] = [r for r in sets["pipeline_run"] if r["payload"]["run_id"] != "run-low"]
    c = _status(tmp_path / "p", sets, "AGT-CM-01")
    # run-kb skipped evals, and kb-reader's manifest has no evals block, so that is allowed.
    assert c["status"] == "PASS"


def test_cm_01_skipped_gate(tmp_path):
    sets = fixture_sets()
    r = next(r for r in sets["pipeline_run"] if r["payload"]["run_id"] == "run-ok")
    r["payload"]["gates"]["evals"]["result"] = "skipped"
    r["payload"]["gates"]["signature"] = "missing"
    rehash(r)
    c = _status(tmp_path, sets, "AGT-CM-01")
    gates = next(o for o in c["offending"] if o["run_id"] == "run-ok")["failed_gates"]
    assert "evals:skipped" in gates and "signature:missing" in gates


# ------------------------------------------------------------------ canary and drill

def test_tst_01_newest_wins_and_fail(tmp_path):
    assert _status(tmp_path, fixture_sets(), "AGT-TST-01")["status"] == "PASS"

    sets = fixture_sets()
    sets["canary"] = [r for r in sets["canary"] if r["payload"]["all_pass"] is False]
    sets["canary"][0]["collected_at"] = "2026-09-27T12:30:00.000Z"
    rehash(sets["canary"][0])
    c = _status(tmp_path / "f", sets, "AGT-TST-01")
    assert c["status"] == "FAIL"
    assert c["offending"][0]["probe"] == "canary_irreversible"


def test_tst_01_stale_after_24h(tmp_path):
    code, res, _ = run(tmp_path, now="2026-09-28T11:00:00Z")
    assert check(res, "AGT-TST-01")["status"] == "STALE"


def test_ir_01_fail_and_stale(tmp_path):
    sets = fixture_sets()
    d = sets["kill_drill"][0]
    d["payload"]["seconds_to_denial"] = 45.0
    d["payload"]["within_sla"] = False
    rehash(d)
    c = _status(tmp_path, sets, "AGT-IR-01")
    assert c["status"] == "FAIL"
    assert c["offending"][0]["seconds_to_denial"] == 45.0

    code, res, _ = run(tmp_path / "s", now="2026-12-30T13:00:00Z")
    assert check(res, "AGT-IR-01")["status"] == "STALE"


def test_ir_01_inconsistent_sla_flag_is_fail(tmp_path):
    sets = fixture_sets()
    d = sets["kill_drill"][0]
    d["payload"]["seconds_to_denial"] = 31.0  # within_sla still says true
    rehash(d)
    assert _status(tmp_path, sets, "AGT-IR-01")["status"] == "FAIL"


# R-17: irreversibility comes from the registry manifest, not from the tool_exec record.

def test_r17_ac_01_uses_manifest_irreversible_flag(tmp_path):
    sets = fixture_sets()
    # e4: email.send_vendor_notice is irreversible in the manifest. The backend says false.
    e = next(r for r in sets["tool_exec"] if r["payload"]["tool"] == "email.send_vendor_notice")
    e["payload"]["irreversible"] = False
    rehash(e)
    c = _status(tmp_path, sets, "AGT-AC-01")
    got = {(o["exec_id"], o["reason"]) for o in c["offending"]}
    assert (e["payload"]["exec_id"], "approval_missing") in got
    assert (e["payload"]["exec_id"], "irreversible_flag_mismatch") in got


def test_r17_ac_01_unknown_tool_or_missing_flag_counts_as_irreversible(tmp_path):
    sets = fixture_sets()
    e = next(r for r in sets["tool_exec"] if r["payload"]["tool"] == "kb.search"
             and r["payload"]["approval_id"] is None)
    e["payload"]["tool"] = "kb.unknown_tool"
    e["payload"].pop("irreversible")
    rehash(e)
    c = _status(tmp_path, sets, "AGT-AC-01")
    got = {(o["exec_id"], o["reason"]) for o in c["offending"]}
    assert (e["payload"]["exec_id"], "approval_missing") in got
