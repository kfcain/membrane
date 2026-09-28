"""Integration: real gateway over HTTP, real OPA, real policy/runtime/authz.rego.

Skips when opa is missing or policy/runtime/authz.rego is absent.
"""
from __future__ import annotations

import json
import os
import shutil
import threading
from pathlib import Path

import jsonschema
import pytest

from membrane import evidence
from membrane.canary.probes import run_canary
from membrane.gateway import approvals, tokens
from membrane.gateway.client import call_tool
from membrane.gateway.opa import policy_files, policy_sha256
from membrane.gateway.server import Gateway, GatewayConfig, make_server
from membrane.gen import write
from membrane.gen.generate import generate
from membrane.manifest import REPO_ROOT, canonical_json, load_registry, sha256_hex
from membrane.respond.drill import run_kill_drill

POLICY_DIR = REPO_ROOT / "policy" / "runtime"
OPA = os.environ.get("MEMBRANE_OPA_BIN", "opa")

pytestmark = [
    pytest.mark.skipif(shutil.which(OPA) is None, reason="opa binary not found"),
    pytest.mark.skipif(not (POLICY_DIR / "authz.rego").exists(), reason="policy/runtime/authz.rego absent"),
]


@pytest.fixture
def gateway(tmp_path, monkeypatch):
    monkeypatch.setenv("MEMBRANE_EVIDENCE_DIR", str(tmp_path / "ev"))
    monkeypatch.setenv("MEMBRANE_STATE_DIR", str(tmp_path / "state"))
    reg = load_registry()
    out = tmp_path / "gen"
    write(out, generate(reg))
    cfg = GatewayConfig(policy_dir=POLICY_DIR, data_path=out / "opa" / "data.json", opa_bin=OPA, opa_url="")
    srv = make_server("127.0.0.1", 0, Gateway(cfg))
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    url = f"http://127.0.0.1:{srv.server_address[1]}"
    yield {"url": url, "reg": reg, "tmp": tmp_path, "data_path": out / "opa" / "data.json"}
    srv.shutdown()
    srv.server_close()


def _schema(name):
    return jsonschema.Draft202012Validator(json.loads((REPO_ROOT / "schema" / name).read_text()),
                                           format_checker=jsonschema.FormatChecker())


def test_runtime_integration_end_to_end(gateway):
    url, reg = gateway["url"], gateway["reg"]
    m = reg["invoice-reconciler"]
    tok = tokens.issue_identity(m.id, m.sha256, tokens.spiffe_id_for(m))
    tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

    # allow
    s, r = call_tool(url, tok, {"tool": "erp.read_invoices", "resource": "invoice/INV-1001", "args": {},
                                "delegator": "alice@example.com"}, traceparent=tp)
    assert (s, r["decision"], r["reasons"]) == (200, "allow", ["within_manifest"])
    assert r["trace_id"] == "4bf92f3577b34da6a3ce929d0e0e4736" and r["result"]["status"] == "ok"

    # deny
    s, r = call_tool(url, tok, {"tool": "erp.drop_ledger", "resource": "x", "args": {}, "delegator": "alice@example.com"})
    assert (s, r["decision"], r["reasons"]) == (403, "deny", ["tool_not_in_manifest"])
    s, r = call_tool(url, None, {"tool": "erp.read_invoices", "resource": "x", "args": {}, "delegator": "a@example.com"})
    assert (s, r["reasons"]) == (403, ["identity_unverified"])

    # require_approval -> approve -> allow
    action = {"tool": "erp.post_adjustment", "resource": "invoice/INV-1001", "args": {"amount_cents": -1250},
              "delegator": "alice@example.com"}
    s, r = call_tool(url, tok, action)
    assert (s, r["decision"], r["reasons"]) == (202, "require_approval", ["approval_required"])
    approval_id = r["approval_id"]
    pending = json.loads((gateway["tmp"] / "state" / "approvals" / f"{approval_id}.json").read_text())
    assert pending["action_sha256"] == tokens.action_sha256(m.id, action["tool"], action["resource"], action["args"])
    with pytest.raises(approvals.ApprovalError):
        approvals.approve(approval_id, "alice@example.com",
                          confirm_action_sha256=pending["action_sha256"])  # delegator cannot approve own request
    assert pending["args"] == action["args"]
    appr, _, _ = approvals.approve(approval_id, "bob@example.com", confirm_action_sha256=pending["action_sha256"])
    s, r = call_tool(url, tok, {**action, "approval_token": appr})
    assert (s, r["decision"], r["reasons"]) == (200, "allow", ["within_manifest"])
    # single use: the same approval does not allow again
    s, r = call_tool(url, tok, {**action, "approval_token": appr})
    assert r["decision"] != "allow"
    # approval for this action does not allow another action
    s, r = call_tool(url, tok, {**action, "args": {"amount_cents": -999999}, "approval_token": appr})
    assert r["decision"] != "allow"

    # canary
    payload, _ = run_canary(reg, url)
    assert payload["all_pass"], payload["probes"]
    assert {p["probe"] for p in payload["probes"]} >= {"unregistered_agent", "tool_not_in_manifest",
                                                        "delegator_required", "approval_required",
                                                        "approval_replay", "manifest_hash_mismatch"}
    assert payload["not_run"]

    # kill drill (throttled beforehand, so restore must put throttled back)
    from membrane.respond import playbook
    from membrane.gateway.state import read_overrides
    playbook.apply(m.id, "throttle", reason="pre-drill", actor="test", manifest=m)
    res = run_kill_drill(m, url, sla_seconds=30)
    assert res["error"] is None
    kd = res["kill_drill"]
    assert kd["within_sla"] and kd["seconds_to_denial"] is not None and kd["seconds_to_denial"] < 30
    assert read_overrides()[m.id]["mode"] == "throttled"

    # ---- evidence ----
    recs = list(evidence.read_all())  # verifies every payload_sha256
    by_kind: dict[str, list] = {}
    for rec in recs:
        by_kind.setdefault(rec["kind"], []).append(rec)
        assert rec["payload_sha256"] == sha256_hex(canonical_json(rec["payload"]))
    env_v, dec_v = _schema("evidence-record.v1.schema.json"), _schema("decision-log.v1.schema.json")
    for rec in recs:
        env_v.validate(rec)
    for rec in by_kind["decision"]:
        dec_v.validate(rec["payload"])
        assert rec["mode"] == "live" and len(rec["trace_id"]) == 32

    expected_policy = policy_sha256(policy_files(POLICY_DIR))
    assert {d["payload"]["policy_sha256"] for d in by_kind["decision"]} == {expected_policy}
    # data_sha256 of the first call: generated manifests plus empty overrides.
    gen = json.loads(gateway["data_path"].read_text())
    first = by_kind["decision"][0]["payload"]
    assert first["data_sha256"] == sha256_hex(canonical_json(
        {"membrane": {"manifests": gen["membrane"]["manifests"], "overrides": {}}}))
    assert first["otel"]["gen_ai.operation.name"] == "execute_tool"
    assert first["otel"]["gen_ai.tool.name"] == "erp.read_invoices"
    assert by_kind["decision"][0]["trace_id"] == "4bf92f3577b34da6a3ce929d0e0e4736"

    # every tool_exec has a matching allow decision
    allows = {d["payload"]["decision_id"]: d["payload"] for d in by_kind["decision"]
              if d["payload"]["decision"] == "allow"}
    assert len(by_kind["tool_exec"]) == 2
    for te in by_kind["tool_exec"]:
        assert te["mode"] == "simulated"
        d = allows[te["payload"]["decision_id"]]
        assert d["action_sha256"] == te["payload"]["action_sha256"]
    irreversible_exec = [te for te in by_kind["tool_exec"] if te["payload"]["irreversible"]]
    assert irreversible_exec and irreversible_exec[0]["payload"]["approval_id"] == approval_id

    assert {a["payload"]["approval_id"] for a in by_kind["approval"]} >= {approval_id}
    assert len(by_kind["canary"]) == 1 and by_kind["canary"][0]["payload"]["all_pass"] is True
    assert len(by_kind["kill_drill"]) == 1
    steps = [r["payload"]["step"] for r in by_kind["response"]]
    assert steps == ["throttle", "kill", "restore"]
    killed = [d for d in by_kind["decision"] if "override_killed" in d["payload"]["reasons"]]
    assert killed, "the drill must observe override_killed at the gateway"


def test_runtime_integration_rate_limit_and_throttle(gateway):
    url, reg = gateway["url"], gateway["reg"]
    m = reg["invoice-reconciler"]
    tok = tokens.issue_identity(m.id, m.sha256, tokens.spiffe_id_for(m))
    # email.send_vendor_notice is irreversible; use erp.read_purchase_orders (60/min) under throttle -> 30/min.
    from membrane.respond import playbook
    playbook.apply(m.id, "throttle", reason="t", actor="t", manifest=m)
    body = {"tool": "erp.read_purchase_orders", "resource": "po/1", "args": {}, "delegator": "a@example.com"}
    results = [call_tool(url, tok, body)[1] for _ in range(31)]
    assert all(r["decision"] == "allow" and "throttled" in r["reasons"] for r in results[:30])
    assert results[30]["decision"] == "deny" and results[30]["reasons"] == ["rate_limited"]


def test_runtime_integration_quarantine_and_restrict(gateway):
    url, reg = gateway["url"], gateway["reg"]
    m = reg["ticket-triager"]
    tok = tokens.issue_identity(m.id, m.sha256, tokens.spiffe_id_for(m))
    body = {"tool": "tickets.read", "resource": "t/1", "args": {}, "delegator": None}
    from membrane.respond import playbook
    assert call_tool(url, tok, body)[1]["decision"] == "allow"
    playbook.apply(m.id, "restrict", reason="t", actor="t", manifest=m)
    assert call_tool(url, tok, body)[1]["decision"] == "require_approval"
    playbook.apply(m.id, "quarantine", reason="t", actor="t", manifest=m)
    assert call_tool(url, tok, body)[1]["reasons"] == ["override_quarantined"]
    playbook.apply(m.id, "restore", reason="t", actor="t", manifest=m)
    assert call_tool(url, tok, body)[1]["decision"] == "allow"
