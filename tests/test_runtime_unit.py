"""Unit tests for the runtime part: tokens, action hash, generators, drift, overrides, gateway fail closed."""
from __future__ import annotations

import json
import os
import stat
import threading
import time
from pathlib import Path

import pytest

from membrane import evidence
from membrane.gateway import tokens
from membrane.gateway.server import Gateway, GatewayConfig, RateLimiter, parse_traceparent
from membrane.gateway.state import read_overrides, write_overrides
from membrane.gen import diff, write
from membrane.gen.generate import generate, opa_data, registry_sha256
from membrane.manifest import REPO_ROOT, load_registry
from membrane.respond import playbook


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("MEMBRANE_EVIDENCE_DIR", str(tmp_path / "ev"))
    monkeypatch.setenv("MEMBRANE_STATE_DIR", str(tmp_path / "state"))
    return tmp_path


@pytest.fixture(scope="module")
def reg():
    return load_registry()


# ---- tokens ---------------------------------------------------------------

def test_runtime_identity_token_roundtrip(env):
    t = tokens.issue_identity("kb-reader", "a" * 64, "spiffe://example.org/ns/agents/sa/kb-reader", ttl=60)
    claims = tokens.verify_identity(t)
    assert claims["agent_id"] == "kb-reader" and claims["manifest_sha256"] == "a" * 64
    assert set(claims) == set(tokens.IDENTITY_FIELDS)


def test_runtime_key_file_created_0600(env):
    tokens.issue_identity("kb-reader", "a" * 64, "spiffe://x/ns/a/sa/b", ttl=60)
    mode = stat.S_IMODE(os.stat(env / "state" / tokens.IDENTITY_KEY).st_mode)
    assert mode == 0o600


def test_runtime_token_expired(env):
    t = tokens.issue_identity("kb-reader", "a" * 64, "spiffe://x/ns/a/sa/b", ttl=-1)
    with pytest.raises(tokens.TokenError, match="expired"):
        tokens.verify_identity(t)


def test_runtime_token_tampered_payload(env):
    t = tokens.issue_identity("kb-reader", "a" * 64, "spiffe://x/ns/a/sa/b", ttl=60)
    body, mac = t.split(".")
    obj = json.loads(tokens._b64d(body))
    obj["agent_id"] = "invoice-reconciler"
    forged = tokens._b64e(json.dumps(obj).encode()) + "." + mac
    with pytest.raises(tokens.TokenError, match="signature"):
        tokens.verify_identity(forged)


def test_runtime_token_wrong_key_class(env):
    """An approval token must not verify as an identity token (separate keys)."""
    t = tokens.issue_approval("00000000-0000-4000-8000-000000000000", "b" * 64, "bob@example.com",
                              int(time.time()) + 60)
    with pytest.raises(tokens.TokenError):
        tokens.verify_identity(t)
    assert tokens.verify_approval(t)["approver"] == "bob@example.com"


@pytest.mark.parametrize("bad", ["", "abc", "a.b.c", "!!!.???"])
def test_runtime_token_malformed(env, bad):
    with pytest.raises(tokens.TokenError):
        tokens.verify_identity(bad)


def test_runtime_spiffe_id(reg):
    assert tokens.spiffe_id_for(reg["invoice-reconciler"]) == \
        "spiffe://example.org/ns/agents-finance/sa/invoice-reconciler"


# ---- action hash ----------------------------------------------------------

def test_runtime_action_hash_stable():
    a = tokens.action_sha256("x", "t", "r", {"b": 2, "a": 1})
    b = tokens.action_sha256("x", "t", "r", {"a": 1, "b": 2})
    assert a == b and len(a) == 64
    # Pinned value guards against accidental change to the canonical form.
    assert a == tokens.sha256_hex(b'{"agent_id":"x","args":{"a":1,"b":2},"resource":"r","tool":"t"}')


def test_runtime_action_hash_sensitive():
    base = tokens.action_sha256("x", "t", "r", {"a": 1})
    assert base != tokens.action_sha256("x", "t", "r", {"a": 2})
    assert base != tokens.action_sha256("y", "t", "r", {"a": 1})
    assert base != tokens.action_sha256("x", "t", "r2", {"a": 1})


# ---- generators -----------------------------------------------------------

def test_runtime_gen_deterministic(reg):
    a = generate(reg)
    b = generate(dict(reversed(list(reg.items()))))
    assert a == b
    for rel, data in a.items():
        assert data.endswith(b"\n"), rel


def test_runtime_gen_opa_shape(reg):
    d = opa_data(reg)["membrane"]["manifests"]
    assert set(opa_data(reg)) == {"membrane"} and set(opa_data(reg)["membrane"]) == {"manifests"}
    ir = d["invoice-reconciler"]
    assert ir["sha256"] == reg["invoice-reconciler"].sha256
    assert ir["tools"]["erp.post_adjustment"] == {"scope": "finance:write", "irreversible": True, "rate_limit_per_min": 5}
    assert d["canary"]["canary"] is True and d["canary"]["approval_required_for"] == ["all"]


def test_runtime_gen_spire_and_k8s(reg):
    out = generate(reg)
    entries = json.loads(out["spire/entries.json"])["entries"]
    assert len(entries) == sum(1 for m in reg.values() if m.spec["runtime"]["type"] == "k8s")
    e = next(x for x in entries if x["hint"] == "kb-reader")
    assert e["selectors"] == [{"type": "k8s", "value": "ns:agents"}, {"type": "k8s", "value": "sa:kb-reader"}]
    assert "k8s/kb-reader.cilium-egress.yaml" not in out  # empty egress: no Cilium file
    assert "k8s/invoice-reconciler.cilium-egress.yaml" in out
    import yaml
    cnp = yaml.safe_load(out["k8s/invoice-reconciler.cilium-egress.yaml"])
    fqdns = [x["matchName"] for x in cnp["spec"]["egress"][1]["toFQDNs"]]
    assert fqdns == sorted(reg["invoice-reconciler"].spec["egress"])
    assert cnp["spec"]["egress"][0]["toPorts"][0]["rules"]["dns"]
    cm = yaml.safe_load(out["k8s/membrane-registry.configmap.yaml"])
    assert set(cm["data"]) == {k for k, m in reg.items() if m.spec["status"] == "active"}
    assert {k: json.loads(v)["sha256"] for k, v in cm["data"].items()} == {k: reg[k].sha256 for k in cm["data"]}


def test_runtime_gen_drift(reg, tmp_path):
    out_dir = tmp_path / "gen"
    expected = generate(reg)
    assert {r for r, _ in diff(out_dir, expected)} == set(expected)  # all missing
    write(out_dir, expected)
    assert diff(out_dir, expected) == []
    (out_dir / "opa/data.json").write_text("{}\n")
    (out_dir / "k8s/ghost-agent.networkpolicy.yaml").write_text("x: 1\n")
    problems = dict(diff(out_dir, expected))
    assert problems == {"opa/data.json": "content differs",
                        "k8s/ghost-agent.networkpolicy.yaml": "not produced by the registry (stale file)"}
    removed = write(out_dir, expected)
    assert removed == ["k8s/ghost-agent.networkpolicy.yaml"] and diff(out_dir, expected) == []


def test_runtime_committed_output_matches_registry(reg):
    """The committed out/generated must match the registry (same as `membrane gen --check`)."""
    out_dir = REPO_ROOT / "out" / "generated"
    if not out_dir.exists():
        pytest.skip("out/generated not generated yet")
    assert diff(out_dir, generate(reg)) == []


def test_runtime_registry_hash_order_free(reg):
    assert registry_sha256(reg) == registry_sha256(dict(reversed(list(reg.items()))))


# ---- overrides and respond -----------------------------------------------

def test_runtime_overrides_atomic_write(env):
    write_overrides({"kb-reader": {"mode": "killed", "set_at": "t", "reason": "r"}})
    assert read_overrides()["kb-reader"]["mode"] == "killed"
    leftovers = [p.name for p in (env / "state").iterdir() if p.name.endswith(".tmp")]
    assert leftovers == []


def test_runtime_overrides_concurrent_writers_never_tear(env):
    stop = threading.Event()
    errors = []

    def writer(i):
        n = 0
        while not stop.is_set():
            write_overrides({f"a{i}": {"mode": "throttled", "set_at": str(n), "reason": "x" * 2000}})
            n += 1

    def reader():
        while not stop.is_set():
            try:
                read_overrides()
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(3)] + [threading.Thread(target=reader)]
    for t in threads:
        t.start()
    time.sleep(0.5)
    stop.set()
    for t in threads:
        t.join()
    assert errors == []


def test_runtime_overrides_corrupt_raises(env):
    (env / "state").mkdir(parents=True, exist_ok=True)
    (env / "state" / "overrides.json").write_text('{"kb-reader": {"mode": "nap"}}')
    with pytest.raises(ValueError):
        read_overrides()


def test_runtime_respond_steps(env, reg):
    m = reg["invoice-reconciler"]
    payload, path = playbook.apply(m.id, "kill", reason="test", actor="tester", manifest=m)
    assert read_overrides()[m.id]["mode"] == "killed"
    assert path and path.name == "response.jsonl"
    assert all(a["dry_run"] for a in payload["actions"] if a["system"] != "gateway")
    assert any("--replicas=0" in a["command"] for a in payload["actions"])
    assert any(a["command"].startswith("spire-server entry delete") for a in payload["actions"])
    playbook.apply(m.id, "restore", reason="test", actor="tester", manifest=m)
    assert m.id not in read_overrides()
    before = read_overrides()
    p2, path2 = playbook.apply(m.id, "quarantine", reason="t", actor="t", manifest=m, dry_run=True)
    assert path2 is None and read_overrides() == before and p2["effective_at"] is None
    recs = list(evidence.read_all(kinds={"response"}))
    assert [r["payload"]["step"] for r in recs] == ["kill", "restore"]


# ---- gateway pieces without OPA ------------------------------------------

def test_runtime_traceparent():
    tid = "4bf92f3577b34da6a3ce929d0e0e4736"
    assert parse_traceparent(f"00-{tid}-00f067aa0ba902b7-01") == tid
    for bad in [None, "", "garbage", f"00-{'0' * 32}-00f067aa0ba902b7-01", f"ff-{tid}-00f067aa0ba902b7-01",
                f"00-{tid.upper()}-00f067aa0ba902b7-01", f"00-{tid}-{'0' * 16}-01"]:
        out = parse_traceparent(bad)
        assert len(out) == 32 and out != tid


def test_runtime_rate_limiter():
    rl = RateLimiter()
    assert [rl.admit("a", "t", 2, now=0.0) for _ in range(3)] == [True, True, False]
    assert rl.admit("a", "t2", 2, now=0.0)  # separate key
    assert rl.admit("a", "t", 2, now=60.0)  # window moved


def _call(gw, token, body):
    return gw.handle_call(json.dumps(body).encode(), f"Bearer {token}", None)


def test_runtime_gateway_fails_closed_missing_data(env, reg):
    m = reg["kb-reader"]
    gw = Gateway(GatewayConfig(policy_dir=REPO_ROOT / "policy" / "runtime", data_path=env / "nope.json"))
    tok = tokens.issue_identity(m.id, m.sha256, tokens.spiffe_id_for(m))
    status, body = _call(gw, tok, {"tool": "kb.search", "resource": "q", "args": {}, "delegator": "a@example.com"})
    assert status == 403 and body["reasons"] == ["policy_error"]
    recs = list(evidence.read_all(kinds={"decision"}))
    assert len(recs) == 1 and recs[0]["payload"]["reasons"] == ["policy_error"]


def test_runtime_gateway_fails_closed_bad_opa(env, reg, tmp_path):
    m = reg["kb-reader"]
    data = tmp_path / "data.json"
    data.write_text(json.dumps(opa_data(reg)))
    pol = tmp_path / "pol"
    pol.mkdir()
    (pol / "authz.rego").write_text("package membrane.authz\nresult := {\"decision\": \"allow\", \"reasons\": [\"x\"]}\n")
    gw = Gateway(GatewayConfig(policy_dir=pol, data_path=data, opa_bin=str(tmp_path / "no-such-opa")))
    tok = tokens.issue_identity(m.id, m.sha256, tokens.spiffe_id_for(m))
    status, body = _call(gw, tok, {"tool": "kb.search", "resource": "q", "args": {}, "delegator": "a@example.com"})
    assert status == 403 and body["reasons"] == ["policy_error"]


def test_runtime_gateway_fails_closed_bad_body(env):
    gw = Gateway(GatewayConfig(policy_dir=REPO_ROOT / "policy" / "runtime", data_path=env / "nope.json"))
    status, body = gw.handle_call(b"not json", None, None)
    assert status == 403 and body["reasons"] == ["policy_error"]
    rec = next(evidence.read_all(kinds={"decision"}))
    assert rec["payload"]["tool"] is None and rec["payload"]["action_sha256"] is None


def test_duplicate_json_keys_rejected():
    import pytest
    from membrane.gateway.server import _no_duplicate_keys
    import json
    with pytest.raises(ValueError):
        json.loads('{"tool":"a","tool":"b"}', object_pairs_hook=_no_duplicate_keys)
    assert json.loads('{"tool":"a"}', object_pairs_hook=_no_duplicate_keys) == {"tool": "a"}


# ------------------------------------------------------------------ R-08: approver sees the args

def _pending(**kw):
    from membrane.gateway import approvals, tokens
    a = dict(agent_id="invoice-reconciler", tool="erp.post_adjustment", resource="invoice/INV-1001",
             args={"amount_cents": -1250, "memo": "dup charge"}, delegator="alice@example.com")
    a.update(kw)
    h = tokens.action_sha256(a["agent_id"], a["tool"], a["resource"], a["args"])
    return approvals.create_pending(action_sha256=h, decision_id="d", trace_id="0" * 32, **a), h


def test_r08_pending_stores_full_action(env):
    from membrane.gateway import approvals
    rec, h = _pending()
    stored = approvals.load(rec["approval_id"])
    assert stored["args"] == {"amount_cents": -1250, "memo": "dup charge"}
    assert (stored["resource"], stored["delegator"], stored["action_sha256"]) == ("invoice/INV-1001", "alice@example.com", h)


def test_r08_approve_needs_matching_confirm_hash(env):
    from membrane.gateway import approvals
    rec, h = _pending()
    with pytest.raises(approvals.ApprovalError, match="confirm"):
        approvals.approve(rec["approval_id"], "bob@example.com", confirm_action_sha256="0" * 64)
    with pytest.raises(approvals.ApprovalError, match="confirm"):
        approvals.approve(rec["approval_id"], "bob@example.com", confirm_action_sha256="")
    assert approvals.load(rec["approval_id"])["status"] == "pending"
    token, payload, path = approvals.approve(rec["approval_id"], "bob@example.com", confirm_action_sha256=h)
    assert payload["args"] == {"amount_cents": -1250, "memo": "dup charge"}
    assert payload["delegator"] == "alice@example.com" and payload["resource"] == "invoice/INV-1001"
    from membrane import evidence
    ev = [r for r in evidence.read_all(kinds={"approval"})]
    assert ev[-1]["payload"]["args"] == payload["args"]


def test_r08_approve_refuses_tampered_pending_args(env):
    import json as _json
    from membrane.gateway import approvals
    from membrane.gateway.state import approvals_dir
    rec, h = _pending()
    path = approvals_dir() / f"{rec['approval_id']}.json"
    doc = _json.loads(path.read_text())
    doc["args"]["amount_cents"] = -1  # what the approver would see no longer matches the hash
    path.write_text(_json.dumps(doc))
    with pytest.raises(approvals.ApprovalError, match="does not match"):
        approvals.approve(rec["approval_id"], "bob@example.com", confirm_action_sha256=h)


def test_r08_cli_shows_action_and_does_not_sign_without_confirm(env, capsys):
    from membrane.cli import main
    rec, h = _pending()
    code = main(["approve", rec["approval_id"], "--approver", "bob@example.com"])
    out = capsys.readouterr()
    assert code != 0
    text = out.out + out.err
    for s in ("invoice-reconciler", "erp.post_adjustment", "invoice/INV-1001", "alice@example.com",
              '"amount_cents":-1250', h):
        assert s in text
    from membrane.gateway import approvals
    assert approvals.load(rec["approval_id"])["status"] == "pending"
    code = main(["approve", rec["approval_id"], "--approver", "bob@example.com", "--confirm-action-sha256", h])
    out = capsys.readouterr()
    assert code == 0 and out.out.strip().count(".") == 1  # the token is on stdout
    assert approvals.load(rec["approval_id"])["status"] == "approved"


# ------------------------------------------------------------------ R-01: exact action binding

@pytest.mark.parametrize("args_text", [
    '{"amount":1e400}', '{"amount":-1e400}', '{"amount":NaN}', '{"amount":Infinity}', '{"amount":-Infinity}',
    '{"amount":0.100000000000000000009}', '{"amount":9007199254740993.0}', '{"n":[1,{"x":1e999}]}',
])
def test_r01_inexact_or_non_finite_numbers_are_rejected(env, args_text):
    gw = Gateway(GatewayConfig(policy_dir=REPO_ROOT / "policy" / "runtime", data_path=env / "nope.json"))
    raw = ('{"tool":"erp.post_adjustment","resource":"r","args":' + args_text + '}').encode()
    status, body = gw.handle_call(raw, None, None)
    assert status == 403 and body["reasons"] == ["policy_error"]
    rec = list(evidence.read_all(kinds={"decision"}))[-1]
    assert rec["payload"]["action_sha256"] is None  # rejected at parse, before any hash


@pytest.mark.parametrize("args_text", ['{"amount":0.1}', '{"amount":10.5}', '{"amount":-1250}', '{"amount":1e300}'])
def test_r01_exact_numbers_are_accepted(env, args_text):
    gw = Gateway(GatewayConfig(policy_dir=REPO_ROOT / "policy" / "runtime", data_path=env / "nope.json"))
    raw = ('{"tool":"erp.post_adjustment","resource":"r","args":' + args_text + '}').encode()
    gw.handle_call(raw, None, None)
    rec = list(evidence.read_all(kinds={"decision"}))[-1]
    assert rec["payload"]["action_sha256"]  # parsed and hashed; policy then decides


def test_r01_distinct_literals_never_share_a_hash():
    from membrane.gateway.server import parse_request_json
    from membrane.gateway.tokens import action_sha256
    seen = {}
    for text in ('{"a":0.1}', '{"a":10}', '{"a":10.0}', '{"a":"10"}', '{"a":1e300}', '{"a":-0.0}', '{"a":0.0}'):
        h = action_sha256("x", "t", "r", parse_request_json(text.encode()))
        assert h not in seen, (text, seen.get(h))
        seen[h] = text


def test_r01_canonical_json_refuses_non_finite():
    from membrane.manifest import canonical_json
    with pytest.raises(ValueError):
        canonical_json({"a": float("nan")})
    with pytest.raises(ValueError):
        canonical_json({"a": float("inf")})
