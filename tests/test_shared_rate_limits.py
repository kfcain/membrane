"""Real SQLite transactions enforce one budget across gateway processes."""
import json
import multiprocessing
import sqlite3
import threading
from concurrent.futures import ProcessPoolExecutor

import pytest

from membrane import evidence
from membrane.gateway import approvals, tokens
from membrane.gateway.client import call_tool
from membrane.gateway.server import Gateway, GatewayConfig, make_server
from membrane.gen.generate import opa_data
from membrane.manifest import canonical_json, load_registry


def _admit_in_process(path):
    from membrane.gateway.rate_limits import SQLiteRateLimiter
    return SQLiteRateLimiter(path).admit("agent", "tool", 7, now=100)


def test_processes_share_one_atomic_budget(tmp_path):
    from membrane.gateway.rate_limits import SQLiteRateLimiter
    path = tmp_path / "rate.db"
    SQLiteRateLimiter(path, initialize=True)
    with ProcessPoolExecutor(max_workers=4, mp_context=multiprocessing.get_context("spawn")) as pool:
        results = list(pool.map(_admit_in_process, [str(path)] * 20))
    assert sum(results) == 7
    assert not SQLiteRateLimiter(path).admit("agent", "tool", 7, now=159.999)
    assert SQLiteRateLimiter(path).admit("agent", "tool", 7, now=160)


def test_restart_keys_and_throttle_use_retained_window(tmp_path):
    from membrane.gateway.rate_limits import SQLiteRateLimiter
    path = tmp_path / "rate.db"
    first = SQLiteRateLimiter(path, initialize=True)
    assert first.admit("a", "x", 4, now=100)
    assert first.admit("a", "x", 4, now=101)
    again = SQLiteRateLimiter(path)
    assert not again.admit("a", "x", 2, now=102)
    assert again.admit("a", "y", 1, now=102)
    assert again.admit("b", "x", 1, now=102)
    assert again.admit("a", "x", 2, now=160)


@pytest.mark.parametrize("fault", ["missing", "replaced", "corrupt", "schema", "clock", "locked"])
def test_failed_shared_state_never_grants_capacity(tmp_path, fault):
    from membrane.gateway.rate_limits import RateLimitStateError, SQLiteRateLimiter
    path = tmp_path / "rate.db"
    limiter = SQLiteRateLimiter(path, timeout=0.05, initialize=True)
    assert limiter.admit("a", "x", 2, now=100)
    lock = None
    if fault == "missing":
        path.unlink()
    elif fault == "replaced":
        path.rename(path.with_suffix(".old"))
        SQLiteRateLimiter(path, initialize=True)
    elif fault == "corrupt":
        path.write_bytes(b"not sqlite")
    elif fault == "schema":
        with sqlite3.connect(path) as db:
            db.execute("DROP TABLE hits")
    elif fault == "locked":
        lock = sqlite3.connect(path)
        lock.execute("BEGIN EXCLUSIVE")
    try:
        with pytest.raises(RateLimitStateError):
            limiter.admit("a", "x", 2, now=99 if fault == "clock" else 101)
    finally:
        if lock:
            lock.close()
    if fault == "missing":
        assert not path.exists()


@pytest.mark.parametrize("limit", [-1, True, 1.5, "3"])
def test_malformed_limits_fail_closed(tmp_path, limit):
    from membrane.gateway.rate_limits import RateLimitStateError, SQLiteRateLimiter
    with pytest.raises(RateLimitStateError):
        SQLiteRateLimiter(tmp_path / "rate.db", initialize=True).admit("a", "x", limit, now=100)


def test_unknown_existing_database_is_not_reinitialized(tmp_path):
    from membrane.gateway.rate_limits import RateLimitStateError, SQLiteRateLimiter
    path = tmp_path / "foreign.db"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE foreign_data(value TEXT)")
    before = path.read_bytes()
    with pytest.raises(RateLimitStateError):
        SQLiteRateLimiter(path)
    assert path.read_bytes() == before


def test_two_http_gateways_enforce_shared_state_and_fail_closed(tmp_path, monkeypatch):
    monkeypatch.setenv("MEMBRANE_EVIDENCE_DIR", str(tmp_path / "evidence"))
    monkeypatch.setenv("MEMBRANE_STATE_DIR", str(tmp_path / "state"))
    registry = load_registry()
    data = opa_data(registry)
    data["membrane"]["manifests"]["kb-reader"]["tools"]["kb.search"]["rate_limit_per_min"] = 2
    data_path = tmp_path / "data.json"
    data_path.write_bytes(canonical_json(data))
    database = tmp_path / "rate.db"
    from membrane.gateway.rate_limits import SQLiteRateLimiter
    SQLiteRateLimiter(database, initialize=True)
    config = GatewayConfig(data_path=data_path, opa_url="", rate_limit_db=database)
    servers = [make_server("127.0.0.1", 0, Gateway(config)) for _ in range(2)]
    threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in servers]
    for t in threads:
        t.start()
    urls = [f"http://127.0.0.1:{s.server_port}" for s in servers]
    agent = registry["kb-reader"]
    token = tokens.issue_identity(agent.id, agent.sha256, tokens.spiffe_id_for(agent))
    action = {"tool": "kb.search", "resource": "kb.public-internal", "args": {"query": "review"},
              "delegator": "alice@example.com"}
    try:
        assert call_tool(urls[0], token, action)[0] == 200
        assert call_tool(urls[1], token, action)[0] == 200
        assert call_tool(urls[0], token, action)[1]["reasons"] == ["rate_limited"]
        assert call_tool(urls[1], token, action)[1]["reasons"] == ["rate_limited"]
        database.unlink()
        status, result = call_tool(urls[1], token, action)
        assert status == 403 and result["reasons"] == ["policy_error"]
        assert len(list(evidence.read_all(kinds={"tool_exec"}))) == 2
        records = list(evidence.read_all(kinds={"decision"}))
        assert len(records) == 5 and all(r["mode"] == "live" for r in records)
        assert records[-1]["payload"]["decision"] == "deny"
    finally:
        for s in servers:
            s.shutdown()
            s.server_close()
        for t in threads:
            t.join(timeout=2)


def test_startup_never_recreates_missing_state_or_resets_existing_state(tmp_path):
    from membrane.gateway.rate_limits import RateLimitStateError, SQLiteRateLimiter
    path = tmp_path / "rate.db"
    with pytest.raises(RateLimitStateError):
        SQLiteRateLimiter(path)
    assert not path.exists()
    limiter = SQLiteRateLimiter(path, initialize=True)
    assert limiter.admit("a", "x", 1, now=100)
    with pytest.raises(RateLimitStateError):
        SQLiteRateLimiter(path, initialize=True)
    assert not SQLiteRateLimiter(path).admit("a", "x", 1, now=101)
    path.unlink()
    with pytest.raises(RateLimitStateError):
        SQLiteRateLimiter(path)
    assert not path.exists()


def test_state_failure_does_not_consume_approval(tmp_path, monkeypatch):
    from membrane.gateway.rate_limits import SQLiteRateLimiter
    from membrane.respond import playbook
    monkeypatch.setenv("MEMBRANE_EVIDENCE_DIR", str(tmp_path / "evidence"))
    monkeypatch.setenv("MEMBRANE_STATE_DIR", str(tmp_path / "state"))
    registry = load_registry()
    data = tmp_path / "data.json"
    data.write_bytes(canonical_json(opa_data(registry)))
    path = tmp_path / "rate.db"
    SQLiteRateLimiter(path, initialize=True)
    gateway = Gateway(GatewayConfig(data_path=data, opa_url="", rate_limit_db=path))
    gateway.limiter.timeout = 0.01
    agent = registry["kb-reader"]
    token = tokens.issue_identity(agent.id, agent.sha256, tokens.spiffe_id_for(agent))
    playbook.apply(agent.id, "restrict", reason="test", actor="test", manifest=agent)
    body = {"tool": "kb.search", "resource": "kb.public-internal", "args": {"query": "review"},
            "delegator": "alice@example.com"}
    def call():
        return gateway.handle_call(json.dumps(body).encode(), f"Bearer {token}", None)
    status, pending = call()
    assert status == 202
    approval, _, _ = approvals.approve(pending["approval_id"], "bob@example.com",
                                      confirm_action_sha256=pending["action_sha256"])
    body["approval_token"] = approval
    with sqlite3.connect(path) as blocker:
        blocker.execute("BEGIN EXCLUSIVE")
        status, reply = call()
    assert status == 403 and reply["reasons"] == ["policy_error"]
    assert approvals.consume(pending["approval_id"], "test-still-unused")
    assert not list(evidence.read_all(kinds={"tool_exec"}))
