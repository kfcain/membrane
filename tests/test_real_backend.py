"""The directory adapter reads real files and never returns an unaudited result."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading

import pytest

from membrane import evidence
from membrane.gateway import approvals, tokens
from membrane.gateway.client import call_tool
from membrane.gateway.server import Gateway, GatewayConfig, make_server
from membrane.gen.generate import opa_data
from membrane.manifest import REPO_ROOT, canonical_json, load_registry, sha256_hex


@pytest.fixture
def corpus(tmp_path, monkeypatch):
    monkeypatch.setenv("MEMBRANE_EVIDENCE_DIR", str(tmp_path / "ev"))
    monkeypatch.setenv("MEMBRANE_STATE_DIR", str(tmp_path / "state"))
    root = tmp_path / "kb"
    root.mkdir()
    (root / "policy.md").write_text("Access policy: Review access each month.\n", encoding="utf-8")
    (root / "procedure.txt").write_text("Review the access list.\n", encoding="utf-8")
    return root


def execute(backend, args=None, **override):
    args = args if args is not None else {"query": "review", "limit": 1}
    fields = dict(decision_id="decision-test", agent_id="kb-reader", tool="kb.search",
                  resource="kb.public-internal", args=args, irreversible=False, approval_id=None,
                  trace_id="1" * 32)
    fields.update(override)
    fields.setdefault("action_hash", tokens.action_sha256(fields["agent_id"], fields["tool"],
                                                         fields["resource"], fields["args"]))
    return backend.execute(**fields)


def test_real_search_and_evidence_bind_exact_input_and_output(corpus):
    from membrane.gateway.backends import DirectoryKBBackend
    result = execute(DirectoryKBBackend(corpus))
    assert result["status"] == "ok"
    output = result["output"]
    assert output["scanned_files"] == 2 and output["truncated"] is True
    assert output["matches"] == [{"document": "policy.md",
        "sha256": sha256_hex((corpus / "policy.md").read_bytes()),
        "excerpt": "Access policy: Review access each month.\n"}]
    record, = evidence.read_all(kinds={"tool_exec"})
    assert record["mode"] == "live" and record["source"] == "membrane.gateway.kb_directory"
    payload = record["payload"]
    assert payload["result"] == "ok" and payload["exec_id"] == result["exec_id"]
    assert payload["output_sha256"] == sha256_hex(canonical_json(output))
    assert payload["action_sha256"] == tokens.action_sha256("kb-reader", "kb.search", "kb.public-internal",
                                                          {"query": "review", "limit": 1})
    assert "Review access" not in json.dumps(record)


@pytest.mark.parametrize("change", [
    {"tool": "tickets.read"}, {"resource": "../secret"}, {"resource": None},
    {"args": {}}, {"args": {"query": " "}}, {"args": {"query": "a" * 257}},
    {"args": {"query": 3}}, {"args": {"query": "a", "limit": True}},
    {"args": {"query": "a", "limit": 0}}, {"args": {"query": "a", "limit": 21}},
    {"args": {"query": "a", "path": "/etc/passwd"}},
])
def test_unsupported_requests_do_not_execute(corpus, change):
    from membrane.gateway.backends import BackendRequestError, DirectoryKBBackend
    with pytest.raises(BackendRequestError):
        execute(DirectoryKBBackend(corpus), **change)
    assert list(evidence.read_all(kinds={"tool_exec"})) == []


def test_hash_mismatch_cannot_execute(corpus):
    from membrane.gateway.backends import BackendRequestError, DirectoryKBBackend
    with pytest.raises(BackendRequestError, match="action_hash_mismatch"):
        execute(DirectoryKBBackend(corpus), action_hash="0" * 64)
    assert list(evidence.read_all(kinds={"tool_exec"})) == []


@pytest.mark.parametrize("fault", ["symlink", "fifo", "invalid_utf8", "missing", "empty", "oversize", "changed"])
def test_read_failures_are_live_error_attempts(corpus, monkeypatch, fault):
    from membrane.gateway import backends
    backend = backends.DirectoryKBBackend(corpus)
    if fault == "symlink":
        (corpus / "linked.md").symlink_to(corpus / "policy.md")
    elif fault == "fifo":
        os.mkfifo(corpus / "pipe.txt")
    elif fault == "invalid_utf8":
        (corpus / "bad.txt").write_bytes(b"\xff")
    elif fault == "missing":
        corpus.rename(corpus.with_name("moved"))
    elif fault == "empty":
        for path in corpus.iterdir():
            path.unlink()
    elif fault == "oversize":
        monkeypatch.setattr(backends, "MAX_DOCUMENT_BYTES", 1)
    else:
        original = backends._read_document
        def changed(root_fd, name, remaining):
            result = original(root_fd, name, remaining)
            (corpus / name).write_text("changed")
            return result
        monkeypatch.setattr(backends, "_read_document", changed)
    result = execute(backend)
    assert result["status"] == "error" and "output" not in result
    record, = evidence.read_all(kinds={"tool_exec"})
    assert record["mode"] == "live" and record["payload"]["result"] == "error"
    assert "output_sha256" not in record["payload"]


def test_search_is_literal_and_checks_the_whole_corpus(corpus):
    from membrane.gateway.backends import DirectoryKBBackend
    result = execute(DirectoryKBBackend(corpus), args={"query": ".*"})
    assert result["output"]["matches"] == []
    assert result["output"]["scanned_files"] == 2


@pytest.fixture
def live_gateway(corpus, tmp_path):
    from membrane.gateway.backends import DirectoryKBBackend
    if shutil.which("opa") is None:
        pytest.skip("opa binary not found")
    registry = load_registry()
    data_path = tmp_path / "data.json"
    data_path.write_bytes(canonical_json(opa_data(registry)))
    backend = DirectoryKBBackend(corpus)
    srv = make_server("127.0.0.1", 0, Gateway(GatewayConfig(data_path=data_path, opa_url=""), backend=backend))
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    agent = registry["kb-reader"]
    token = tokens.issue_identity(agent.id, agent.sha256, tokens.spiffe_id_for(agent))
    yield {"url": f"http://127.0.0.1:{srv.server_port}", "token": token, "backend": backend,
           "agent": agent, "corpus": corpus, "registry": registry}
    srv.shutdown()
    srv.server_close()
    thread.join(timeout=2)


ACTION = {"tool": "kb.search", "resource": "kb.public-internal", "args": {"query": "review"},
          "delegator": "alice@example.com"}


def test_http_policy_execution_and_failure_contract(live_gateway, monkeypatch):
    g = live_gateway
    status, reply = call_tool(g["url"], g["token"], ACTION)
    assert status == 200 and reply["decision"] == "allow" and reply["result"]["status"] == "ok"
    assert len(reply["result"]["output"]["matches"]) == 2
    records = list(evidence.read_all())
    decision = next(r for r in records if r["kind"] == "decision")
    execution = next(r for r in records if r["kind"] == "tool_exec")
    assert decision["payload"]["decision_id"] == execution["payload"]["decision_id"] == reply["decision_id"]
    assert decision["payload"]["action_sha256"] == execution["payload"]["action_sha256"]

    def must_not_execute(**kw):
        pytest.fail("denied call reached the backend")
    with monkeypatch.context() as patch:
        patch.setattr(g["backend"], "execute", must_not_execute)
        assert call_tool(g["url"], None, ACTION)[0] == 403
        assert call_tool(g["url"], g["token"], {**ACTION, "tool": "tickets.read"})[0] == 403
        assert call_tool(g["url"], g["token"], {**ACTION, "args": {"query": "x", "path": "../secret"}})[0] == 403
        assert call_tool(g["url"], g["token"], {**ACTION, "resource": "../secret"})[0] == 403
    assert len(list(evidence.read_all(kinds={"tool_exec"}))) == 1

    g["corpus"].rename(g["corpus"].with_name("moved"))
    status, reply = call_tool(g["url"], g["token"], ACTION)
    assert status == 502 and reply["decision"] == "allow" and reply["result"]["status"] == "error"
    decisions = list(evidence.read_all(kinds={"decision"}))
    assert len(decisions) == 6
    assert list(evidence.read_all(kinds={"tool_exec"}))[-1]["payload"]["result"] == "error"


def test_approval_and_replay_with_real_backend(live_gateway):
    from membrane.respond import playbook
    g = live_gateway
    playbook.apply("kb-reader", "restrict", reason="test", actor="test", manifest=g["agent"])
    status, pending = call_tool(g["url"], g["token"], ACTION)
    assert status == 202 and list(evidence.read_all(kinds={"tool_exec"})) == []
    token, _, _ = approvals.approve(pending["approval_id"], "bob@example.com",
                                   confirm_action_sha256=pending["action_sha256"])
    approved = {**ACTION, "approval_token": token}
    assert call_tool(g["url"], g["token"], approved)[0] == 200
    assert call_tool(g["url"], g["token"], approved)[0] == 403
    record, = evidence.read_all(kinds={"tool_exec"})
    assert record["payload"]["approval_id"] == pending["approval_id"]


def test_audit_failure_withholds_result(live_gateway, monkeypatch):
    g = live_gateway
    original = evidence.emit
    def fail_execution_record(kind, *args, **kw):
        if kind == "tool_exec":
            raise OSError("disk failure")
        return original(kind, *args, **kw)
    monkeypatch.setattr(evidence, "emit", fail_execution_record)
    status, reply = call_tool(g["url"], g["token"], ACTION)
    assert status == 500 and reply["decision"] == "deny" and "result" not in reply
    assert len(list(evidence.read_all(kinds={"decision"}))) == 1


def test_live_execution_counts_without_nonlive_override(live_gateway):
    from datetime import datetime, timezone
    from membrane.checks.catalog import load_catalog
    from membrane.checks.engine import evaluate_check, load_evidence
    g = live_gateway
    assert call_tool(g["url"], g["token"], ACTION)[0] == 200
    records = [item.record for item in load_evidence([evidence.evidence_dir()])]
    check = next(c for c in load_catalog().checks if c.id == "AGT-AU-01")
    result = evaluate_check(check, records, g["registry"], datetime.now(timezone.utc), False)
    assert result["status"] == "PASS" and result["examined"] == 1
    assert result["record_counts"]["tool_exec"]["eligible"] == 1


@pytest.mark.parametrize("fault", ["root_replaced", "root_symlink", "ancestor_symlink", "hardlink",
                                 "document_count", "entry_count", "total_size", "late_bad_file"])
def test_corpus_boundary_failures_return_no_partial_output(corpus, monkeypatch, fault):
    from membrane.gateway import backends
    backend = backends.DirectoryKBBackend(corpus)
    if fault in {"root_replaced", "root_symlink"}:
        moved = corpus.with_name("moved")
        corpus.rename(moved)
        if fault == "root_symlink":
            corpus.symlink_to(moved, target_is_directory=True)
        else:
            corpus.mkdir()
            (corpus / "new.txt").write_text("review")
    elif fault == "ancestor_symlink":
        moved = corpus.parent.with_name(corpus.parent.name + "-moved")
        corpus.parent.rename(moved)
        corpus.parent.symlink_to(moved, target_is_directory=True)
    elif fault == "hardlink":
        os.link(corpus / "policy.md", corpus / "linked.md")
    elif fault == "document_count":
        monkeypatch.setattr(backends, "MAX_DOCUMENTS", 1)
    elif fault == "entry_count":
        monkeypatch.setattr(backends, "MAX_DIRECTORY_ENTRIES", 1)
    elif fault == "total_size":
        monkeypatch.setattr(backends, "MAX_CORPUS_BYTES", 50)
    else:
        (corpus / "z-invalid.txt").write_bytes(b"\xff")
    result = execute(backend)
    assert result["status"] == "error" and "output" not in result
    record, = evidence.read_all(kinds={"tool_exec"})
    assert record["payload"]["result"] == "error"


def test_invalid_request_does_not_create_pending_approval(live_gateway):
    from membrane.respond import playbook
    from membrane.gateway.state import state_dir
    g = live_gateway
    playbook.apply("kb-reader", "restrict", reason="test", actor="test", manifest=g["agent"])
    status, reply = call_tool(g["url"], g["token"], {**ACTION, "args": {"query": "x", "path": "secret"}})
    assert status == 403 and reply["reasons"] == ["backend_request_invalid"]
    assert not list((state_dir() / "approvals").glob("*.json"))
    assert not list(evidence.read_all(kinds={"tool_exec"}))


@pytest.mark.parametrize("options", [["--backend", "kb-directory"], ["--kb-root", "/tmp"],
                                    ["--backend", "kb-directory", "--kb-root", "/no-such-membrane-kb"]])
def test_cli_refuses_bad_backend_configuration(options):
    process = subprocess.run([sys.executable, "-m", "membrane.cli", "gateway", "serve", *options],
                             capture_output=True, text=True, timeout=5, cwd=REPO_ROOT)
    assert process.returncode == 2 and "FAIL" in process.stderr
