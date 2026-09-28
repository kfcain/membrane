"""Evidence records. Every component writes records through this module.

A record is one JSON object on one line in an append-only JSONL file.
The envelope schema is schema/evidence-record.v1.schema.json.

Rules:
- mode is "live", "simulated", or "fixture". Only "live" records can
  produce a PASS in the check engine unless the operator passes the
  explicit demo flag. See docs/CONTRACTS.md.
- payload_sha256 is the SHA-256 of the canonical JSON of payload.
- record_sha256 is the SHA-256 of the canonical JSON of the whole record
  without the record_sha256 field. It covers the envelope (id, kind, source,
  mode, collected_at, agent_id, trace_id) and payload_sha256.
- read_all verifies both hashes and fails closed on a mismatch or absence.
  The hashes detect accidental or naive edits. They do not stop a writer
  that recomputes the hashes. Beacon provides custody.
- Writers never rewrite or delete a line.
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .manifest import REPO_ROOT, canonical_json, sha256_hex

SCHEMA = "membrane.evidence.v1"
KINDS = {
    "decision",       # gateway authorization decision (payload: decision-log.v1)
    "approval",       # human approval issued for one action hash
    "tool_exec",      # tool backend executed an action
    "canary",         # negative test run result
    "response",       # response playbook step (throttle/restrict/quarantine/kill)
    "kill_drill",     # measured time from kill decision to full denial
    "generation",     # generator run: manifests hash -> outputs hash
    "inventory",      # observed running agent workloads
    "egress_flow",    # network flow observations for agent workloads
    "secret_scan",    # model-provider credential scan results
    "pipeline_run",   # CI/CD run for an agent deploy (gate results)
    "check_result",   # check engine output
}
MODES = {"live", "simulated", "fixture"}


def evidence_dir() -> Path:
    return Path(os.environ.get("MEMBRANE_EVIDENCE_DIR", REPO_ROOT / "var" / "evidence"))


def now_rfc3339() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def record_sha256(record: dict) -> str:
    """SHA-256 of the canonical JSON of the record without its record_sha256 field."""
    return sha256_hex(canonical_json({k: v for k, v in record.items() if k != "record_sha256"}))


def seal(record: dict) -> dict:
    """Set payload_sha256 and record_sha256 from the current content. Writers only."""
    record["payload_sha256"] = sha256_hex(canonical_json(record["payload"]))
    record["record_sha256"] = record_sha256(record)
    return record


def make_record(kind: str, source: str, payload: dict, *, mode: str, agent_id: str | None = None,
                trace_id: str | None = None, collected_at: str | None = None,
                record_id: str | None = None) -> dict:
    if kind not in KINDS:
        raise ValueError(f"unknown evidence kind {kind!r}")
    if mode not in MODES:
        raise ValueError(f"unknown mode {mode!r}")
    return seal({
        "schema": SCHEMA,
        "id": record_id or str(uuid.uuid4()),
        "kind": kind,
        "source": source,
        "mode": mode,
        "collected_at": collected_at or now_rfc3339(),
        "agent_id": agent_id,
        "trace_id": trace_id,
        "payload": payload,
    })


def append(record: dict, filename: str | None = None, directory: Path | None = None) -> Path:
    """Append one record. Default file is <kind>.jsonl in the evidence dir."""
    directory = Path(directory or evidence_dir())
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / (filename or f"{record['kind']}.jsonl")
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")
    return path


def emit(kind: str, source: str, payload: dict, *, mode: str, **kw: Any) -> dict:
    directory = kw.pop("directory", None)
    rec = make_record(kind, source, payload, mode=mode, **kw)
    append(rec, directory=directory)
    return rec


def read_all(directory: Path | None = None, kinds: set[str] | None = None) -> Iterator[dict]:
    """Yield every record in every *.jsonl file. Verify both hashes; fail closed."""
    directory = Path(directory or evidence_dir())
    if not directory.exists():
        return
    for path in sorted(directory.glob("*.jsonl")):
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            rec = json.loads(line)
            if rec.get("schema") != SCHEMA:
                raise ValueError(f"{path}:{n}: unexpected schema {rec.get('schema')!r}")
            if sha256_hex(canonical_json(rec["payload"])) != rec["payload_sha256"]:
                raise ValueError(f"{path}:{n}: payload_sha256 mismatch (record {rec['id']})")
            if not isinstance(rec.get("record_sha256"), str):
                raise ValueError(f"{path}:{n}: record_sha256 missing (record {rec.get('id')})")
            if record_sha256(rec) != rec["record_sha256"]:
                raise ValueError(f"{path}:{n}: record_sha256 mismatch (record {rec.get('id')})")
            if kinds is None or rec["kind"] in kinds:
                yield rec
