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
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

import jsonschema

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


# Source custody is a bounded snapshot. It does not change the writer API.
MAX_BYTES = 16 * 1024 * 1024
MAX_FILES = 256


class CustodyError(ValueError):
    """The source files cannot form a complete custody observation."""


def configured_dirs() -> list[Path]:
    """Read an explicit JSON list of absolute paths, or use the evidence dir."""
    raw = os.environ.get("MEMBRANE_EVIDENCE_DIRS")
    if raw is None:
        return [evidence_dir().absolute()]
    try:
        values = json.loads(raw)
    except ValueError as exc:
        raise CustodyError("MEMBRANE_EVIDENCE_DIRS must be a JSON list of absolute paths") from exc
    if (not isinstance(values, list) or not values or
            any(not isinstance(p, str) or not p or not Path(p).is_absolute() for p in values)):
        raise CustodyError("MEMBRANE_EVIDENCE_DIRS must be a nonempty JSON list of absolute paths")
    return [Path(p) for p in values]


def _file_state(st) -> tuple:
    return st.st_dev, st.st_ino, st.st_mode, st.st_size, st.st_mtime_ns, st.st_ctime_ns


def _read_file(path: Path, remaining: int) -> tuple[bytes, tuple]:
    """Read a regular file without following a final symlink or blocking on a FIFO."""
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
    with os.fdopen(os.open(path, flags), "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise CustodyError(f"not a regular evidence file: {path}")
        if before.st_size > remaining:
            raise CustodyError("source bundle exceeds the size limit")
        raw = stream.read(remaining + 1)
        after = os.fstat(stream.fileno())
    if len(raw) > remaining:
        raise CustodyError("source bundle exceeds the size limit")
    if _file_state(before) != _file_state(after) or len(raw) != before.st_size:
        raise CustodyError(f"evidence file changed during the snapshot: {path}")
    return raw, _file_state(after)


def _unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CustodyError("duplicate JSON key in evidence")
        result[key] = value
    return result


def _reject_constant(value):
    raise CustodyError("non-finite JSON number in evidence")


def _custody_records(raw: bytes, path: Path, validator) -> tuple[str, list[dict]]:
    if not raw or not raw.endswith(b"\n"):
        raise CustodyError(f"empty or incomplete evidence file: {path}")
    text = raw.decode("utf-8")
    records = []
    for number, line in enumerate(text.split("\n"), 1):
        if not line.strip():
            continue
        record = json.loads(line, object_pairs_hook=_unique_keys, parse_constant=_reject_constant)
        if not validator.is_valid(record):
            raise CustodyError(f"invalid evidence envelope: {path}:{number}")
        if (sha256_hex(canonical_json(record["payload"])) != record["payload_sha256"] or
                record_sha256(record) != record["record_sha256"]):
            raise CustodyError(f"evidence hash mismatch: {path}:{number}")
        records.append({key: record[key] for key in
                        ("id", "kind", "mode", "payload_sha256", "record_sha256")})
    if not records:
        raise CustodyError(f"no records in evidence file: {path}")
    return text, records


def _source_files(directories: list[Path]) -> list[Path]:
    paths = []
    for directory in directories:
        found = False
        for path in directory.glob("*.jsonl"):
            paths.append(path)
            found = True
            if len(paths) > MAX_FILES:
                raise CustodyError("source bundle exceeds the file count limit")
        if not found:
            raise CustodyError(f"no evidence files in directory: {directory}")
    return sorted(paths)


def snapshot_bundle(directories: list[Path]) -> dict:
    """Retain all top-level JSONL bytes in the selected dirs, or fail as one unit.

    This checks for observed changes while files are read. It is not a filesystem
    transaction. Stop writers, or use a closed log segment, before collection.
    """
    try:
        if not directories:
            raise CustodyError("no source evidence directories")
        roots = sorted({Path(d).resolve(strict=True) for d in directories})
        if any(not d.is_dir() for d in roots):
            raise CustodyError("source evidence path is not a directory")
        root_ids = {d: (d.stat().st_dev, d.stat().st_ino) for d in roots}
        paths = _source_files(roots)
        schema = json.loads((REPO_ROOT / "schema/evidence-record.v1.schema.json").read_text())
        validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
        artifacts, states, by_id = [], {}, {}
        total_bytes = 0
        for path in paths:
            raw, states[path] = _read_file(path, MAX_BYTES - total_bytes)
            total_bytes += len(raw)
            text, records = _custody_records(raw, path, validator)
            for record in records:
                prior = by_id.get(record["id"])
                if prior is not None and prior != record["record_sha256"]:
                    raise CustodyError(f"conflicting record id: {record['id']}")
                by_id[record["id"]] = record["record_sha256"]
            artifacts.append({"name": path.name, "source_path": str(path), "size_bytes": len(raw),
                              "sha256": sha256_hex(raw), "content_utf8": text, "records": records})
        if _source_files(roots) != paths:
            raise CustodyError("evidence file set changed during the snapshot")
        for root, identity in root_ids.items():
            st = root.stat()
            if (st.st_dev, st.st_ino) != identity:
                raise CustodyError("evidence directory changed during the snapshot")
        for path, state in states.items():
            if _file_state(path.lstat()) != state:
                raise CustodyError(f"evidence file changed during the snapshot: {path}")
        return {"schema": "membrane.source-bundle.v1", "source_directories": [str(d) for d in roots],
                "file_count": len(artifacts), "total_bytes": total_bytes,
                "unique_record_count": len(by_id),
                "record_modes": sorted({r["mode"] for a in artifacts for r in a["records"]}),
                "artifacts": artifacts}
    except CustodyError:
        raise
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
        # Do not put source contents into the failure observation.
        raise CustodyError(f"cannot snapshot source evidence ({type(exc).__name__})") from exc
