"""Source custody must retain exact bytes and fail on incomplete inputs."""
from __future__ import annotations

import hashlib
import json

import pytest

from membrane import evidence
from membrane.manifest import canonical_json


def sample(tmp_path, *, mode="live"):
    directory = tmp_path / "evidence"
    record = evidence.make_record("canary", "test", {"message": "line one\nline two é"}, mode=mode)
    evidence.append(record, directory=directory)
    return directory, record


def test_snapshot_retains_exact_bytes_and_all_files(tmp_path):
    from membrane.evidence import snapshot_bundle
    directory, record = sample(tmp_path)
    path = directory / "canary.jsonl"
    raw = path.read_bytes().replace(b"\n", b"\r\n")
    path.write_bytes(raw)
    evidence.emit("generation", "test", {"outputs": {}}, mode="live", directory=directory)
    bundle = snapshot_bundle([directory])
    artifacts = {a["name"]: a for a in bundle["artifacts"]}
    assert set(artifacts) == {"canary.jsonl", "generation.jsonl"}
    artifact = artifacts[path.name]
    assert artifact["content_utf8"].encode("utf-8") == raw
    assert artifact["sha256"] == hashlib.sha256(raw).hexdigest()
    assert artifact["size_bytes"] == len(raw)
    assert artifact["records"] == [{k: record[k] for k in
                                    ("id", "kind", "mode", "payload_sha256", "record_sha256")}]
    manifest = {k: v for k, v in bundle.items() if k != "artifacts"}
    assert manifest["unique_record_count"] == 2
    assert bundle == snapshot_bundle([directory])


@pytest.mark.parametrize("damage", ["payload", "envelope", "mode", "hash", "json", "array", "duplicate", "partial"])
def test_bad_record_stops_bundle(tmp_path, damage):
    from membrane.evidence import CustodyError, snapshot_bundle
    directory, rec = sample(tmp_path)
    if damage == "payload":
        rec["payload"]["message"] = "changed"
    elif damage == "envelope":
        rec["source"] = "changed"
    elif damage == "mode":
        rec["mode"] = "unknown"
        evidence.seal(rec)
    elif damage == "hash":
        del rec["record_sha256"]
    text = json.dumps(rec) + "\n"
    if damage == "json":
        text = "{\n"
    elif damage == "array":
        text = "[]\n"
    elif damage == "duplicate":
        text = '{"mode":"fixture",' + text[1:]
    elif damage == "partial":
        text = text.rstrip("\n")
    (directory / "canary.jsonl").write_text(text)
    with pytest.raises(CustodyError):
        snapshot_bundle([directory])


def test_conflicting_ids_fail_but_identical_copies_are_retained(tmp_path):
    from membrane.evidence import CustodyError, snapshot_bundle
    directory, record = sample(tmp_path)
    other = tmp_path / "other"
    evidence.append(record, directory=other)
    bundle = snapshot_bundle([other, directory])
    assert len(bundle["artifacts"]) == 2
    assert bundle["unique_record_count"] == 1
    record["source"] = "different"
    evidence.seal(record)
    (other / "canary.jsonl").write_bytes(canonical_json(record) + b"\n")
    with pytest.raises(CustodyError, match="conflicting record id"):
        snapshot_bundle([directory, other])


@pytest.mark.parametrize("case", ["missing", "empty_dir", "empty_file", "symlink", "fifo"])
def test_missing_empty_or_special_files_fail(tmp_path, case):
    from membrane.evidence import CustodyError, snapshot_bundle
    import os
    directory = tmp_path / "evidence"
    if case != "missing":
        directory.mkdir()
    path = directory / "canary.jsonl"
    if case == "empty_file":
        path.write_text("")
    elif case == "symlink":
        source, _ = sample(tmp_path / "outside")
        path.symlink_to(source / path.name)
    elif case == "fifo":
        os.mkfifo(path)
    with pytest.raises(CustodyError):
        snapshot_bundle([directory])


def test_total_size_and_file_count_limits_fail(tmp_path, monkeypatch):
    from membrane import evidence as custody
    directory, _ = sample(tmp_path)
    monkeypatch.setattr(custody, "MAX_BYTES", 5)
    with pytest.raises(custody.CustodyError, match="size limit"):
        custody.snapshot_bundle([directory])
    monkeypatch.setattr(custody, "MAX_BYTES", 16 * 1024 * 1024)
    monkeypatch.setattr(custody, "MAX_FILES", 0)
    with pytest.raises(custody.CustodyError, match="file count"):
        custody.snapshot_bundle([directory])


@pytest.mark.parametrize("change", ["append", "add", "replace"])
def test_changed_file_set_or_bytes_fail(tmp_path, monkeypatch, change):
    from membrane import evidence as custody
    directory, record = sample(tmp_path)
    original = custody._read_file

    def changed(path, remaining):
        result = original(path, remaining)
        if change == "append":
            evidence.append(record, directory=directory)
        elif change == "add":
            evidence.append(record, filename="new.jsonl", directory=directory)
        else:
            raw = path.read_bytes()
            path.unlink()
            path.write_bytes(raw)
        return result

    monkeypatch.setattr(custody, "_read_file", changed)
    with pytest.raises(custody.CustodyError, match="changed"):
        custody.snapshot_bundle([directory])


def test_directory_configuration_is_explicit_and_fails_closed(tmp_path, monkeypatch):
    from membrane.evidence import CustodyError, configured_dirs
    monkeypatch.setenv("MEMBRANE_EVIDENCE_DIRS", json.dumps([str(tmp_path)]))
    assert configured_dirs() == [tmp_path]
    for bad in ("", "not-json", "[]", '[""]', '[1]', '{}', '["relative"]'):
        monkeypatch.setenv("MEMBRANE_EVIDENCE_DIRS", bad)
        with pytest.raises(CustodyError):
            configured_dirs()
