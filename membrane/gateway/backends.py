"""Bounded, read-only tools. Only actual execution attempts write live evidence."""
from __future__ import annotations

import os
import stat
import uuid
from pathlib import Path
from typing import Protocol

from .. import evidence
from ..manifest import canonical_json, sha256_hex
from .tokens import action_sha256

MAX_DIRECTORY_ENTRIES = 512
MAX_DOCUMENTS = 128
MAX_DOCUMENT_BYTES = 256 * 1024
MAX_CORPUS_BYTES = 2 * 1024 * 1024
MAX_EXCERPT_CHARS = 1024
RESOURCE = "kb.public-internal"
SOURCE = "membrane.gateway.kb_directory"


class BackendRequestError(ValueError):
    """The backend cannot execute this action. No tool has run."""


class ToolBackend(Protocol):
    def validate_request(self, *, tool: str, resource, args: dict, irreversible) -> None: ...

    def execute(self, *, decision_id: str, agent_id: str, tool: str, resource, args: dict,
                action_hash: str, irreversible, approval_id, trace_id: str) -> dict: ...


def _signature(info: os.stat_result) -> tuple:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _open_root(root: Path) -> int:
    """Walk each component without following links. The caller owns the descriptor."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(root.anchor, flags)
    try:
        for part in root.parts[1:]:
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read_document(root_fd: int, name: str, remaining: int) -> tuple[bytes, tuple]:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                 dir_fd=root_fd)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError("document_not_regular_or_linked")
        limit = min(MAX_DOCUMENT_BYTES, remaining)
        if before.st_size > limit:
            raise ValueError("corpus_size_limit")
        raw = stream.read(limit + 1)
        if len(raw) > limit or _signature(before) != _signature(os.fstat(stream.fileno())):
            raise ValueError("document_changed_or_too_large")
        return raw, _signature(before)


class DirectoryKBBackend:
    """Search top-level UTF-8 .md and .txt files under one operator-selected root."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(os.path.abspath(root))
        try:
            fd = _open_root(self.root)
            try:
                info = os.fstat(fd)
                self._root_identity = (info.st_dev, info.st_ino)
            finally:
                os.close(fd)
        except OSError as exc:
            raise ValueError("kb root must be an existing directory without symlink components") from exc

    def validate_request(self, *, tool: str, resource, args: dict, irreversible) -> None:
        if tool != "kb.search" or resource != RESOURCE or irreversible is not False:
            raise BackendRequestError("unsupported_backend_action")
        if not isinstance(args, dict) or set(args) - {"query", "limit"}:
            raise BackendRequestError("unsupported_backend_args")
        query = args.get("query")
        limit = args.get("limit", 5)
        if not isinstance(query, str) or not query.strip() or len(query) > 256:
            raise BackendRequestError("invalid_query")
        if type(limit) is not int or not 1 <= limit <= 20:
            raise BackendRequestError("invalid_limit")

    def _search(self, args: dict) -> dict:
        fd = _open_root(self.root)
        try:
            before = os.fstat(fd)
            if (before.st_dev, before.st_ino) != self._root_identity:
                raise ValueError("root_changed")
            names = []
            with os.scandir(fd) as entries:
                for count, entry in enumerate(entries, 1):
                    if count > MAX_DIRECTORY_ENTRIES:
                        raise ValueError("directory_entry_limit")
                    if Path(entry.name).suffix.lower() in {".md", ".txt"}:
                        names.append(entry.name)
            if not names or len(names) > MAX_DOCUMENTS:
                raise ValueError("document_count_limit")
            matches, signatures, documents = [], {}, []
            remaining = MAX_CORPUS_BYTES
            query = args["query"].lower()
            for name in sorted(names):
                raw, signature = _read_document(fd, name, remaining)
                remaining -= len(raw)
                content = raw.decode("utf-8", errors="strict")
                signatures[name] = signature
                digest = sha256_hex(raw)
                documents.append({"document": name, "sha256": digest})
                # Literal case-insensitive search. No regular expression or code execution.
                index = content.lower().find(query)
                if index >= 0:
                    start = max(0, index - MAX_EXCERPT_CHARS // 4)
                    matches.append({"document": name, "sha256": digest,
                                    "excerpt": content[start:start + MAX_EXCERPT_CHARS]})
            for name, signature in signatures.items():
                if _signature(os.stat(name, dir_fd=fd, follow_symlinks=False)) != signature:
                    raise ValueError("document_changed")
            check_fd = _open_root(self.root)
            try:
                if _signature(os.fstat(check_fd)) != _signature(before):
                    raise ValueError("root_changed")
            finally:
                os.close(check_fd)
            limit = args.get("limit", 5)
            return {"matches": matches[:limit], "scanned_files": len(names),
                    "truncated": len(matches) > limit,
                    "corpus_sha256": sha256_hex(canonical_json(documents))}
        finally:
            os.close(fd)

    def execute(self, *, decision_id: str, agent_id: str, tool: str, resource, args: dict,
                action_hash: str, irreversible, approval_id, trace_id: str) -> dict:
        self.validate_request(tool=tool, resource=resource, args=args, irreversible=irreversible)
        if action_hash != action_sha256(agent_id, tool, resource, args):
            raise BackendRequestError("action_hash_mismatch")
        exec_id = str(uuid.uuid4())
        payload = {"exec_id": exec_id, "decision_id": decision_id, "agent_id": agent_id,
                   "tool": tool, "resource": resource, "action_sha256": action_hash,
                   "irreversible": irreversible, "approval_id": approval_id,
                   "executed_at": evidence.now_rfc3339(), "backend_id": "kb-directory-v1"}
        try:
            output = self._search(args)
        except (OSError, ValueError):
            payload.update(result="error", error="kb_read_failed")
            result = {"status": "error", "exec_id": exec_id, "error": "kb_read_failed"}
        else:
            payload.update(result="ok", output_sha256=sha256_hex(canonical_json(output)),
                           corpus_sha256=output["corpus_sha256"], scanned_files=output["scanned_files"])
            result = {"status": "ok", "exec_id": exec_id, "output": output}
        # Withhold both successful and failed results if the execution record cannot be written.
        evidence.emit("tool_exec", SOURCE, payload, mode="live", agent_id=agent_id, trace_id=trace_id)
        return result
