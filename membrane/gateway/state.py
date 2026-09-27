"""Runtime state on disk: the state directory, the overrides file, and file locks.

The overrides file holds the response playbook state for each agent. The
gateway reads it on every request. Writers replace it atomically: they write
a temporary file in the same directory, flush it to disk, and rename it over
the old file. A reader never sees a partial file.
"""
from __future__ import annotations

import contextlib
import fcntl
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Iterator

from ..manifest import REPO_ROOT

OVERRIDE_MODES = ("throttled", "restricted", "quarantined", "killed")


def state_dir() -> Path:
    return Path(os.environ.get("MEMBRANE_STATE_DIR", REPO_ROOT / "var" / "state"))


def overrides_path() -> Path:
    return state_dir() / "overrides.json"


def approvals_dir() -> Path:
    return state_dir() / "approvals"


def atomic_write_json(path: Path, obj: Any, mode: int = 0o644) -> None:
    """Write JSON to a temp file in the same directory, fsync, then rename."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, sort_keys=True, indent=2)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


@contextlib.contextmanager
def locked(name: str) -> Iterator[None]:
    """Hold an exclusive advisory lock on <state>/<name>.lock."""
    d = state_dir()
    d.mkdir(parents=True, exist_ok=True)
    with open(d / f"{name}.lock", "a+") as fh:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


def read_overrides() -> dict:
    """Return the overrides map. A missing file means no overrides.

    A file that exists but does not parse raises ValueError. The gateway
    treats that as a policy error and denies (fail closed).
    """
    path = overrides_path()
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: overrides must be a JSON object")
    for agent_id, entry in data.items():
        if not isinstance(entry, dict) or entry.get("mode") not in OVERRIDE_MODES:
            raise ValueError(f"{path}: invalid override for {agent_id!r}")
    return data


def write_overrides(data: dict) -> None:
    atomic_write_json(overrides_path(), data)
