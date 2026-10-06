"""Persistent sliding windows for gateway processes on one trusted local filesystem."""
from __future__ import annotations

import math
import os
import sqlite3
import stat
import time
from contextlib import closing
from pathlib import Path

APPLICATION_ID = 0x4D42524C
SCHEMA_VERSION = 1


class RateLimitStateError(RuntimeError):
    """Shared rate state is unavailable or invalid. The gateway must deny."""


class SQLiteRateLimiter:
    """One atomic budget per (agent, tool), retained across process restarts.

    This adapter requires local filesystem locking. Do not use it on NFS or
    as a multi-host store. Operators must protect the database and its directory.
    """

    def __init__(self, path: str | Path, *, timeout: float = 1.0, initialize: bool = False) -> None:
        self.path = Path(path).absolute()
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("rate limit timeout must be positive and finite")
        self.timeout = timeout
        try:
            if initialize:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                os.close(fd)
            self._identity = self._file_identity()
            with closing(self._connect()) as db:
                if initialize:
                    db.execute("BEGIN IMMEDIATE")
                    db.execute("CREATE TABLE state (singleton INTEGER PRIMARY KEY CHECK(singleton = 1), "
                               "last_seen REAL NOT NULL CHECK(last_seen >= 0))")
                    db.execute("INSERT INTO state VALUES (1, 0)")
                    db.execute("CREATE TABLE hits (agent_id TEXT NOT NULL, tool TEXT NOT NULL, "
                               "admitted_at REAL NOT NULL CHECK(admitted_at >= 0))")
                    db.execute("CREATE INDEX budget_window ON hits(agent_id, tool, admitted_at)")
                    db.execute("CREATE INDEX expired_hits ON hits(admitted_at)")
                    db.execute(f"PRAGMA application_id = {APPLICATION_ID}")
                    db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                    db.commit()
                self._validate(db)
        except (OSError, sqlite3.Error, ValueError) as exc:
            raise RateLimitStateError("rate_limit_state_unavailable") from exc

    def _file_identity(self) -> tuple[int, int]:
        info = self.path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise RateLimitStateError("rate_limit_state_not_regular")
        return info.st_dev, info.st_ino

    def _connect(self) -> sqlite3.Connection:
        if self._file_identity() != self._identity:
            raise RateLimitStateError("rate_limit_state_replaced")
        # mode=rw prevents a missing store from silently becoming a new budget.
        db = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True,
                             timeout=self.timeout, isolation_level=None)
        try:
            db.execute("PRAGMA synchronous = FULL")
            return db
        except BaseException:
            db.close()
            raise

    @staticmethod
    def _validate(db: sqlite3.Connection) -> float:
        if (db.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID
                or db.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION):
            raise RateLimitStateError("rate_limit_schema_mismatch")
        row = db.execute("SELECT last_seen FROM state WHERE singleton = 1").fetchone()
        if row is None or type(row[0]) not in {int, float} or not math.isfinite(row[0]) or row[0] < 0:
            raise RateLimitStateError("rate_limit_clock_invalid")
        db.execute("SELECT agent_id, tool, admitted_at FROM hits LIMIT 0")
        return row[0]

    def admit(self, agent_id: str, tool: str, limit_per_min: int | None, now: float | None = None) -> bool:
        if limit_per_min is not None and (type(limit_per_min) is not int or limit_per_min < 0):
            raise RateLimitStateError("rate_limit_value_invalid")
        try:
            with closing(self._connect()) as db:
                db.execute("BEGIN IMMEDIATE")
                last_seen = self._validate(db)
                # Read the wall clock after the write lock, so contenders cannot reverse its order.
                instant = time.time() if now is None else now
                if (type(instant) not in {int, float} or not math.isfinite(instant)
                        or instant < last_seen):
                    raise RateLimitStateError("rate_limit_clock_regressed")
                db.execute("DELETE FROM hits WHERE admitted_at <= ?", (instant - 60,))
                count = db.execute("SELECT COUNT(*) FROM hits WHERE agent_id = ? AND tool = ?",
                                   (agent_id, tool)).fetchone()[0]
                admitted = not limit_per_min or count < limit_per_min
                if admitted and limit_per_min:
                    db.execute("INSERT INTO hits VALUES (?, ?, ?)", (agent_id, tool, instant))
                db.execute("UPDATE state SET last_seen = ? WHERE singleton = 1", (instant,))
                if self._file_identity() != self._identity:
                    raise RateLimitStateError("rate_limit_state_replaced")
                db.commit()
                return admitted
        except (OSError, sqlite3.Error, ValueError) as exc:
            raise RateLimitStateError("rate_limit_state_unavailable") from exc
