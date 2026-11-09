"""Versioned single-grant policy state for the trusted local service harness."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from contextlib import contextmanager

from agent_auth.policy import AuthorizationError, validate_permissions


class PolicyStateError(ValueError):
    pass


class PolicyConflict(PolicyStateError):
    """The update's expected version is no longer current."""


class PolicyState:
    """SQLite transaction per read/update; no in-memory allow cache.

    The caller owns the database directory. This does not protect against a
    privileged local writer, rollback of the entire file or storage loss.
    """
    def __init__(self, path, agent_id, policy_id, initial_policy):
        self.path = str(Path(path).resolve())
        initialize = not Path(self.path).exists()
        self.agent_id, self.policy_id = agent_id, policy_id
        permissions = validate_permissions(initial_policy["permissions"])
        with self._connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("CREATE TABLE IF NOT EXISTS policy (singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
                       "agent_id TEXT NOT NULL, policy_id TEXT NOT NULL, version INTEGER NOT NULL CHECK(version>0), "
                       "permissions TEXT NOT NULL)")
            if initialize:
                db.execute("INSERT INTO policy VALUES (1, ?, ?, 1, ?)",
                           (agent_id, policy_id, json.dumps(permissions)))
        self.snapshot()  # Fail startup if an existing record is invalid or misbound.

    @contextmanager
    def _connect(self):
        db = sqlite3.connect(self.path, timeout=2)
        try:
            db.execute("PRAGMA synchronous=FULL")
            with db:
                yield db
        finally:
            db.close()

    def _decode(self, row):
        if row is None or row[0] != self.agent_id or row[1] != self.policy_id:
            raise PolicyStateError("stored policy identity mismatch or missing record")
        if type(row[2]) is not int or row[2] < 1:
            raise PolicyStateError("invalid stored version")
        try:
            permissions = validate_permissions(json.loads(row[3]))
        except (ValueError, TypeError, AuthorizationError) as exc:
            raise PolicyStateError("invalid stored permissions") from exc
        return {"version": row[2], "permissions": permissions}

    def snapshot(self):
        with self._connect() as db:
            row = db.execute("SELECT agent_id, policy_id, version, permissions FROM policy WHERE singleton=1").fetchone()
        return self._decode(row)

    def replace(self, policy, *, expected_version):
        permissions = validate_permissions(policy["permissions"])
        if type(expected_version) is not int or expected_version < 1:
            raise PolicyStateError("positive integer expected_version required")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT agent_id, policy_id, version, permissions FROM policy WHERE singleton=1").fetchone()
            current = self._decode(row)
            if current["version"] != expected_version:
                raise PolicyConflict("stale policy version")
            next_version = expected_version + 1
            db.execute("UPDATE policy SET version=?, permissions=? WHERE singleton=1",
                       (next_version, json.dumps(permissions)))
        return next_version  # Acknowledge only after the transaction commits.
