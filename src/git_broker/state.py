"""Durable single-use capabilities and intent records for the trusted broker.

The state directory must be owned by the broker account. Other processes running
as that account are trusted: SQLite is not an isolation boundary against them.
An unfinished reservation is never automatically replayed after a restart.
Each session can issue at most 256 grants over its lifetime. Grant rows are not
pruned: retention must preserve this cumulative accounting. Deployment still
requires global disk quotas and an owner-managed retention policy.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sqlite3
import stat
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import cast

from .errors import Denied
from .models import OperationPlan

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY, verifier TEXT UNIQUE NOT NULL, principal TEXT NOT NULL,
    expires INTEGER NOT NULL, remaining INTEGER NOT NULL CHECK(remaining >= 0),
    revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS grants (
    id TEXT PRIMARY KEY, verifier TEXT UNIQUE NOT NULL,
    session_id TEXT NOT NULL REFERENCES sessions(id), digest TEXT NOT NULL,
    revision TEXT NOT NULL, expires INTEGER NOT NULL, spent INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS grants_session ON grants(session_id);
CREATE TABLE IF NOT EXISTS operations (
    id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES sessions(id),
    grant_id TEXT UNIQUE NOT NULL REFERENCES grants(id), request_id TEXT NOT NULL,
    digest TEXT NOT NULL, revision TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('reserved','succeeded','failed_or_unknown')),
    result TEXT, UNIQUE(session_id, request_id)
);
CREATE TABLE IF NOT EXISTS tombstones (
    repository TEXT NOT NULL, branch TEXT NOT NULL, PRIMARY KEY(repository, branch)
);
CREATE TABLE IF NOT EXISTS events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT, time INTEGER NOT NULL,
    event TEXT NOT NULL, subject TEXT NOT NULL
);
"""


def _verifier(token: str) -> str:
    """Hash a high-entropy capability without storing its bearer value."""
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
        raise Denied("invalid capability")
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _positive(value: int, maximum: int) -> None:
    """Reject unbounded lifetimes and budgets, including boolean coercions."""
    if type(value) is not int or not 1 <= value <= maximum:
        raise Denied("invalid capability limits")


class State:
    """Serialize authorization and accounting in owner-only SQLite storage."""

    def __init__(self, root: Path) -> None:
        """Create private state or refuse unsafe existing state, without repairing it."""
        root = root.absolute()
        try:
            root.mkdir(mode=0o700, parents=False, exist_ok=True)
            info = root.lstat()
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700
            ):
                raise Denied("state directory must be private and broker-owned")
            # Resolve the platform's trusted parent aliases (for example /tmp on
            # macOS), after refusing a symlink at the state directory itself.
            self.root = root.resolve(strict=True)
            self.path = self.root / "state.sqlite3"
            descriptor = (
                os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                if not self.path.exists()
                else None
            )
            if descriptor is not None:
                os.fsync(descriptor)
                os.close(descriptor)
                directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            self._check_files()
            with self._connection() as connection:
                connection.executescript(_SCHEMA)
        except (OSError, sqlite3.Error) as error:
            raise Denied("state storage is unavailable") from error

    def _check_files(self) -> None:
        """Reject symlink, hardlink, and permission attacks on database files."""
        info = self.root.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise Denied("state directory is unsafe")
        for suffix in ("", "-journal", "-wal", "-shm"):
            path = Path(str(self.path) + suffix)
            try:
                info = path.lstat()
            except FileNotFoundError:
                if not suffix:
                    raise Denied("state storage is unavailable") from None
                continue
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise Denied("state file is unsafe")

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        """Use an immediate transaction so checks and reservations are atomic."""
        self._check_files()
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            if connection.in_transaction:
                connection.commit()
        except sqlite3.Error as error:
            if connection is not None and connection.in_transaction:
                connection.rollback()
            raise Denied("state storage operation failed") from error
        except BaseException:
            if connection is not None and connection.in_transaction:
                connection.rollback()
            raise
        finally:
            if connection is not None:
                connection.close()

    @staticmethod
    def _event(connection: sqlite3.Connection, event: str, subject: str) -> None:
        """Append a minimal audit record in the same durable transaction."""
        connection.execute(
            "INSERT INTO events(time,event,subject) VALUES(?,?,?)",
            (int(time.time()), event, subject),
        )

    @staticmethod
    def _session(connection: sqlite3.Connection, token: str) -> sqlite3.Row:
        """Authenticate a session; exhausted sessions can still inspect results."""
        row = connection.execute(
            "SELECT * FROM sessions WHERE verifier=?", (_verifier(token),)
        ).fetchone()
        if row is None or row["revoked"] or row["expires"] <= int(time.time()):
            raise Denied("session is invalid or expired")
        return cast(sqlite3.Row, row)

    @staticmethod
    def _operation(row: sqlite3.Row, *, newly_reserved: bool = False) -> dict[str, object]:
        """Return only public operation fields, never the capability verifier."""
        return {
            "id": row["id"],
            "state": row["state"],
            "result": json.loads(row["result"]) if row["result"] is not None else None,
            "newly_reserved": newly_reserved,
        }

    def issue_session(self, principal: str, ttl: int, uses: int) -> dict[str, object]:
        """Issue a bounded session from the owner-only administrative interface."""
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", principal):
            raise Denied("invalid principal")
        _positive(ttl, 86400)
        _positive(uses, 10000)
        identifier, token = secrets.token_hex(16), secrets.token_urlsafe(32)
        expires = int(time.time()) + ttl
        with self._connection() as connection:
            connection.execute(
                "INSERT INTO sessions(id,verifier,principal,expires,remaining) VALUES(?,?,?,?,?)",
                (identifier, _verifier(token), principal, expires, uses),
            )
            self._event(connection, "session_issued", identifier)
        return {"id": identifier, "token": token, "expires": expires}

    def authenticate(self, token: str) -> dict[str, object]:
        """Return the authenticated principal and remaining budget."""
        with self._connection() as connection:
            row = self._session(connection, token)
            return {key: row[key] for key in ("id", "principal", "expires", "remaining")}

    def request_grant(
        self, session_token: str, plan: OperationPlan, revision: str, ttl: int
    ) -> dict[str, object]:
        """Issue an exact-plan grant only after the caller checks standing policy."""
        _positive(ttl, 300)
        self._revision(revision)
        identifier, token = secrets.token_hex(16), secrets.token_urlsafe(32)
        with self._connection() as connection:
            session = self._session(connection, session_token)
            if session["remaining"] <= 0:
                raise Denied("session operation budget is exhausted")
            issued = connection.execute(
                "SELECT count(*) FROM grants WHERE session_id=?", (session["id"],)
            ).fetchone()[0]
            if issued >= 256:
                raise Denied("session grant issuance limit is exhausted")
            outstanding = connection.execute(
                "SELECT count(*) FROM grants WHERE session_id=? AND spent=0 AND expires>?",
                (session["id"], int(time.time())),
            ).fetchone()[0]
            if outstanding >= 64:
                raise Denied("too many outstanding grants")
            expires = min(int(time.time()) + ttl, session["expires"])
            connection.execute(
                "INSERT INTO grants(id,verifier,session_id,digest,revision,expires) "
                "VALUES(?,?,?,?,?,?)",
                (identifier, _verifier(token), session["id"], plan.digest(), revision, expires),
            )
            self._event(connection, "grant_issued", identifier)
        return {"id": identifier, "token": token, "expires": expires}

    @staticmethod
    def _revision(revision: str) -> None:
        """Require a canonical digest of the entire owner policy."""
        if not re.fullmatch(r"[0-9a-f]{64}", revision):
            raise Denied("invalid policy revision")

    def begin(
        self,
        session_token: str,
        grant_token: str,
        plan: OperationPlan,
        revision: str,
        request_id: str,
    ) -> dict[str, object]:
        """Reserve once; only a result with newly_reserved=true permits execution.

        A duplicate may retrieve its previous intent even if its grant expired or
        policy changed. It never receives permission to execute again. The session
        must still be valid. Use get_operation to inspect after a policy change.
        """
        self._revision(revision)
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", request_id):
            raise Denied("invalid idempotency key")
        digest = plan.digest()
        with self._connection() as connection:
            session = self._session(connection, session_token)
            grant = connection.execute(
                "SELECT * FROM grants WHERE verifier=?", (_verifier(grant_token),)
            ).fetchone()
            if grant is None or grant["session_id"] != session["id"]:
                raise Denied("grant is invalid")
            previous = connection.execute(
                "SELECT * FROM operations WHERE session_id=? AND request_id=?",
                (session["id"], request_id),
            ).fetchone()
            if previous is not None:
                if previous["digest"] != digest or previous["grant_id"] != grant["id"]:
                    raise Denied("idempotency key conflicts with an earlier operation")
                return self._operation(previous)
            if (
                grant["spent"]
                or grant["expires"] <= int(time.time())
                or grant["digest"] != digest
                or grant["revision"] != revision
                or session["remaining"] <= 0
            ):
                raise Denied("grant is spent, expired, or does not authorize this plan")
            if plan.operation == "push" and not plan.expected_old:
                deleted = connection.execute(
                    "SELECT 1 FROM tombstones WHERE repository=? AND branch=?",
                    (plan.repository, plan.branch),
                ).fetchone()
                if deleted is not None:
                    raise Denied("deleted branch name requires owner recovery")
            if plan.operation == "delete":
                connection.execute(
                    "INSERT OR IGNORE INTO tombstones(repository,branch) VALUES(?,?)",
                    (plan.repository, plan.branch),
                )
            identifier = secrets.token_hex(16)
            connection.execute("UPDATE grants SET spent=1 WHERE id=?", (grant["id"],))
            connection.execute(
                "UPDATE sessions SET remaining=remaining-1 WHERE id=?", (session["id"],)
            )
            connection.execute(
                "INSERT INTO operations(id,session_id,grant_id,request_id,digest,revision,state) "
                "VALUES(?,?,?,?,?,?,'reserved')",
                (identifier, session["id"], grant["id"], request_id, digest, revision),
            )
            self._event(connection, "operation_reserved", identifier)
            return {"id": identifier, "state": "reserved", "result": None, "newly_reserved": True}

    def finish(self, operation_id: str, result: dict[str, object] | None, succeeded: bool) -> None:
        """Persist a final outcome without refunding an ambiguous execution."""
        try:
            encoded = json.dumps(result, allow_nan=False, separators=(",", ":"))
        except (TypeError, ValueError) as error:
            raise Denied("invalid operation result") from error
        if len(encoded.encode()) > 65536 or type(succeeded) is not bool:
            raise Denied("invalid operation result")
        state = "succeeded" if succeeded else "failed_or_unknown"
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM operations WHERE id=?", (operation_id,)
            ).fetchone()
            if row is None:
                raise Denied("operation is unavailable")
            if row["state"] != "reserved":
                if row["state"] == state and row["result"] == encoded:
                    return
                raise Denied("operation already has a terminal outcome")
            connection.execute(
                "UPDATE operations SET state=?,result=? WHERE id=?",
                (state, encoded, operation_id),
            )
            self._event(connection, "operation_" + state, operation_id)

    def get_operation(self, session_token: str, operation_id: str) -> dict[str, object]:
        """Return caller-owned intent or result, never automatically redispatch it."""
        with self._connection() as connection:
            session = self._session(connection, session_token)
            row = connection.execute(
                "SELECT * FROM operations WHERE id=? AND session_id=?",
                (operation_id, session["id"]),
            ).fetchone()
            if row is None:
                raise Denied("operation is unavailable")
            return self._operation(row)

    def revoke(self, session_id: str) -> bool:
        """Invalidate a session and all its unspent grants via the owner interface."""
        with self._connection() as connection:
            changed = (
                connection.execute(
                    "UPDATE sessions SET revoked=1 WHERE id=? AND revoked=0", (session_id,)
                ).rowcount
                == 1
            )
            if changed:
                self._event(connection, "session_revoked", session_id)
            return changed

    def audit(self, limit: int = 100) -> list[dict[str, object]]:
        """Read recent structured events from the owner-only interface."""
        _positive(limit, 10000)
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT sequence,time,event,subject FROM events ORDER BY sequence DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(row) for row in rows]
