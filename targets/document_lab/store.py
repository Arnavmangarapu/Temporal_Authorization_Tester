"""Per-application SQLite data and the intentionally selectable authorization defect."""

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import hmac
import json
import secrets
import sqlite3
from threading import RLock
from uuid import uuid4

from document_lab.settings import LabSettings


class LabError(Exception):
    def __init__(self, status: int, detail: str):
        self.status = status
        self.detail = detail
        super().__init__(detail)


@dataclass(frozen=True)
class Session:
    user_id: str
    snapshot: frozenset[str]
    write_snapshot: frozenset[str]
    role: str


def password_digest(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)


class LabStore:
    """One connection per app; a lock makes each operation/reset atomic.

    No sleeping tasks perform revocation. Delayed access is calculated from the
    injected monotonic clock, so enforcement also works after a quiet period.
    """

    def __init__(self, settings: LabSettings, clock: Callable[[], float]):
        self.settings = settings
        self.clock = clock
        self.lock = RLock()
        self.db = sqlite3.connect(":memory:", check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys = ON")
        self.db.executescript("""
            CREATE TABLE users (
                id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL,
                salt BLOB NOT NULL, password_hash BLOB NOT NULL,
                role TEXT NOT NULL, previous_role TEXT, role_changed_at REAL
            );
            CREATE TABLE sessions (
                token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
                snapshot TEXT NOT NULL
            );
            CREATE TABLE documents (
                id TEXT PRIMARY KEY, owner_id TEXT NOT NULL REFERENCES users(id),
                content TEXT NOT NULL, access_model TEXT NOT NULL,
                previous_owner_id TEXT, transferred_at REAL
            );
            CREATE TABLE shares (
                document_id TEXT NOT NULL REFERENCES documents(id),
                subject_id TEXT NOT NULL REFERENCES users(id),
                permission TEXT NOT NULL,
                revoked_at REAL,
                PRIMARY KEY (document_id, subject_id)
            );
        """)
        self.seed_credentials = []
        for username in ("alice", "bob", "charlie"):
            salt = secrets.token_bytes(16)
            password = getattr(settings, f"{username}_password").get_secret_value()
            self.seed_credentials.append((username, salt, password_digest(password, salt)))
        self.reset()

    def close(self) -> None:
        with self.lock:
            self.db.close()

    def reset(self) -> None:
        with self.lock, self.db:
            for table in ("sessions", "shares", "documents", "users"):
                self.db.execute(f"DELETE FROM {table}")
            for username, salt, digest in self.seed_credentials:
                self.db.execute(
                    "INSERT INTO users VALUES (?, ?, ?, ?, ?, NULL, NULL)",
                    (str(uuid4()), username, salt, digest, "admin" if username == "alice" else "viewer"),
                )

    def login(self, username: str, password: str) -> dict:
        with self.lock, self.db:
            user = self.db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            if user is None or not hmac.compare_digest(
                user["password_hash"], password_digest(password, user["salt"])
            ):
                raise LabError(401, "Invalid credentials")
            shares = list(self.db.execute(
                "SELECT document_id, permission FROM shares WHERE subject_id = ? AND revoked_at IS NULL",
                (user["id"],),
            ))
            owned = [row[0] for row in self.db.execute("SELECT id FROM documents WHERE owner_id = ?", (user["id"],))]
            snapshot = {"read": [*owned, *(row[0] for row in shares)],
                        "write": [*owned, *(row[0] for row in shares if row[1] == "write")], "role": user["role"]}
            token = secrets.token_urlsafe(32)
            self.db.execute(
                "INSERT INTO sessions VALUES (?, ?, ?)",
                (self._token_hash(token), user["id"], json.dumps(snapshot)),
            )
            return {"access_token": token, "token_type": "bearer", "user_id": user["id"], "username": username}

    @staticmethod
    def _token_hash(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def _session(self, token: str) -> Session:
        row = self.db.execute(
            "SELECT * FROM sessions WHERE token_hash = ?", (self._token_hash(token),)
        ).fetchone()
        if row is None:
            raise LabError(401, "Invalid session")
        snapshot = json.loads(row["snapshot"])
        return Session(row["user_id"], frozenset(snapshot["read"]), frozenset(snapshot["write"]), snapshot["role"])

    def _document(self, document_id: str) -> sqlite3.Row:
        document = self.db.execute("SELECT * FROM documents WHERE id = ?", (document_id,)).fetchone()
        if document is None:
            raise LabError(404, "Document not found")
        return document

    def _owned_document(self, document_id: str, owner_id: str) -> sqlite3.Row:
        document = self._document(document_id)
        if document["owner_id"] != owner_id:
            raise LabError(403, "Only the owner can manage sharing")
        return document

    def create_document(self, token: str, content: str, access_model: str = "sharing") -> dict:
        with self.lock, self.db:
            session = self._session(token)
            document_id = str(uuid4())
            self.db.execute("INSERT INTO documents VALUES (?, ?, ?, ?, NULL, NULL)", (document_id, session.user_id, content, access_model))
            return {"id": document_id, "owner_id": session.user_id, "content": content}

    def grant(self, token: str, document_id: str, subject_id: str, permission: str = "read") -> None:
        with self.lock, self.db:
            session = self._session(token)
            self._owned_document(document_id, session.user_id)
            if self.db.execute("SELECT id FROM users WHERE id = ?", (subject_id,)).fetchone() is None:
                raise LabError(404, "Subject not found")
            self.db.execute("""
                INSERT INTO shares VALUES (?, ?, ?, NULL)
                ON CONFLICT(document_id, subject_id) DO UPDATE SET revoked_at = NULL, permission = excluded.permission
            """, (document_id, subject_id, permission))

    def revoke(self, token: str, document_id: str, subject_id: str) -> None:
        with self.lock, self.db:
            session = self._session(token)
            self._owned_document(document_id, session.user_id)
            if self.db.execute(
                "SELECT subject_id FROM shares WHERE document_id = ? AND subject_id = ?",
                (document_id, subject_id),
            ).fetchone() is None:
                raise LabError(404, "Share not found")
            # Repeated revocations must not postpone an already running deadline.
            self.db.execute("""
                UPDATE shares SET revoked_at = COALESCE(revoked_at, ?)
                WHERE document_id = ? AND subject_id = ?
            """, (self.clock(), document_id, subject_id))

    def _allowed(self, session: Session, document: sqlite3.Row, action: str) -> bool:
        user = self.db.execute("SELECT * FROM users WHERE id = ?", (session.user_id,)).fetchone()
        if document["owner_id"] == session.user_id or user["role"] == "admin":
            return True
        allowed = False
        model = document["access_model"]
        if model == "sharing":
            share = self.db.execute("SELECT * FROM shares WHERE document_id = ? AND subject_id = ?", (document["id"], session.user_id)).fetchone()
            if share is not None and (action == "read" or share["permission"] == "write"):
                allowed = share["revoked_at"] is None or (
                    self.settings.mode == "delayed" and self.clock() < share["revoked_at"] + self.settings.revocation_delay_seconds)
        elif model == "role":
            allowed = user["role"] == "editor" or (
                self.settings.mode == "delayed" and user["previous_role"] == "editor" and user["role_changed_at"] is not None
                and self.clock() < user["role_changed_at"] + self.settings.revocation_delay_seconds)
        elif model == "ownership":
            allowed = self.settings.mode == "delayed" and document["previous_owner_id"] == session.user_id and document["transferred_at"] is not None and self.clock() < document["transferred_at"] + self.settings.revocation_delay_seconds
        if self.settings.mode == "stale_session":
            snapshot = session.snapshot if action == "read" else session.write_snapshot
            allowed |= document["id"] in snapshot or (model == "role" and session.role == "editor")
        return bool(allowed)

    @staticmethod
    def _output(document) -> dict:
        return {key: document[key] for key in ("id", "owner_id", "content")}

    def read(self, token: str, document_id: str) -> dict:
        with self.lock:
            session = self._session(token)
            document = self._document(document_id)
            if not self._allowed(session, document, "read"):
                raise LabError(403, "Read access denied")
            return self._output(document)

    def write(self, token: str, document_id: str, content: str) -> dict:
        with self.lock:
            session = self._session(token)
            document = self._document(document_id)
            allowed = self._allowed(session, document, "write")
            if not allowed and self.settings.mode != "write_side_effect":
                raise LabError(403, "Write access denied")
            # Intentional defect mode: commit the mutation before returning 403.
            with self.db:
                self.db.execute("UPDATE documents SET content = ? WHERE id = ?", (content, document_id))
            if not allowed:
                raise LabError(403, "Write access denied")
            return self._output(self._document(document_id))

    def change_role(self, token: str, subject_id: str, role: str) -> None:
        with self.lock, self.db:
            session = self._session(token)
            actor = self.db.execute("SELECT role FROM users WHERE id = ?", (session.user_id,)).fetchone()
            if actor[0] != "admin":
                raise LabError(403, "Administrator required")
            subject = self.db.execute("SELECT role FROM users WHERE id = ?", (subject_id,)).fetchone()
            if subject is None:
                raise LabError(404, "Subject not found")
            if subject[0] != role:
                self.db.execute("UPDATE users SET previous_role = role, role = ?, role_changed_at = ? WHERE id = ?", (role, self.clock(), subject_id))

    def transfer(self, token: str, document_id: str, new_owner_id: str) -> None:
        with self.lock, self.db:
            session = self._session(token)
            document = self._document(document_id)
            actor = self.db.execute("SELECT role FROM users WHERE id = ?", (session.user_id,)).fetchone()
            if document["owner_id"] != session.user_id and actor[0] != "admin":
                raise LabError(403, "Owner or administrator required")
            if self.db.execute("SELECT id FROM users WHERE id = ?", (new_owner_id,)).fetchone() is None:
                raise LabError(404, "New owner not found")
            if document["owner_id"] != new_owner_id:
                self.db.execute("UPDATE documents SET previous_owner_id = owner_id, owner_id = ?, transferred_at = ? WHERE id = ?", (new_owner_id, self.clock(), document_id))
