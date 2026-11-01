"""Small SQLite queue, independent from target databases and browser sessions."""

from contextlib import contextmanager
import json
from pathlib import Path
import sqlite3
from uuid import uuid4

from temporal_auth.runner.evidence import utc_now


ACTIVE = ("queued", "running", "cancelling")


class Store:
    def __init__(self, root: Path):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = self.root / "workspace.sqlite3"
        with self.connection() as db:
            db.executescript("""
                PRAGMA journal_mode=DELETE;
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY, spec TEXT NOT NULL, status TEXT NOT NULL,
                    created TEXT NOT NULL, started TEXT, finished TEXT,
                    cancel_requested INTEGER NOT NULL DEFAULT 0,
                    result TEXT, error TEXT
                );
                CREATE TABLE IF NOT EXISTS claims (
                    job_id TEXT PRIMARY KEY, worker_pid INTEGER
                );
            """)
        self.path.chmod(0o600)

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def decode(row):
        if row is None:
            return None
        data = dict(row)
        data["spec"] = json.loads(data["spec"])
        data["result"] = json.loads(data["result"]) if data["result"] else {}
        return data

    def create(self, spec):
        identifier = str(uuid4())
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT count(*) FROM jobs WHERE status IN ('queued','running','cancelling')").fetchone()[0] >= 20:
                raise ValueError("The queue is full. Wait for existing experiments to finish.")
            db.execute("INSERT INTO jobs(id,spec,status,created) VALUES(?,?,'queued',?)",
                       (identifier, spec.model_dump_json(), utc_now()))
        return identifier

    def get(self, identifier):
        with self.connection() as db:
            return self.decode(db.execute("SELECT * FROM jobs WHERE id=?", (identifier,)).fetchone())

    def list(self, view="all"):
        with self.connection() as db:
            rows = [self.decode(r) for r in db.execute("SELECT * FROM jobs ORDER BY created DESC LIMIT 200")]
        if view == "active": return [r for r in rows if r["status"] in ACTIVE]
        if view == "findings": return [r for r in rows if r["result"].get("verdict") in ("candidate", "confirmed_violation")]
        if view == "inconclusive": return [r for r in rows if r["result"].get("verdict") == "inconclusive"]
        return rows

    def claim(self, owner_pid=None):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM jobs WHERE status='queued' ORDER BY created LIMIT 1").fetchone()
            if row is None: return None
            db.execute("UPDATE jobs SET status='running',started=? WHERE id=?", (utc_now(), row["id"]))
            db.execute("INSERT OR REPLACE INTO claims(job_id,worker_pid) VALUES(?,?)", (row["id"], owner_pid))
        return self.get(row["id"])

    def cancel(self, identifier):
        with self.connection() as db:
            db.execute("UPDATE jobs SET status=CASE WHEN status='queued' THEN 'cancelled' ELSE 'cancelling' END, "
                       "cancel_requested=1, finished=CASE WHEN status='queued' THEN ? ELSE finished END "
                       "WHERE id=? AND status IN ('queued','running','cancelling')", (utc_now(), identifier))
        return self.get(identifier)

    def cancelled(self, identifier):
        row = self.get(identifier)
        return row is None or bool(row["cancel_requested"])

    def finish(self, identifier, status, result, error=None):
        with self.connection() as db:
            # Cancellation wins a race with a just-completed workflow without
            # discarding its actual observed verdict/evidence.
            db.execute("UPDATE jobs SET status=CASE WHEN cancel_requested=1 THEN 'cancelled' ELSE ? END, "
                       "result=?,error=?,finished=? WHERE id=?",
                       (status, json.dumps(result), error, utc_now(), identifier))

    def interrupt_unfinished(self, owner_pid=None):
        with self.connection() as db:
            query = "UPDATE jobs SET status='interrupted',error='worker_interrupted',finished=? WHERE status IN ('running','cancelling')"
            parameters = [utc_now()]
            if owner_pid is not None:
                query += " AND id IN (SELECT job_id FROM claims WHERE worker_pid=?)"
                parameters.append(owner_pid)
            db.execute(query, parameters)
