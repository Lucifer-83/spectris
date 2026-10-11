import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

def _default_db_path() -> Path:
    """The audit log must live in a per-user *writable* location. When installed
    from a package the app sits under a read-only prefix (e.g. /opt/Spectris),
    so writing the DB next to the binary fails with 'unable to open database
    file'. Use the XDG data dir (honors XDG_DATA_HOME), falling back to
    ~/.local/share/spectris/."""
    base = os.environ.get("XDG_DATA_HOME")
    root = Path(base) if base else Path.home() / ".local" / "share"
    return root / "spectris" / "engagement_log.sqlite3"


# Overridable so Docker can point the audit log at a persistent volume.
DB_PATH = Path(os.environ["WIFI_DB_PATH"]) if os.environ.get("WIFI_DB_PATH") else _default_db_path()

SCHEMA = """
CREATE TABLE IF NOT EXISTS action_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    result TEXT NOT NULL,
    detail TEXT
);
"""


@contextmanager
def get_connection(db_path: Path = DB_PATH):
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    # timeout + WAL + busy_timeout: FastAPI runs these sync endpoints in a
    # threadpool, so several log writes/reads can land at once. WAL lets a reader
    # and a writer coexist, and the busy timeout waits out a brief lock instead of
    # failing with "database is locked". (PRAGMAs are cheap and idempotent.)
    conn = sqlite3.connect(db_path, timeout=5.0)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute(SCHEMA)
        conn.commit()
        yield conn
    finally:
        conn.close()


def log_action(action: str, target: str | None, result: str, detail: str = "", db_path: Path = DB_PATH) -> None:
    with get_connection(db_path) as conn:
        conn.execute(
            "INSERT INTO action_log (timestamp, action, target, result, detail) VALUES (?, ?, ?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(), action, target, result, detail),
        )
        conn.commit()


def get_log(db_path: Path = DB_PATH) -> list[dict]:
    with get_connection(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM action_log ORDER BY id DESC").fetchall()
        return [dict(row) for row in rows]


def clear_log(db_path: Path = DB_PATH) -> int:
    """Wipe the audit log, then drop a single 'log-cleared' marker so the fact
    that it was cleared (and when) is itself recorded. Returns the row count that
    was removed."""
    with get_connection(db_path) as conn:
        removed = conn.execute("SELECT COUNT(*) FROM action_log").fetchone()[0]
        conn.execute("DELETE FROM action_log")
        conn.execute(
            "INSERT INTO action_log (timestamp, action, target, result, detail) VALUES (?, ?, ?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(), "log-cleared", None, "success", f"cleared {removed} entries"),
        )
        conn.commit()
        return removed
