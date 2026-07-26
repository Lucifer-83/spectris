import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

# Overridable so Docker can point the audit log at a persistent volume.
DB_PATH = Path(
    os.environ.get("WIFI_DB_PATH", Path(__file__).resolve().parent.parent / "engagement_log.sqlite3")
)

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
    conn = sqlite3.connect(db_path)
    try:
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
