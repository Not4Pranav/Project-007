from __future__ import annotations

import contextlib
import sqlite3
from pathlib import Path

SCHEMA_PATH = Path(__file__).with_name("schema.sql")

# SQLite defaults are tuned for durability on a laptop; a fixture database
# loaded 250k rows at a time and read by a load test wants throughput + WAL.
TUNE = (
    ("journal_mode", "WAL"),
    ("synchronous", "NORMAL"),
    ("cache_size", "-65536"),   # 64 MB
    ("temp_store", "MEMORY"),
    ("mmap_size", "268435456"),
    ("busy_timeout", "10000"),
)


def connect(path: str | Path, *, create_parents: bool = True) -> sqlite3.Connection:
    p = Path(path)
    if create_parents and str(p) != ":memory:" and not str(p).startswith("file:"):
        p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(p, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    for key, value in TUNE:
        conn.execute(f"PRAGMA {key}={value}")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


ADDITIVE_COLUMNS: tuple[tuple[str, str, str], ...] = (
    ("users", "is_synthetic_abuse", "INTEGER NOT NULL DEFAULT 0"),
)


def migrate(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA_PATH.read_text())
    ensure_columns(conn)


def ensure_columns(conn: sqlite3.Connection) -> None:
    """`CREATE TABLE IF NOT EXISTS` never changes an existing table, so fixture
    databases created by an older version need explicit ADD COLUMN."""
    for table, column, decl in ADDITIVE_COLUMNS:
        have = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
        if column not in have:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")


def reset(conn: sqlite3.Connection) -> None:
    for table in ("flags", "events", "sessions", "invite_edges", "credentials", "users", "meta"):
        conn.execute(f"DELETE FROM {table}")
    with contextlib.suppress(sqlite3.OperationalError):  # no AUTOINCREMENT anywhere
        conn.execute("DELETE FROM sqlite_sequence")


def set_meta(conn: sqlite3.Connection, key: str, value: object) -> None:
    conn.execute(
        "INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, str(value)),
    )


def get_meta(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return None if row is None else row["value"]


def table_counts(conn: sqlite3.Connection) -> dict[str, int]:
    out: dict[str, int] = {}
    for t in ("users", "credentials", "sessions", "events", "invite_edges", "flags"):
        out[t] = conn.execute(f"SELECT COUNT(*) AS c FROM {t}").fetchone()["c"]
    return out
