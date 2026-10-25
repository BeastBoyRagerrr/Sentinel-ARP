"""Database helper module for the Sentinel-ARP project."""

from contextlib import contextmanager
from datetime import datetime, timezone
import sqlite3
from typing import Any, Generator, Optional


@contextmanager
def _get_connection(path: str) -> Generator[sqlite3.Connection, None, None]:
    """Open a new database connection with a 5s timeout and WAL mode enabled."""
    conn = sqlite3.connect(path, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    try:
        yield conn
    finally:
        conn.close()


def init_db(path: str = "sentinel.db") -> None:
    """Initialize database tables if they do not already exist."""
    with _get_connection(path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS devices (
                ip TEXT PRIMARY KEY,
                mac TEXT,
                fingerprint TEXT,
                last_seen TEXT,
                bandwidth_bytes INTEGER DEFAULT 0
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                type TEXT,
                severity TEXT,
                detail TEXT
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS policies (
                ip TEXT PRIMARY KEY,
                action TEXT,
                updated TEXT
            );
            """
        )
        conn.commit()


def insert_alert(
    alert_type: str,
    detail: str,
    severity: str = "INFO",
    path: str = "sentinel.db",
) -> int:
    """Insert an alert with UTC ISO timestamp and return the new row ID."""
    init_db(path)
    now_ts = datetime.now(timezone.utc).isoformat()
    with _get_connection(path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO alerts (timestamp, type, severity, detail)
            VALUES (?, ?, ?, ?);
            """,
            (now_ts, alert_type, severity, detail),
        )
        conn.commit()
        return cursor.lastrowid


def upsert_device(
    ip: str,
    mac: str,
    fingerprint: Optional[str] = None,
    bandwidth_bytes: Optional[int] = None,
    path: str = "sentinel.db",
) -> None:
    """
    Insert or update a device record by IP.

    Always refreshes last_seen to current UTC ISO timestamp.
    Only overwrites fingerprint or bandwidth_bytes when a value is passed.
    """
    init_db(path)
    now_ts = datetime.now(timezone.utc).isoformat()
    with _get_connection(path) as conn:
        conn.execute(
            """
            INSERT INTO devices (ip, mac, fingerprint, last_seen, bandwidth_bytes)
            VALUES (:ip, :mac, :fingerprint, :last_seen, COALESCE(:bandwidth_bytes, 0))
            ON CONFLICT(ip) DO UPDATE SET
                mac = :mac,
                last_seen = :last_seen,
                fingerprint = CASE
                    WHEN :fingerprint IS NOT NULL THEN :fingerprint
                    ELSE devices.fingerprint
                END,
                bandwidth_bytes = CASE
                    WHEN :bandwidth_bytes IS NOT NULL THEN :bandwidth_bytes
                    ELSE devices.bandwidth_bytes
                END;
            """,
            {
                "ip": ip,
                "mac": mac,
                "fingerprint": fingerprint,
                "last_seen": now_ts,
                "bandwidth_bytes": bandwidth_bytes,
            },
        )
        conn.commit()


def get_devices(path: str = "sentinel.db") -> list[dict[str, Any]]:
    """Return all devices as a list of dicts."""
    init_db(path)
    with _get_connection(path) as conn:
        cursor = conn.execute(
            """
            SELECT ip, mac, fingerprint, last_seen, bandwidth_bytes
            FROM devices
            ORDER BY last_seen DESC;
            """
        )
        return [dict(row) for row in cursor.fetchall()]


def get_alerts(limit: int = 50, path: str = "sentinel.db") -> list[dict[str, Any]]:
    """Return alerts as a list of dicts, newest first."""
    init_db(path)
    with _get_connection(path) as conn:
        cursor = conn.execute(
            """
            SELECT id, timestamp, type, severity, detail
            FROM alerts
            ORDER BY timestamp DESC, id DESC
            LIMIT ?;
            """,
            (limit,),
        )
        return [dict(row) for row in cursor.fetchall()]


def set_policy(ip: str, action: str, path: str = "sentinel.db") -> None:
    """Set or update policy for an IP address."""
    init_db(path)
    now_ts = datetime.now(timezone.utc).isoformat()
    with _get_connection(path) as conn:
        conn.execute(
            """
            INSERT INTO policies (ip, action, updated)
            VALUES (:ip, :action, :updated)
            ON CONFLICT(ip) DO UPDATE SET
                action = excluded.action,
                updated = excluded.updated;
            """,
            {
                "ip": ip,
                "action": action,
                "updated": now_ts,
            },
        )
        conn.commit()


def get_policies(path: str = "sentinel.db") -> list[dict[str, Any]]:
    """Return all policies as a list of dicts."""
    init_db(path)
    with _get_connection(path) as conn:
        cursor = conn.execute(
            """
            SELECT ip, action, updated
            FROM policies
            ORDER BY updated DESC;
            """
        )
        return [dict(row) for row in cursor.fetchall()]
