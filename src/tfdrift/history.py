"""Drift scan history — stores results in a local SQLite database."""

from __future__ import annotations

import json
import sqlite3
import uuid
from pathlib import Path

from tfdrift.models import ScanReport

DEFAULT_DB_PATH = Path.home() / ".tfdrift" / "history.db"


def _connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def _init_db(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            scanned_at TEXT NOT NULL,
            base_dir TEXT NOT NULL,
            workspace_count INTEGER NOT NULL,
            drift_count INTEGER NOT NULL,
            error_count INTEGER NOT NULL,
            duration_seconds REAL NOT NULL,
            severity_counts TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS drifted_resources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            workspace_path TEXT NOT NULL,
            resource_address TEXT NOT NULL,
            resource_type TEXT NOT NULL,
            action TEXT NOT NULL,
            severity TEXT NOT NULL,
            attribute_count INTEGER NOT NULL
        );
    """)


def save_scan(report: ScanReport, db_path: Path = DEFAULT_DB_PATH) -> str:
    """Persist a completed scan report to the history database."""
    scan_id = str(uuid.uuid4())
    with _connect(db_path) as conn:
        _init_db(conn)
        conn.execute(
            """INSERT INTO scans
               (id, scanned_at, base_dir, workspace_count, drift_count,
                error_count, duration_seconds, severity_counts)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_id,
                report.scan_started_at,
                report.config_path or ".",
                report.total_workspaces,
                report.total_drift_count,
                len(report.errors),
                round(report.total_duration_seconds, 2),
                json.dumps(report.severity_counts()),
            ),
        )
        for result in report.results:
            for resource in result.drifted_resources:
                conn.execute(
                    """INSERT INTO drifted_resources
                       (scan_id, workspace_path, resource_address,
                        resource_type, action, severity, attribute_count)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        scan_id,
                        result.workspace_path,
                        resource.full_address,
                        resource.resource_type,
                        resource.action.value,
                        resource.severity.value,
                        len(resource.changes),
                    ),
                )
    return scan_id


def list_scans(db_path: Path = DEFAULT_DB_PATH, limit: int = 10) -> list[dict]:
    """Return the most recent scans, newest first."""
    if not db_path.exists():
        return []
    with _connect(db_path) as conn:
        _init_db(conn)
        rows = conn.execute(
            """SELECT id, scanned_at, base_dir, workspace_count, drift_count,
                      error_count, duration_seconds, severity_counts
               FROM scans ORDER BY scanned_at DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    results = []
    for row in rows:
        d = dict(row)
        d["severity_counts"] = json.loads(d["severity_counts"])
        results.append(d)
    return results


def get_scan_resources(scan_id: str, db_path: Path = DEFAULT_DB_PATH) -> list[dict]:
    """Return all drifted resources for a specific scan."""
    if not db_path.exists():
        return []
    with _connect(db_path) as conn:
        rows = conn.execute(
            """SELECT workspace_path, resource_address, resource_type,
                      action, severity, attribute_count
               FROM drifted_resources
               WHERE scan_id = ?
               ORDER BY severity DESC, resource_address""",
            (scan_id,),
        ).fetchall()
    return [dict(r) for r in rows]
