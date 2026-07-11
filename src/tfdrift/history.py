"""Drift scan history — stores results in a local SQLite database."""

from __future__ import annotations

import json
import re
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
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


def parse_since(since: str) -> datetime:
    """Parse a human-friendly lookback string into a UTC datetime.

    Accepts: 1h, 6h, 24h, 7d, 30d, or an ISO-8601 date (2026-01-01).
    """
    since = since.strip().lower()
    m = re.fullmatch(r"(\d+)(h|d)", since)
    if m:
        n, unit = int(m.group(1)), m.group(2)
        delta = timedelta(hours=n) if unit == "h" else timedelta(days=n)
        return datetime.now(timezone.utc) - delta
    # Try ISO date
    try:
        return datetime.fromisoformat(since).replace(tzinfo=timezone.utc)
    except ValueError:
        raise ValueError(
            f"Invalid --since value '{since}'. Use formats like 7d, 24h, or 2026-01-01."
        )


def list_scans(
    db_path: Path = DEFAULT_DB_PATH,
    limit: int = 10,
    since: str | None = None,
) -> list[dict]:
    """Return the most recent scans, newest first.

    Args:
        limit: Maximum number of scans to return.
        since: Optional lookback string (e.g. '7d', '24h', '2026-01-01').
    """
    if not db_path.exists():
        return []
    with _connect(db_path) as conn:
        _init_db(conn)
        if since:
            cutoff = parse_since(since).isoformat()
            rows = conn.execute(
                """SELECT id, scanned_at, base_dir, workspace_count, drift_count,
                          error_count, duration_seconds, severity_counts
                   FROM scans WHERE scanned_at >= ?
                   ORDER BY scanned_at DESC LIMIT ?""",
                (cutoff, limit),
            ).fetchall()
        else:
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


def get_repeat_offenders(
    db_path: Path = DEFAULT_DB_PATH,
    limit: int = 10,
    since: str | None = None,
) -> list[dict]:
    """Return resources that have drifted most frequently, ranked by drift count."""
    if not db_path.exists():
        return []
    with _connect(db_path) as conn:
        _init_db(conn)
        if since:
            cutoff = parse_since(since).isoformat()
            rows = conn.execute(
                """SELECT dr.resource_address, dr.resource_type, dr.severity,
                          COUNT(*) as drift_count,
                          MAX(s.scanned_at) as last_seen
                   FROM drifted_resources dr
                   JOIN scans s ON s.id = dr.scan_id
                   WHERE s.scanned_at >= ?
                   GROUP BY dr.resource_address, dr.resource_type, dr.severity
                   ORDER BY drift_count DESC
                   LIMIT ?""",
                (cutoff, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT dr.resource_address, dr.resource_type, dr.severity,
                          COUNT(*) as drift_count,
                          MAX(s.scanned_at) as last_seen
                   FROM drifted_resources dr
                   JOIN scans s ON s.id = dr.scan_id
                   GROUP BY dr.resource_address, dr.resource_type, dr.severity
                   ORDER BY drift_count DESC
                   LIMIT ?""",
                (limit,),
            ).fetchall()
    return [dict(r) for r in rows]


def get_daily_summary(
    db_path: Path = DEFAULT_DB_PATH,
    since: str | None = None,
) -> list[dict]:
    """Return per-day drift counts for trend visualization."""
    if not db_path.exists():
        return []
    with _connect(db_path) as conn:
        _init_db(conn)
        base_query = """
            SELECT substr(scanned_at, 1, 10) as day,
                   COUNT(*) as scan_count,
                   SUM(drift_count) as total_drift,
                   SUM(CASE WHEN drift_count > 0 THEN 1 ELSE 0 END) as scans_with_drift
            FROM scans
            {where}
            GROUP BY day
            ORDER BY day DESC
        """
        if since:
            cutoff = parse_since(since).isoformat()
            rows = conn.execute(
                base_query.format(where="WHERE scanned_at >= ?"), (cutoff,)
            ).fetchall()
        else:
            rows = conn.execute(base_query.format(where="")).fetchall()
    return [dict(r) for r in rows]


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
