"""Tests for drift suppression — DB helpers, run_scan filtering, and CLI."""

from __future__ import annotations

from datetime import timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from tfdrift.cli import main
from tfdrift.history import (
    clear_suppression,
    get_active_suppressions,
    list_suppressions,
    parse_duration,
    save_suppression,
)
from tfdrift.models import ChangeAction, DriftedResource, Severity, WorkspaceScanResult

# ---------------------------------------------------------------------------
# parse_duration
# ---------------------------------------------------------------------------


class TestParseDuration:
    def test_minutes(self):
        assert parse_duration("30m") == timedelta(minutes=30)

    def test_hours(self):
        assert parse_duration("4h") == timedelta(hours=4)

    def test_days(self):
        assert parse_duration("7d") == timedelta(days=7)

    def test_invalid_raises(self):
        import pytest
        with pytest.raises(ValueError, match="Invalid duration"):
            parse_duration("2w")

    def test_case_insensitive(self):
        assert parse_duration("2H") == timedelta(hours=2)


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------


class TestSuppressionDB:
    def test_save_and_list(self, tmp_path):
        db = tmp_path / "h.db"
        save_suppression("aws_instance.web", "4h", "maintenance", db)
        rows = list_suppressions(db)
        assert len(rows) == 1
        assert rows[0]["resource_pattern"] == "aws_instance.web"
        assert rows[0]["reason"] == "maintenance"

    def test_active_suppression_returned(self, tmp_path):
        db = tmp_path / "h.db"
        save_suppression("aws_instance.web", "1h", None, db)
        active = get_active_suppressions(db)
        assert len(active) == 1
        assert active[0]["resource_pattern"] == "aws_instance.web"

    def test_expired_suppression_not_returned(self, tmp_path):
        from datetime import datetime
        db = tmp_path / "h.db"
        # Manually insert an already-expired suppression
        from tfdrift.history import _connect, _init_db
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        with _connect(db) as conn:
            _init_db(conn)
            conn.execute(
                "INSERT INTO suppressions (resource_pattern, suppressed_at, expires_at, active) "
                "VALUES (?, ?, ?, 1)",
                ("aws_instance.old", past, past),
            )
        active = get_active_suppressions(db)
        assert len(active) == 0

    def test_clear_suppression(self, tmp_path):
        db = tmp_path / "h.db"
        save_suppression("aws_instance.web", "4h", None, db)
        assert len(get_active_suppressions(db)) == 1
        removed = clear_suppression("aws_instance.web", db)
        assert removed == 1
        assert len(get_active_suppressions(db)) == 0

    def test_clear_nonexistent_returns_zero(self, tmp_path):
        db = tmp_path / "h.db"
        assert clear_suppression("aws_instance.missing", db) == 0

    def test_no_db_returns_empty(self, tmp_path):
        db = tmp_path / "nonexistent.db"
        assert get_active_suppressions(db) == []
        assert list_suppressions(db) == []

    def test_list_include_expired(self, tmp_path):
        from datetime import datetime
        db = tmp_path / "h.db"
        save_suppression("aws_instance.active", "4h", None, db)
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        from tfdrift.history import _connect, _init_db
        with _connect(db) as conn:
            _init_db(conn)
            conn.execute(
                "INSERT INTO suppressions (resource_pattern, suppressed_at, expires_at, active) "
                "VALUES (?, ?, ?, 1)",
                ("aws_instance.expired", past, past),
            )
        all_rows = list_suppressions(db, include_expired=True)
        assert len(all_rows) == 2
        active_only = list_suppressions(db, include_expired=False)
        assert len(active_only) == 1


# ---------------------------------------------------------------------------
# run_scan suppression filtering
# ---------------------------------------------------------------------------


def _make_drifted(address: str) -> DriftedResource:
    return DriftedResource(
        address=address,
        resource_type=address.split(".")[0],
        resource_name=address.split(".")[1],
        action=ChangeAction.UPDATE,
        severity=Severity.MEDIUM,
    )


class TestRunScanSuppressions:
    def test_suppressed_resource_removed_from_result(self, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        (ws / "main.tf").write_text("# tf")

        from tfdrift.config import TfdriftConfig
        from tfdrift.detectors.drift import run_scan

        config = TfdriftConfig(scan_paths=["."], workers=1)
        suppressions = [{"resource_pattern": "aws_instance.web"}]

        with patch("tfdrift.detectors.drift.scan_workspace") as mock_scan:
            mock_scan.return_value = WorkspaceScanResult(
                workspace_path=str(ws),
                drifted_resources=[
                    _make_drifted("aws_instance.web"),
                    _make_drifted("aws_s3_bucket.data"),
                ],
            )
            report = run_scan(config, base_dir=str(tmp_path), suppressions=suppressions)

        assert report.total_drift_count == 1
        assert report.results[0].drifted_resources[0].address == "aws_s3_bucket.data"
        assert report.results[0].suppressed_count == 1
        assert report.total_suppressed_count == 1

    def test_wildcard_suppression_pattern(self, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        (ws / "main.tf").write_text("# tf")

        from tfdrift.config import TfdriftConfig
        from tfdrift.detectors.drift import run_scan

        config = TfdriftConfig(scan_paths=["."], workers=1)
        suppressions = [{"resource_pattern": "aws_autoscaling_group.*"}]

        with patch("tfdrift.detectors.drift.scan_workspace") as mock_scan:
            mock_scan.return_value = WorkspaceScanResult(
                workspace_path=str(ws),
                drifted_resources=[
                    _make_drifted("aws_autoscaling_group.web"),
                    _make_drifted("aws_autoscaling_group.api"),
                    _make_drifted("aws_instance.app"),
                ],
            )
            report = run_scan(config, base_dir=str(tmp_path), suppressions=suppressions)

        assert report.total_drift_count == 1
        assert report.total_suppressed_count == 2

    def test_no_suppressions_returns_all_drift(self, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        (ws / "main.tf").write_text("# tf")

        from tfdrift.config import TfdriftConfig
        from tfdrift.detectors.drift import run_scan

        config = TfdriftConfig(scan_paths=["."], workers=1)

        with patch("tfdrift.detectors.drift.scan_workspace") as mock_scan:
            mock_scan.return_value = WorkspaceScanResult(
                workspace_path=str(ws),
                drifted_resources=[_make_drifted("aws_instance.web")],
            )
            report = run_scan(config, base_dir=str(tmp_path), suppressions=None)

        assert report.total_drift_count == 1
        assert report.total_suppressed_count == 0


# ---------------------------------------------------------------------------
# CLI suppress command
# ---------------------------------------------------------------------------


class TestSuppressCLI:
    def test_create_suppression(self, tmp_path):
        runner = CliRunner()
        db = str(tmp_path / "h.db")
        result = runner.invoke(
            main,
            ["suppress", "aws_instance.web", "--duration", "4h",
             "--reason", "maintenance window", "--db", db],
        )
        assert result.exit_code == 0
        assert "aws_instance.web" in result.output
        assert "4h" in result.output

    def test_list_suppressions(self, tmp_path):
        runner = CliRunner()
        db = str(tmp_path / "h.db")
        save_suppression("aws_instance.web", "4h", "test", Path(db))
        result = runner.invoke(main, ["suppress", "--list", "--db", db])
        assert result.exit_code == 0
        assert "aws_instance.web" in result.output

    def test_list_empty(self, tmp_path):
        runner = CliRunner()
        db = str(tmp_path / "h.db")
        result = runner.invoke(main, ["suppress", "--list", "--db", db])
        assert result.exit_code == 0
        assert "No active suppressions" in result.output

    def test_clear_suppression(self, tmp_path):
        runner = CliRunner()
        db = str(tmp_path / "h.db")
        save_suppression("aws_instance.web", "4h", None, Path(db))
        result = runner.invoke(main, ["suppress", "--clear", "aws_instance.web", "--db", db])
        assert result.exit_code == 0
        assert "Cleared 1" in result.output

    def test_clear_nonexistent(self, tmp_path):
        runner = CliRunner()
        db = str(tmp_path / "h.db")
        result = runner.invoke(main, ["suppress", "--clear", "aws_instance.missing", "--db", db])
        assert result.exit_code == 0
        assert "No active suppressions" in result.output

    def test_invalid_duration(self, tmp_path):
        runner = CliRunner()
        db = str(tmp_path / "h.db")
        result = runner.invoke(
            main, ["suppress", "aws_instance.web", "--duration", "2w", "--db", db]
        )
        assert result.exit_code != 0

    def test_no_pattern_no_flag_shows_error(self, tmp_path):
        runner = CliRunner()
        db = str(tmp_path / "h.db")
        result = runner.invoke(main, ["suppress", "--db", db])
        assert result.exit_code != 0
