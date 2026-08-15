"""Tests for CLI behavior."""
import csv
import io
from unittest.mock import patch

from click.testing import CliRunner

from tfdrift.cli import main
from tfdrift.models import (
    AttributeChange,
    ChangeAction,
    DriftedResource,
    ScanReport,
    Severity,
    WorkspaceScanResult,
)
from tfdrift.reporters.output import report_csv, report_github_actions


def test_version():
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "tfdrift" in result.output


def test_init_creates_config(tmp_path):
    runner = CliRunner()
    result = runner.invoke(main, ["init", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert (tmp_path / ".tfdrift.yml").exists()


def test_init_wont_overwrite(tmp_path):
    (tmp_path / ".tfdrift.yml").write_text("existing: true")
    runner = CliRunner()
    result = runner.invoke(main, ["init", "--path", str(tmp_path)])
    assert "already exists" in result.output


def _make_report_with_drift() -> ScanReport:
    return ScanReport(
        results=[
            WorkspaceScanResult(
                workspace_path="/tmp/ws",
                drifted_resources=[
                    DriftedResource(
                        address="aws_instance.web",
                        resource_type="aws_instance",
                        resource_name="web",
                        action=ChangeAction.UPDATE,
                        severity=Severity.HIGH,
                        changes=[
                            AttributeChange(
                                attribute="instance_type",
                                old_value="t3.micro",
                                new_value="t3.large",
                            )
                        ],
                    ),
                    DriftedResource(
                        address="aws_s3_bucket.data",
                        resource_type="aws_s3_bucket",
                        resource_name="data",
                        action=ChangeAction.UPDATE,
                        severity=Severity.MEDIUM,
                        changes=[
                            AttributeChange(
                                attribute="acl",
                                old_value="private",
                                new_value="public-read",
                            )
                        ],
                    ),
                ],
            )
        ]
    )


class TestReportCsv:
    def test_csv_has_header(self):
        report = ScanReport(results=[])
        csv_out = report_csv(report)
        reader = csv.DictReader(io.StringIO(csv_out))
        assert reader.fieldnames == [
            "scan_time", "workspace", "severity", "resource",
            "resource_type", "action", "changed_attributes", "changes_detail",
            "owner", "cost_delta_monthly",
        ]

    def test_csv_row_per_resource(self):
        report = _make_report_with_drift()
        csv_out = report_csv(report)
        rows = list(csv.DictReader(io.StringIO(csv_out)))
        assert len(rows) == 2

    def test_csv_row_values(self):
        report = _make_report_with_drift()
        csv_out = report_csv(report)
        rows = list(csv.DictReader(io.StringIO(csv_out)))
        first = rows[0]
        assert first["workspace"] == "/tmp/ws"
        assert first["severity"] == "high"
        assert first["resource"] == "aws_instance.web"
        assert first["resource_type"] == "aws_instance"
        assert first["action"] == "update"
        assert first["changed_attributes"] == "instance_type"
        assert "t3.micro" in first["changes_detail"]
        assert "t3.large" in first["changes_detail"]

    def test_csv_min_severity_filters_rows(self):
        report = _make_report_with_drift()
        csv_out = report_csv(report, min_severity="high")
        rows = list(csv.DictReader(io.StringIO(csv_out)))
        assert len(rows) == 1
        assert rows[0]["severity"] == "high"

    def test_csv_no_drift_only_header(self):
        report = ScanReport(results=[WorkspaceScanResult(workspace_path="/tmp/clean")])
        csv_out = report_csv(report)
        rows = list(csv.DictReader(io.StringIO(csv_out)))
        assert len(rows) == 0

    def test_csv_error_workspace_appears_as_row(self):
        report = ScanReport(
            results=[
                WorkspaceScanResult(
                    workspace_path="/tmp/broken",
                    error="terraform init failed",
                )
            ]
        )
        csv_out = report_csv(report)
        rows = list(csv.DictReader(io.StringIO(csv_out)))
        assert len(rows) == 1
        assert rows[0]["severity"] == "error"
        assert "terraform init failed" in rows[0]["changes_detail"]

    def test_csv_writes_to_file(self, tmp_path):
        report = _make_report_with_drift()
        out_file = tmp_path / "drift.csv"
        result = report_csv(report, output_path=str(out_file))
        assert result == str(out_file)
        assert out_file.exists()
        rows = list(csv.DictReader(out_file.open()))
        assert len(rows) == 2

    def test_csv_multiple_changes_pipe_separated(self):
        report = ScanReport(
            results=[
                WorkspaceScanResult(
                    workspace_path="/tmp/ws",
                    drifted_resources=[
                        DriftedResource(
                            address="aws_instance.web",
                            resource_type="aws_instance",
                            resource_name="web",
                            action=ChangeAction.UPDATE,
                            severity=Severity.HIGH,
                            changes=[
                                AttributeChange("instance_type", "t3.micro", "t3.large"),
                                AttributeChange("ami", "ami-old", "ami-new"),
                            ],
                        )
                    ],
                )
            ]
        )
        csv_out = report_csv(report)
        rows = list(csv.DictReader(io.StringIO(csv_out)))
        attrs = rows[0]["changed_attributes"].split("|")
        assert "instance_type" in attrs
        assert "ami" in attrs


def _make_high_and_medium_report() -> ScanReport:
    """Report with one HIGH and one MEDIUM resource."""
    return ScanReport(
        results=[
            WorkspaceScanResult(
                workspace_path="/tmp/ws",
                drifted_resources=[
                    DriftedResource(
                        address="aws_instance.web",
                        resource_type="aws_instance",
                        resource_name="web",
                        action=ChangeAction.UPDATE,
                        severity=Severity.HIGH,
                        changes=[AttributeChange("instance_type", "t3.micro", "t3.large")],
                    ),
                    DriftedResource(
                        address="aws_s3_bucket.data",
                        resource_type="aws_s3_bucket",
                        resource_name="data",
                        action=ChangeAction.UPDATE,
                        severity=Severity.MEDIUM,
                        changes=[AttributeChange("acl", "private", "public-read")],
                    ),
                ],
            )
        ]
    )


class TestFailOnSeverityCLI:
    """Exit-code and messaging behaviour for --fail-on."""

    def _invoke_scan(self, report: ScanReport, extra_args: list):  # type: ignore[return]
        runner = CliRunner()
        with patch("tfdrift.cli.run_scan", return_value=report), \
             patch("tfdrift.cli._save_history"):
            return runner.invoke(main, ["scan", "--path", "/tmp"] + extra_args)

    def test_exit_1_when_drift_above_threshold(self):
        report = _make_high_and_medium_report()
        result = self._invoke_scan(report, ["--fail-on", "high"])
        assert result.exit_code == 1

    def test_exit_0_when_drift_below_threshold(self):
        report = _make_high_and_medium_report()
        # Threshold is critical — drift is only HIGH/MEDIUM, so exit 0
        result = self._invoke_scan(report, ["--fail-on", "critical"])
        assert result.exit_code == 0

    def test_exit_1_without_fail_on_flag(self):
        report = _make_high_and_medium_report()
        result = self._invoke_scan(report, [])
        assert result.exit_code == 1

    def test_prints_threshold_reached_message(self):
        report = _make_high_and_medium_report()
        result = self._invoke_scan(report, ["--fail-on", "high"])
        assert "Fail threshold reached" in result.output

    def test_prints_below_threshold_message(self):
        report = _make_high_and_medium_report()
        result = self._invoke_scan(report, ["--fail-on", "critical"])
        assert "below" in result.output.lower() or "exit 0" in result.output

    def test_exact_severity_at_boundary_triggers(self):
        report = _make_high_and_medium_report()
        # HIGH drift with --fail-on high → should trigger
        result = self._invoke_scan(report, ["--fail-on", "high"])
        assert result.exit_code == 1

    def test_medium_drift_does_not_trigger_high_threshold(self):
        # Report with only MEDIUM drift
        report = ScanReport(
            results=[
                WorkspaceScanResult(
                    workspace_path="/tmp/ws",
                    drifted_resources=[
                        DriftedResource(
                            address="aws_s3_bucket.data",
                            resource_type="aws_s3_bucket",
                            resource_name="data",
                            action=ChangeAction.UPDATE,
                            severity=Severity.MEDIUM,
                            changes=[AttributeChange("acl", "private", "public")],
                        )
                    ],
                )
            ]
        )
        result = self._invoke_scan(report, ["--fail-on", "high"])
        assert result.exit_code == 0

    def test_no_drift_exits_0_regardless_of_fail_on(self):
        report = ScanReport(results=[WorkspaceScanResult(workspace_path="/tmp/clean")])
        result = self._invoke_scan(report, ["--fail-on", "low"])
        assert result.exit_code == 0


class TestFailOnSeverityGHA:
    """GHA annotation emitted when fail-on threshold is breached."""

    def test_emits_error_annotation_when_threshold_breached(self, capsys):
        report = _make_high_and_medium_report()
        report_github_actions(report, fail_on_severity="high")
        out = capsys.readouterr().out
        assert "::error" in out
        assert "fail-on-severity" in out

    def test_no_error_annotation_when_below_threshold(self, capsys):
        report = _make_high_and_medium_report()
        report_github_actions(report, fail_on_severity="critical")
        out = capsys.readouterr().out
        # Should not have the top-level fail-on error annotation
        assert "fail-on-severity" not in out

    def test_no_error_annotation_when_no_drift(self, capsys):
        report = ScanReport(results=[WorkspaceScanResult(workspace_path="/tmp/clean")])
        report_github_actions(report, fail_on_severity="low")
        out = capsys.readouterr().out
        assert "fail-on-severity" not in out


class TestExcludeResource:
    def _invoke_scan(self, report: ScanReport, extra_args: list):
        runner = CliRunner()
        with patch("tfdrift.cli.run_scan", return_value=report), \
             patch("tfdrift.cli._save_history"):
            return runner.invoke(main, ["scan", "--path", "/tmp"] + extra_args)

    def test_excludes_matching_resource(self):
        report = _make_report_with_drift()
        result = self._invoke_scan(report, ["--exclude-resource", "aws_instance*"])
        assert result.exit_code == 1
        assert "aws_instance.web" not in result.output

    def test_keeps_non_matching_resources(self):
        report = _make_report_with_drift()
        result = self._invoke_scan(report, ["--exclude-resource", "aws_instance*"])
        assert "aws_s3_bucket.data" in result.output

    def test_excludes_all_resources_exits_0(self):
        report = _make_report_with_drift()
        result = self._invoke_scan(report, ["--exclude-resource", "*"])
        assert result.exit_code == 0

    def test_no_exclude_shows_all_resources(self):
        report = _make_report_with_drift()
        result = self._invoke_scan(report, [])
        assert result.exit_code == 1
        assert "aws_instance.web" in result.output


class TestDiffCLI:
    def test_diff_identical_reports_exits_0(self, tmp_path):
        import json as _json
        report = {
            "summary": {},
            "workspaces": [{
                "workspace_path": "/infra/prod",
                "drifted_resources": [
                    {"address": "aws_instance.web", "action": "update",
                     "severity": "high", "changes": []}
                ],
            }],
        }
        baseline = tmp_path / "baseline.json"
        current = tmp_path / "current.json"
        baseline.write_text(_json.dumps(report))
        current.write_text(_json.dumps(report))

        runner = CliRunner()
        result = runner.invoke(main, ["diff", str(baseline), str(current)])
        assert result.exit_code == 0
        assert "persisting" in result.output.lower()

    def test_diff_new_drift_detected(self, tmp_path):
        import json as _json
        baseline = {"summary": {}, "workspaces": [
            {"workspace_path": "/p", "drifted_resources": []}
        ]}
        current = {
            "summary": {},
            "workspaces": [{
                "workspace_path": "/p",
                "drifted_resources": [
                    {"address": "aws_instance.web", "action": "update",
                     "severity": "high", "changes": []}
                ],
            }],
        }
        b = tmp_path / "b.json"
        c = tmp_path / "c.json"
        b.write_text(_json.dumps(baseline))
        c.write_text(_json.dumps(current))

        runner = CliRunner()
        result = runner.invoke(main, ["diff", str(b), str(c)])
        assert result.exit_code == 0
        assert "new" in result.output.lower()

    def test_diff_fail_on_new_exits_1(self, tmp_path):
        import json as _json
        baseline = {"summary": {}, "workspaces": [
            {"workspace_path": "/p", "drifted_resources": []}
        ]}
        current = {
            "summary": {},
            "workspaces": [{
                "workspace_path": "/p",
                "drifted_resources": [
                    {"address": "aws_instance.web", "action": "update",
                     "severity": "high", "changes": []}
                ],
            }],
        }
        b = tmp_path / "b.json"
        c = tmp_path / "c.json"
        b.write_text(_json.dumps(baseline))
        c.write_text(_json.dumps(current))

        runner = CliRunner()
        result = runner.invoke(main, ["diff", str(b), str(c), "--fail-on-new"])
        assert result.exit_code == 1

    def test_diff_json_output(self, tmp_path):
        import json as _json
        report = {"summary": {}, "workspaces": [{"workspace_path": "/p", "drifted_resources": []}]}
        b = tmp_path / "b.json"
        c = tmp_path / "c.json"
        b.write_text(_json.dumps(report))
        c.write_text(_json.dumps(report))

        runner = CliRunner()
        result = runner.invoke(main, ["diff", str(b), str(c), "--format", "json"])
        assert result.exit_code == 0
        parsed = _json.loads(result.output)
        assert "summary" in parsed
        assert "new_drift" in parsed
