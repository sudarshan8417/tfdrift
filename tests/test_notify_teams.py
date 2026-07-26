"""Tests for Microsoft Teams notification support."""
from unittest.mock import MagicMock, patch

import requests

from tfdrift.models import (
    AttributeChange,
    ChangeAction,
    DriftedResource,
    ScanReport,
    Severity,
    WorkspaceScanResult,
)
from tfdrift.reporters.output import notify_teams


def _clean_report() -> ScanReport:
    return ScanReport(
        results=[
            WorkspaceScanResult(
                workspace_path="/infra/prod",
                drifted_resources=[],
            )
        ]
    )


def _drift_report(severity: Severity = Severity.HIGH) -> ScanReport:
    return ScanReport(
        results=[
            WorkspaceScanResult(
                workspace_path="/infra/prod",
                drifted_resources=[
                    DriftedResource(
                        address="aws_instance.web",
                        resource_type="aws_instance",
                        resource_name="web",
                        action=ChangeAction.UPDATE,
                        severity=severity,
                        changes=[
                            AttributeChange(
                                attribute="instance_type",
                                old_value="t3.micro",
                                new_value="t3.large",
                            )
                        ],
                    )
                ],
            )
        ]
    )


class TestNotifyTeams:
    def test_returns_false_when_no_drift(self):
        assert notify_teams(_clean_report(), "https://example.webhook.office.com/x") is False

    def test_returns_false_when_drift_below_min_severity(self):
        report = _drift_report(Severity.LOW)
        result = notify_teams(report, "https://example.webhook.office.com/x", min_severity="high")
        assert result is False

    def test_sends_message_card_payload(self):
        report = _drift_report(Severity.HIGH)
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None

        with patch("tfdrift.reporters.output.requests.post", return_value=mock_resp) as mock_post:
            result = notify_teams(report, "https://example.webhook.office.com/x")

        assert result is True
        mock_post.assert_called_once()
        _, kwargs = mock_post.call_args
        payload = kwargs["json"]
        assert payload["@type"] == "MessageCard"
        assert payload["@context"] == "https://schema.org/extensions"
        assert "Terraform Drift Detected" in payload["title"]
        assert len(payload["sections"]) >= 1

    def test_payload_contains_resource_facts(self):
        report = _drift_report(Severity.HIGH)
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None

        with patch("tfdrift.reporters.output.requests.post", return_value=mock_resp) as mock_post:
            notify_teams(report, "https://example.webhook.office.com/x")

        payload = mock_post.call_args[1]["json"]
        all_facts = [f for section in payload["sections"] for f in section.get("facts", [])]
        fact_names = [f["name"] for f in all_facts]
        assert any("aws_instance.web" in name for name in fact_names)

    def test_theme_color_red_for_critical(self):
        report = _drift_report(Severity.CRITICAL)
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None

        with patch("tfdrift.reporters.output.requests.post", return_value=mock_resp) as mock_post:
            notify_teams(report, "https://example.webhook.office.com/x")

        payload = mock_post.call_args[1]["json"]
        assert payload["themeColor"] == "FF4444"

    def test_theme_color_orange_for_medium(self):
        report = _drift_report(Severity.MEDIUM)
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None

        with patch("tfdrift.reporters.output.requests.post", return_value=mock_resp) as mock_post:
            notify_teams(report, "https://example.webhook.office.com/x", min_severity="low")

        payload = mock_post.call_args[1]["json"]
        assert payload["themeColor"] == "FFA500"

    def test_returns_false_on_http_error(self):
        report = _drift_report(Severity.HIGH)

        with patch("tfdrift.reporters.output.requests.post") as mock_post:
            mock_post.return_value.raise_for_status.side_effect = requests.RequestException("500")
            result = notify_teams(report, "https://example.webhook.office.com/x")

        assert result is False

    def test_returns_false_on_connection_error(self):
        report = _drift_report(Severity.HIGH)

        with patch(
            "tfdrift.reporters.output.requests.post",
            side_effect=requests.ConnectionError(),
        ):
            result = notify_teams(report, "https://example.webhook.office.com/x")

        assert result is False

    def test_respects_10_resource_cap(self):
        resources = [
            DriftedResource(
                address=f"aws_instance.web{i}",
                resource_type="aws_instance",
                resource_name=f"web{i}",
                action=ChangeAction.UPDATE,
                severity=Severity.HIGH,
                changes=[
                    AttributeChange(
                        attribute="instance_type", old_value="t3.micro", new_value="t3.large"
                    )
                ],
            )
            for i in range(15)
        ]
        report = ScanReport(
            results=[WorkspaceScanResult(workspace_path="/infra/prod", drifted_resources=resources)]
        )
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None

        with patch("tfdrift.reporters.output.requests.post", return_value=mock_resp) as mock_post:
            notify_teams(report, "https://example.webhook.office.com/x", min_severity="low")

        payload = mock_post.call_args[1]["json"]
        resource_section = next(
            s for s in payload["sections"] if s.get("title") == "Drifted Resources"
        )
        assert len(resource_section["facts"]) <= 10
