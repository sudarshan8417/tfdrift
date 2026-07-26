"""Tests for OpsGenie notification support."""
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
from tfdrift.reporters.output import notify_opsgenie


def _clean_report() -> ScanReport:
    return ScanReport(
        results=[
            WorkspaceScanResult(workspace_path="/infra/prod", drifted_resources=[])
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


class TestNotifyOpsgenie:
    def test_returns_false_when_no_drift(self):
        assert notify_opsgenie(_clean_report(), "fake-api-key") is False

    def test_returns_false_when_drift_below_min_severity(self):
        report = _drift_report(Severity.LOW)
        result = notify_opsgenie(report, "fake-api-key", min_severity="high")
        assert result is False

    def test_sends_alert_payload(self):
        report = _drift_report(Severity.HIGH)
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None

        with patch("tfdrift.reporters.output.requests.post", return_value=mock_resp) as mock_post:
            result = notify_opsgenie(report, "fake-api-key")

        assert result is True
        mock_post.assert_called_once()
        _, kwargs = mock_post.call_args
        assert kwargs["json"]["message"].startswith("Terraform drift detected")
        assert kwargs["json"]["source"] == "tfdrift"

    def test_priority_p1_for_critical(self):
        report = _drift_report(Severity.CRITICAL)
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None

        with patch("tfdrift.reporters.output.requests.post", return_value=mock_resp) as mock_post:
            notify_opsgenie(report, "fake-api-key", min_severity="low")

        payload = mock_post.call_args[1]["json"]
        assert payload["priority"] == "P1"

    def test_priority_p2_for_high(self):
        report = _drift_report(Severity.HIGH)
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None

        with patch("tfdrift.reporters.output.requests.post", return_value=mock_resp) as mock_post:
            notify_opsgenie(report, "fake-api-key")

        payload = mock_post.call_args[1]["json"]
        assert payload["priority"] == "P2"

    def test_uses_us_endpoint_by_default(self):
        report = _drift_report(Severity.HIGH)
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None

        with patch("tfdrift.reporters.output.requests.post", return_value=mock_resp) as mock_post:
            notify_opsgenie(report, "fake-api-key")

        url = mock_post.call_args[0][0]
        assert "api.opsgenie.com" in url
        assert "eu" not in url

    def test_uses_eu_endpoint_when_region_eu(self):
        report = _drift_report(Severity.HIGH)
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None

        with patch("tfdrift.reporters.output.requests.post", return_value=mock_resp) as mock_post:
            notify_opsgenie(report, "fake-api-key", region="eu")

        url = mock_post.call_args[0][0]
        assert "api.eu.opsgenie.com" in url

    def test_authorization_header_uses_genie_key(self):
        report = _drift_report(Severity.HIGH)
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None

        with patch("tfdrift.reporters.output.requests.post", return_value=mock_resp) as mock_post:
            notify_opsgenie(report, "my-secret-key")

        headers = mock_post.call_args[1]["headers"]
        assert headers["Authorization"] == "GenieKey my-secret-key"

    def test_payload_includes_alias_for_deduplication(self):
        report = _drift_report(Severity.HIGH)
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None

        with patch("tfdrift.reporters.output.requests.post", return_value=mock_resp) as mock_post:
            notify_opsgenie(report, "fake-api-key")

        payload = mock_post.call_args[1]["json"]
        assert payload["alias"] == "tfdrift-drift-detected"

    def test_returns_false_on_http_error(self):
        report = _drift_report(Severity.HIGH)

        with patch("tfdrift.reporters.output.requests.post") as mock_post:
            mock_post.return_value.raise_for_status.side_effect = requests.RequestException("403")
            result = notify_opsgenie(report, "bad-key")

        assert result is False

    def test_returns_false_on_connection_error(self):
        report = _drift_report(Severity.HIGH)

        with patch(
            "tfdrift.reporters.output.requests.post",
            side_effect=requests.ConnectionError(),
        ):
            result = notify_opsgenie(report, "fake-api-key")

        assert result is False
