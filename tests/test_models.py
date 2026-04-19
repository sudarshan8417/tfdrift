"""Tests for tfdrift models and severity classification."""

import json

from tfdrift.models import (
    AttributeChange,
    ChangeAction,
    DriftedResource,
    ScanReport,
    Severity,
    WorkspaceScanResult,
)
from tfdrift.severity import SeverityClassifier


class TestSeverity:
    def test_severity_ordering(self):
        assert Severity.INFO < Severity.LOW
        assert Severity.LOW < Severity.MEDIUM
        assert Severity.MEDIUM < Severity.HIGH
        assert Severity.HIGH < Severity.CRITICAL

    def test_classify_security_group_ingress_is_critical(self):
        classifier = SeverityClassifier()
        resource = DriftedResource(
            address="aws_security_group.main",
            resource_type="aws_security_group",
            resource_name="main",
            action=ChangeAction.UPDATE,
            changes=[AttributeChange(attribute="ingress", old_value=[], new_value=[{}])],
        )
        assert classifier.classify(resource) == Severity.CRITICAL

    def test_classify_iam_policy_is_critical(self):
        classifier = SeverityClassifier()
        resource = DriftedResource(
            address="aws_iam_policy.admin",
            resource_type="aws_iam_policy",
            resource_name="admin",
            action=ChangeAction.UPDATE,
            changes=[AttributeChange(attribute="policy", old_value="{}", new_value="{}")],
        )
        assert classifier.classify(resource) == Severity.CRITICAL

    def test_classify_instance_type_is_high(self):
        classifier = SeverityClassifier()
        resource = DriftedResource(
            address="aws_instance.web",
            resource_type="aws_instance",
            resource_name="web",
            action=ChangeAction.UPDATE,
            changes=[
                AttributeChange(
                    attribute="instance_type",
                    old_value="t3.micro",
                    new_value="t3.large",
                )
            ],
        )
        assert classifier.classify(resource) == Severity.HIGH

    def test_classify_tags_is_low(self):
        classifier = SeverityClassifier()
        resource = DriftedResource(
            address="aws_instance.web",
            resource_type="aws_instance",
            resource_name="web",
            action=ChangeAction.UPDATE,
            changes=[
                AttributeChange(
                    attribute="tags",
                    old_value={"Name": "old"},
                    new_value={"Name": "new"},
                )
            ],
        )
        assert classifier.classify(resource) == Severity.LOW

    def test_classify_uses_highest_severity_attribute(self):
        classifier = SeverityClassifier()
        resource = DriftedResource(
            address="aws_security_group.main",
            resource_type="aws_security_group",
            resource_name="main",
            action=ChangeAction.UPDATE,
            changes=[
                AttributeChange(attribute="tags", old_value={}, new_value={}),
                AttributeChange(attribute="ingress", old_value=[], new_value=[{}]),
            ],
        )
        # Should be CRITICAL because ingress > tags
        assert classifier.classify(resource) == Severity.CRITICAL

    def test_classify_unknown_attribute_is_medium(self):
        classifier = SeverityClassifier()
        resource = DriftedResource(
            address="aws_instance.web",
            resource_type="aws_instance",
            resource_name="web",
            action=ChangeAction.UPDATE,
            changes=[
                AttributeChange(attribute="some_random_attr", old_value="a", new_value="b")
            ],
        )
        assert classifier.classify(resource) == Severity.MEDIUM

    def test_from_config_extends_defaults(self):
        config = {
            "severity": {
                "critical": ["aws_lambda_function.*.code"],
            }
        }
        classifier = SeverityClassifier.from_config(config)
        resource = DriftedResource(
            address="aws_lambda_function.api",
            resource_type="aws_lambda_function",
            resource_name="api",
            action=ChangeAction.UPDATE,
            changes=[AttributeChange(attribute="code", old_value="v1", new_value="v2")],
        )
        assert classifier.classify(resource) == Severity.CRITICAL


class TestModels:
    def test_drifted_resource_full_address_without_module(self):
        r = DriftedResource(
            address="aws_instance.web",
            resource_type="aws_instance",
            resource_name="web",
            action=ChangeAction.UPDATE,
        )
        assert r.full_address == "aws_instance.web"

    def test_drifted_resource_full_address_with_module(self):
        r = DriftedResource(
            address="aws_instance.web",
            resource_type="aws_instance",
            resource_name="web",
            action=ChangeAction.UPDATE,
            module="module.vpc",
        )
        assert r.full_address == "module.vpc.aws_instance.web"

    def test_workspace_result_no_drift(self):
        result = WorkspaceScanResult(workspace_path="/tmp/test")
        assert not result.has_drift
        assert result.drift_count == 0
        assert result.max_severity is None

    def test_workspace_result_with_drift(self):
        result = WorkspaceScanResult(
            workspace_path="/tmp/test",
            drifted_resources=[
                DriftedResource(
                    address="aws_instance.web",
                    resource_type="aws_instance",
                    resource_name="web",
                    action=ChangeAction.UPDATE,
                    severity=Severity.HIGH,
                ),
            ],
        )
        assert result.has_drift
        assert result.drift_count == 1
        assert result.max_severity == Severity.HIGH

    def test_scan_report_summary(self):
        report = ScanReport(
            results=[
                WorkspaceScanResult(
                    workspace_path="/tmp/a",
                    drifted_resources=[
                        DriftedResource(
                            address="aws_instance.a",
                            resource_type="aws_instance",
                            resource_name="a",
                            action=ChangeAction.UPDATE,
                            severity=Severity.HIGH,
                        ),
                    ],
                ),
                WorkspaceScanResult(workspace_path="/tmp/b"),
            ]
        )
        assert report.total_drift_count == 1
        assert report.workspaces_with_drift == 1
        assert report.total_workspaces == 2
        assert report.has_drift
        assert report.max_severity == Severity.HIGH

    def test_scan_report_to_json(self):
        report = ScanReport(results=[])
        report.finish()
        data = json.loads(report.to_json())
        assert "summary" in data
        assert data["summary"]["total_workspaces"] == 0

    def test_attribute_change_sensitive(self):
        change = AttributeChange(
            attribute="password",
            old_value="secret123",
            new_value="newsecret",
            sensitive=True,
        )
        d = change.to_dict()
        assert d["old_value"] == "(sensitive)"
        assert d["new_value"] == "(sensitive)"

    def test_severity_counts(self):
        report = ScanReport(
            results=[
                WorkspaceScanResult(
                    workspace_path="/tmp/a",
                    drifted_resources=[
                        DriftedResource(
                            address="r1", resource_type="t", resource_name="n",
                            action=ChangeAction.UPDATE, severity=Severity.CRITICAL,
                        ),
                        DriftedResource(
                            address="r2", resource_type="t", resource_name="n",
                            action=ChangeAction.UPDATE, severity=Severity.HIGH,
                        ),
                        DriftedResource(
                            address="r3", resource_type="t", resource_name="n",
                            action=ChangeAction.UPDATE, severity=Severity.HIGH,
                        ),
                    ],
                ),
            ]
        )
        counts = report.severity_counts()
        assert counts["critical"] == 1
        assert counts["high"] == 2
