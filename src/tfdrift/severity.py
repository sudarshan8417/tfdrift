"""Severity classification engine for drift detection.

Classifies drifted resources by security impact based on resource type
and attribute. Users can override these via .tfdrift.yml configuration.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field

from tfdrift.models import DriftedResource, Severity

# Default severity rules — security-critical resources and attributes
DEFAULT_CRITICAL_PATTERNS = [
    # AWS
    "aws_security_group.*.ingress",
    "aws_security_group.*.egress",
    "aws_security_group_rule.*",
    "aws_iam_policy.*.policy",
    "aws_iam_role.*.assume_role_policy",
    "aws_iam_role_policy.*.policy",
    "aws_iam_user_policy.*.policy",
    "aws_s3_bucket_public_access_block.*",
    "aws_s3_bucket_policy.*.policy",
    "aws_kms_key.*.key_policy",
    "aws_vpc.*.enable_dns_hostnames",
    "aws_network_acl_rule.*",
    # Azure
    "azurerm_network_security_group.*.security_rule",
    "azurerm_network_security_rule.*",
    "azurerm_role_assignment.*",
    "azurerm_role_definition.*.permissions",
    "azurerm_key_vault_access_policy.*",
    "azurerm_storage_account.*.allow_blob_public_access",
    "azurerm_storage_account.*.network_rules",
    # GCP
    "google_compute_firewall.*.allow",
    "google_compute_firewall.*.deny",
    "google_compute_firewall.*.source_ranges",
    "google_project_iam_binding.*",
    "google_project_iam_member.*",
    "google_storage_bucket_iam_binding.*",
    "google_kms_crypto_key_iam_binding.*",
]

DEFAULT_HIGH_PATTERNS = [
    # AWS
    "aws_instance.*.instance_type",
    "aws_instance.*.ami",
    "aws_instance.*.user_data",
    "aws_rds_instance.*.engine_version",
    "aws_rds_instance.*.publicly_accessible",
    "aws_rds_instance.*.storage_encrypted",
    "aws_s3_bucket.*.versioning",
    "aws_s3_bucket.*.server_side_encryption_configuration",
    "aws_lambda_function.*.runtime",
    "aws_lambda_function.*.environment",
    "aws_cloudfront_distribution.*.viewer_certificate",
    "aws_elasticache_cluster.*.engine_version",
    "aws_eks_cluster.*.version",
    # Azure
    "azurerm_virtual_machine.*.vm_size",
    "azurerm_linux_virtual_machine.*.size",
    "azurerm_windows_virtual_machine.*.size",
    "azurerm_sql_server.*.administrator_login_password",
    "azurerm_storage_account.*.enable_https_traffic_only",
    "azurerm_kubernetes_cluster.*.kubernetes_version",
    # GCP
    "google_compute_instance.*.machine_type",
    "google_compute_instance.*.boot_disk",
    "google_sql_database_instance.*.database_version",
    "google_container_cluster.*.min_master_version",
    "google_storage_bucket.*.uniform_bucket_level_access",
]

DEFAULT_LOW_PATTERNS = [
    "*.tags",
    "*.tags.*",
    "*.labels",
    "*.labels.*",
    "*.description",
]


@dataclass
class SeverityClassifier:
    """Classifies drift severity based on resource type and changed attributes."""

    critical_patterns: list[str] = field(
        default_factory=lambda: list(DEFAULT_CRITICAL_PATTERNS)
    )
    high_patterns: list[str] = field(
        default_factory=lambda: list(DEFAULT_HIGH_PATTERNS)
    )
    low_patterns: list[str] = field(
        default_factory=lambda: list(DEFAULT_LOW_PATTERNS)
    )

    def classify(self, resource: DriftedResource) -> Severity:
        """Determine the severity of a drifted resource.

        If a resource has multiple changed attributes, the highest severity
        among them is used.
        """
        if not resource.changes:
            # No specific attribute changes — classify by resource type alone
            return self._classify_resource_type(resource.resource_type)

        max_severity = Severity.INFO
        for change in resource.changes:
            # Build the target string: e.g. "aws_security_group.main.ingress"
            target = f"{resource.resource_type}.{resource.resource_name}.{change.attribute}"
            severity = self._match_pattern(target)
            if severity > max_severity:
                max_severity = severity

        return max_severity

    def _classify_resource_type(self, resource_type: str) -> Severity:
        """Fallback classification by resource type when no attribute info."""
        security_types = {
            "aws_security_group",
            "aws_security_group_rule",
            "aws_iam_policy",
            "aws_iam_role",
            "aws_iam_role_policy",
            "aws_iam_user_policy",
            "aws_network_acl_rule",
        }
        if resource_type in security_types:
            return Severity.HIGH
        return Severity.MEDIUM

    def _match_pattern(self, target: str) -> Severity:
        """Match a resource.attribute pattern against severity rules."""
        for pattern in self.critical_patterns:
            if fnmatch.fnmatch(target, pattern):
                return Severity.CRITICAL

        for pattern in self.high_patterns:
            if fnmatch.fnmatch(target, pattern):
                return Severity.HIGH

        for pattern in self.low_patterns:
            if fnmatch.fnmatch(target, pattern):
                return Severity.LOW

        return Severity.MEDIUM

    @classmethod
    def from_config(cls, config: dict) -> SeverityClassifier:
        """Create a classifier from .tfdrift.yml severity config."""
        severity_config = config.get("severity", {})
        kwargs = {}
        if "critical" in severity_config:
            kwargs["critical_patterns"] = (
                list(DEFAULT_CRITICAL_PATTERNS) + severity_config["critical"]
            )
        if "high" in severity_config:
            kwargs["high_patterns"] = (
                list(DEFAULT_HIGH_PATTERNS) + severity_config["high"]
            )
        if "low" in severity_config:
            kwargs["low_patterns"] = (
                list(DEFAULT_LOW_PATTERNS) + severity_config["low"]
            )
        return cls(**kwargs)
