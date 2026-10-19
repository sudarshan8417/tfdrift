"""Severity classification for drifted resources.

The idea: not all drift is equal. Someone changing a tag is whatever,
but someone opening up a security group to 0.0.0.0/0 is a fire.
This module maps resource types + attributes to severity levels
using fnmatch patterns, so you can customize it in .tfdrift.yml.

Ships with ~60 built-in rules for AWS, Azure, and GCP.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field

from tfdrift.models import DriftedResource, Severity

# Patterns prefixed with "regex:" are treated as regular expressions.
# All other patterns use fnmatch glob syntax (the original behaviour).
_REGEX_PREFIX = "regex:"

# Default severity rules — security-critical resources and attributes
DEFAULT_CRITICAL_PATTERNS = [
    # AWS — IAM / access control
    "aws_security_group.*.ingress",
    "aws_security_group.*.egress",
    "aws_security_group_rule.*",
    "aws_iam_policy.*.policy",
    "aws_iam_role.*.assume_role_policy",
    "aws_iam_role_policy.*.policy",
    "aws_iam_role_policy_attachment.*",
    "aws_iam_user_policy.*.policy",
    # AWS — S3 public access
    "aws_s3_bucket_public_access_block.*",
    "aws_s3_bucket_policy.*.policy",
    "aws_s3_bucket_acl.*.acl",
    # AWS — KMS: attribute is 'policy' in all provider versions
    "aws_kms_key.*.policy",
    # AWS — network
    "aws_vpc.*.enable_dns_hostnames",
    "aws_network_acl_rule.*",
    # AWS — SQS / SNS policies
    "aws_sqs_queue_policy.*.policy",
    "aws_sns_topic_policy.*.policy",
    # AWS — audit / detective controls
    "aws_cloudtrail.*.enable_logging",
    "aws_guardduty_detector.*.enable",
    # AWS — RDS: losing deletion protection is catastrophic; backup loss is High (see below)
    "aws_db_instance.*.deletion_protection",
    "aws_rds_cluster.*.deletion_protection",
    # Azure
    "azurerm_network_security_group.*.security_rule",
    "azurerm_network_security_rule.*",
    "azurerm_role_assignment.*",
    "azurerm_role_definition.*.permissions",
    "azurerm_key_vault_access_policy.*",
    # azurerm_storage_account: support both AzureRM 2.x and 3.x attribute names
    "azurerm_storage_account.*.allow_blob_public_access",
    "azurerm_storage_account.*.allow_nested_items_to_be_public",
    "azurerm_storage_account.*.network_rules",
    "azurerm_storage_account_network_rules.*.default_action",
    # GCP — IAM (both iam_binding and iam_member variants)
    "google_compute_firewall.*.allow",
    "google_compute_firewall.*.deny",
    "google_compute_firewall.*.source_ranges",
    "google_project_iam_binding.*",
    "google_project_iam_member.*",
    "google_storage_bucket_iam_binding.*",
    "google_storage_bucket_iam_member.*",
    "google_kms_crypto_key_iam_binding.*",
    "google_kms_crypto_key_iam_member.*",
    "google_service_account_iam_member.*",
    "google_service_account_iam_binding.*",
    # GCP — nested: SQL authorized networks opened to 0.0.0.0/0
    "google_sql_database_instance.*.settings.ip_configuration.authorized_networks",
]

DEFAULT_HIGH_PATTERNS = [
    # AWS EC2
    "aws_instance.*.instance_type",
    "aws_instance.*.ami",
    "aws_instance.*.user_data",
    # AWS EC2 — IMDSv2 enforcement (nested attribute path after plan JSON flattening)
    "aws_instance.*.metadata_options.http_tokens",
    # AWS RDS
    "aws_rds_instance.*.engine_version",
    "aws_rds_instance.*.publicly_accessible",
    "aws_rds_instance.*.storage_encrypted",
    "aws_db_instance.*.multi_az",
    "aws_db_instance.*.publicly_accessible",
    "aws_db_instance.*.storage_encrypted",
    # RDS backup loss is a persistence risk (High), not a security perimeter breach (Critical)
    "aws_db_instance.*.backup_retention_period",
    "aws_rds_cluster.*.backup_retention_period",
    "aws_rds_cluster.*.engine_version",
    # AWS S3 — encryption
    "aws_s3_bucket.*.versioning",
    "aws_s3_bucket.*.server_side_encryption_configuration",
    "aws_s3_bucket_server_side_encryption_configuration.*",
    # AWS EBS encryption
    "aws_ebs_encryption_by_default.*.enabled",
    # AWS Lambda
    "aws_lambda_function.*.runtime",
    "aws_lambda_function.*.environment",
    "aws_lambda_function_url.*.authorization_type",
    # AWS ECS
    "aws_ecs_task_definition.*.container_definitions",
    "aws_ecs_task_definition.*.task_role_arn",
    "aws_ecs_task_definition.*.execution_role_arn",
    # AWS EKS
    "aws_eks_cluster.*.version",
    "aws_eks_node_group.*.instance_types",
    "aws_eks_node_group.*.ami_type",
    # AWS load balancer / TLS
    "aws_lb_listener.*.ssl_policy",
    # AWS CloudFront — top-level key and nested minimum_protocol_version
    "aws_cloudfront_distribution.*.viewer_certificate",
    "aws_cloudfront_distribution.*.viewer_certificate.minimum_protocol_version",
    # AWS ElastiCache
    "aws_elasticache_cluster.*.engine_version",
    "aws_elasticache_replication_group.*.automatic_failover_enabled",
    # Azure — VM sizes
    "azurerm_virtual_machine.*.vm_size",
    "azurerm_linux_virtual_machine.*.size",
    "azurerm_windows_virtual_machine.*.size",
    # Azure — SQL
    "azurerm_sql_server.*.administrator_login_password",
    "azurerm_mssql_server.*",
    "azurerm_mssql_firewall_rule.*",
    # Azure — storage TLS: support both AzureRM 2.x and 3.x attribute names
    "azurerm_storage_account.*.enable_https_traffic_only",
    "azurerm_storage_account.*.https_traffic_only_enabled",
    "azurerm_storage_account.*.min_tls_version",
    # Azure — key vault
    "azurerm_key_vault.*.purge_protection_enabled",
    # Azure — web / app service
    "azurerm_linux_web_app.*.https_only",
    "azurerm_windows_web_app.*.https_only",
    # Azure — AKS
    "azurerm_kubernetes_cluster.*.kubernetes_version",
    "azurerm_kubernetes_cluster.*.api_server_access_profile",
    # Azure — security & compliance
    "azurerm_security_center_subscription_pricing.*.tier",
    "azurerm_postgresql_flexible_server_firewall_rule.*",
    "azurerm_monitor_diagnostic_setting.*.enabled_log",
    "azurerm_linux_virtual_machine.*.disable_password_authentication",
    # GCP — compute
    "google_compute_instance.*.machine_type",
    "google_compute_instance.*.boot_disk",
    # GCP — compute nested attributes
    "google_compute_instance.*.service_account.scopes",
    "google_compute_firewall.*.disabled",
    "google_compute_subnetwork.*.log_config",
    "google_compute_project_metadata_item.*",
    # GCP — SQL
    "google_sql_database_instance.*.database_version",
    "google_sql_database_instance.*.settings.ip_configuration.ssl_mode",
    # GCP — GKE
    "google_container_cluster.*.min_master_version",
    "google_container_cluster.*.master_authorized_networks_config",
    # GCP — storage
    "google_storage_bucket.*.uniform_bucket_level_access",
    "google_storage_bucket.*.public_access_prevention",
    # GCP — KMS
    "google_kms_crypto_key.*.rotation_period",
]

DEFAULT_MEDIUM_PATTERNS = [
    # AWS Lambda — concurrency limits affect availability but aren't security issues
    "aws_lambda_function.*.reserved_concurrent_executions",
    "aws_lambda_function.*.timeout",
    "aws_lambda_function.*.memory_size",
    # AWS EKS — scaling changes affect cost/capacity but not directly security
    "aws_eks_node_group.*.scaling_config",
    # AWS Autoscaling — min/max affect availability guarantees
    "aws_autoscaling_group.*.min_size",
    "aws_autoscaling_group.*.max_size",
    # AWS ECS — task count changes are operational but not critical
    "aws_ecs_service.*.desired_count",
    # AWS ElastiCache
    "aws_elasticache_cluster.*.num_cache_nodes",
    # Azure
    "azurerm_linux_virtual_machine_scale_set.*.sku",
    "azurerm_windows_virtual_machine_scale_set.*.sku",
]

DEFAULT_LOW_PATTERNS = [
    "*.tags",
    "*.tags.*",
    "*.labels",
    "*.labels.*",
    "*.description",
    # Autoscaling desired count is operational noise in most environments
    "aws_autoscaling_group.*.desired_capacity",
    "aws_ecs_service.*.health_check_grace_period_seconds",
]


def _pattern_matches(pattern: str, target: str) -> bool:
    """Return True if target matches pattern.

    Patterns starting with 'regex:' are treated as regular expressions
    anchored to the full string. All other patterns use fnmatch.
    """
    if pattern.startswith(_REGEX_PREFIX):
        expr = pattern[len(_REGEX_PREFIX):]
        try:
            return bool(re.fullmatch(expr, target))
        except re.error:
            return False
    return fnmatch.fnmatch(target, pattern)


@dataclass
class SeverityClassifier:
    """Classifies drift severity based on resource type and changed attributes."""

    critical_patterns: list[str] = field(
        default_factory=lambda: list(DEFAULT_CRITICAL_PATTERNS)
    )
    high_patterns: list[str] = field(
        default_factory=lambda: list(DEFAULT_HIGH_PATTERNS)
    )
    medium_patterns: list[str] = field(
        default_factory=lambda: list(DEFAULT_MEDIUM_PATTERNS)
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
        """Match a resource.attribute pattern against severity rules.

        Patterns prefixed with 'regex:' are compiled as regular expressions.
        All other patterns use fnmatch glob syntax.
        """
        for pattern in self.critical_patterns:
            if _pattern_matches(pattern, target):
                return Severity.CRITICAL

        for pattern in self.high_patterns:
            if _pattern_matches(pattern, target):
                return Severity.HIGH

        for pattern in self.medium_patterns:
            if _pattern_matches(pattern, target):
                return Severity.MEDIUM

        for pattern in self.low_patterns:
            if _pattern_matches(pattern, target):
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
        if "medium" in severity_config:
            kwargs["medium_patterns"] = (
                list(DEFAULT_MEDIUM_PATTERNS) + severity_config["medium"]
            )
        if "low" in severity_config:
            kwargs["low_patterns"] = (
                list(DEFAULT_LOW_PATTERNS) + severity_config["low"]
            )
        return cls(**kwargs)
