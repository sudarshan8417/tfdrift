"""Tests for the severity classification engine."""
from tfdrift.models import AttributeChange, ChangeAction, DriftedResource, Severity
from tfdrift.severity import SeverityClassifier


def _resource(resource_type: str, name: str, attribute: str) -> DriftedResource:
    return DriftedResource(
        address=f"{resource_type}.{name}",
        resource_type=resource_type,
        resource_name=name,
        action=ChangeAction.UPDATE,
        changes=[AttributeChange(attribute=attribute, old_value="old", new_value="new")],
    )


class TestCriticalPatterns:
    def setup_method(self):
        self.clf = SeverityClassifier()

    def test_security_group_ingress(self):
        r = _resource("aws_security_group", "web", "ingress")
        assert self.clf.classify(r) == Severity.CRITICAL

    def test_iam_role_assume_policy(self):
        r = _resource("aws_iam_role", "lambda_exec", "assume_role_policy")
        assert self.clf.classify(r) == Severity.CRITICAL

    def test_s3_bucket_public_access_block(self):
        r = _resource("aws_s3_bucket_public_access_block", "my_bucket", "block_public_acls")
        assert self.clf.classify(r) == Severity.CRITICAL

    def test_rds_deletion_protection(self):
        r = _resource("aws_db_instance", "prod_db", "deletion_protection")
        assert self.clf.classify(r) == Severity.CRITICAL

    def test_rds_backup_retention(self):
        # backup_retention_period is a persistence risk (High), not a perimeter breach
        r = _resource("aws_db_instance", "prod_db", "backup_retention_period")
        assert self.clf.classify(r) == Severity.HIGH

    def test_rds_cluster_deletion_protection(self):
        r = _resource("aws_rds_cluster", "aurora_prod", "deletion_protection")
        assert self.clf.classify(r) == Severity.CRITICAL

    def test_gcp_firewall_allow(self):
        r = _resource("google_compute_firewall", "allow_http", "allow")
        assert self.clf.classify(r) == Severity.CRITICAL


class TestHighPatterns:
    def setup_method(self):
        self.clf = SeverityClassifier()

    def test_ec2_instance_type(self):
        r = _resource("aws_instance", "web", "instance_type")
        assert self.clf.classify(r) == Severity.HIGH

    def test_rds_multi_az(self):
        r = _resource("aws_db_instance", "prod_db", "multi_az")
        assert self.clf.classify(r) == Severity.HIGH

    def test_rds_publicly_accessible(self):
        r = _resource("aws_db_instance", "prod_db", "publicly_accessible")
        assert self.clf.classify(r) == Severity.HIGH

    def test_ecs_task_container_definitions(self):
        r = _resource("aws_ecs_task_definition", "api", "container_definitions")
        assert self.clf.classify(r) == Severity.HIGH

    def test_eks_node_group_instance_types(self):
        r = _resource("aws_eks_node_group", "workers", "instance_types")
        assert self.clf.classify(r) == Severity.HIGH

    def test_lambda_runtime(self):
        r = _resource("aws_lambda_function", "processor", "runtime")
        assert self.clf.classify(r) == Severity.HIGH

    def test_eks_cluster_version(self):
        r = _resource("aws_eks_cluster", "prod", "version")
        assert self.clf.classify(r) == Severity.HIGH


class TestMediumPatterns:
    def setup_method(self):
        self.clf = SeverityClassifier()

    def test_lambda_timeout(self):
        r = _resource("aws_lambda_function", "processor", "timeout")
        assert self.clf.classify(r) == Severity.MEDIUM

    def test_lambda_memory_size(self):
        r = _resource("aws_lambda_function", "processor", "memory_size")
        assert self.clf.classify(r) == Severity.MEDIUM

    def test_lambda_reserved_concurrency(self):
        r = _resource("aws_lambda_function", "processor", "reserved_concurrent_executions")
        assert self.clf.classify(r) == Severity.MEDIUM

    def test_eks_node_group_scaling_config(self):
        r = _resource("aws_eks_node_group", "workers", "scaling_config")
        assert self.clf.classify(r) == Severity.MEDIUM

    def test_asg_min_size(self):
        r = _resource("aws_autoscaling_group", "web_asg", "min_size")
        assert self.clf.classify(r) == Severity.MEDIUM

    def test_asg_max_size(self):
        r = _resource("aws_autoscaling_group", "web_asg", "max_size")
        assert self.clf.classify(r) == Severity.MEDIUM

    def test_ecs_desired_count_is_medium(self):
        r = _resource("aws_ecs_service", "api", "desired_count")
        assert self.clf.classify(r) == Severity.MEDIUM


class TestLowPatterns:
    def setup_method(self):
        self.clf = SeverityClassifier()

    def test_tags(self):
        r = _resource("aws_instance", "web", "tags")
        assert self.clf.classify(r) == Severity.LOW

    def test_nested_tags(self):
        r = _resource("aws_instance", "web", "tags.Name")
        assert self.clf.classify(r) == Severity.LOW

    def test_description(self):
        r = _resource("aws_security_group", "web", "description")
        assert self.clf.classify(r) == Severity.LOW

    def test_asg_desired_capacity(self):
        r = _resource("aws_autoscaling_group", "web_asg", "desired_capacity")
        assert self.clf.classify(r) == Severity.LOW


class TestNewCriticalPatterns:
    """Patterns added in the multi-cloud pattern expansion."""

    def setup_method(self):
        self.clf = SeverityClassifier()

    def test_iam_role_policy_attachment(self):
        r = _resource("aws_iam_role_policy_attachment", "admin", "policy_arn")
        assert self.clf.classify(r) == Severity.CRITICAL

    def test_s3_bucket_acl(self):
        r = _resource("aws_s3_bucket_acl", "my_bucket", "acl")
        assert self.clf.classify(r) == Severity.CRITICAL

    def test_kms_key_policy_attr_name(self):
        # Terraform attribute is 'policy', not 'key_policy'
        r = _resource("aws_kms_key", "cmk", "policy")
        assert self.clf.classify(r) == Severity.CRITICAL

    def test_cloudtrail_logging(self):
        r = _resource("aws_cloudtrail", "trail", "enable_logging")
        assert self.clf.classify(r) == Severity.CRITICAL

    def test_guardduty_detector(self):
        r = _resource("aws_guardduty_detector", "main", "enable")
        assert self.clf.classify(r) == Severity.CRITICAL

    def test_sns_topic_policy(self):
        r = _resource("aws_sns_topic_policy", "topic", "policy")
        assert self.clf.classify(r) == Severity.CRITICAL

    def test_sqs_queue_policy(self):
        r = _resource("aws_sqs_queue_policy", "queue", "policy")
        assert self.clf.classify(r) == Severity.CRITICAL

    def test_azure_storage_account_network_rules_resource(self):
        r = _resource("azurerm_storage_account_network_rules", "rules", "default_action")
        assert self.clf.classify(r) == Severity.CRITICAL

    def test_azure_storage_allow_nested_public(self):
        # AzureRM 3.x renamed allow_blob_public_access
        r = _resource("azurerm_storage_account", "sa", "allow_nested_items_to_be_public")
        assert self.clf.classify(r) == Severity.CRITICAL

    def test_gcp_storage_bucket_iam_member(self):
        r = _resource("google_storage_bucket_iam_member", "bucket", "member")
        assert self.clf.classify(r) == Severity.CRITICAL

    def test_gcp_kms_crypto_key_iam_member(self):
        r = _resource("google_kms_crypto_key_iam_member", "key", "member")
        assert self.clf.classify(r) == Severity.CRITICAL

    def test_gcp_service_account_iam_member(self):
        r = _resource("google_service_account_iam_member", "sa", "role")
        assert self.clf.classify(r) == Severity.CRITICAL

    def test_gcp_sql_nested_authorized_networks(self):
        # Nested path emitted after _flatten_changes walks the settings dict
        r = _resource(
            "google_sql_database_instance",
            "db",
            "settings.ip_configuration.authorized_networks",
        )
        assert self.clf.classify(r) == Severity.CRITICAL


class TestNewHighPatterns:
    """High-severity patterns added in the multi-cloud expansion."""

    def setup_method(self):
        self.clf = SeverityClassifier()

    def test_lambda_function_url_auth(self):
        r = _resource("aws_lambda_function_url", "fn", "authorization_type")
        assert self.clf.classify(r) == Severity.HIGH

    def test_lb_listener_ssl_policy(self):
        r = _resource("aws_lb_listener", "https", "ssl_policy")
        assert self.clf.classify(r) == Severity.HIGH

    def test_s3_sse_config_resource(self):
        r = _resource("aws_s3_bucket_server_side_encryption_configuration", "bucket", "rule")
        assert self.clf.classify(r) == Severity.HIGH

    def test_ebs_encryption_by_default(self):
        r = _resource("aws_ebs_encryption_by_default", "main", "enabled")
        assert self.clf.classify(r) == Severity.HIGH

    def test_imdsv2_nested_path(self):
        r = _resource("aws_instance", "web", "metadata_options.http_tokens")
        assert self.clf.classify(r) == Severity.HIGH

    def test_cloudfront_nested_tls_version(self):
        r = _resource(
            "aws_cloudfront_distribution",
            "cdn",
            "viewer_certificate.minimum_protocol_version",
        )
        assert self.clf.classify(r) == Severity.HIGH

    def test_azure_storage_tls_new_attr_name(self):
        # AzureRM 3.x uses https_traffic_only_enabled
        r = _resource("azurerm_storage_account", "sa", "https_traffic_only_enabled")
        assert self.clf.classify(r) == Severity.HIGH

    def test_azure_storage_min_tls(self):
        r = _resource("azurerm_storage_account", "sa", "min_tls_version")
        assert self.clf.classify(r) == Severity.HIGH

    def test_azure_key_vault_purge_protection(self):
        r = _resource("azurerm_key_vault", "kv", "purge_protection_enabled")
        assert self.clf.classify(r) == Severity.HIGH

    def test_azure_mssql_server(self):
        r = _resource("azurerm_mssql_server", "sql", "public_network_access_enabled")
        assert self.clf.classify(r) == Severity.HIGH

    def test_azure_mssql_firewall_rule(self):
        r = _resource("azurerm_mssql_firewall_rule", "fw", "end_ip_address")
        assert self.clf.classify(r) == Severity.HIGH

    def test_azure_linux_web_app_https(self):
        r = _resource("azurerm_linux_web_app", "app", "https_only")
        assert self.clf.classify(r) == Severity.HIGH

    def test_azure_aks_api_server_profile(self):
        r = _resource("azurerm_kubernetes_cluster", "aks", "api_server_access_profile")
        assert self.clf.classify(r) == Severity.HIGH

    def test_azure_security_center_pricing(self):
        r = _resource("azurerm_security_center_subscription_pricing", "sc", "tier")
        assert self.clf.classify(r) == Severity.HIGH

    def test_azure_pg_firewall_rule(self):
        r = _resource(
            "azurerm_postgresql_flexible_server_firewall_rule", "fw", "end_ip_address"
        )
        assert self.clf.classify(r) == Severity.HIGH

    def test_azure_monitor_diagnostic_setting(self):
        r = _resource("azurerm_monitor_diagnostic_setting", "diag", "enabled_log")
        assert self.clf.classify(r) == Severity.HIGH

    def test_azure_vm_disable_password_auth(self):
        r = _resource("azurerm_linux_virtual_machine", "vm", "disable_password_authentication")
        assert self.clf.classify(r) == Severity.HIGH

    def test_gcp_kms_rotation_period(self):
        r = _resource("google_kms_crypto_key", "key", "rotation_period")
        assert self.clf.classify(r) == Severity.HIGH

    def test_gcp_compute_metadata_item(self):
        r = _resource("google_compute_project_metadata_item", "oslogin", "value")
        assert self.clf.classify(r) == Severity.HIGH

    def test_gcp_firewall_disabled(self):
        r = _resource("google_compute_firewall", "fw", "disabled")
        assert self.clf.classify(r) == Severity.HIGH

    def test_gcp_subnetwork_log_config(self):
        r = _resource("google_compute_subnetwork", "subnet", "log_config")
        assert self.clf.classify(r) == Severity.HIGH

    def test_gcp_storage_public_access_prevention(self):
        r = _resource("google_storage_bucket", "bucket", "public_access_prevention")
        assert self.clf.classify(r) == Severity.HIGH

    def test_gcp_gke_authorized_networks_config(self):
        r = _resource("google_container_cluster", "gke", "master_authorized_networks_config")
        assert self.clf.classify(r) == Severity.HIGH

    def test_gcp_compute_instance_service_account_scopes(self):
        r = _resource("google_compute_instance", "vm", "service_account.scopes")
        assert self.clf.classify(r) == Severity.HIGH

    def test_gcp_sql_nested_ssl_mode(self):
        r = _resource(
            "google_sql_database_instance",
            "db",
            "settings.ip_configuration.ssl_mode",
        )
        assert self.clf.classify(r) == Severity.HIGH


class TestNestedAttrFlattening:
    """Tests for _flatten_changes in drift.py."""

    def test_top_level_scalar(self):
        from tfdrift.detectors.drift import _flatten_changes
        result = _flatten_changes({"a": 1}, {"a": 2})
        assert result == [("a", 1, 2)]

    def test_nested_dict_emits_both_levels(self):
        from tfdrift.detectors.drift import _flatten_changes
        before = {"settings": {"tier": "small", "flag": False}}
        after = {"settings": {"tier": "small", "flag": True}}
        result = _flatten_changes(before, after)
        paths = [r[0] for r in result]
        assert "settings" in paths
        assert "settings.flag" in paths

    def test_deeply_nested_path(self):
        from tfdrift.detectors.drift import _flatten_changes
        before = {"settings": {"ip": {"ssl_mode": "ENCRYPTED"}}}
        after = {"settings": {"ip": {"ssl_mode": "UNENCRYPTED"}}}
        result = _flatten_changes(before, after)
        paths = [r[0] for r in result]
        assert "settings.ip.ssl_mode" in paths

    def test_unchanged_keys_excluded(self):
        from tfdrift.detectors.drift import _flatten_changes
        before = {"a": 1, "b": 2}
        after = {"a": 1, "b": 3}
        result = _flatten_changes(before, after)
        paths = [r[0] for r in result]
        assert "a" not in paths
        assert "b" in paths

    def test_is_sensitive_nested(self):
        from tfdrift.detectors.drift import _is_sensitive
        sensitive = {"settings": {"password": True}}
        assert _is_sensitive(sensitive, "settings.password") is True
        assert _is_sensitive(sensitive, "settings.tier") is False
        assert _is_sensitive(sensitive, "other") is False


class TestFromConfig:
    def test_medium_patterns_merged_from_config(self):
        clf = SeverityClassifier.from_config({
            "severity": {
                "medium": ["aws_sqs_queue.*.visibility_timeout_seconds"]
            }
        })
        r = _resource("aws_sqs_queue", "my_queue", "visibility_timeout_seconds")
        assert clf.classify(r) == Severity.MEDIUM
