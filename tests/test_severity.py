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
        r = _resource("aws_db_instance", "prod_db", "backup_retention_period")
        assert self.clf.classify(r) == Severity.CRITICAL

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


class TestFromConfig:
    def test_medium_patterns_merged_from_config(self):
        clf = SeverityClassifier.from_config({
            "severity": {
                "medium": ["aws_sqs_queue.*.visibility_timeout_seconds"]
            }
        })
        r = _resource("aws_sqs_queue", "my_queue", "visibility_timeout_seconds")
        assert clf.classify(r) == Severity.MEDIUM
