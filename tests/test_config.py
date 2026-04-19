"""Tests for tfdrift configuration loading."""

import tempfile
from pathlib import Path

from tfdrift.config import IgnoreRule, TfdriftConfig, load_config


class TestIgnoreRules:
    def test_exact_match(self):
        rule = IgnoreRule(resource="aws_instance.web", attribute="tags")
        assert rule.matches("aws_instance.web", "tags")
        assert not rule.matches("aws_instance.api", "tags")

    def test_wildcard_resource(self):
        rule = IgnoreRule(resource="aws_autoscaling_group.*", attribute="desired_capacity")
        assert rule.matches("aws_autoscaling_group.web", "desired_capacity")
        assert rule.matches("aws_autoscaling_group.api", "desired_capacity")
        assert not rule.matches("aws_autoscaling_group.web", "max_size")

    def test_resource_only(self):
        rule = IgnoreRule(resource="aws_autoscaling_group.*")
        assert rule.matches("aws_autoscaling_group.web")
        assert rule.matches("aws_autoscaling_group.web", "any_attribute")

    def test_wildcard_attribute(self):
        rule = IgnoreRule(resource="*", attribute="tags.*")
        assert rule.matches("aws_instance.web", "tags.Name")
        assert rule.matches("aws_s3_bucket.data", "tags.Env")


class TestConfig:
    def test_load_defaults(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config = load_config(base_dir=tmpdir)
            assert config.scan_paths == ["."]
            assert config.terraform_binary == "terraform"
            assert config.remediation.auto_fix is False
            assert config.remediation.max_changes == 5

    def test_load_yaml_config(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_content = """\
scan:
  paths:
    - ./infra
    - ./modules
  exclude:
    - "**/test/**"

remediation:
  auto_fix: true
  max_changes: 10
  allowed_environments:
    - dev

terraform_binary: tofu
"""
            config_file = Path(tmpdir) / ".tfdrift.yml"
            config_file.write_text(config_content)

            config = load_config(base_dir=tmpdir)
            assert config.scan_paths == ["./infra", "./modules"]
            assert config.remediation.auto_fix is True
            assert config.remediation.max_changes == 10
            assert config.remediation.allowed_environments == ["dev"]
            assert config.terraform_binary == "tofu"

    def test_load_ignore_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ignore_content = """\
# Autoscaling drift is expected
aws_autoscaling_group.*.desired_capacity
aws_ecs_service.*.desired_count

# Tags managed externally
*.tags
"""
            ignore_file = Path(tmpdir) / ".tfdriftignore"
            ignore_file.write_text(ignore_content)

            config = load_config(base_dir=tmpdir)
            assert len(config.ignore_rules) == 3
            assert config.should_ignore("aws_autoscaling_group.web", "desired_capacity")
            assert config.should_ignore("aws_ecs_service.api", "desired_count")
            assert not config.should_ignore("aws_instance.web", "instance_type")

    def test_should_ignore_combined(self):
        config = TfdriftConfig(
            ignore_rules=[
                IgnoreRule(resource="aws_autoscaling_group.*", attribute="desired_capacity"),
            ]
        )
        assert config.should_ignore("aws_autoscaling_group.web", "desired_capacity")
        assert not config.should_ignore("aws_autoscaling_group.web", "max_size")
        assert not config.should_ignore("aws_instance.web", "desired_capacity")
