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

    def test_fail_on_default_is_none(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config = load_config(base_dir=tmpdir)
            assert config.fail_on is None

    def test_fail_on_loaded_from_yaml(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / ".tfdrift.yml"
            config_file.write_text("scan:\n  fail_on: high\n")
            config = load_config(base_dir=tmpdir)
            assert config.fail_on == "high"

    def test_fail_on_critical_loaded_from_yaml(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / ".tfdrift.yml"
            config_file.write_text("scan:\n  fail_on: critical\n")
            config = load_config(base_dir=tmpdir)
            assert config.fail_on == "critical"

    def test_teams_webhook_defaults_to_none(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config = load_config(base_dir=tmpdir)
            assert config.notifications.teams_webhook_url is None
            assert config.notifications.teams_min_severity == "high"

    def test_teams_webhook_loaded_from_yaml(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / ".tfdrift.yml"
            config_file.write_text(
                "notifications:\n"
                "  teams:\n"
                "    webhook_url: https://example.webhook.office.com/abc\n"
                "    min_severity: critical\n"
            )
            config = load_config(base_dir=tmpdir)
            assert config.notifications.teams_webhook_url == "https://example.webhook.office.com/abc"
            assert config.notifications.teams_min_severity == "critical"

    def test_opsgenie_defaults_to_none(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config = load_config(base_dir=tmpdir)
            assert config.notifications.opsgenie_api_key is None
            assert config.notifications.opsgenie_min_severity == "high"
            assert config.notifications.opsgenie_region == "us"

    def test_opsgenie_loaded_from_yaml(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / ".tfdrift.yml"
            config_file.write_text(
                "notifications:\n"
                "  opsgenie:\n"
                "    api_key: abc-123\n"
                "    min_severity: critical\n"
                "    region: eu\n"
            )
            config = load_config(base_dir=tmpdir)
            assert config.notifications.opsgenie_api_key == "abc-123"
            assert config.notifications.opsgenie_min_severity == "critical"
            assert config.notifications.opsgenie_region == "eu"

    def test_opsgenie_api_key_env_var_expansion(self, monkeypatch):
        monkeypatch.setenv("OG_API_KEY", "env-key-xyz")
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / ".tfdrift.yml"
            config_file.write_text(
                "notifications:\n"
                "  opsgenie:\n"
                "    api_key: ${OG_API_KEY}\n"
            )
            config = load_config(base_dir=tmpdir)
            assert config.notifications.opsgenie_api_key == "env-key-xyz"

    def test_teams_webhook_env_var_expansion(self, monkeypatch):
        monkeypatch.setenv("TEAMS_WEBHOOK", "https://example.webhook.office.com/env")
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / ".tfdrift.yml"
            config_file.write_text(
                "notifications:\n"
                "  teams:\n"
                "    webhook_url: ${TEAMS_WEBHOOK}\n"
            )
            config = load_config(base_dir=tmpdir)
            assert config.notifications.teams_webhook_url == "https://example.webhook.office.com/env"
