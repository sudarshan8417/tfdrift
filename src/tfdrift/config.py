"""Configuration loader for tfdrift.

Loads settings from .tfdrift.yml and .tfdriftignore files.
"""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class IgnoreRule:
    """A rule for ignoring expected drift."""

    resource: str
    attribute: str | None = None

    def matches(self, resource_address: str, attribute: str | None = None) -> bool:
        """Check if this rule matches a given resource and attribute."""
        if not fnmatch.fnmatch(resource_address, self.resource):
            return False
        if self.attribute and attribute:
            return fnmatch.fnmatch(attribute, self.attribute)
        # If rule has no attribute filter, it matches all attributes
        return self.attribute is None


@dataclass
class NotificationConfig:
    """Notification settings."""

    slack_webhook_url: str | None = None
    slack_channel: str | None = None
    slack_min_severity: str = "high"
    webhook_url: str | None = None
    webhook_method: str = "POST"


@dataclass
class RemediationConfig:
    """Auto-remediation settings."""

    auto_fix: bool = False
    allowed_environments: list[str] = field(default_factory=list)
    require_approval: bool = True
    max_changes: int = 5


@dataclass
class TfdriftConfig:
    """Complete tfdrift configuration."""

    scan_paths: list[str] = field(default_factory=lambda: ["."])
    exclude_patterns: list[str] = field(
        default_factory=lambda: ["**/.terraform/**", "**/test/**"]
    )
    severity_config: dict = field(default_factory=dict)
    notifications: NotificationConfig = field(default_factory=NotificationConfig)
    remediation: RemediationConfig = field(default_factory=RemediationConfig)
    ignore_rules: list[IgnoreRule] = field(default_factory=list)
    terraform_binary: str = "terraform"

    def should_ignore(self, resource_address: str, attribute: str | None = None) -> bool:
        """Check if drift on a resource/attribute should be ignored."""
        return any(rule.matches(resource_address, attribute) for rule in self.ignore_rules)


def _expand_env_vars(value: str) -> str:
    """Expand environment variables in string values like ${VAR_NAME}."""
    if isinstance(value, str):
        return os.path.expandvars(value)
    return value


def _parse_ignore_rules_from_config(config: dict) -> list[IgnoreRule]:
    """Parse ignore rules from .tfdrift.yml config."""
    rules = []
    for entry in config.get("ignore", []):
        if isinstance(entry, dict):
            rules.append(
                IgnoreRule(
                    resource=entry.get("resource", "*"),
                    attribute=entry.get("attribute"),
                )
            )
        elif isinstance(entry, str):
            # Simple pattern: "aws_autoscaling_group.*.desired_capacity"
            parts = entry.rsplit(".", 1)
            if len(parts) == 2:
                rules.append(IgnoreRule(resource=parts[0], attribute=parts[1]))
            else:
                rules.append(IgnoreRule(resource=entry))
    return rules


def _parse_ignore_file(path: Path) -> list[IgnoreRule]:
    """Parse a .tfdriftignore file."""
    rules: list[IgnoreRule] = []
    if not path.exists():
        return rules

    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Pattern format: resource_type.name.attribute
        # e.g., aws_autoscaling_group.*.desired_capacity
        parts = line.rsplit(".", 1)
        if len(parts) == 2:
            rules.append(IgnoreRule(resource=parts[0], attribute=parts[1]))
        else:
            rules.append(IgnoreRule(resource=line))

    return rules


def load_config(config_path: str | None = None, base_dir: str = ".") -> TfdriftConfig:
    """Load tfdrift configuration from file and environment.

    Searches for .tfdrift.yml in the base directory if no explicit path given.
    Also loads .tfdriftignore if present.
    """
    base = Path(base_dir)
    raw_config: dict = {}

    # Find config file
    if config_path:
        config_file = Path(config_path)
    else:
        for name in [".tfdrift.yml", ".tfdrift.yaml", "tfdrift.yml", "tfdrift.yaml"]:
            candidate = base / name
            if candidate.exists():
                config_file = candidate
                break
        else:
            config_file = None

    # Parse YAML config
    if config_file and config_file.exists():
        with open(config_file) as f:
            raw_config = yaml.safe_load(f) or {}

    # Build config object
    scan_config = raw_config.get("scan", {})
    notif_config = raw_config.get("notifications", {})
    remed_config = raw_config.get("remediation", {})

    notifications = NotificationConfig(
        slack_webhook_url=_expand_env_vars(
            notif_config.get("slack", {}).get("webhook_url", "")
        )
        or None,
        slack_channel=notif_config.get("slack", {}).get("channel"),
        slack_min_severity=notif_config.get("slack", {}).get("min_severity", "high"),
        webhook_url=_expand_env_vars(
            notif_config.get("webhook", {}).get("url", "")
        )
        or None,
        webhook_method=notif_config.get("webhook", {}).get("method", "POST"),
    )

    remediation = RemediationConfig(
        auto_fix=remed_config.get("auto_fix", False),
        allowed_environments=remed_config.get("allowed_environments", []),
        require_approval=remed_config.get("require_approval", True),
        max_changes=remed_config.get("max_changes", 5),
    )

    # Collect ignore rules from both config and .tfdriftignore
    ignore_rules = _parse_ignore_rules_from_config(raw_config)
    ignore_rules.extend(_parse_ignore_file(base / ".tfdriftignore"))

    return TfdriftConfig(
        scan_paths=scan_config.get("paths", ["."]),
        exclude_patterns=scan_config.get(
            "exclude", ["**/.terraform/**", "**/test/**"]
        ),
        severity_config=raw_config.get("severity", {}),
        notifications=notifications,
        remediation=remediation,
        ignore_rules=ignore_rules,
        terraform_binary=raw_config.get("terraform_binary", "terraform"),
    )
