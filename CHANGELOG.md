# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `tfdrift diff` command — compare two JSON scan reports to show new, resolved, and persisting drift; `--fail-on-new` flag exits 1 on net-new drift (ideal for CI gate)
- `--exclude-resource` flag on `scan` — exclude resources matching a glob pattern from output (e.g. `--exclude-resource "aws_autoscaling*"`)
- Explicit `medium` severity tier in the classifier with patterns for Lambda timeout/memory/concurrency, EKS node group scaling, ASG min/max size, and ECS desired count
- New `critical` patterns for RDS/Aurora `deletion_protection` and `backup_retention_period`
- New `high` patterns for ECS task definitions, EKS node group instance types, and RDS multi-AZ / publicly accessible
- `medium` severity block now configurable in `.tfdrift.yml` under `severity.medium`

## [0.5.0] - 2026-07-26

### Added
- Microsoft Teams Incoming Webhook notification support — `--teams-webhook` flag on `scan` and `watch`, plus `notifications.teams` config block in `.tfdrift.yml`
- Teams alerts use the MessageCard format with severity-colored theme, a summary section, and up to 10 individual drifted resource facts
- OpsGenie Alerts API v2 notification support — `--opsgenie-key` flag on `scan` and `watch`, plus `notifications.opsgenie` config block in `.tfdrift.yml`
- OpsGenie alerts map tfdrift severity to OpsGenie priorities (critical→P1, high→P2, medium→P3, low→P4) and support both US and EU API regions

## [0.2.3] - 2026-06-07

### Added
- `--format csv` output for `tfdrift scan` — one row per drifted resource, pipe-separated multi-attribute columns, compatible with Excel/Sheets/pandas
- Error workspaces appear as a dedicated row in CSV output with `severity=error`
- `--min-severity` filter applies to CSV output the same as table and markdown
- `--min-severity` flag for `tfdrift watch` — filters the live table the same way as `scan`

### Changed
- PyPI classifier bumped from Alpha to Beta

## [0.2.2] - 2026-05-28

### Added
- `--min-severity` filter for `tfdrift scan` — only report drift at or above the specified level (info/low/medium/high/critical)
- Total scan duration displayed in table output summary
- Before/after values shown in Markdown report change column (previously attribute names only)

### Fixed
- `--interval` in `tfdrift watch` now validates the format and surfaces a clear error for invalid values
- Workspace block skipped in table output when all resources are filtered out by `--min-severity`
- User-Agent header updated to reflect current version

## [0.2.1] - 2026-05-14

### Added
- Watch mode clears the terminal between scans and shows a live header with scan count and timestamp
- Before/after values shown in table output change column (previously only attribute names were listed)

### Changed
- Severity ranking, deduplication logic, and notification helpers refactored for clarity

## [0.2.0] - 2026-05-01

### Added
- PagerDuty Events API v2 notification support
- HTML report generation (`tfdrift report` command)
- Azure and GCP severity classification rules
- `--max-depth` flag to limit workspace discovery depth
- `--exit-on-error` flag to stop scanning on first workspace error
- `--quiet` flag for CI/CD pipelines (suppresses all output except errors)
- Dockerfile for containerized usage

## [0.1.1] - 2026-04-21

### Added
- `--var-file` flag to pass .tfvars files to terraform plan
- `--var` flag to pass individual variables to terraform plan
- Auto-detection of .tfvars files in workspace directories
- `auto_detect_var_files` configuration option in .tfdrift.yml
- `var_files` and `vars` configuration options in .tfdrift.yml

### Fixed
- Workspaces with required variables no longer fail silently
- mypy type checking errors resolved

## [0.1.0] - 2026-04-19

### Added
- Initial release of tfdrift
- Multi-workspace Terraform drift detection
- Severity classification engine with 30+ built-in AWS rules
- `tfdrift scan` command with table, JSON, and Markdown output
- `tfdrift watch` command for continuous monitoring
- `tfdrift init` command for configuration scaffolding
- Slack and webhook notification support
- Auto-remediation with safety guards
- `.tfdriftignore` file support
- `.tfdrift.yml` configuration file support
- GitHub Actions CI/CD workflow
- Exit codes for CI/CD integration (0=clean, 1=drift, 2=error, 3=remediated)
