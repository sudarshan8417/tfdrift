# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.5] - 2026-10-19

### Added
- **~30 new severity patterns** covering previously missed AWS, Azure, and GCP resources:
  AWS: `aws_iam_role_policy_attachment`, `aws_s3_bucket_acl`, `aws_cloudtrail`, `aws_guardduty_detector`,
  `aws_sns_topic_policy`, `aws_sqs_queue_policy`, `aws_lambda_function_url`, `aws_lb_listener`,
  `aws_s3_bucket_server_side_encryption_configuration`, `aws_ebs_encryption_by_default`;
  Azure: `azurerm_mssql_server`, `azurerm_mssql_firewall_rule`, `azurerm_linux_web_app`,
  `azurerm_key_vault` (purge_protection), `azurerm_security_center_subscription_pricing`,
  `azurerm_postgresql_flexible_server_firewall_rule`, `azurerm_monitor_diagnostic_setting`,
  `azurerm_storage_account_network_rules`, `azurerm_kubernetes_cluster` (api_server_access_profile),
  `azurerm_linux_virtual_machine` (disable_password_authentication);
  GCP: `google_storage_bucket_iam_member`, `google_kms_crypto_key_iam_member`,
  `google_service_account_iam_member`, `google_kms_crypto_key` (rotation_period),
  `google_compute_project_metadata_item`, `google_compute_firewall` (disabled),
  `google_compute_subnetwork` (log_config), `google_storage_bucket` (public_access_prevention),
  `google_container_cluster` (master_authorized_networks_config)
- **Nested attribute detection** in `parse_plan_changes` — the plan diff now walks into nested
  dicts and emits dot-separated paths (e.g. `settings.ip_configuration.authorized_networks`)
  alongside the top-level key, allowing fine-grained patterns to target deep attributes
- New Critical patterns for GCP nested SQL network rules
- New High patterns for AWS IMDSv2 (`metadata_options.http_tokens`), CloudFront TLS version,
  and GCP SQL SSL mode and Compute service-account scopes

### Fixed
- `aws_kms_key` pattern corrected from `key_policy` to `policy` (Terraform attribute name)
- Azure `azurerm_storage_account` patterns updated for AzureRM 3.x attribute renames:
  `allow_nested_items_to_be_public` (was `allow_blob_public_access`) and
  `https_traffic_only_enabled` (was `enable_https_traffic_only`) — both old and new names
  are now recognised so existing deployments continue to work

### Changed
- `aws_db_instance.*.backup_retention_period` and `aws_rds_cluster.*.backup_retention_period`
  reclassified from Critical to High — backup loss is a persistence/availability risk, not a
  security-perimeter breach

## [0.5.4] - 2026-10-08

### Added
- GitHub Actions Marketplace action (`action.yml`) — drop `uses: sudarshan8417/tfdrift@v1`
  into any workflow; handles Python setup, install, scan, PR annotations, step summary,
  and SARIF upload in one step with no boilerplate
- `--sarif-output` flag on `tfdrift scan` — write a SARIF 2.1.0 file alongside the primary
  output format in a single scan run, avoiding a redundant `terraform plan` invocation in CI
- Action exposes `drift-count` and `has-drift` outputs for conditional downstream steps
- Two ready-to-use example workflows: scheduled scan with Code Scanning upload and a PR gate
  that blocks merges on high+ severity drift

## [0.5.3] - 2026-09-14

### Added
- SARIF 2.1.0 output format (`--format sarif`) for `tfdrift scan` — upload the result
  with `github/codeql-action/upload-sarif` to surface drift as native GitHub Code Scanning
  alerts in pull requests and the Security tab
- Five severity-mapped SARIF rules (TFD001–TFD005): critical/high emit `error` level,
  medium emits `warning`, low/info emit `note`
- `partialFingerprints` on each result for stable cross-scan deduplication in GitHub
- `--format sarif` respected by `--output` to write `results.sarif` directly to disk

## [0.5.1] - 2026-08-02

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
