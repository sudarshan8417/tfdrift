# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
