"""tfdrift CLI — Terraform drift detection, reporting, and remediation."""

from __future__ import annotations

import logging
import sys
import time

import click
from rich.console import Console

from tfdrift.config import TfdriftConfig, load_config
from tfdrift.detectors.drift import run_scan
from tfdrift.models import ScanReport
from tfdrift.remediators.fix import remediate_report
from tfdrift.reporters.output import (
    notify_pagerduty,
    notify_slack,
    notify_webhook,
    report_html,
    report_json,
    report_markdown,
    report_table,
)

console = Console()


def setup_logging(verbose: bool = False, quiet: bool = False) -> None:
    if quiet:
        level = logging.ERROR
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


@click.group()
@click.version_option(version="0.2.0", prog_name="tfdrift")
def main():
    """tfdrift — Continuous Terraform drift detection and remediation."""
    pass


@main.command()
@click.option(
    "--path", "-p", default=".",
    help="Root path to scan for Terraform workspaces",
)
@click.option(
    "--format", "-f", "output_format",
    type=click.Choice(["table", "json", "markdown"]),
    default="table", help="Output format",
)
@click.option(
    "--output", "-o", "output_path",
    default=None, help="Write report to file",
)
@click.option(
    "--config", "-c", "config_path",
    default=None, help="Path to .tfdrift.yml",
)
@click.option(
    "--auto-fix", is_flag=True, default=False,
    help="Auto-remediate detected drift",
)
@click.option(
    "--confirm", is_flag=True, default=False,
    help="Confirm auto-remediation (required with --auto-fix)",
)
@click.option(
    "--dry-run", is_flag=True, default=False,
    help="Show what would be fixed without applying",
)
@click.option(
    "--env", default=None,
    help="Environment name (for remediation safety checks)",
)
@click.option(
    "--slack-webhook", default=None,
    help="Slack webhook URL for notifications",
)
@click.option(
    "--var-file", "var_files", multiple=True,
    help="Path to .tfvars file (can be specified multiple times)",
)
@click.option(
    "--var", "cli_vars", multiple=True,
    help="Variable in key=value format (can be specified multiple times)",
)
@click.option(
    "--quiet", "-q", is_flag=True, default=False,
    help="Suppress all output except errors. Useful for CI/CD",
)
@click.option(
    "--max-depth", default=None, type=int,
    help="Max directory depth for workspace discovery",
)
@click.option(
    "--exit-on-error", is_flag=True, default=False,
    help="Stop scanning immediately when a workspace errors",
)
@click.option(
    "--binary", default=None,
    help="Path to terraform/tofu binary (e.g., --binary tofu)",
)
@click.option(
    "--verbose", "-v", is_flag=True, default=False,
    help="Enable verbose logging",
)
def scan(
    path: str,
    output_format: str,
    output_path: str | None,
    config_path: str | None,
    auto_fix: bool,
    confirm: bool,
    dry_run: bool,
    env: str | None,
    slack_webhook: str | None,
    var_files: tuple[str, ...],
    cli_vars: tuple[str, ...],
    quiet: bool,
    max_depth: int | None,
    exit_on_error: bool,
    binary: str | None,
    verbose: bool,
) -> None:
    """Scan Terraform workspaces for infrastructure drift."""
    setup_logging(verbose, quiet)

    config = load_config(config_path=config_path, base_dir=path)

    # CLI overrides
    if var_files:
        config.var_files = list(var_files)
    if cli_vars:
        for var_str in cli_vars:
            if "=" in var_str:
                key, value = var_str.split("=", 1)
                config.vars[key] = value
    if max_depth is not None:
        config.max_depth = max_depth
    if exit_on_error:
        config.exit_on_error = True
    if binary:
        config.terraform_binary = binary

    # Run scan
    if quiet:
        report = run_scan(config, base_dir=path)
    else:
        with console.status("[bold]Scanning for drift...", spinner="dots"):
            report = run_scan(config, base_dir=path)

    # Output
    if not quiet:
        if output_format == "table":
            report_table(report, console)
        elif output_format == "json":
            json_output = report_json(report, output_path)
            if not output_path:
                console.print(json_output)
        elif output_format == "markdown":
            md_output = report_markdown(report, output_path)
            if not output_path:
                console.print(md_output)
        if output_path and output_format != "table":
            console.print(f"📄 Report written to {output_path}")
    elif output_path:
        if output_format == "json":
            report_json(report, output_path)
        elif output_format == "markdown":
            report_markdown(report, output_path)

    # Notifications
    _send_notifications(report, config, slack_webhook)

    # Auto-remediation
    if auto_fix and report.has_drift:
        _handle_remediation(report, config, env, confirm, dry_run, quiet)

    # Exit codes
    if report.has_drift:
        sys.exit(1)
    elif report.errors:
        sys.exit(2)
    else:
        sys.exit(0)


@main.command()
@click.option("--path", "-p", default=".", help="Root path to scan")
@click.option(
    "--interval", "-i", default="30m",
    help="Scan interval (e.g., 5m, 1h, 30s)",
)
@click.option(
    "--config", "-c", "config_path",
    default=None, help="Path to .tfdrift.yml",
)
@click.option("--slack-webhook", default=None, help="Slack webhook URL")
@click.option(
    "--binary", default=None,
    help="Path to terraform/tofu binary",
)
@click.option(
    "--verbose", "-v", is_flag=True, default=False,
    help="Enable verbose logging",
)
def watch(
    path: str,
    interval: str,
    config_path: str | None,
    slack_webhook: str | None,
    binary: str | None,
    verbose: bool,
) -> None:
    """Continuously monitor for drift at a set interval."""
    setup_logging(verbose)

    seconds = _parse_interval(interval)
    config = load_config(config_path=config_path, base_dir=path)

    if slack_webhook:
        config.notifications.slack_webhook_url = slack_webhook
    if binary:
        config.terraform_binary = binary

    console.print(
        f"👀 Watching for drift every {interval} (Ctrl+C to stop)\n",
        style="bold",
    )

    scan_count = 0
    try:
        while True:
            scan_count += 1
            console.print(f"--- Scan #{scan_count} ---", style="dim")

            report = run_scan(config, base_dir=path)
            report_table(report, console)

            if report.has_drift:
                _send_notifications(report, config, None)

            console.print(f"\nNext scan in {interval}...\n", style="dim")
            time.sleep(seconds)

    except KeyboardInterrupt:
        console.print("\n\n👋 Watch mode stopped.", style="bold")


@main.command()
@click.option("--path", "-p", default=".", help="Root path to scan")
@click.option(
    "--output", "-o", "output_path",
    default="drift-report.html", help="Output HTML file",
)
@click.option(
    "--config", "-c", "config_path",
    default=None, help="Path to .tfdrift.yml",
)
@click.option(
    "--binary", default=None,
    help="Path to terraform/tofu binary",
)
@click.option(
    "--verbose", "-v", is_flag=True, default=False,
    help="Enable verbose logging",
)
def report(
    path: str,
    output_path: str,
    config_path: str | None,
    binary: str | None,
    verbose: bool,
) -> None:
    """Generate an HTML drift report."""
    setup_logging(verbose)

    config = load_config(config_path=config_path, base_dir=path)
    if binary:
        config.terraform_binary = binary

    with console.status("[bold]Scanning for drift...", spinner="dots"):
        scan_report = run_scan(config, base_dir=path)

    report_html(scan_report, output_path)
    console.print(f"📄 HTML report written to {output_path}", style="green")

    if scan_report.has_drift:
        sys.exit(1)
    elif scan_report.errors:
        sys.exit(2)
    else:
        sys.exit(0)


@main.command()
@click.option("--path", "-p", default=".", help="Directory to initialize")
def init(path: str) -> None:
    """Create a starter .tfdrift.yml configuration file."""
    from pathlib import Path

    config_path = Path(path) / ".tfdrift.yml"

    if config_path.exists():
        console.print(f"⚠️  {config_path} already exists.", style="yellow")
        return

    starter_config = """\
# tfdrift configuration
# Docs: https://github.com/sudarshan8417/tfdrift

scan:
  paths:
    - .
  exclude:
    - "**/.terraform/**"
    - "**/test/**"
  # auto_detect_var_files: true
  # var_files:
  #   - terraform.tfvars
  # vars:
  #   environment: dev
  # max_depth: 3
  # exit_on_error: false

severity:
  critical:
    # - aws_security_group.*.ingress
    # - azurerm_network_security_group.*.security_rule
    # - google_compute_firewall.*.allow
  high:
    # - aws_instance.*.instance_type
    # - azurerm_virtual_machine.*.vm_size

notifications:
  slack:
    webhook_url: ${SLACK_WEBHOOK_URL}
    channel: "#infra-alerts"
    min_severity: high
  # pagerduty:
  #   routing_key: ${PAGERDUTY_ROUTING_KEY}
  #   min_severity: critical

remediation:
  auto_fix: false
  allowed_environments:
    - dev
    - staging
  require_approval: true
  max_changes: 5

# Use OpenTofu instead of Terraform:
# terraform_binary: tofu
"""
    config_path.write_text(starter_config)
    console.print(f"✅ Created {config_path}", style="green")
    console.print("Edit the file to customize your drift detection settings.")


# --- Internal helpers ---


def _send_notifications(
    report: ScanReport,  # noqa: F821
    config: TfdriftConfig,  # noqa: F821
    slack_webhook_override: str | None,
) -> None:
    """Send all configured notifications."""
    if not report.has_drift:
        return

    webhook_url = slack_webhook_override or (
        config.notifications.slack_webhook_url if config.notifications else None
    )
    if webhook_url:
        notify_slack(
            report,
            webhook_url,
            channel=(
                config.notifications.slack_channel
                if config.notifications else None
            ),
            min_severity=(
                config.notifications.slack_min_severity
                if config.notifications else "high"
            ),
        )

    if config.notifications and config.notifications.webhook_url:
        notify_webhook(
            report,
            config.notifications.webhook_url,
            config.notifications.webhook_method,
        )

    if config.notifications and config.notifications.pagerduty_routing_key:
        notify_pagerduty(
            report,
            config.notifications.pagerduty_routing_key,
            min_severity=config.notifications.pagerduty_min_severity,
        )


def _handle_remediation(
    report: ScanReport,  # noqa: F821
    config: TfdriftConfig,  # noqa: F821
    env: str | None,
    confirm: bool,
    dry_run: bool,
    quiet: bool,
) -> None:
    """Handle auto-remediation logic."""
    if not confirm and not dry_run:
        console.print(
            "\n⚠️  --auto-fix requires --confirm (or --dry-run) for safety.",
            style="bold yellow",
        )
        sys.exit(2)

    if not quiet:
        console.print("\n🔧 Auto-remediation:", style="bold")

    results = remediate_report(
        report,
        config.remediation,
        environment=env,
        dry_run=dry_run,
        terraform_binary=config.terraform_binary,
    )

    if not quiet:
        for r in results:
            if r.dry_run:
                console.print(
                    f"  [DRY RUN] Would fix {r.resources_fixed} "
                    f"resource(s) in {r.workspace_path}",
                    style="cyan",
                )
            elif r.success:
                console.print(
                    f"  ✅ Fixed {r.resources_fixed} "
                    f"resource(s) in {r.workspace_path}",
                    style="green",
                )
            elif r.skipped_reason:
                console.print(
                    f"  ⏭️  Skipped {r.workspace_path}: {r.skipped_reason}",
                    style="yellow",
                )
            else:
                console.print(
                    f"  ❌ Failed {r.workspace_path}: {r.error}",
                    style="red",
                )

    if any(r.success and not r.dry_run for r in results):
        sys.exit(3)


def _parse_interval(interval: str) -> int:
    """Parse an interval string like '30m', '1h', '30s' to seconds."""
    interval = interval.strip().lower()
    if interval.endswith("s"):
        return int(interval[:-1])
    elif interval.endswith("m"):
        return int(interval[:-1]) * 60
    elif interval.endswith("h"):
        return int(interval[:-1]) * 3600
    else:
        return int(interval)


if __name__ == "__main__":
    main()
