"""tfdrift CLI — Terraform drift detection, reporting, and remediation."""

from __future__ import annotations

import fnmatch
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path

import click
from rich.console import Console

from tfdrift.config import TfdriftConfig, load_config
from tfdrift.detectors.drift import run_scan
from tfdrift.history import (
    DEFAULT_DB_PATH,
    get_daily_summary,
    get_repeat_offenders,
    list_scans,
    save_scan,
)
from tfdrift.models import ScanReport, Severity, WorkspaceScanResult
from tfdrift.remediators.fix import remediate_report
from tfdrift.reporters.output import (
    notify_pagerduty,
    notify_slack,
    notify_webhook,
    report_csv,
    report_github_actions,
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
@click.version_option(version="0.2.5", prog_name="tfdrift")
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
    type=click.Choice(["table", "json", "markdown", "csv"]),
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
@click.option(
    "--min-severity",
    type=click.Choice(["info", "low", "medium", "high", "critical"]),
    default=None,
    help="Only report drift at or above this severity level",
)
@click.option(
    "--fail-on",
    type=click.Choice(["info", "low", "medium", "high", "critical"]),
    default=None,
    help="Only exit 1 when drift meets or exceeds this severity (default: any drift)",
)
@click.option(
    "--resource", "resource_filter", default=None,
    help="Filter output to resources matching this pattern (e.g. 'aws_s3*')",
)
@click.option(
    "--workers", "-w", default=None, type=int,
    help="Number of parallel workers for scanning workspaces (default: 4)",
)
@click.option(
    "--gha", "github_actions", is_flag=True, default=False,
    help="Force GitHub Actions output (auto-detected when $GITHUB_ACTIONS=true)",
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
    min_severity: str | None,
    fail_on: str | None,
    resource_filter: str | None,
    workers: int | None,
    github_actions: bool,
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
    if workers is not None:
        config.workers = workers

    # Run scan
    if quiet:
        report = run_scan(config, base_dir=path)
    else:
        with console.status("[bold]Scanning for drift...", spinner="dots"):
            report = run_scan(config, base_dir=path)

    # Resource filter
    if resource_filter:
        report = ScanReport(
            results=[
                WorkspaceScanResult(
                    workspace_path=r.workspace_path,
                    drifted_resources=[
                        res for res in r.drifted_resources
                        if fnmatch.fnmatch(res.full_address, resource_filter)
                    ],
                    error=r.error,
                    scan_duration_seconds=r.scan_duration_seconds,
                    terraform_version=r.terraform_version,
                )
                for r in report.results
            ],
            scan_started_at=report.scan_started_at,
            scan_finished_at=report.scan_finished_at,
            config_path=report.config_path,
        )

    # Output
    if output_format == "json":
        output = report_json(report, output_path, min_severity=min_severity)
    elif output_format == "markdown":
        output = report_markdown(report, output_path, min_severity=min_severity)
    elif output_format == "csv":
        output = report_csv(report, output_path, min_severity=min_severity)
    else:
        output = None

    if not quiet:
        if output_format == "table":
            report_table(report, console, min_severity=min_severity)
        elif output is not None and not output_path:
            console.print(output)
        if output_path and output_format != "table":
            console.print(f"📄 Report written to {output_path}")

    # Notifications
    _send_notifications(report, config, slack_webhook)

    # GitHub Actions annotations + step summary
    if github_actions or os.environ.get("GITHUB_ACTIONS") == "true":
        report_github_actions(report, min_severity=min_severity)

    # Auto-remediation
    if auto_fix and report.has_drift:
        _handle_remediation(report, config, env, confirm, dry_run, quiet)

    # Save to history (silent — never break the scan over a history write failure)
    _save_history(report, config)

    # Exit codes
    if report.has_drift:
        if fail_on:
            fail_sev = Severity(fail_on)
            qualifies = any(
                resource.severity >= fail_sev
                for result in report.results
                for resource in result.drifted_resources
            )
            sys.exit(1 if qualifies else 0)
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
@click.option(
    "--min-severity",
    type=click.Choice(["info", "low", "medium", "high", "critical"]),
    default=None,
    help="Only show drift at or above this severity level",
)
@click.option(
    "--quiet", "-q", is_flag=True, default=False,
    help="Suppress all output except errors. Notifications still fire.",
)
@click.option(
    "--workers", "-w", default=None, type=int,
    help="Number of parallel workers for scanning workspaces (default: 4)",
)
@click.option(
    "--fail-on",
    type=click.Choice(["info", "low", "medium", "high", "critical"]),
    default=None,
    help="Exit 1 and stop watching when drift meets or exceeds this severity",
)
def watch(
    path: str,
    interval: str,
    config_path: str | None,
    slack_webhook: str | None,
    binary: str | None,
    verbose: bool,
    min_severity: str | None,
    quiet: bool,
    workers: int | None,
    fail_on: str | None,
) -> None:
    """Continuously monitor for drift at a set interval."""
    setup_logging(verbose, quiet)

    try:
        seconds = _parse_interval(interval)
    except ValueError:
        raise click.BadParameter(
            f"'{interval}' is not a valid interval. Use formats like 30s, 5m, or 1h.",
            param_hint="--interval",
        )
    config = load_config(config_path=config_path, base_dir=path)

    if slack_webhook:
        config.notifications.slack_webhook_url = slack_webhook
    if binary:
        config.terraform_binary = binary
    if workers is not None:
        config.workers = workers

    scan_count = 0
    try:
        while True:
            scan_count += 1
            if not quiet:
                console.clear()
                console.print(
                    f"👀 tfdrift watch — every {interval} — "
                    f"scan #{scan_count} at {datetime.now().strftime('%H:%M:%S')} "
                    f"(Ctrl+C to stop)",
                    style="bold",
                )

            if quiet:
                report = run_scan(config, base_dir=path)
            else:
                with console.status("[bold]Scanning for drift...", spinner="dots"):
                    report = run_scan(config, base_dir=path)

            if not quiet:
                report_table(report, console, min_severity=min_severity)

            _save_history(report, config)

            if report.has_drift:
                _send_notifications(report, config, None)

                if fail_on:
                    fail_sev = Severity(fail_on)
                    qualifies = any(
                        resource.severity >= fail_sev
                        for result in report.results
                        for resource in result.drifted_resources
                    )
                    if qualifies:
                        if not quiet:
                            console.print(
                                f"\n[bold red]Drift at or above '{fail_on}' detected "
                                f"— stopping watch.[/bold red]"
                            )
                        sys.exit(1)

            if not quiet:
                console.print(f"\nNext scan in {interval}...", style="dim")
            time.sleep(seconds)

    except KeyboardInterrupt:
        if not quiet:
            console.print("\n👋 Watch mode stopped.", style="bold")


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
@click.option(
    "--min-severity",
    type=click.Choice(["info", "low", "medium", "high", "critical"]),
    default=None,
    help="Only include drift at or above this severity level",
)
def report(
    path: str,
    output_path: str,
    config_path: str | None,
    binary: str | None,
    verbose: bool,
    min_severity: str | None,
) -> None:
    """Generate an HTML drift report."""
    setup_logging(verbose)

    config = load_config(config_path=config_path, base_dir=path)
    if binary:
        config.terraform_binary = binary

    with console.status("[bold]Scanning for drift...", spinner="dots"):
        scan_report = run_scan(config, base_dir=path)

    report_html(scan_report, output_path, min_severity=min_severity)
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

    webhook_url = slack_webhook_override or config.notifications.slack_webhook_url
    if webhook_url:
        notify_slack(
            report,
            webhook_url,
            channel=config.notifications.slack_channel,
            min_severity=config.notifications.slack_min_severity,
        )

    if config.notifications.webhook_url:
        notify_webhook(
            report,
            config.notifications.webhook_url,
            config.notifications.webhook_method,
        )

    if config.notifications.pagerduty_routing_key:
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


def _save_history(report: ScanReport, config: TfdriftConfig) -> None:
    """Persist scan to history DB, silently ignoring any errors."""
    try:
        db_path = Path(config.history_db) if config.history_db else DEFAULT_DB_PATH
        save_scan(report, db_path)
    except Exception:
        pass


@main.command()
@click.option(
    "--limit", "-n", default=10, type=int,
    help="Number of recent scans to show (default: 10)",
)
@click.option(
    "--format", "-f", "output_format",
    type=click.Choice(["table", "json"]),
    default="table",
    help="Output format",
)
@click.option(
    "--db", default=None,
    help="Path to history database (default: ~/.tfdrift/history.db)",
)
@click.option(
    "--since", default=None,
    help="Only show scans from this lookback period (e.g. 7d, 24h, 2026-01-01)",
)
@click.option(
    "--top", "show_top", is_flag=True, default=False,
    help="Show repeat offenders — resources that drift most frequently",
)
@click.option(
    "--trend", "show_trend", is_flag=True, default=False,
    help="Show per-day drift frequency trend",
)
def history(
    limit: int,
    output_format: str,
    db: str | None,
    since: str | None,
    show_top: bool,
    show_trend: bool,
) -> None:
    """Show past drift scan history."""
    from rich.table import Table

    db_path = Path(db) if db else DEFAULT_DB_PATH
    try:
        scans = list_scans(db_path, limit=limit, since=since)
    except ValueError as e:
        raise click.BadParameter(str(e), param_hint="--since")

    if not scans and not show_top and not show_trend:
        console.print("No scan history found.", style="dim")
        return

    if output_format == "json":
        out: dict = {"scans": scans}
        if show_top:
            out["repeat_offenders"] = get_repeat_offenders(db_path, limit=limit, since=since)
        if show_trend:
            out["daily_trend"] = get_daily_summary(db_path, since=since)
        console.print(json.dumps(out, indent=2, default=str))
        return

    # Scans table
    if scans:
        title = f"Drift History — {len(scans)} scan(s)"
        if since:
            title += f" since {since}"
        table = Table(title=title, show_lines=False, header_style="bold")
        table.add_column("When")
        table.add_column("Base Dir", style="dim")
        table.add_column("Workspaces", justify="right")
        table.add_column("Drifted", justify="right")
        table.add_column("Severities")
        table.add_column("Errors", justify="right")
        table.add_column("Duration", justify="right", style="dim")

        for scan in scans:
            drifted = scan["drift_count"]
            drift_cell = f"[bold red]{drifted}[/bold red]" if drifted else "[green]0[/green]"
            sev_counts = scan["severity_counts"]
            sev_parts = []
            for sev, color in [
                ("critical", "bold red"), ("high", "red"),
                ("medium", "yellow"), ("low", "blue"),
            ]:
                if sev_counts.get(sev):
                    sev_parts.append(f"[{color}]{sev_counts[sev]} {sev}[/{color}]")
            sev_cell = ", ".join(sev_parts) if sev_parts else "—"
            when = scan["scanned_at"][:16].replace("T", " ")
            errors = str(scan["error_count"]) if scan["error_count"] else "—"
            table.add_row(
                when, scan["base_dir"], str(scan["workspace_count"]),
                drift_cell, sev_cell, errors, f"{scan['duration_seconds']:.1f}s",
            )
        console.print(table)

    # Repeat offenders table
    if show_top:
        offenders = get_repeat_offenders(db_path, limit=limit, since=since)
        if offenders:
            console.print()
            top_table = Table(
                title="Repeat Offenders — most frequently drifted resources",
                header_style="bold",
            )
            top_table.add_column("Resource", min_width=35)
            top_table.add_column("Type")
            top_table.add_column("Severity")
            top_table.add_column("Drift Count", justify="right")
            top_table.add_column("Last Seen")
            for r in offenders:
                top_table.add_row(
                    r["resource_address"],
                    r["resource_type"],
                    r["severity"],
                    f"[bold red]{r['drift_count']}[/bold red]",
                    r["last_seen"][:16].replace("T", " "),
                )
            console.print(top_table)
        else:
            console.print("No repeat offenders found.", style="dim")

    # Daily trend table
    if show_trend:
        daily = get_daily_summary(db_path, since=since)
        if daily:
            console.print()
            trend_table = Table(title="Daily Drift Trend", header_style="bold")
            trend_table.add_column("Date")
            trend_table.add_column("Scans", justify="right")
            trend_table.add_column("Scans w/ Drift", justify="right")
            trend_table.add_column("Total Resources Drifted", justify="right")
            for row in daily:
                drifted_scans = row["scans_with_drift"]
                trend_table.add_row(
                    row["day"],
                    str(row["scan_count"]),
                    f"[bold red]{drifted_scans}[/bold red]" if drifted_scans else "0",
                    str(row["total_drift"] or 0),
                )
            console.print(trend_table)
        else:
            console.print("No trend data found.", style="dim")


if __name__ == "__main__":
    main()
