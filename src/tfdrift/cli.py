"""tfdrift CLI — Terraform drift detection, reporting, and remediation."""

from __future__ import annotations

import fnmatch
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import click
from rich.console import Console

from tfdrift.blame import lookup_blame
from tfdrift.cache import WorkspaceCache
from tfdrift.config import TfdriftConfig, load_config
from tfdrift.detectors.drift import run_scan
from tfdrift.history import (
    DEFAULT_DB_PATH,
    clear_suppression,
    detect_anomaly,
    get_active_suppressions,
    get_daily_summary,
    get_repeat_offenders,
    list_scans,
    list_suppressions,
    log_audit_event,
    parse_duration,
    query_audit_log,
    save_scan,
    save_suppression,
)
from tfdrift.models import ScanReport, Severity, WorkspaceScanResult
from tfdrift.remediators.fix import remediate_report
from tfdrift.reporters.output import (
    notify_opsgenie,
    notify_pagerduty,
    notify_slack,
    notify_teams,
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
@click.version_option(version="0.5.2", prog_name="tfdrift")
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
    "--teams-webhook", default=None,
    help="Microsoft Teams Incoming Webhook URL for notifications",
)
@click.option(
    "--opsgenie-key", default=None,
    help="OpsGenie API key for alert notifications",
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
    "--exclude-resource", "exclude_resource", default=None,
    help="Exclude resources matching this pattern from output (e.g. 'aws_autoscaling*')",
)
@click.option(
    "--workers", "-w", default=None, type=int,
    help="Number of parallel workers for scanning workspaces (default: 4)",
)
@click.option(
    "--gha", "github_actions", is_flag=True, default=False,
    help="Force GitHub Actions output (auto-detected when $GITHUB_ACTIONS=true)",
)
@click.option(
    "--blame", "run_blame", is_flag=True, default=False,
    help="Look up who changed each drifted resource in CloudTrail (requires tfdrift[aws])",
)
@click.option(
    "--blame-days", default=7, type=int,
    help="Lookback window for --blame in days (default: 7)",
)
@click.option(
    "--blame-region", default=None,
    help="AWS region for --blame CloudTrail queries",
)
@click.option(
    "--incremental", is_flag=True, default=False,
    help="Skip clean, unchanged workspaces using a local scan cache (~/.tfdrift/scan_cache.json)",
)
@click.option(
    "--anomaly-threshold", "anomaly_threshold", default=None, type=int,
    help=(
        "Warn when drift count is this many percent above the 7-day rolling average. "
        "Example: --anomaly-threshold 30 alerts when drift is 30%% above baseline."
    ),
)
@click.option(
    "--budget-threshold", "budget_threshold", default=None, type=float,
    help=(
        "Warn when the total estimated monthly cost delta across all drifted resources "
        "exceeds this amount in USD. Example: --budget-threshold 500"
    ),
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
    teams_webhook: str | None,
    opsgenie_key: str | None,
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
    exclude_resource: str | None,
    workers: int | None,
    github_actions: bool,
    run_blame: bool,
    blame_days: int,
    blame_region: str | None,
    incremental: bool,
    anomaly_threshold: int | None,
    budget_threshold: float | None,
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

    # Build workspace cache when incremental mode is requested
    workspace_cache: WorkspaceCache | None = None
    if incremental or config.incremental:
        workspace_cache = WorkspaceCache()

    # Load active suppressions
    db_path = Path(config.history_db) if config.history_db else DEFAULT_DB_PATH
    suppressions = get_active_suppressions(db_path)

    # Run scan
    if quiet:
        report = run_scan(
            config, base_dir=path, workspace_cache=workspace_cache, suppressions=suppressions
        )
    else:
        with console.status("[bold]Scanning for drift...", spinner="dots"):
            report = run_scan(
                config, base_dir=path, workspace_cache=workspace_cache, suppressions=suppressions
            )

    if workspace_cache:
        workspace_cache.save()

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

    # Exclude resource filter
    if exclude_resource:
        report = ScanReport(
            results=[
                WorkspaceScanResult(
                    workspace_path=r.workspace_path,
                    drifted_resources=[
                        res for res in r.drifted_resources
                        if not fnmatch.fnmatch(res.full_address, exclude_resource)
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
            if report.total_suppressed_count:
                console.print(
                    f"[dim]ℹ {report.total_suppressed_count} suppressed resource(s) hidden "
                    f"— run [bold]tfdrift suppress --list[/bold] to review.[/dim]"
                )
        elif output is not None and not output_path:
            console.print(output)
        if output_path and output_format != "table":
            console.print(f"📄 Report written to {output_path}")

    # Resolve fail-on threshold: CLI flag > config file
    effective_fail_on = fail_on or config.fail_on

    # Notifications
    _send_notifications(report, config, slack_webhook, teams_webhook, opsgenie_key)

    # GitHub Actions annotations + step summary
    if github_actions or os.environ.get("GITHUB_ACTIONS") == "true":
        report_github_actions(
            report,
            min_severity=min_severity,
            fail_on_severity=effective_fail_on,
        )

    # Inline CloudTrail blame
    if run_blame and report.has_drift:
        _run_inline_blame(report, blame_days, blame_region, quiet)

    # Auto-remediation
    if auto_fix and report.has_drift:
        _handle_remediation(report, config, env, confirm, dry_run, quiet)

    # Save to history (silent — never break the scan over a history write failure)
    _save_history(report, config)

    # Anomaly detection
    if anomaly_threshold is not None and report.total_drift_count > 0 and not quiet:
        db_path = Path(config.history_db) if config.history_db else DEFAULT_DB_PATH
        is_anomaly, avg, pct = detect_anomaly(
            current_count=report.total_drift_count,
            threshold_pct=anomaly_threshold,
            db_path=db_path,
        )
        if is_anomaly and avg is not None and pct is not None:
            console.print(
                f"\n[bold yellow]⚠ Anomaly detected:[/bold yellow] "
                f"{report.total_drift_count} drift(s) is [bold]{pct:.0f}%[/bold] above "
                f"the {7}-day rolling average of {avg:.1f}.",
                highlight=False,
            )

    # Budget threshold check
    if budget_threshold is not None and not quiet:
        total_cost = report.cost_delta_total
        if total_cost is not None and total_cost > budget_threshold:
            from tfdrift.pricing import format_cost_delta
            console.print(
                f"\n[bold red]💸 Budget threshold exceeded:[/bold red] "
                f"estimated monthly cost impact is [bold]{format_cost_delta(total_cost)}[/bold] "
                f"(threshold: {format_cost_delta(budget_threshold)}).",
                highlight=False,
            )

    # Exit codes
    if report.has_drift:
        if effective_fail_on:
            fail_sev = Severity(effective_fail_on)
            breaching = [
                resource
                for result in report.results
                for resource in result.drifted_resources
                if resource.severity >= fail_sev
            ]
            if breaching:
                if not quiet:
                    console.print(
                        f"\n[bold red]✗ Fail threshold reached:[/bold red] "
                        f"{len(breaching)} drift(s) at or above "
                        f"[bold]'{effective_fail_on}'[/bold] severity.",
                        highlight=False,
                    )
                sys.exit(1)
            else:
                if not quiet:
                    console.print(
                        f"\n[dim]Drift detected, but none at or above "
                        f"'{effective_fail_on}' — exit 0.[/dim]",
                        highlight=False,
                    )
                sys.exit(0)
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
    "--teams-webhook", default=None,
    help="Microsoft Teams Incoming Webhook URL for notifications",
)
@click.option(
    "--opsgenie-key", default=None,
    help="OpsGenie API key for alert notifications",
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
@click.option(
    "--exclude-resource", "exclude_resource", default=None,
    help="Exclude resources matching this pattern from output (e.g. 'aws_autoscaling*')",
)
def watch(
    path: str,
    interval: str,
    config_path: str | None,
    slack_webhook: str | None,
    teams_webhook: str | None,
    opsgenie_key: str | None,
    binary: str | None,
    verbose: bool,
    min_severity: str | None,
    quiet: bool,
    workers: int | None,
    fail_on: str | None,
    exclude_resource: str | None,
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
    if teams_webhook:
        config.notifications.teams_webhook_url = teams_webhook
    if opsgenie_key:
        config.notifications.opsgenie_api_key = opsgenie_key
    if binary:
        config.terraform_binary = binary
    if workers is not None:
        config.workers = workers

    # Watch mode always uses incremental scanning — skip unchanged clean workspaces
    # between cycles to keep each cycle fast.
    watch_cache = WorkspaceCache()

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

            # Reload suppressions each cycle so new ones take effect immediately
            watch_db = Path(config.history_db) if config.history_db else DEFAULT_DB_PATH
            watch_suppressions = get_active_suppressions(watch_db)

            if quiet:
                report = run_scan(
                    config, base_dir=path,
                    workspace_cache=watch_cache, suppressions=watch_suppressions,
                )
            else:
                with console.status("[bold]Scanning for drift...", spinner="dots"):
                    report = run_scan(
                        config, base_dir=path,
                        workspace_cache=watch_cache, suppressions=watch_suppressions,
                    )

            watch_cache.save()

            if exclude_resource:
                report = ScanReport(
                    results=[
                        WorkspaceScanResult(
                            workspace_path=r.workspace_path,
                            drifted_resources=[
                                res for res in r.drifted_resources
                                if not fnmatch.fnmatch(res.full_address, exclude_resource)
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
@click.option(
    "--path", "-p", default=".",
    help="Root path to scan for Terraform workspaces",
)
@click.option(
    "--config", "-c", "config_path",
    default=None, help="Path to .tfdrift.yml",
)
@click.option(
    "--binary", default=None,
    help="Path to terraform/tofu binary (e.g., --binary tofu)",
)
@click.option(
    "--provider",
    type=click.Choice(["anthropic", "openai"]),
    default=None,
    help="AI provider (auto-detected from ANTHROPIC_API_KEY / OPENAI_API_KEY)",
)
@click.option(
    "--output", "-o", "output_path",
    default="drift-remediation.tf",
    help="Output .tf file path (default: drift-remediation.tf)",
)
@click.option(
    "--all", "fix_all", is_flag=True, default=False,
    help="Remediate all drifted resources without prompting",
)
@click.option(
    "--verbose", "-v", is_flag=True, default=False,
    help="Enable verbose logging",
)
def remediate(
    path: str,
    config_path: str | None,
    binary: str | None,
    provider: str | None,
    output_path: str,
    fix_all: bool,
    verbose: bool,
) -> None:
    """Generate an AI-powered Terraform remediation plan for detected drift.

    Scans your workspaces, shows drifted resources, then asks which ones
    to include. An AI model analyses the drift and writes a ready-to-review
    .tf file you can apply with terraform apply.

    Requires ANTHROPIC_API_KEY (uses Claude) or OPENAI_API_KEY (uses GPT-4o).
    Install the matching package: pip install 'tfdrift[ai]'
    """
    from tfdrift.remediators.ai import detect_provider, generate_remediation_plan

    setup_logging(verbose)
    config = load_config(config_path=config_path, base_dir=path)
    if binary:
        config.terraform_binary = binary

    # --- Scan ---
    with console.status("[bold]Scanning for drift...", spinner="dots"):
        report = run_scan(config, base_dir=path)

    if not report.has_drift:
        console.print("[bold green]✓ No drift detected.[/bold green]")
        sys.exit(0)

    # --- List drifted resources ---
    all_resources: list[tuple[str, str]] = []  # (workspace_path, full_address)
    for result in report.results:
        for r in result.drifted_resources:
            all_resources.append((result.workspace_path, r.full_address))

    from tfdrift.reporters.output import SEVERITY_EMOJI
    console.print(f"\n[bold]Found {len(all_resources)} drifted resource(s):[/bold]")
    for result in report.results:
        for r in result.drifted_resources:
            idx = all_resources.index((result.workspace_path, r.full_address)) + 1
            sev_icon = SEVERITY_EMOJI.get(r.severity, "")
            n_changes = len(r.changes)
            change_label = f"{n_changes} attribute change(s)" if n_changes else r.action.value
            console.print(
                f"  [dim]{idx}.[/dim] [bold]{r.full_address}[/bold] "
                f"{sev_icon} [dim]{r.severity.value}[/dim] — {change_label}"
            )

    # placeholder for selection and AI call (next commits)
    raise NotImplementedError("selection + AI call not yet wired")


@main.command()
@click.argument("baseline", metavar="BASELINE")
@click.argument("current", metavar="CURRENT")
@click.option(
    "--format", "-f", "output_format",
    type=click.Choice(["table", "json"]),
    default="table",
    help="Output format",
)
@click.option(
    "--fail-on-new", is_flag=True, default=False,
    help="Exit 1 if there is any net-new drift (useful in CI)",
)
def diff(baseline: str, current: str, output_format: str, fail_on_new: bool) -> None:
    """Compare two JSON scan reports and show new, resolved, and persisting drift.

    BASELINE is the path to the older JSON report.
    CURRENT is the path to the newer JSON report.

    Example:
      tfdrift scan --format json --output baseline.json
      tfdrift scan --format json --output current.json
      tfdrift diff baseline.json current.json
    """
    from tfdrift.models import Severity
    from tfdrift.reporters.diff import compute_diff, load_report
    from tfdrift.reporters.output import SEVERITY_EMOJI

    try:
        baseline_report = load_report(baseline)
    except (OSError, ValueError) as e:
        raise click.ClickException(f"Could not read baseline report: {e}")

    try:
        current_report = load_report(current)
    except (OSError, ValueError) as e:
        raise click.ClickException(f"Could not read current report: {e}")

    result = compute_diff(baseline_report, current_report)

    if output_format == "json":
        import json as _json
        console.print(_json.dumps({
            "summary": result.summary,
            "new_drift": result.new_drift,
            "resolved_drift": result.resolved_drift,
            "persisting_drift": result.persisting_drift,
        }, indent=2))
        if fail_on_new and result.has_new_drift:
            sys.exit(1)
        return

    # Table output
    summary = result.summary
    console.print()
    console.print(
        f"📊 Drift diff: [bold green]+{summary['new']} new[/bold green]  "
        f"[bold red]-{summary['resolved']} resolved[/bold red]  "
        f"[dim]{summary['persisting']} persisting[/dim]"
    )
    console.print()

    def _print_section(title: str, resources: list, style: str) -> None:
        if not resources:
            return
        from rich.table import Table
        table = Table(title=title, show_header=True, header_style="bold", padding=(0, 1))
        table.add_column("Severity", width=10)
        table.add_column("Resource", min_width=35)
        table.add_column("Action", width=10)
        table.add_column("Workspace", min_width=25)
        for r in resources:
            sev = r.get("severity", "medium")
            try:
                sev_emoji = SEVERITY_EMOJI.get(Severity(sev), "")
            except ValueError:
                sev_emoji = ""
            table.add_row(
                f"{sev_emoji} {sev}",
                r.get("address", "—"),
                r.get("action", "—"),
                r.get("_workspace", "—"),
                style=style,
            )
        console.print(table)
        console.print()

    _print_section("🆕 New Drift", result.new_drift, "green")
    _print_section("✅ Resolved Drift", result.resolved_drift, "")
    _print_section("⏳ Persisting Drift", result.persisting_drift, "dim")

    if not any([result.new_drift, result.resolved_drift, result.persisting_drift]):
        console.print("✅ No differences between reports.", style="bold green")

    if fail_on_new and result.has_new_drift:
        sys.exit(1)


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
  # fail_on: high   # exit 1 only when drift at or above this severity

severity:
  # Patterns use fnmatch glob syntax by default.
  # Prefix a pattern with "regex:" to use a full regular expression instead.
  # Examples:
  #   fnmatch:  aws_security_group.*.ingress
  #   regex:    regex:aws_.*_policy\\..*\\.policy
  critical:
    # - aws_security_group.*.ingress
    # - azurerm_network_security_group.*.security_rule
    # - google_compute_firewall.*.allow
    # - "regex:aws_iam_(role|user)_policy\\..*\\.policy"
  high:
    # - aws_instance.*.instance_type
    # - azurerm_virtual_machine.*.vm_size
    # - "regex:aws_(db|rds)_instance\\..*\\.instance_class"
  medium:
    # - aws_sqs_queue.*.visibility_timeout_seconds
    # - aws_lambda_function.*.memory_size

notifications:
  slack:
    webhook_url: ${SLACK_WEBHOOK_URL}
    channel: "#infra-alerts"
    min_severity: high
  # teams:
  #   webhook_url: ${TEAMS_WEBHOOK_URL}
  #   min_severity: high
  # opsgenie:
  #   api_key: ${OPSGENIE_API_KEY}
  #   min_severity: high
  #   region: us   # or eu
  # pagerduty:
  #   routing_key: ${PAGERDUTY_ROUTING_KEY}
  #   min_severity: critical
  # digest_mode: false        # only notify on net-new drift, skip repeat alerts
  # digest_hours: 24          # lookback window for repeat detection

remediation:
  auto_fix: false
  allowed_environments:
    - dev
    - staging
  require_approval: true
  max_changes: 5
  # pre_apply_hook: ./scripts/pre-apply.sh
  # post_apply_hook: ./scripts/post-apply.sh

# Use OpenTofu instead of Terraform:
# terraform_binary: tofu
"""
    config_path.write_text(starter_config)
    console.print(f"✅ Created {config_path}", style="green")
    console.print("Edit the file to customize your drift detection settings.")


# --- Internal helpers ---


def _filter_digest(report: ScanReport, config: TfdriftConfig) -> ScanReport:
    """In digest mode, drop resources that have already been seen recently."""
    from datetime import timedelta

    from tfdrift.history import _connect, _init_db

    hours = config.notifications.digest_hours
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    db_path = DEFAULT_DB_PATH

    try:
        with _connect(db_path) as conn:
            _init_db(conn)
            seen_rows = conn.execute(
                "SELECT DISTINCT resource_address FROM drifted_resources dr "
                "JOIN scans s ON s.id = dr.scan_id WHERE s.scanned_at >= ?",
                (cutoff,),
            ).fetchall()
        seen = {r["resource_address"] for r in seen_rows}
    except Exception:
        return report

    filtered = ScanReport(
        results=[
            WorkspaceScanResult(
                workspace_path=r.workspace_path,
                drifted_resources=[
                    res for res in r.drifted_resources
                    if res.full_address not in seen
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
    return filtered


def _send_notifications(
    report: ScanReport,  # noqa: F821
    config: TfdriftConfig,  # noqa: F821
    slack_webhook_override: str | None,
    teams_webhook_override: str | None = None,
    opsgenie_key_override: str | None = None,
) -> None:
    """Send all configured notifications."""
    if not report.has_drift:
        return

    if config.notifications.digest_mode:
        report = _filter_digest(report, config)
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

    teams_url = teams_webhook_override or config.notifications.teams_webhook_url
    if teams_url:
        notify_teams(
            report,
            teams_url,
            min_severity=config.notifications.teams_min_severity,
        )

    og_key = opsgenie_key_override or config.notifications.opsgenie_api_key
    if og_key:
        notify_opsgenie(
            report,
            og_key,
            min_severity=config.notifications.opsgenie_min_severity,
            region=config.notifications.opsgenie_region,
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


def _run_inline_blame(
    report: ScanReport,
    days: int,
    region: str | None,
    quiet: bool,
) -> None:
    """Run CloudTrail blame for every drifted resource and print inline results."""
    from rich.table import Table

    if not quiet:
        console.print("\n🔍 CloudTrail blame lookup...", style="bold")

    table = Table(header_style="bold", show_lines=False)
    table.add_column("Resource", min_width=35)
    table.add_column("Event")
    table.add_column("Actor", style="yellow")
    table.add_column("Time")
    table.add_column("Source IP")

    found_any = False
    for result in report.results:
        for resource in result.drifted_resources:
            blame_result = lookup_blame(
                resource_address=resource.full_address,
                resource_type=resource.resource_type,
                region=region,
                lookback_days=days,
            )
            if blame_result:
                found_any = True
                table.add_row(
                    resource.full_address,
                    blame_result.event_name,
                    blame_result.actor,
                    blame_result.event_time[:16].replace("T", " "),
                    blame_result.source_ip,
                )
            else:
                table.add_row(
                    resource.full_address, "—", "—", "—", "—"
                )

    if found_any and not quiet:
        console.print(table)
    elif not quiet:
        console.print(
            "[dim]No CloudTrail events found. "
            "Try --blame-days 30 or verify CloudTrail is enabled.[/dim]"
        )


@main.command()
@click.argument("resource_address")
@click.option(
    "--type", "-t", "resource_type", required=True,
    help="Terraform resource type (e.g. aws_instance)",
)
@click.option(
    "--region", "-r", default=None,
    help="AWS region to query (defaults to AWS_DEFAULT_REGION or boto3 config)",
)
@click.option(
    "--days", "-d", default=7, type=int,
    help="How many days back to search CloudTrail (default: 7, max: 90)",
)
@click.option(
    "--profile", default=None,
    help="AWS profile name (uses default credential chain if not set)",
)
@click.option(
    "--format", "-f", "output_format",
    type=click.Choice(["table", "json"]),
    default="table",
    help="Output format",
)
def blame(
    resource_address: str,
    resource_type: str,
    region: str | None,
    days: int,
    profile: str | None,
    output_format: str,
) -> None:
    """Look up who last changed a resource in AWS CloudTrail.

    RESOURCE_ADDRESS is the Terraform full address, e.g. aws_instance.web
    or module.vpc.aws_security_group.main.

    Requires boto3: pip install tfdrift[aws]
    """
    from rich.table import Table

    console.print(
        f"🔍 Querying CloudTrail for [bold]{resource_address}[/bold] "
        f"(last {days} day(s))...",
    )

    result = lookup_blame(
        resource_address=resource_address,
        resource_type=resource_type,
        region=region,
        lookback_days=days,
        profile=profile,
    )

    if result is None:
        console.print(
            "\n[dim]No CloudTrail events found for this resource in the given time window.\n"
            "Try --days 30 or check that CloudTrail is enabled in this region.[/dim]"
        )
        sys.exit(1)

    if output_format == "json":
        console.print(json.dumps(result.to_dict(), indent=2))
        return

    table = Table(title=f"CloudTrail Blame — {resource_address}", header_style="bold")
    table.add_column("Field", style="dim", width=20)
    table.add_column("Value")

    table.add_row("Event", result.event_name)
    table.add_row("Time", result.event_time[:19].replace("T", " "))
    table.add_row("Actor", f"[bold yellow]{result.actor}[/bold yellow]")
    table.add_row("Source IP", result.source_ip)
    table.add_row("Region", result.region)
    table.add_row("Event ID", result.event_id)

    console.print()
    console.print(table)


@main.command()
@click.argument("resource_pattern", required=False, default=None)
@click.option(
    "--duration", "-d", default="24h",
    help="How long to suppress drift on this resource (e.g. 30m, 4h, 7d). Default: 24h",
)
@click.option(
    "--reason", "-r", default=None,
    help="Optional note explaining why this drift is suppressed",
)
@click.option(
    "--list", "show_list", is_flag=True, default=False,
    help="List all active suppressions",
)
@click.option(
    "--clear", "clear_pattern", default=None,
    help="Deactivate suppressions matching this resource pattern",
)
@click.option(
    "--all", "include_expired", is_flag=True, default=False,
    help="Include expired suppressions when listing (use with --list)",
)
@click.option(
    "--db", default=None,
    help="Path to history database (default: ~/.tfdrift/history.db)",
)
def suppress(
    resource_pattern: str | None,
    duration: str,
    reason: str | None,
    show_list: bool,
    clear_pattern: str | None,
    include_expired: bool,
    db: str | None,
) -> None:
    """Suppress drift alerts on a resource for a set duration.

    RESOURCE_PATTERN is an fnmatch glob — e.g. aws_instance.web or
    "aws_autoscaling_group.*".  Suppressed resources are hidden from scan
    output and do not affect exit codes until the suppression expires.

    \b
    Examples:
      tfdrift suppress aws_instance.web --duration 4h --reason "maintenance"
      tfdrift suppress "aws_autoscaling_group.*" --duration 1d
      tfdrift suppress --list
      tfdrift suppress --clear aws_instance.web
    """
    from rich.table import Table

    db_path = Path(db) if db else DEFAULT_DB_PATH

    # --clear
    if clear_pattern:
        removed = clear_suppression(clear_pattern, db_path)
        if removed:
            log_audit_event(
                action="suppress.clear",
                target=clear_pattern,
                details=f"cleared {removed} suppression(s)",
                db_path=db_path,
            )
            console.print(
                f"[green]✓ Cleared {removed} suppression(s) for '{clear_pattern}'.[/green]"
            )
        else:
            console.print(
                f"[yellow]No active suppressions found for '{clear_pattern}'.[/yellow]"
            )
        return

    # --list
    if show_list:
        rows = list_suppressions(db_path, include_expired=include_expired)
        if not rows:
            console.print("[dim]No active suppressions.[/dim]")
            return
        table = Table(
            title="Active Suppressions" if not include_expired else "All Suppressions",
            header_style="bold",
        )
        table.add_column("Pattern", min_width=30)
        table.add_column("Reason")
        table.add_column("Suppressed At")
        table.add_column("Expires At")
        if include_expired:
            table.add_column("Active")
        for row in rows:
            expires = row["expires_at"][:16].replace("T", " ")
            suppressed_at = row["suppressed_at"][:16].replace("T", " ")
            cells: list[str] = [
                row["resource_pattern"],
                row["reason"] or "—",
                suppressed_at,
                expires,
            ]
            if include_expired:
                cells.append("[green]yes[/green]" if row["active"] else "[dim]no[/dim]")
            table.add_row(*cells)
        console.print(table)
        return

    # Create new suppression
    if not resource_pattern:
        raise click.UsageError(
            "Provide a RESOURCE_PATTERN to suppress, or use --list / --clear."
        )

    try:
        parse_duration(duration)  # validate before writing to DB
    except ValueError as e:
        raise click.BadParameter(str(e), param_hint="--duration")

    save_suppression(resource_pattern, duration, reason, db_path)
    log_audit_event(
        action="suppress.create",
        target=resource_pattern,
        details=f"duration={duration}" + (f", reason={reason}" if reason else ""),
        db_path=db_path,
    )

    console.print(
        f"[green]✓ Suppressing drift on [bold]{resource_pattern}[/bold] "
        f"for {duration}.[/green]"
    )
    if reason:
        console.print(f"  Reason: {reason}", style="dim")
    console.print(
        "  Run [bold]tfdrift suppress --list[/bold] to see all active suppressions.",
        style="dim",
    )


@main.command("audit-log")
@click.option(
    "--limit", "-n", default=50, type=int,
    help="Maximum number of events to show (default: 50)",
)
@click.option(
    "--since", default=None,
    help="Only show events from this lookback period (e.g. 7d, 24h, 2026-01-01)",
)
@click.option(
    "--action", default=None,
    help="Filter by action type (e.g. suppress.create, suppress.clear)",
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
def audit_log(
    limit: int,
    since: str | None,
    action: str | None,
    output_format: str,
    db: str | None,
) -> None:
    """Display the immutable audit event log.

    Records all suppress, clear, and scan actions with timestamps.

    \b
    Examples:
      tfdrift audit-log
      tfdrift audit-log --since 7d --action suppress.create
      tfdrift audit-log --format json
    """
    from rich.table import Table

    db_path = Path(db) if db else DEFAULT_DB_PATH
    try:
        events = query_audit_log(db_path=db_path, limit=limit, since=since, action=action)
    except ValueError as e:
        raise click.BadParameter(str(e), param_hint="--since")

    if not events:
        console.print("[dim]No audit events found.[/dim]")
        return

    if output_format == "json":
        console.print(json.dumps(events, indent=2, default=str))
        return

    title = f"Audit Log — {len(events)} event(s)"
    if since:
        title += f" since {since}"
    table = Table(title=title, header_style="bold", show_lines=False)
    table.add_column("When", style="dim")
    table.add_column("Action")
    table.add_column("Target", min_width=30)
    table.add_column("Actor", style="yellow")
    table.add_column("Details")

    for ev in events:
        when = ev["occurred_at"][:16].replace("T", " ")
        table.add_row(
            when,
            ev["action"],
            ev["target"],
            ev["actor"] or "—",
            ev["details"] or "—",
        )
    console.print(table)


if __name__ == "__main__":
    main()
