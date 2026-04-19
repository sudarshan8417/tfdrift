"""Output reporters for drift scan results.

Supports table (rich), JSON, Markdown, and Slack webhook output.
"""

from __future__ import annotations

import logging
from pathlib import Path

import requests
from rich.console import Console
from rich.table import Table
from rich.text import Text

from tfdrift.models import ScanReport, Severity

logger = logging.getLogger(__name__)

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


def report_table(report: ScanReport, console: Console | None = None) -> None:
    """Print a rich table summary to the console."""
    if console is None:
        console = Console()

    # Summary header
    if report.has_drift:
        console.print(
            f"\n⚠️  Drift detected: {report.total_drift_count} resource(s) "
            f"across {report.workspaces_with_drift}/{report.total_workspaces} workspace(s)\n",
            style="bold yellow",
        )
    else:
        console.print(
            f"\n✅ No drift detected across {report.total_workspaces} workspace(s)\n",
            style="bold green",
        )
        return

    # Severity summary
    counts = report.severity_counts()
    if counts:
        parts = []
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            count = counts.get(sev.value, 0)
            if count > 0:
                parts.append(f"{SEVERITY_EMOJI.get(sev, '')} {sev.value}: {count}")
        if parts:
            console.print("  ".join(parts) + "\n")

    # Detailed table per workspace
    for result in report.results:
        if result.error:
            console.print(f"❌ {result.workspace_path}: {result.error}", style="red")
            continue

        if not result.has_drift:
            continue

        console.print(
            f"📂 {result.workspace_path} "
            f"({result.drift_count} drifted, {result.scan_duration_seconds:.1f}s)",
            style="bold",
        )

        table = Table(show_header=True, header_style="bold", padding=(0, 1))
        table.add_column("Severity", width=10)
        table.add_column("Resource", min_width=30)
        table.add_column("Action", width=10)
        table.add_column("Changed attributes", min_width=20)

        for resource in result.drifted_resources:
            sev_style = SEVERITY_COLORS.get(resource.severity, "")
            sev_text = Text(resource.severity.value.upper(), style=sev_style)

            changed_attrs = ", ".join(c.attribute for c in resource.changes) or "—"

            table.add_row(
                sev_text,
                resource.full_address,
                resource.action.value,
                changed_attrs,
            )

        console.print(table)
        console.print()

    # Errors summary
    if report.errors:
        console.print(f"\n⚠️  {len(report.errors)} workspace(s) had errors:", style="yellow")
        for err in report.errors:
            console.print(f"  • {err}", style="dim red")


def report_json(report: ScanReport, output_path: str | None = None) -> str:
    """Output the report as JSON.

    If output_path is given, writes to file and returns the path.
    Otherwise returns the JSON string.
    """
    json_str = report.to_json(indent=2)

    if output_path:
        Path(output_path).write_text(json_str)
        logger.info("JSON report written to %s", output_path)
        return output_path

    return json_str


def report_markdown(report: ScanReport, output_path: str | None = None) -> str:
    """Generate a Markdown drift report."""
    lines: list[str] = []
    lines.append("# Terraform Drift Report\n")
    lines.append(f"**Scan time:** {report.scan_started_at}\n")

    if report.has_drift:
        lines.append(
            f"**Status:** ⚠️ Drift detected — {report.total_drift_count} resource(s) "
            f"across {report.workspaces_with_drift}/{report.total_workspaces} workspace(s)\n"
        )
    else:
        lines.append(
            f"**Status:** ✅ No drift detected across {report.total_workspaces} workspace(s)\n"
        )

    # Severity summary
    counts = report.severity_counts()
    if counts:
        lines.append("## Severity summary\n")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            count = counts.get(sev.value, 0)
            if count > 0:
                lines.append(f"| {SEVERITY_EMOJI.get(sev, '')} {sev.value} | {count} |")
        lines.append("")

    # Per-workspace details
    for result in report.results:
        if result.error:
            lines.append(f"## ❌ {result.workspace_path}\n")
            lines.append(f"Error: `{result.error}`\n")
            continue

        if not result.has_drift:
            continue

        lines.append(f"## 📂 {result.workspace_path}\n")
        lines.append(
            f"Drifted resources: {result.drift_count} "
            f"| Scan time: {result.scan_duration_seconds:.1f}s\n"
        )

        lines.append("| Severity | Resource | Action | Changed attributes |")
        lines.append("|----------|----------|--------|--------------------|")

        for resource in result.drifted_resources:
            emoji = SEVERITY_EMOJI.get(resource.severity, "")
            changed = ", ".join(f"`{c.attribute}`" for c in resource.changes) or "—"
            lines.append(
                f"| {emoji} {resource.severity.value} | `{resource.full_address}` "
                f"| {resource.action.value} | {changed} |"
            )

        lines.append("")

    md_content = "\n".join(lines)

    if output_path:
        Path(output_path).write_text(md_content)
        logger.info("Markdown report written to %s", output_path)
        return output_path

    return md_content


def notify_slack(
    report: ScanReport,
    webhook_url: str,
    channel: str | None = None,
    min_severity: str = "high",
) -> bool:
    """Send a drift notification to Slack via webhook."""
    if not report.has_drift:
        return False

    min_sev = Severity(min_severity)

    # Filter to resources at or above minimum severity
    critical_resources = []
    for result in report.results:
        for resource in result.drifted_resources:
            if resource.severity >= min_sev:
                critical_resources.append((result.workspace_path, resource))

    if not critical_resources:
        return False

    # Build Slack message
    counts = report.severity_counts()
    severity_line = " | ".join(
        f"{SEVERITY_EMOJI.get(Severity(k), '')} {k}: {v}"
        for k, v in counts.items()
        if v > 0
    )

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"⚠️ Terraform Drift Detected — {report.total_drift_count} resource(s)",
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*Workspaces scanned:* {report.total_workspaces}\n"
                    f"*With drift:* {report.workspaces_with_drift}\n"
                    f"*Severity:* {severity_line}"
                ),
            },
        },
        {"type": "divider"},
    ]

    # Add top resources (limit to 10)
    for workspace_path, resource in critical_resources[:10]:
        emoji = SEVERITY_EMOJI.get(resource.severity, "")
        changed = ", ".join(f"`{c.attribute}`" for c in resource.changes[:5]) or "—"
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"{emoji} *{resource.severity.value.upper()}* — "
                        f"`{resource.full_address}`\n"
                        f"Action: {resource.action.value} | Changed: {changed}"
                    ),
                },
            }
        )

    payload: dict = {"blocks": blocks}
    if channel:
        payload["channel"] = channel

    try:
        resp = requests.post(webhook_url, json=payload, timeout=10)
        resp.raise_for_status()
        logger.info("Slack notification sent successfully")
        return True
    except requests.RequestException as e:
        logger.error("Failed to send Slack notification: %s", e)
        return False


def notify_webhook(report: ScanReport, url: str, method: str = "POST") -> bool:
    """Send drift report to a generic webhook endpoint."""
    try:
        resp = requests.request(
            method=method,
            url=url,
            json=report.to_dict(),
            timeout=10,
            headers={"Content-Type": "application/json", "User-Agent": "tfdrift/0.1"},
        )
        resp.raise_for_status()
        logger.info("Webhook notification sent to %s", url)
        return True
    except requests.RequestException as e:
        logger.error("Failed to send webhook notification: %s", e)
        return False
