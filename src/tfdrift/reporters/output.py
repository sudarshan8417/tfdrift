"""Output formatting and notifications.

Handles all the ways we present drift results to the user:
- Rich terminal tables (the default)
- JSON (for piping to jq or other tools)
- Markdown (for PRs and reports)
- HTML (standalone report page)
- CSV (for spreadsheets and data pipelines)
- Slack webhooks
- Microsoft Teams Incoming Webhooks (MessageCard format)
- OpsGenie Alerts API v2
- PagerDuty Events API v2
- Generic webhooks
"""

from __future__ import annotations

import csv
import io
import logging
import os
from pathlib import Path
from typing import Any

import requests
from rich.console import Console
from rich.table import Table
from rich.text import Text

from tfdrift.models import (
    AttributeChange,
    DriftedResource,
    ScanReport,
    Severity,
    WorkspaceScanResult,
)
from tfdrift.pricing import format_cost_delta

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


def _format_change(change: AttributeChange) -> str:
    if change.sensitive:
        return f"{change.attribute}: (sensitive)"

    old, new = change.old_value, change.new_value

    if isinstance(old, list) or isinstance(new, list):
        old_n = len(old) if isinstance(old, list) else 0
        new_n = len(new) if isinstance(new, list) else 0
        return f"{change.attribute}: [{old_n}] → [{new_n}]"

    if isinstance(old, dict) or isinstance(new, dict):
        return f"{change.attribute}: (map changed)"

    def _trunc(v: Any, n: int = 18) -> str:
        if v is None:
            return "∅"
        s = str(v)
        return (s[:n] + "…") if len(s) > n else s

    return f"{change.attribute}: {_trunc(old)} → {_trunc(new)}"


def _qualifying_resources(
    report: ScanReport, min_sev: Severity
) -> list[tuple[str, DriftedResource]]:
    return [
        (result.workspace_path, resource)
        for result in report.results
        for resource in result.drifted_resources
        if resource.severity >= min_sev
    ]


def report_table(
    report: ScanReport,
    console: Console | None = None,
    min_severity: str | None = None,
) -> None:
    """Print a rich table summary to the console."""
    if console is None:
        console = Console()

    min_sev = Severity(min_severity) if min_severity else None

    # Summary header
    if report.has_drift:
        console.print(
            f"\n⚠️  Drift detected: {report.total_drift_count} resource(s) "
            f"across {report.workspaces_with_drift}/{report.total_workspaces} workspace(s) "
            f"in {report.total_duration_seconds:.1f}s\n",
            style="bold yellow",
        )
    else:
        console.print(
            f"\n✅ No drift detected across {report.total_workspaces} workspace(s) "
            f"in {report.total_duration_seconds:.1f}s\n",
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

        visible = [
            r for r in result.drifted_resources
            if not min_sev or r.severity >= min_sev
        ]
        if not visible:
            continue

        console.print(
            f"📂 {result.workspace_path} "
            f"({len(visible)} drifted, {result.scan_duration_seconds:.1f}s)",
            style="bold",
        )

        has_costs = any(r.cost_delta_monthly is not None for r in visible)

        table = Table(show_header=True, header_style="bold", padding=(0, 1))
        table.add_column("Severity", width=10)
        table.add_column("Resource", min_width=30)
        table.add_column("Action", width=10)
        table.add_column("Changes", min_width=40)
        if has_costs:
            table.add_column("Cost Impact", width=12, justify="right")

        for resource in visible:
            sev_style = SEVERITY_COLORS.get(resource.severity, "")
            sev_text = Text(resource.severity.value.upper(), style=sev_style)

            changed_attrs = "\n".join(_format_change(c) for c in resource.changes) or "—"

            row: list[Any] = [
                sev_text,
                resource.full_address,
                resource.action.value,
                changed_attrs,
            ]
            if has_costs:
                delta = resource.cost_delta_monthly
                cost_str = format_cost_delta(delta)
                if delta is not None:
                    cost_style = "bold red" if delta > 0 else "bold green"
                    row.append(Text(cost_str, style=cost_style))
                else:
                    row.append(Text(cost_str, style="dim"))
            table.add_row(*row)

        console.print(table)
        console.print()

    # Total cost impact across all drifted resources
    all_deltas = [
        r.cost_delta_monthly
        for result in report.results
        for r in result.drifted_resources
        if r.cost_delta_monthly is not None
    ]
    if all_deltas:
        total = sum(all_deltas)
        style = "bold red" if total > 0 else "bold green"
        console.print(
            f"💰 Estimated cost impact: [{style}]{format_cost_delta(total)}[/{style}]"
            f"  [dim](on-demand us-east-1 — approximate)[/dim]\n"
        )

    # Errors summary
    if report.errors:
        console.print(f"\n⚠️  {len(report.errors)} workspace(s) had errors:", style="yellow")
        for err in report.errors:
            console.print(f"  • {err}", style="dim red")


def report_json(
    report: ScanReport,
    output_path: str | None = None,
    min_severity: str | None = None,
) -> str:
    """Output the report as JSON.

    If output_path is given, writes to file and returns the path.
    Otherwise returns the JSON string.
    """
    if min_severity:
        min_sev = Severity(min_severity)
        report = ScanReport(
            results=[
                WorkspaceScanResult(
                    workspace_path=r.workspace_path,
                    drifted_resources=[
                        res for res in r.drifted_resources if res.severity >= min_sev
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

    json_str = report.to_json(indent=2)

    if output_path:
        Path(output_path).write_text(json_str)
        logger.info("JSON report written to %s", output_path)
        return output_path

    return json_str


def report_markdown(
    report: ScanReport,
    output_path: str | None = None,
    min_severity: str | None = None,
) -> str:
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
    lines.append(f"**Scan duration:** {report.total_duration_seconds:.1f}s\n")

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

    min_sev = Severity(min_severity) if min_severity else None

    # Per-workspace details
    for result in report.results:
        if result.error:
            lines.append(f"## ❌ {result.workspace_path}\n")
            lines.append(f"Error: `{result.error}`\n")
            continue

        if not result.has_drift:
            continue

        visible = [
            r for r in result.drifted_resources
            if not min_sev or r.severity >= min_sev
        ]
        if not visible:
            continue

        lines.append(f"## 📂 {result.workspace_path}\n")
        lines.append(
            f"Drifted resources: {len(visible)} "
            f"| Scan time: {result.scan_duration_seconds:.1f}s\n"
        )

        lines.append("| Severity | Resource | Action | Changes |")
        lines.append("|----------|----------|--------|---------|")

        for resource in visible:
            emoji = SEVERITY_EMOJI.get(resource.severity, "")
            changed = ", ".join(_format_change(c) for c in resource.changes) or "—"
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


def report_csv(
    report: ScanReport,
    output_path: str | None = None,
    min_severity: str | None = None,
) -> str:
    """Generate a CSV drift report.

    Columns: scan_time, workspace, severity, resource, resource_type,
             action, changed_attributes, changes_detail
    """
    min_sev = Severity(min_severity) if min_severity else None

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "scan_time",
        "workspace",
        "severity",
        "resource",
        "resource_type",
        "action",
        "changed_attributes",
        "changes_detail",
    ])

    for result in report.results:
        if result.error:
            writer.writerow([
                report.scan_started_at,
                result.workspace_path,
                "error",
                "",
                "",
                "",
                "",
                result.error,
            ])
            continue

        for resource in result.drifted_resources:
            if min_sev and resource.severity < min_sev:
                continue

            changed_attrs = "|".join(c.attribute for c in resource.changes)
            changes_detail = "|".join(_format_change(c) for c in resource.changes)

            writer.writerow([
                report.scan_started_at,
                result.workspace_path,
                resource.severity.value,
                resource.full_address,
                resource.resource_type,
                resource.action.value,
                changed_attrs,
                changes_detail,
            ])

    csv_content = buf.getvalue()

    if output_path:
        Path(output_path).write_text(csv_content)
        logger.info("CSV report written to %s", output_path)
        return output_path

    return csv_content


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
    critical_resources = _qualifying_resources(report, min_sev)
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


def notify_teams(
    report: ScanReport,
    webhook_url: str,
    min_severity: str = "high",
) -> bool:
    """Send a drift notification to Microsoft Teams via Incoming Webhook.

    Uses the MessageCard format supported by all Teams Incoming Webhook connectors.
    """
    if not report.has_drift:
        return False

    min_sev = Severity(min_severity)
    qualifying = _qualifying_resources(report, min_sev)
    if not qualifying:
        return False

    counts = report.severity_counts()
    severity_line = " | ".join(
        f"{SEVERITY_EMOJI.get(Severity(k), '')} {k}: {v}"
        for k, v in counts.items()
        if v > 0
    )

    # Theme color: red for critical/high, orange for medium, blue otherwise
    if report.max_severity in (Severity.CRITICAL, Severity.HIGH):
        theme_color = "FF4444"
    elif report.max_severity == Severity.MEDIUM:
        theme_color = "FFA500"
    else:
        theme_color = "0078D4"

    facts_summary = [
        {"name": "Workspaces scanned", "value": str(report.total_workspaces)},
        {"name": "Workspaces with drift", "value": str(report.workspaces_with_drift)},
        {"name": "Resources drifted", "value": str(report.total_drift_count)},
        {"name": "Severity breakdown", "value": severity_line or "—"},
    ]

    resource_facts = []
    for workspace_path, resource in qualifying[:10]:
        emoji = SEVERITY_EMOJI.get(resource.severity, "")
        changed = ", ".join(f"`{c.attribute}`" for c in resource.changes[:5]) or "—"
        resource_facts.append({
            "name": f"{emoji} {resource.severity.value.upper()} — {resource.full_address}",
            "value": f"{resource.action.value} | {workspace_path} | changed: {changed}",
        })

    sections = [
        {
            "activityTitle": (
                f"⚠️ {report.total_drift_count} resource(s) drifted "
                f"across {report.workspaces_with_drift}/{report.total_workspaces} workspace(s)"
            ),
            "facts": facts_summary,
        },
    ]
    if resource_facts:
        sections.append({"title": "Drifted Resources", "facts": resource_facts})

    payload = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": f"Terraform drift detected: {report.total_drift_count} resource(s)",
        "themeColor": theme_color,
        "title": "Terraform Drift Detected",
        "sections": sections,
    }

    try:
        resp = requests.post(webhook_url, json=payload, timeout=10)
        resp.raise_for_status()
        logger.info("Teams notification sent successfully")
        return True
    except requests.RequestException as e:
        logger.error("Failed to send Teams notification: %s", e)
        return False


def notify_webhook(report: ScanReport, url: str, method: str = "POST") -> bool:
    """Send drift report to a generic webhook endpoint."""
    try:
        resp = requests.request(
            method=method,
            url=url,
            json=report.to_dict(),
            timeout=10,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "tfdrift/0.4.0",
            },
        )
        resp.raise_for_status()
        logger.info("Webhook notification sent to %s", url)
        return True
    except requests.RequestException as e:
        logger.error("Failed to send webhook notification: %s", e)
        return False


def notify_opsgenie(
    report: ScanReport,
    api_key: str,
    min_severity: str = "high",
    region: str = "us",
) -> bool:
    """Send a drift alert to OpsGenie via the Alerts API v2.

    Supports both US (api.opsgenie.com) and EU (api.eu.opsgenie.com) regions.
    """
    if not report.has_drift:
        return False

    min_sev = Severity(min_severity)
    if not _qualifying_resources(report, min_sev):
        return False

    # Map tfdrift severity → OpsGenie priority (P1–P4)
    og_priority = {
        Severity.CRITICAL: "P1",
        Severity.HIGH: "P2",
        Severity.MEDIUM: "P3",
        Severity.LOW: "P4",
        Severity.INFO: "P5",
    }
    priority = og_priority.get(report.max_severity or Severity.MEDIUM, "P3")

    counts = report.severity_counts()
    severity_line = ", ".join(f"{k}: {v}" for k, v in counts.items() if v > 0)

    description_lines = [
        f"Workspaces scanned: {report.total_workspaces}",
        f"Workspaces with drift: {report.workspaces_with_drift}",
        f"Total drifted resources: {report.total_drift_count}",
        f"Severity breakdown: {severity_line}",
        "",
    ]
    for workspace_path, resource in _qualifying_resources(report, min_sev)[:10]:
        emoji = SEVERITY_EMOJI.get(resource.severity, "")
        changed = ", ".join(c.attribute for c in resource.changes[:5]) or "—"
        description_lines.append(
            f"{emoji} [{resource.severity.value.upper()}] {resource.full_address}"
            f" — {resource.action.value} ({workspace_path}) — changed: {changed}"
        )

    base_url = (
        "https://api.eu.opsgenie.com" if region == "eu" else "https://api.opsgenie.com"
    )

    payload = {
        "message": (
            f"Terraform drift detected: {report.total_drift_count} resource(s) "
            f"across {report.workspaces_with_drift}/{report.total_workspaces} workspace(s)"
        ),
        "alias": "tfdrift-drift-detected",
        "description": "\n".join(description_lines),
        "priority": priority,
        "tags": [
            "terraform", "drift",
            f"severity:{report.max_severity.value if report.max_severity else 'unknown'}",
        ],
        "details": {
            "total_drift": str(report.total_drift_count),
            "workspaces_scanned": str(report.total_workspaces),
            "workspaces_with_drift": str(report.workspaces_with_drift),
            "max_severity": report.max_severity.value if report.max_severity else "none",
            "severity_counts": severity_line,
        },
        "source": "tfdrift",
        "entity": "infrastructure",
    }

    try:
        resp = requests.post(
            f"{base_url}/v2/alerts",
            json=payload,
            headers={
                "Authorization": f"GenieKey {api_key}",
                "Content-Type": "application/json",
            },
            timeout=10,
        )
        resp.raise_for_status()
        logger.info("OpsGenie alert sent successfully (priority %s)", priority)
        return True
    except requests.RequestException as e:
        logger.error("Failed to send OpsGenie alert: %s", e)
        return False


def notify_pagerduty(
    report: ScanReport,
    routing_key: str,
    min_severity: str = "critical",
) -> bool:
    """Send a PagerDuty alert via Events API v2."""
    if not report.has_drift:
        return False

    min_sev = Severity(min_severity)
    if not _qualifying_resources(report, min_sev):
        return False

    counts = report.severity_counts()
    severity_line = ", ".join(
        f"{k}: {v}" for k, v in counts.items() if v > 0
    )

    # Map tfdrift severity to PagerDuty severity
    pd_severity = "warning"
    if report.max_severity == Severity.CRITICAL:
        pd_severity = "critical"
    elif report.max_severity == Severity.HIGH:
        pd_severity = "error"

    payload = {
        "routing_key": routing_key,
        "event_action": "trigger",
        "payload": {
            "summary": (
                f"Terraform drift detected: {report.total_drift_count} "
                f"resource(s) across "
                f"{report.workspaces_with_drift} workspace(s)"
            ),
            "severity": pd_severity,
            "source": "tfdrift",
            "component": "infrastructure",
            "custom_details": {
                "total_drift": report.total_drift_count,
                "workspaces_scanned": report.total_workspaces,
                "workspaces_with_drift": report.workspaces_with_drift,
                "severity_counts": severity_line,
                "max_severity": (
                    report.max_severity.value
                    if report.max_severity else "none"
                ),
            },
        },
    }

    try:
        resp = requests.post(
            "https://events.pagerduty.com/v2/enqueue",
            json=payload,
            timeout=10,
        )
        resp.raise_for_status()
        logger.info("PagerDuty alert sent successfully")
        return True
    except requests.RequestException as e:
        logger.error("Failed to send PagerDuty alert: %s", e)
        return False


def report_html(
    report: ScanReport,
    output_path: str,
    min_severity: str | None = None,
) -> str:
    """Generate a standalone HTML drift report."""
    min_sev = Severity(min_severity) if min_severity else None
    counts = report.severity_counts()

    rows_html = ""
    for result in report.results:
        if result.error:
            rows_html += (
                f'<tr class="error"><td colspan="5">'
                f"❌ {result.workspace_path}: {result.error}</td></tr>\n"
            )
            continue
        for resource in result.drifted_resources:
            if min_sev and resource.severity < min_sev:
                continue
            sev = resource.severity.value
            emoji = SEVERITY_EMOJI.get(resource.severity, "")
            changed = ", ".join(c.attribute for c in resource.changes) or "—"
            rows_html += (
                f'<tr class="sev-{sev}">'
                f"<td>{emoji} {sev.upper()}</td>"
                f"<td>{resource.full_address}</td>"
                f"<td>{resource.action.value}</td>"
                f"<td>{changed}</td>"
                f"<td>{result.workspace_path}</td>"
                f"</tr>\n"
            )

    status = "Drift Detected" if report.has_drift else "No Drift"
    status_color = "#e74c3c" if report.has_drift else "#27ae60"
    sev_summary = " | ".join(
        f"{k}: {v}" for k, v in counts.items() if v > 0
    ) or "clean"

    html = f"""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>tfdrift Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI',
    sans-serif; margin: 0; padding: 20px; background: #0d1117;
    color: #c9d1d9; }}
  .header {{ text-align: center; padding: 30px 0; }}
  .header h1 {{ margin: 0; font-size: 28px; }}
  .status {{ display: inline-block; padding: 6px 16px; border-radius: 20px;
    font-weight: 600; background: {status_color}22;
    color: {status_color}; border: 1px solid {status_color}44;
    margin: 12px 0; }}
  .stats {{ display: flex; gap: 12px; justify-content: center;
    margin: 20px 0; flex-wrap: wrap; }}
  .stat {{ background: #161b22; border: 1px solid #30363d;
    border-radius: 8px; padding: 12px 20px; text-align: center; }}
  .stat-value {{ font-size: 24px; font-weight: 700; color: #58a6ff; }}
  .stat-label {{ font-size: 12px; color: #8b949e; margin-top: 4px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 20px;
    background: #161b22; border-radius: 8px; overflow: hidden; }}
  th {{ background: #21262d; padding: 12px; text-align: left;
    font-size: 13px; color: #8b949e; text-transform: uppercase;
    letter-spacing: 0.5px; }}
  td {{ padding: 10px 12px; border-top: 1px solid #21262d;
    font-size: 14px; }}
  .sev-critical td:first-child {{ color: #f85149; font-weight: 600; }}
  .sev-high td:first-child {{ color: #f0883e; font-weight: 600; }}
  .sev-medium td:first-child {{ color: #d29922; }}
  .sev-low td:first-child {{ color: #58a6ff; }}
  .error td {{ color: #f85149; font-style: italic; }}
  .footer {{ text-align: center; margin-top: 30px; font-size: 12px;
    color: #484f58; }}
</style>
</head>
<body>
<div class="header">
  <h1>tfdrift Report</h1>
  <div class="status">{status}</div>
  <div style="color:#8b949e; font-size:13px; margin-top:8px">
    {report.scan_started_at}</div>
</div>
<div class="stats">
  <div class="stat">
    <div class="stat-value">{report.total_workspaces}</div>
    <div class="stat-label">Workspaces scanned</div>
  </div>
  <div class="stat">
    <div class="stat-value">{report.workspaces_with_drift}</div>
    <div class="stat-label">With drift</div>
  </div>
  <div class="stat">
    <div class="stat-value">{report.total_drift_count}</div>
    <div class="stat-label">Resources drifted</div>
  </div>
  <div class="stat">
    <div class="stat-value">{sev_summary}</div>
    <div class="stat-label">Severity</div>
  </div>
</div>
<table>
<thead>
  <tr>
    <th>Severity</th><th>Resource</th><th>Action</th>
    <th>Changed</th><th>Workspace</th>
  </tr>
</thead>
<tbody>
{rows_html or '<tr><td colspan="5" style="text-align:center">No drift</td></tr>'}
</tbody>
</table>
<div class="footer">
  Generated by <a href="https://github.com/sudarshan8417/tfdrift"
  style="color:#58a6ff">tfdrift</a>
</div>
</body>
</html>"""

    Path(output_path).write_text(html)
    logger.info("HTML report written to %s", output_path)
    return output_path


# Severity → GitHub Actions workflow command level
_GHA_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "notice",
    Severity.INFO: "notice",
}


def report_github_actions(
    report: ScanReport,
    min_severity: str | None = None,
    fail_on_severity: str | None = None,
) -> None:
    """Emit GitHub Actions workflow commands and write the step summary.

    - Prints ::error:: / ::warning:: / ::notice:: annotations to stdout so
      they appear inline in the Actions log and as PR check annotations.
    - Writes a Markdown drift table to $GITHUB_STEP_SUMMARY so the job
      summary page shows a human-readable overview.
    """
    min_sev = Severity(min_severity) if min_severity else Severity.INFO

    # Emit a top-level error annotation when the fail-on threshold is breached
    if fail_on_severity and report.has_drift:
        fail_sev = Severity(fail_on_severity)
        breaching = sum(
            1
            for result in report.results
            for resource in result.drifted_resources
            if resource.severity >= fail_sev
        )
        if breaching:
            print(
                f"::error title=tfdrift fail-on-severity::"
                f"{breaching} drift(s) at or above '{fail_on_severity}' severity detected."
            )

    # Emit annotations for every qualifying drifted resource
    for result in report.results:
        for resource in result.drifted_resources:
            if resource.severity < min_sev:
                continue
            level = _GHA_LEVEL[resource.severity]
            changed = ", ".join(c.attribute for c in resource.changes[:5])
            if len(resource.changes) > 5:
                changed += f" (+{len(resource.changes) - 5} more)"
            title = f"Drift: {resource.full_address} [{resource.severity.value}]"
            msg = (
                f"{resource.action.value} — workspace: {result.workspace_path}"
                + (f" — changed: {changed}" if changed else "")
            )
            print(f"::{level} title={title}::{msg}")

    # Write step summary
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return

    lines: list[str] = []

    if report.has_drift:
        lines.append(
            f"## ⚠️ Terraform Drift Detected\n\n"
            f"**{report.total_drift_count} resource(s) drifted** across "
            f"**{report.workspaces_with_drift}/{report.total_workspaces} workspace(s)**\n"
        )

        sev_counts = report.severity_counts()
        badges = []
        for sev, emoji in [
            ("critical", "🔴"), ("high", "🟠"), ("medium", "🟡"), ("low", "🔵")
        ]:
            if sev_counts.get(sev):
                badges.append(f"{emoji} {sev_counts[sev]} {sev}")
        if badges:
            lines.append(" &nbsp; ".join(badges) + "\n")

        lines.append(
            "| Severity | Resource | Type | Action | Changed Attributes |\n"
            "|---|---|---|---|---|\n"
        )
        for result in report.results:
            for resource in result.drifted_resources:
                if resource.severity < min_sev:
                    continue
                emoji = SEVERITY_EMOJI.get(resource.severity, "")
                changed = ", ".join(f"`{c.attribute}`" for c in resource.changes[:5])
                if len(resource.changes) > 5:
                    changed += f" +{len(resource.changes) - 5} more"
                lines.append(
                    f"| {emoji} {resource.severity.value} "
                    f"| `{resource.full_address}` "
                    f"| {resource.resource_type} "
                    f"| {resource.action.value} "
                    f"| {changed or '—'} |\n"
                )
    else:
        lines.append(
            f"## ✅ No Terraform Drift\n\n"
            f"All **{report.total_workspaces} workspace(s)** are in sync.\n"
        )

    lines.append(
        f"\n> Scanned in {report.total_duration_seconds:.1f}s · "
        f"[tfdrift](https://github.com/sudarshan8417/tfdrift)\n"
    )

    try:
        with open(summary_path, "a") as f:
            f.writelines(lines)
        logger.info("GitHub Actions step summary written to %s", summary_path)
    except OSError as e:
        logger.warning("Could not write step summary: %s", e)
