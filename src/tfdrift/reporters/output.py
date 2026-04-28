"""Output formatting and notifications.

Handles all the ways we present drift results to the user:
- Rich terminal tables (the default)
- JSON (for piping to jq or other tools)
- Markdown (for PRs and reports)
- HTML (standalone report page)
- Slack webhooks
- PagerDuty Events API v2
- Generic webhooks
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
            headers={
                "Content-Type": "application/json",
                "User-Agent": "tfdrift/0.2",
            },
        )
        resp.raise_for_status()
        logger.info("Webhook notification sent to %s", url)
        return True
    except requests.RequestException as e:
        logger.error("Failed to send webhook notification: %s", e)
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

    # Check if any resources meet the severity threshold
    has_qualifying = False
    for result in report.results:
        for resource in result.drifted_resources:
            if resource.severity >= min_sev:
                has_qualifying = True
                break

    if not has_qualifying:
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


def report_html(report: ScanReport, output_path: str) -> str:
    """Generate a standalone HTML drift report."""
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
