#!/usr/bin/env python3
"""Demo script — simulates a tfdrift scan with realistic output.

Usage:
    python demo.py

Record it with:
    # Option A: asciinema (then convert to GIF with agg or svg-term)
    asciinema rec demo.cast -c "python demo.py"

    # Option B: terminalizer (npm install -g terminalizer)
    terminalizer record demo -c "python demo.py"
    terminalizer render demo

    # Option C: just use a screen recorder (OBS, ScreenToGif on Windows)
"""

import sys
import time

from rich.console import Console
from rich.table import Table
from rich.text import Text

console = Console()


def slow_print(text, delay=0.03, **kwargs):
    """Print text character by character for demo effect."""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    sys.stdout.write("\n")


def demo():
    # Simulate typing the command
    console.print()
    slow_print("$ tfdrift scan --path ./infrastructure", delay=0.05)
    time.sleep(0.5)

    # Scanning animation
    with console.status("[bold]Scanning for drift...", spinner="dots"):
        time.sleep(2.5)

    # Results
    console.print(
        "\n⚠️  Drift detected: [bold yellow]7 resource(s)[/] "
        "across [bold yellow]2/4[/] workspace(s)\n"
    )

    console.print(
        "🔴 critical: 2  🟠 high: 2  🟡 medium: 2  🔵 low: 1\n"
    )

    # Workspace 1
    console.print(
        "📂 [bold]infrastructure/production[/] "
        "(5 drifted, 3.2s)",
    )

    table1 = Table(show_header=True, header_style="bold", padding=(0, 1))
    table1.add_column("Severity", width=10)
    table1.add_column("Resource", min_width=35)
    table1.add_column("Action", width=10)
    table1.add_column("Changed attributes", min_width=25)

    table1.add_row(
        Text("CRITICAL", style="bold red"),
        "aws_security_group.api_sg",
        "update",
        "ingress",
    )
    table1.add_row(
        Text("CRITICAL", style="bold red"),
        "aws_iam_role_policy.lambda_exec",
        "update",
        "policy",
    )
    table1.add_row(
        Text("HIGH", style="red"),
        "aws_instance.web_server",
        "update",
        "instance_type, ami",
    )
    table1.add_row(
        Text("HIGH", style="red"),
        "aws_rds_instance.primary",
        "update",
        "publicly_accessible",
    )
    table1.add_row(
        Text("LOW", style="cyan"),
        "aws_s3_bucket.assets",
        "update",
        "tags",
    )

    console.print(table1)
    console.print()
    time.sleep(0.5)

    # Workspace 2
    console.print(
        "📂 [bold]infrastructure/staging[/] "
        "(2 drifted, 1.8s)",
    )

    table2 = Table(show_header=True, header_style="bold", padding=(0, 1))
    table2.add_column("Severity", width=10)
    table2.add_column("Resource", min_width=35)
    table2.add_column("Action", width=10)
    table2.add_column("Changed attributes", min_width=25)

    table2.add_row(
        Text("MEDIUM", style="yellow"),
        "aws_lambda_function.processor",
        "update",
        "runtime, environment",
    )
    table2.add_row(
        Text("MEDIUM", style="yellow"),
        "aws_cloudfront_distribution.cdn",
        "update",
        "viewer_certificate",
    )

    console.print(table2)
    console.print()
    time.sleep(0.3)

    # Clean workspaces
    console.print("📂 [dim]infrastructure/shared[/] — [green]no drift[/]")
    console.print("📂 [dim]infrastructure/networking[/] — [green]no drift[/]")
    console.print()

    time.sleep(1)

    # Summary
    console.print(
        "[dim]Scan completed in 5.0s • 4 workspaces • "
        "7 drifted resources • max severity: CRITICAL[/]"
    )
    console.print()


if __name__ == "__main__":
    demo()
