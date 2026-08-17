"""AI-powered remediation plan generation for detected drift.

Supports Anthropic (Claude) and OpenAI (GPT-4o).
Provider is auto-selected from ANTHROPIC_API_KEY / OPENAI_API_KEY env vars,
or forced via the --provider flag.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

from tfdrift.models import DriftedResource, ScanReport


@dataclass
class AIRemediationPlan:
    """Generated remediation plan from an AI provider."""

    provider: str
    model: str
    resources_analyzed: int
    hcl_content: str
    analysis_summary: str


def _format_drift_for_prompt(
    workspace_resources: list[tuple[str, list[DriftedResource]]],
) -> str:
    """Serialize drift results into a human-readable block for the AI prompt."""
    lines: list[str] = []
    for workspace, resources in workspace_resources:
        lines.append(f"Workspace: {workspace}")
        for r in resources:
            lines.append(f"\n  Resource: {r.full_address}")
            lines.append(f"  Type: {r.resource_type}")
            lines.append(f"  Action needed: {r.action.value}")
            lines.append(f"  Severity: {r.severity.value}")
            if r.changes:
                lines.append("  Drifted attributes (desired -> actual):")
                for change in r.changes:
                    if change.sensitive:
                        lines.append(f"    {change.attribute}: (sensitive value changed)")
                    else:
                        lines.append(
                            f"    {change.attribute}: "
                            f"desired={json.dumps(change.old_value)}, "
                            f"actual_now={json.dumps(change.new_value)}"
                        )
    return "\n".join(lines)
