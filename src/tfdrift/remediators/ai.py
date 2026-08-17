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


def _build_prompt(drift_summary: str) -> str:
    return f"""You are a Terraform infrastructure expert. The resources below have drifted — \
someone made out-of-band changes to cloud infrastructure, causing it to diverge from \
the Terraform configuration.

Your task: generate a Terraform .tf file that corrects this drift by restoring every \
drifted resource to its DESIRED state (the "desired" value in each attribute).

Drift details:
{drift_summary}

Rules:
- Output ONLY valid HCL — no markdown code fences, no prose outside of # comments
- Begin with a comment block summarising the drift and what is being corrected
- Write one complete resource block per drifted resource, using the DESIRED values
- For attributes not listed in the drift, add a comment: # ... other attributes unchanged
- Include a comment on each corrected attribute explaining the change

Generate the remediation .tf file:"""


def _call_anthropic(prompt: str) -> tuple[str, str]:
    """Call Claude via the Anthropic SDK; return (model_id, hcl_text)."""
    try:
        import anthropic
    except ImportError:
        raise ImportError(
            "anthropic package not installed. Run: pip install 'tfdrift[ai]'"
        )

    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    model = "claude-opus-4-7"

    with client.messages.stream(
        model=model,
        max_tokens=4096,
        thinking={"type": "adaptive"},
        messages=[{"role": "user", "content": prompt}],
    ) as stream:
        response = stream.get_final_message()

    hcl = "\n".join(
        block.text
        for block in response.content
        if block.type == "text"
    )
    return model, hcl.strip()


def _call_openai(prompt: str) -> tuple[str, str]:
    """Call GPT-4o via the OpenAI SDK; return (model_id, hcl_text)."""
    try:
        from openai import OpenAI
    except ImportError:
        raise ImportError(
            "openai package not installed. Run: pip install 'tfdrift[ai]'"
        )

    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    model = "gpt-4o"

    response = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        max_tokens=4096,
    )
    hcl = response.choices[0].message.content or ""
    return model, hcl.strip()


def detect_provider() -> str:
    """Return the AI provider to use based on available env vars.

    Anthropic is preferred over OpenAI when both keys are present.
    """
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    if os.environ.get("OPENAI_API_KEY"):
        return "openai"
    raise OSError(
        "No AI provider configured. Set ANTHROPIC_API_KEY or OPENAI_API_KEY."
    )


def generate_remediation_plan(
    report: ScanReport,
    selected_addresses: list[str] | None = None,
    provider: str | None = None,
) -> AIRemediationPlan:
    """Generate an AI-powered remediation .tf file for drifted resources.

    Args:
        report: Completed scan report containing drift results.
        selected_addresses: Restrict to these resource addresses; None means all.
        provider: 'anthropic' or 'openai'. Auto-detected from env vars when None.
    """
    workspace_resources: list[tuple[str, list[DriftedResource]]] = []
    total = 0

    for result in report.results:
        resources = list(result.drifted_resources)
        if selected_addresses is not None:
            resources = [r for r in resources if r.full_address in selected_addresses]
        if resources:
            workspace_resources.append((result.workspace_path, resources))
            total += len(resources)

    if not workspace_resources:
        raise ValueError("No drifted resources selected for remediation.")

    if provider is None:
        provider = detect_provider()
    elif provider not in ("anthropic", "openai"):
        raise ValueError(f"Unknown provider '{provider}'. Choose 'anthropic' or 'openai'.")

    drift_summary = _format_drift_for_prompt(workspace_resources)
    prompt = _build_prompt(drift_summary)

    if provider == "anthropic":
        model, hcl = _call_anthropic(prompt)
    else:
        model, hcl = _call_openai(prompt)

    analysis = (
        f"Analyzed {total} drifted resource(s) across "
        f"{len(workspace_resources)} workspace(s) using {provider} ({model})"
    )

    return AIRemediationPlan(
        provider=provider,
        model=model,
        resources_analyzed=total,
        hcl_content=hcl,
        analysis_summary=analysis,
    )
