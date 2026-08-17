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
