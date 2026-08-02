"""Drift diff — compare two tfdrift JSON scan reports.

Useful in CI to detect net-new drift since the last scan:
    tfdrift scan --format json --output baseline.json
    # ... time passes, something changes ...
    tfdrift diff baseline.json current.json
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class DriftDiff:
    """Result of comparing two scan reports."""

    new_drift: list[dict[str, Any]] = field(default_factory=list)
    resolved_drift: list[dict[str, Any]] = field(default_factory=list)
    persisting_drift: list[dict[str, Any]] = field(default_factory=list)

    @property
    def has_new_drift(self) -> bool:
        return len(self.new_drift) > 0

    @property
    def summary(self) -> dict[str, int]:
        return {
            "new": len(self.new_drift),
            "resolved": len(self.resolved_drift),
            "persisting": len(self.persisting_drift),
        }


def _resource_key(resource: dict[str, Any]) -> str:
    """Stable key for deduplicating resources across reports."""
    return f"{resource.get('address', '')}::{resource.get('action', '')}"


def _collect_resources(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Flatten all drifted resources from a report into a keyed dict."""
    resources: dict[str, dict[str, Any]] = {}
    for workspace in report.get("workspaces", []):
        for resource in workspace.get("drifted_resources", []):
            key = _resource_key(resource)
            resources[key] = {**resource, "_workspace": workspace["workspace_path"]}
    return resources


def load_report(path: str) -> dict[str, Any]:
    """Load a tfdrift JSON report from disk."""
    content = Path(path).read_text()
    data: dict[str, Any] = json.loads(content)
    return data


def compute_diff(baseline: dict[str, Any], current: dict[str, Any]) -> DriftDiff:
    """Compare two scan reports and return a DriftDiff.

    - new_drift: resources drifted in current but not in baseline
    - resolved_drift: resources that were drifted in baseline but clean in current
    - persisting_drift: resources drifted in both
    """
    baseline_resources = _collect_resources(baseline)
    current_resources = _collect_resources(current)

    baseline_keys = set(baseline_resources)
    current_keys = set(current_resources)

    return DriftDiff(
        new_drift=[current_resources[k] for k in sorted(current_keys - baseline_keys)],
        resolved_drift=[baseline_resources[k] for k in sorted(baseline_keys - current_keys)],
        persisting_drift=[current_resources[k] for k in sorted(current_keys & baseline_keys)],
    )
