"""Data models for tfdrift."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Drift severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @staticmethod
    def _order() -> list[str]:
        return ["info", "low", "medium", "high", "critical"]

    def _rank(self) -> int:
        return self._order().index(self.value)

    def __lt__(self, other: Severity) -> bool:
        return self._rank() < other._rank()

    def __le__(self, other: Severity) -> bool:
        return self._rank() <= other._rank()

    def __gt__(self, other: Severity) -> bool:
        return self._rank() > other._rank()

    def __ge__(self, other: Severity) -> bool:
        return self._rank() >= other._rank()


class ChangeAction(str, Enum):
    """Terraform change actions."""

    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    REPLACE = "replace"
    NO_OP = "no-op"


@dataclass
class AttributeChange:
    """A single attribute that has drifted."""

    attribute: str
    old_value: Any = None
    new_value: Any = None
    sensitive: bool = False

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if self.sensitive:
            d["old_value"] = "(sensitive)"
            d["new_value"] = "(sensitive)"
        return d


@dataclass
class DriftedResource:
    """A single resource that has drifted from its Terraform state."""

    address: str
    resource_type: str
    resource_name: str
    action: ChangeAction
    severity: Severity = Severity.MEDIUM
    changes: list[AttributeChange] = field(default_factory=list)
    module: str | None = None

    @property
    def full_address(self) -> str:
        if self.module:
            return f"{self.module}.{self.address}"
        return self.address

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.full_address,
            "resource_type": self.resource_type,
            "resource_name": self.resource_name,
            "action": self.action.value,
            "severity": self.severity.value,
            "changes": [c.to_dict() for c in self.changes],
        }


@dataclass
class WorkspaceScanResult:
    """Results from scanning a single Terraform workspace."""

    workspace_path: str
    drifted_resources: list[DriftedResource] = field(default_factory=list)
    error: str | None = None
    scan_duration_seconds: float = 0.0
    terraform_version: str | None = None

    @property
    def has_drift(self) -> bool:
        return len(self.drifted_resources) > 0

    @property
    def drift_count(self) -> int:
        return len(self.drifted_resources)

    @property
    def max_severity(self) -> Severity | None:
        if not self.drifted_resources:
            return None
        return max(r.severity for r in self.drifted_resources)

    def to_dict(self) -> dict[str, Any]:
        return {
            "workspace_path": self.workspace_path,
            "has_drift": self.has_drift,
            "drift_count": self.drift_count,
            "max_severity": self.max_severity.value if self.max_severity else None,
            "error": self.error,
            "scan_duration_seconds": round(self.scan_duration_seconds, 2),
            "terraform_version": self.terraform_version,
            "drifted_resources": [r.to_dict() for r in self.drifted_resources],
        }


@dataclass
class ScanReport:
    """Aggregated report across all workspaces."""

    results: list[WorkspaceScanResult] = field(default_factory=list)
    scan_started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    scan_finished_at: str | None = None
    config_path: str | None = None

    @property
    def total_drift_count(self) -> int:
        return sum(r.drift_count for r in self.results)

    @property
    def workspaces_with_drift(self) -> int:
        return sum(1 for r in self.results if r.has_drift)

    @property
    def total_workspaces(self) -> int:
        return len(self.results)

    @property
    def has_drift(self) -> bool:
        return self.total_drift_count > 0

    @property
    def max_severity(self) -> Severity | None:
        severities = [r.max_severity for r in self.results if r.max_severity]
        return max(severities) if severities else None

    @property
    def errors(self) -> list[str]:
        return [r.error for r in self.results if r.error]

    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for result in self.results:
            for resource in result.drifted_resources:
                sev = resource.severity.value
                counts[sev] = counts.get(sev, 0) + 1
        return counts

    def finish(self) -> None:
        self.scan_finished_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": {
                "total_workspaces": self.total_workspaces,
                "workspaces_with_drift": self.workspaces_with_drift,
                "total_drift_count": self.total_drift_count,
                "max_severity": self.max_severity.value if self.max_severity else None,
                "severity_counts": self.severity_counts(),
                "has_errors": len(self.errors) > 0,
            },
            "scan_started_at": self.scan_started_at,
            "scan_finished_at": self.scan_finished_at,
            "config_path": self.config_path,
            "workspaces": [r.to_dict() for r in self.results],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
