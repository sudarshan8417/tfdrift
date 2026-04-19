"""Auto-remediation engine for Terraform drift.

Applies terraform apply to fix detected drift, with safety guards
to prevent accidental damage.
"""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass

from tfdrift.config import RemediationConfig
from tfdrift.models import ScanReport, Severity, WorkspaceScanResult

logger = logging.getLogger(__name__)


@dataclass
class RemediationResult:
    """Result of an auto-remediation attempt."""

    workspace_path: str
    success: bool
    resources_fixed: int = 0
    error: str | None = None
    skipped_reason: str | None = None
    dry_run: bool = False


def check_safety_guards(
    result: WorkspaceScanResult,
    config: RemediationConfig,
    environment: str | None = None,
) -> str | None:
    """Check if it's safe to auto-remediate this workspace.

    Returns None if safe, or a reason string if remediation should be skipped.
    """
    # Check environment allowlist
    if config.allowed_environments and environment:
        if environment not in config.allowed_environments:
            return (
                f"Environment '{environment}' not in allowed list: "
                f"{config.allowed_environments}"
            )

    # Check max changes limit
    if result.drift_count > config.max_changes:
        return (
            f"Too many changes ({result.drift_count}) — "
            f"exceeds safety limit of {config.max_changes}. "
            f"Review manually."
        )

    # Block auto-fix if any critical severity drift involves destructive actions
    for resource in result.drifted_resources:
        if resource.severity == Severity.CRITICAL and resource.action.value in (
            "delete",
            "replace",
        ):
            return (
                f"Critical resource '{resource.full_address}' would be "
                f"{resource.action.value}d — manual review required"
            )

    return None


def remediate_workspace(
    workspace_path: str,
    config: RemediationConfig,
    result: WorkspaceScanResult,
    environment: str | None = None,
    dry_run: bool = False,
    terraform_binary: str = "terraform",
) -> RemediationResult:
    """Attempt to auto-remediate drift in a single workspace."""
    # Safety checks
    skip_reason = check_safety_guards(result, config, environment)
    if skip_reason:
        logger.warning("Skipping remediation for %s: %s", workspace_path, skip_reason)
        return RemediationResult(
            workspace_path=workspace_path,
            success=False,
            skipped_reason=skip_reason,
        )

    if dry_run:
        logger.info(
            "[DRY RUN] Would remediate %d resource(s) in %s",
            result.drift_count,
            workspace_path,
        )
        return RemediationResult(
            workspace_path=workspace_path,
            success=True,
            resources_fixed=result.drift_count,
            dry_run=True,
        )

    # Run terraform apply
    logger.info("Applying remediation to %s (%d resources)...", workspace_path, result.drift_count)

    try:
        apply_result = subprocess.run(
            [
                terraform_binary,
                "apply",
                "-auto-approve",
                "-input=false",
                "-no-color",
            ],
            cwd=workspace_path,
            capture_output=True,
            text=True,
            timeout=600,
        )

        if apply_result.returncode != 0:
            return RemediationResult(
                workspace_path=workspace_path,
                success=False,
                error=f"terraform apply failed: {apply_result.stderr[:500]}",
            )

        logger.info("Successfully remediated drift in %s", workspace_path)
        return RemediationResult(
            workspace_path=workspace_path,
            success=True,
            resources_fixed=result.drift_count,
        )

    except subprocess.TimeoutExpired:
        return RemediationResult(
            workspace_path=workspace_path,
            success=False,
            error="terraform apply timed out after 600 seconds",
        )


def remediate_report(
    report: ScanReport,
    config: RemediationConfig,
    environment: str | None = None,
    dry_run: bool = False,
    terraform_binary: str = "terraform",
) -> list[RemediationResult]:
    """Remediate all drifted workspaces in a scan report."""
    results = []

    for workspace_result in report.results:
        if not workspace_result.has_drift:
            continue

        result = remediate_workspace(
            workspace_path=workspace_result.workspace_path,
            config=config,
            result=workspace_result,
            environment=environment,
            dry_run=dry_run,
            terraform_binary=terraform_binary,
        )
        results.append(result)

    return results
