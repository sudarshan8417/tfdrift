"""Drift detection engine.

Discovers Terraform workspaces, runs `terraform plan`, and parses
the JSON output to identify drifted resources.
"""

from __future__ import annotations

import fnmatch
import json
import logging
import subprocess
import time
from pathlib import Path

from tfdrift.config import TfdriftConfig
from tfdrift.models import (
    AttributeChange,
    ChangeAction,
    DriftedResource,
    ScanReport,
    WorkspaceScanResult,
)
from tfdrift.severity import SeverityClassifier

logger = logging.getLogger(__name__)

# Mapping from terraform plan actions to our ChangeAction enum
ACTION_MAP = {
    "create": ChangeAction.CREATE,
    "update": ChangeAction.UPDATE,
    "delete": ChangeAction.DELETE,
    "create,delete": ChangeAction.REPLACE,
    "delete,create": ChangeAction.REPLACE,
    "no-op": ChangeAction.NO_OP,
    "read": ChangeAction.NO_OP,
}


def discover_workspaces(
    paths: list[str],
    exclude_patterns: list[str],
    base_dir: str = ".",
) -> list[Path]:
    """Find all Terraform workspace directories.

    A workspace is any directory containing .tf files.
    """
    workspaces = []
    base = Path(base_dir).resolve()

    for scan_path in paths:
        root = (base / scan_path).resolve()
        if not root.exists():
            logger.warning("Scan path does not exist: %s", root)
            continue

        if root.is_file():
            continue

        # Check if this directory itself is a workspace
        tf_files = list(root.glob("*.tf"))
        if tf_files:
            workspaces.append(root)

        # Recurse into subdirectories
        for child in root.rglob("*.tf"):
            workspace_dir = child.parent
            if workspace_dir in workspaces:
                continue

            # Check exclude patterns
            rel_path = str(workspace_dir.relative_to(base))
            if any(fnmatch.fnmatch(rel_path, pat) for pat in exclude_patterns):
                continue

            workspaces.append(workspace_dir)

    # Deduplicate and sort
    seen = set()
    unique = []
    for ws in workspaces:
        if ws not in seen:
            seen.add(ws)
            unique.append(ws)

    return sorted(unique)


def run_terraform_plan(
    workspace_path: Path,
    terraform_binary: str = "terraform",
) -> tuple[dict | None, str | None]:
    """Run `terraform plan` in JSON mode and return parsed output.

    Returns:
        (plan_json, error_message) — one of them will be None.
    """
    # First, ensure terraform is initialized
    init_result = subprocess.run(
        [terraform_binary, "init", "-backend=true", "-input=false", "-no-color"],
        cwd=str(workspace_path),
        capture_output=True,
        text=True,
        timeout=300,
    )

    if init_result.returncode != 0:
        return None, f"terraform init failed: {init_result.stderr[:500]}"

    # Run terraform plan with JSON output
    plan_result = subprocess.run(
        [
            terraform_binary,
            "plan",
            "-detailed-exitcode",
            "-input=false",
            "-no-color",
            "-out=tfdrift.tfplan",
        ],
        cwd=str(workspace_path),
        capture_output=True,
        text=True,
        timeout=600,
    )

    # Exit code 0 = no changes, 1 = error, 2 = changes detected
    if plan_result.returncode == 1:
        return None, f"terraform plan failed: {plan_result.stderr[:500]}"

    if plan_result.returncode == 0:
        # No changes — no drift
        return {"resource_changes": []}, None

    # Convert plan to JSON for parsing
    show_result = subprocess.run(
        [terraform_binary, "show", "-json", "tfdrift.tfplan"],
        cwd=str(workspace_path),
        capture_output=True,
        text=True,
        timeout=120,
    )

    if show_result.returncode != 0:
        return None, f"terraform show failed: {show_result.stderr[:500]}"

    try:
        plan_json = json.loads(show_result.stdout)
        return plan_json, None
    except json.JSONDecodeError as e:
        return None, f"Failed to parse plan JSON: {e}"
    finally:
        # Clean up plan file
        plan_file = workspace_path / "tfdrift.tfplan"
        if plan_file.exists():
            plan_file.unlink()


def parse_plan_changes(
    plan_json: dict,
    classifier: SeverityClassifier,
    config: TfdriftConfig,
) -> list[DriftedResource]:
    """Parse terraform plan JSON and extract drifted resources."""
    drifted = []

    for change in plan_json.get("resource_changes", []):
        # Skip data sources
        if change.get("mode") == "data":
            continue

        actions = change.get("change", {}).get("actions", [])
        action_key = ",".join(actions) if isinstance(actions, list) else str(actions)
        action = ACTION_MAP.get(action_key, ChangeAction.UPDATE)

        # Skip no-ops
        if action == ChangeAction.NO_OP:
            continue

        resource_address = change.get("address", "")
        resource_type = change.get("type", "")
        resource_name = change.get("name", "")
        module = change.get("module_address")

        # Extract attribute-level changes
        before = change.get("change", {}).get("before") or {}
        after = change.get("change", {}).get("after") or {}
        after_sensitive = change.get("change", {}).get("after_sensitive") or {}

        attribute_changes = []
        if isinstance(before, dict) and isinstance(after, dict):
            all_keys = set(before.keys()) | set(after.keys())
            for key in sorted(all_keys):
                old_val = before.get(key)
                new_val = after.get(key)
                if old_val != new_val:
                    is_sensitive = (
                        isinstance(after_sensitive, dict)
                        and after_sensitive.get(key, False)
                    )

                    # Check ignore rules
                    if config.should_ignore(resource_address, key):
                        continue

                    attribute_changes.append(
                        AttributeChange(
                            attribute=key,
                            old_value=old_val,
                            new_value=new_val,
                            sensitive=is_sensitive,
                        )
                    )

        # Check if the entire resource is ignored
        if config.should_ignore(resource_address):
            continue

        # Skip if all attribute changes were ignored
        if action == ChangeAction.UPDATE and not attribute_changes:
            continue

        resource = DriftedResource(
            address=resource_address,
            resource_type=resource_type,
            resource_name=resource_name,
            action=action,
            changes=attribute_changes,
            module=module,
        )

        # Classify severity
        resource.severity = classifier.classify(resource)

        drifted.append(resource)

    return drifted


def get_terraform_version(terraform_binary: str = "terraform") -> str | None:
    """Get the installed Terraform version."""
    try:
        result = subprocess.run(
            [terraform_binary, "version", "-json"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            return str(data.get("terraform_version"))
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        pass
    return None


def scan_workspace(
    workspace_path: Path,
    config: TfdriftConfig,
    classifier: SeverityClassifier,
) -> WorkspaceScanResult:
    """Scan a single Terraform workspace for drift."""
    start_time = time.monotonic()
    tf_version = get_terraform_version(config.terraform_binary)

    logger.info("Scanning workspace: %s", workspace_path)

    plan_json, error = run_terraform_plan(workspace_path, config.terraform_binary)

    if error or plan_json is None:
        return WorkspaceScanResult(
            workspace_path=str(workspace_path),
            error=error or "terraform plan returned no output",
            scan_duration_seconds=time.monotonic() - start_time,
            terraform_version=tf_version,
        )

    drifted = parse_plan_changes(plan_json, classifier, config)

    return WorkspaceScanResult(
        workspace_path=str(workspace_path),
        drifted_resources=drifted,
        scan_duration_seconds=time.monotonic() - start_time,
        terraform_version=tf_version,
    )


def run_scan(config: TfdriftConfig, base_dir: str = ".") -> ScanReport:
    """Run a full drift scan across all workspaces.

    This is the main entry point for the drift detection engine.
    """
    report = ScanReport(config_path=base_dir)
    classifier = SeverityClassifier.from_config({"severity": config.severity_config})

    # Discover workspaces
    workspaces = discover_workspaces(
        paths=config.scan_paths,
        exclude_patterns=config.exclude_patterns,
        base_dir=base_dir,
    )

    logger.info("Found %d Terraform workspace(s)", len(workspaces))

    if not workspaces:
        logger.warning("No Terraform workspaces found in scan paths: %s", config.scan_paths)

    # Scan each workspace
    for workspace in workspaces:
        result = scan_workspace(workspace, config, classifier)
        report.results.append(result)

        if result.has_drift:
            logger.warning(
                "Drift detected in %s: %d resource(s) drifted",
                workspace,
                result.drift_count,
            )
        elif result.error:
            logger.error("Error scanning %s: %s", workspace, result.error)
        else:
            logger.info("No drift in %s", workspace)

    report.finish()
    return report
