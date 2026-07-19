"""Incremental scan cache — skip unchanged, clean workspaces between watch cycles."""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_CACHE_PATH = Path.home() / ".tfdrift" / "scan_cache.json"


class WorkspaceCache:
    """Per-workspace cache for incremental scanning.

    Tracks the content hash of each workspace's .tf/.tfvars files and the
    outcome of the last scan so that unchanged, clean workspaces can be
    skipped on subsequent cycles.

    Skip logic:
    - A workspace is only skippable when it was clean (no drift, no error),
      its .tf/.tfvars files haven't changed, AND it hasn't yet hit the
      rescan_clean_every threshold.
    - Workspaces with active drift or errors are always re-scanned so users
      get up-to-date status.
    """

    def __init__(self, cache_path: Path | None = None):
        self._path = cache_path or DEFAULT_CACHE_PATH
        self._data: dict[str, dict] = {}
        self._load()

    def _load(self) -> None:
        if self._path.exists():
            try:
                self._data = json.loads(self._path.read_text())
            except (json.JSONDecodeError, OSError):
                logger.debug("Could not read scan cache from %s — starting fresh", self._path)
                self._data = {}

    def save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(json.dumps(self._data, indent=2))
        except OSError as exc:
            logger.debug("Could not save scan cache: %s", exc)

    @staticmethod
    def compute_hash(workspace_path: Path) -> str:
        """Return a short SHA256 digest of all .tf and .tfvars files in the workspace."""
        h = hashlib.sha256()
        files = sorted(
            list(workspace_path.glob("*.tf"))
            + list(workspace_path.glob("*.tfvars"))
        )
        for f in files:
            try:
                h.update(f.name.encode())
                h.update(f.read_bytes())
            except OSError:
                pass
        return h.hexdigest()[:16]

    def should_skip(self, workspace_path: Path, rescan_clean_every: int = 5) -> bool:
        """Return True when it is safe to skip scanning this workspace this cycle.

        Safe to skip when:
        1. We have a prior scan result for the workspace.
        2. The prior scan was clean (no drift, no error).
        3. The workspace's .tf/.tfvars files have not changed.
        4. The workspace has been skipped fewer than (rescan_clean_every - 1) consecutive times.
        """
        key = str(workspace_path)
        entry = self._data.get(key)
        if entry is None:
            return False

        if entry.get("had_drift") or entry.get("had_error"):
            return False

        current_hash = self.compute_hash(workspace_path)
        if current_hash != entry.get("tf_hash"):
            return False

        skips_so_far = entry.get("skips_since_last_scan", 0)
        return skips_so_far < rescan_clean_every - 1

    def record_scan(
        self,
        workspace_path: Path,
        had_drift: bool,
        had_error: bool,
    ) -> None:
        """Store the outcome of a completed workspace scan."""
        self._data[str(workspace_path)] = {
            "tf_hash": self.compute_hash(workspace_path),
            "had_drift": had_drift,
            "had_error": had_error,
            "last_scanned_at": datetime.now(timezone.utc).isoformat(),
            "skips_since_last_scan": 0,
        }

    def record_skip(self, workspace_path: Path) -> None:
        """Increment the consecutive-skip counter for a workspace skipped this cycle."""
        key = str(workspace_path)
        if key in self._data:
            self._data[key]["skips_since_last_scan"] = (
                self._data[key].get("skips_since_last_scan", 0) + 1
            )
