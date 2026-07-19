"""Tests for incremental scanning — WorkspaceCache and run_scan cache integration."""

from __future__ import annotations

import json
from unittest.mock import patch

from tfdrift.cache import WorkspaceCache
from tfdrift.models import WorkspaceScanResult

# ---------------------------------------------------------------------------
# WorkspaceCache unit tests
# ---------------------------------------------------------------------------


class TestWorkspaceCacheHash:
    def test_empty_workspace_has_stable_hash(self, tmp_path):
        h1 = WorkspaceCache.compute_hash(tmp_path)
        h2 = WorkspaceCache.compute_hash(tmp_path)
        assert h1 == h2

    def test_adding_tf_file_changes_hash(self, tmp_path):
        before = WorkspaceCache.compute_hash(tmp_path)
        (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "b" {}')
        after = WorkspaceCache.compute_hash(tmp_path)
        assert before != after

    def test_modifying_tf_file_changes_hash(self, tmp_path):
        f = tmp_path / "main.tf"
        f.write_text('resource "aws_s3_bucket" "b" {}')
        h1 = WorkspaceCache.compute_hash(tmp_path)
        f.write_text('resource "aws_s3_bucket" "b" { bucket = "new" }')
        h2 = WorkspaceCache.compute_hash(tmp_path)
        assert h1 != h2

    def test_tfvars_file_included_in_hash(self, tmp_path):
        (tmp_path / "main.tf").write_text('variable "env" {}')
        h1 = WorkspaceCache.compute_hash(tmp_path)
        (tmp_path / "terraform.tfvars").write_text('env = "prod"')
        h2 = WorkspaceCache.compute_hash(tmp_path)
        assert h1 != h2

    def test_hash_is_16_hex_chars(self, tmp_path):
        h = WorkspaceCache.compute_hash(tmp_path)
        assert len(h) == 16
        assert all(c in "0123456789abcdef" for c in h)


class TestWorkspaceCacheShouldSkip:
    def test_unknown_workspace_not_skipped(self, tmp_path):
        cache = WorkspaceCache(tmp_path / "cache.json")
        ws = tmp_path / "ws"
        ws.mkdir()
        assert cache.should_skip(ws) is False

    def test_clean_unchanged_workspace_skipped(self, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        (ws / "main.tf").write_text("# tf")

        cache = WorkspaceCache(tmp_path / "cache.json")
        cache.record_scan(ws, had_drift=False, had_error=False)

        assert cache.should_skip(ws, rescan_clean_every=5) is True

    def test_drifted_workspace_not_skipped(self, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        (ws / "main.tf").write_text("# tf")

        cache = WorkspaceCache(tmp_path / "cache.json")
        cache.record_scan(ws, had_drift=True, had_error=False)

        assert cache.should_skip(ws) is False

    def test_errored_workspace_not_skipped(self, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        (ws / "main.tf").write_text("# tf")

        cache = WorkspaceCache(tmp_path / "cache.json")
        cache.record_scan(ws, had_drift=False, had_error=True)

        assert cache.should_skip(ws) is False

    def test_changed_files_not_skipped(self, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        f = ws / "main.tf"
        f.write_text("# original")

        cache = WorkspaceCache(tmp_path / "cache.json")
        cache.record_scan(ws, had_drift=False, had_error=False)

        f.write_text("# changed")
        assert cache.should_skip(ws) is False

    def test_skip_exhausted_after_n_cycles(self, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        (ws / "main.tf").write_text("# tf")

        cache = WorkspaceCache(tmp_path / "cache.json")
        cache.record_scan(ws, had_drift=False, had_error=False)

        # rescan_clean_every=3: skip twice, must scan on third cycle
        assert cache.should_skip(ws, rescan_clean_every=3) is True
        cache.record_skip(ws)
        assert cache.should_skip(ws, rescan_clean_every=3) is True
        cache.record_skip(ws)
        assert cache.should_skip(ws, rescan_clean_every=3) is False

    def test_record_scan_resets_skip_counter(self, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        (ws / "main.tf").write_text("# tf")

        cache = WorkspaceCache(tmp_path / "cache.json")
        cache.record_scan(ws, had_drift=False, had_error=False)
        cache.record_skip(ws)
        cache.record_skip(ws)

        # Simulating a forced rescan resets the counter
        cache.record_scan(ws, had_drift=False, had_error=False)
        assert cache.should_skip(ws, rescan_clean_every=3) is True


class TestWorkspaceCachePersistence:
    def test_save_and_reload(self, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        (ws / "main.tf").write_text("# tf")

        cache_file = tmp_path / "cache.json"
        cache = WorkspaceCache(cache_file)
        cache.record_scan(ws, had_drift=False, had_error=False)
        cache.save()

        assert cache_file.exists()
        data = json.loads(cache_file.read_text())
        assert str(ws) in data

    def test_reload_preserves_skip_decision(self, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        (ws / "main.tf").write_text("# tf")

        cache_file = tmp_path / "cache.json"
        cache1 = WorkspaceCache(cache_file)
        cache1.record_scan(ws, had_drift=False, had_error=False)
        cache1.save()

        cache2 = WorkspaceCache(cache_file)
        assert cache2.should_skip(ws) is True

    def test_corrupt_cache_file_handled_gracefully(self, tmp_path):
        cache_file = tmp_path / "cache.json"
        cache_file.write_text("not valid json{{{")

        cache = WorkspaceCache(cache_file)  # should not raise
        assert cache._data == {}


# ---------------------------------------------------------------------------
# run_scan integration with WorkspaceCache
# ---------------------------------------------------------------------------


class TestRunScanIncremental:
    """Test that run_scan correctly skips and scans workspaces based on cache state."""

    def _make_config(self, paths, base_dir):
        from tfdrift.config import TfdriftConfig
        return TfdriftConfig(
            scan_paths=[str(p.relative_to(base_dir)) for p in paths],
            workers=1,
            rescan_clean_every=5,
        )

    def test_first_scan_scans_all_workspaces(self, tmp_path):
        ws1 = tmp_path / "ws1"
        ws1.mkdir()
        (ws1 / "main.tf").write_text("# ws1")

        from tfdrift.cache import WorkspaceCache
        from tfdrift.config import TfdriftConfig
        from tfdrift.detectors.drift import run_scan

        config = TfdriftConfig(scan_paths=["."], workers=1, rescan_clean_every=5)
        cache = WorkspaceCache(tmp_path / "cache.json")

        with patch("tfdrift.detectors.drift.scan_workspace") as mock_scan:
            mock_scan.return_value = WorkspaceScanResult(
                workspace_path=str(ws1),
                drifted_resources=[],
            )
            report = run_scan(config, base_dir=str(tmp_path), workspace_cache=cache)

        mock_scan.assert_called_once()
        assert len(report.results) == 1
        assert report.results[0].skipped is False

    def test_second_scan_skips_clean_unchanged_workspace(self, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        (ws / "main.tf").write_text("# ws")

        from tfdrift.config import TfdriftConfig
        from tfdrift.detectors.drift import run_scan

        config = TfdriftConfig(scan_paths=["."], workers=1, rescan_clean_every=5)
        cache = WorkspaceCache(tmp_path / "cache.json")

        # First scan — populate cache
        with patch("tfdrift.detectors.drift.scan_workspace") as mock_scan:
            mock_scan.return_value = WorkspaceScanResult(
                workspace_path=str(ws), drifted_resources=[]
            )
            run_scan(config, base_dir=str(tmp_path), workspace_cache=cache)

        # Second scan — should skip
        with patch("tfdrift.detectors.drift.scan_workspace") as mock_scan2:
            mock_scan2.return_value = WorkspaceScanResult(
                workspace_path=str(ws), drifted_resources=[]
            )
            report = run_scan(config, base_dir=str(tmp_path), workspace_cache=cache)

        mock_scan2.assert_not_called()
        assert len(report.results) == 1
        assert report.results[0].skipped is True

    def test_workspace_with_drift_is_rescanned(self, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        (ws / "main.tf").write_text("# ws")

        from tfdrift.config import TfdriftConfig
        from tfdrift.detectors.drift import run_scan
        from tfdrift.models import ChangeAction, DriftedResource

        config = TfdriftConfig(scan_paths=["."], workers=1, rescan_clean_every=5)
        cache = WorkspaceCache(tmp_path / "cache.json")

        drifted = DriftedResource(
            address="aws_instance.web",
            resource_type="aws_instance",
            resource_name="web",
            action=ChangeAction.UPDATE,
        )

        # First scan — drift found, cache records had_drift=True
        with patch("tfdrift.detectors.drift.scan_workspace") as mock_scan:
            mock_scan.return_value = WorkspaceScanResult(
                workspace_path=str(ws), drifted_resources=[drifted]
            )
            run_scan(config, base_dir=str(tmp_path), workspace_cache=cache)

        # Second scan — must NOT skip (drift was detected)
        with patch("tfdrift.detectors.drift.scan_workspace") as mock_scan2:
            mock_scan2.return_value = WorkspaceScanResult(
                workspace_path=str(ws), drifted_resources=[drifted]
            )
            run_scan(config, base_dir=str(tmp_path), workspace_cache=cache)

        mock_scan2.assert_called_once()

    def test_changed_tf_file_forces_rescan(self, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        tf_file = ws / "main.tf"
        tf_file.write_text("# original")

        from tfdrift.config import TfdriftConfig
        from tfdrift.detectors.drift import run_scan

        config = TfdriftConfig(scan_paths=["."], workers=1, rescan_clean_every=5)
        cache = WorkspaceCache(tmp_path / "cache.json")

        with patch("tfdrift.detectors.drift.scan_workspace") as mock_scan:
            mock_scan.return_value = WorkspaceScanResult(
                workspace_path=str(ws), drifted_resources=[]
            )
            run_scan(config, base_dir=str(tmp_path), workspace_cache=cache)

        # Modify the .tf file
        tf_file.write_text("# changed")

        with patch("tfdrift.detectors.drift.scan_workspace") as mock_scan2:
            mock_scan2.return_value = WorkspaceScanResult(
                workspace_path=str(ws), drifted_resources=[]
            )
            run_scan(config, base_dir=str(tmp_path), workspace_cache=cache)

        mock_scan2.assert_called_once()

    def test_no_cache_scans_all_workspaces(self, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        (ws / "main.tf").write_text("# ws")

        from tfdrift.config import TfdriftConfig
        from tfdrift.detectors.drift import run_scan

        config = TfdriftConfig(scan_paths=["."], workers=1)

        with patch("tfdrift.detectors.drift.scan_workspace") as mock_scan:
            mock_scan.return_value = WorkspaceScanResult(
                workspace_path=str(ws), drifted_resources=[]
            )
            report = run_scan(config, base_dir=str(tmp_path), workspace_cache=None)

        mock_scan.assert_called_once()
        assert report.results[0].skipped is False
