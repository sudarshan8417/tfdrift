"""Tests for drift diff comparison logic."""
import json
import tempfile

from tfdrift.reporters.diff import DriftDiff, compute_diff, load_report


def _make_report(resources: list[dict]) -> dict:
    return {
        "summary": {"total_drift_count": len(resources)},
        "workspaces": [
            {
                "workspace_path": "/infra/prod",
                "drifted_resources": resources,
            }
        ],
    }


def _resource(address: str, action: str = "update", severity: str = "high") -> dict:
    return {"address": address, "action": action, "severity": severity, "changes": []}


class TestComputeDiff:
    def test_all_new_when_baseline_empty(self):
        baseline = _make_report([])
        current = _make_report([_resource("aws_instance.web"), _resource("aws_s3_bucket.data")])
        result = compute_diff(baseline, current)
        assert len(result.new_drift) == 2
        assert len(result.resolved_drift) == 0
        assert len(result.persisting_drift) == 0

    def test_all_resolved_when_current_empty(self):
        baseline = _make_report([_resource("aws_instance.web")])
        current = _make_report([])
        result = compute_diff(baseline, current)
        assert len(result.new_drift) == 0
        assert len(result.resolved_drift) == 1
        assert len(result.persisting_drift) == 0

    def test_persisting_when_same_resource_in_both(self):
        r = _resource("aws_instance.web")
        result = compute_diff(_make_report([r]), _make_report([r]))
        assert len(result.new_drift) == 0
        assert len(result.resolved_drift) == 0
        assert len(result.persisting_drift) == 1

    def test_mixed_new_resolved_persisting(self):
        old_only = _resource("aws_lambda_function.processor")
        both = _resource("aws_security_group.web")
        new_only = _resource("aws_db_instance.prod")

        baseline = _make_report([old_only, both])
        current = _make_report([both, new_only])
        result = compute_diff(baseline, current)

        assert len(result.new_drift) == 1
        assert result.new_drift[0]["address"] == "aws_db_instance.prod"
        assert len(result.resolved_drift) == 1
        assert result.resolved_drift[0]["address"] == "aws_lambda_function.processor"
        assert len(result.persisting_drift) == 1
        assert result.persisting_drift[0]["address"] == "aws_security_group.web"

    def test_action_is_part_of_key(self):
        """Same resource with different action = different key."""
        update = _resource("aws_instance.web", action="update")
        delete = _resource("aws_instance.web", action="delete")
        result = compute_diff(_make_report([update]), _make_report([delete]))
        assert len(result.new_drift) == 1
        assert len(result.resolved_drift) == 1

    def test_workspace_path_is_attached_to_resources(self):
        r = _resource("aws_instance.web")
        result = compute_diff(_make_report([]), _make_report([r]))
        assert result.new_drift[0]["_workspace"] == "/infra/prod"

    def test_empty_diff_when_both_empty(self):
        result = compute_diff(_make_report([]), _make_report([]))
        assert result.summary == {"new": 0, "resolved": 0, "persisting": 0}
        assert not result.has_new_drift


class TestDriftDiff:
    def test_has_new_drift_true(self):
        d = DriftDiff(new_drift=[_resource("aws_instance.web")])
        assert d.has_new_drift is True

    def test_has_new_drift_false(self):
        d = DriftDiff()
        assert d.has_new_drift is False

    def test_summary_counts(self):
        d = DriftDiff(
            new_drift=[_resource("a")],
            resolved_drift=[_resource("b"), _resource("c")],
            persisting_drift=[_resource("d")],
        )
        assert d.summary == {"new": 1, "resolved": 2, "persisting": 1}


class TestLoadReport:
    def test_loads_json_from_file(self):
        report = _make_report([_resource("aws_instance.web")])
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(report, f)
            path = f.name
        loaded = load_report(path)
        assert loaded["summary"]["total_drift_count"] == 1

    def test_raises_on_missing_file(self):
        import pytest
        with pytest.raises(OSError):
            load_report("/nonexistent/path/report.json")
