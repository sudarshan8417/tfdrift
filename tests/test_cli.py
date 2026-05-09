"""Tests for CLI behavior."""
from click.testing import CliRunner

from tfdrift.cli import main


def test_version():
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "tfdrift" in result.output


def test_init_creates_config(tmp_path):
    runner = CliRunner()
    result = runner.invoke(main, ["init", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert (tmp_path / ".tfdrift.yml").exists()


def test_init_wont_overwrite(tmp_path):
    (tmp_path / ".tfdrift.yml").write_text("existing: true")
    runner = CliRunner()
    result = runner.invoke(main, ["init", "--path", str(tmp_path)])
    assert "already exists" in result.output
