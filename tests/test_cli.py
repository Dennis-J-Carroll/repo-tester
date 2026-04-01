import json
import pytest
from unittest.mock import patch, MagicMock
from click.testing import CliRunner
from repo_tester.cli import main
from repo_tester.report import Finding


def _mock_clone(findings_by_scanner=None):
    """Context manager mock that yields a fake RepoContext."""
    from unittest.mock import MagicMock
    from contextlib import contextmanager
    from repo_tester.context import RepoContext
    from pathlib import Path
    import tempfile, shutil

    @contextmanager
    def _ctx(url):
        tmpdir = tempfile.mkdtemp()
        try:
            ctx = RepoContext(url=url, owner="x", repo="y", local_path=Path(tmpdir))
            ctx.files = []
            ctx.install_scripts = []
            yield ctx
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    return _ctx


def test_cli_clean_repo_exit_zero():
    runner = CliRunner()
    with patch("repo_tester.cli.clone_repo", _mock_clone()), \
         patch("repo_tester.cli.SCANNERS", []):
        result = runner.invoke(main, ["https://github.com/x/y"])
    assert result.exit_code == 0
    assert "No issues found" in result.output


def test_cli_findings_exit_one():
    from repo_tester.scanners.base import BaseScanner

    class FakeScanner(BaseScanner):
        name = "fake"
        priority = 1
        def scan(self, repo):
            return [Finding(severity="CRITICAL", title="Bad", detail="Very bad")]

    runner = CliRunner()
    with patch("repo_tester.cli.clone_repo", _mock_clone()), \
         patch("repo_tester.cli.SCANNERS", [FakeScanner()]):
        result = runner.invoke(main, ["https://github.com/x/y"])
    assert result.exit_code == 1
    assert "CRITICAL" in result.output


def test_cli_json_format():
    runner = CliRunner()
    with patch("repo_tester.cli.clone_repo", _mock_clone()), \
         patch("repo_tester.cli.SCANNERS", []):
        result = runner.invoke(main, ["https://github.com/x/y", "--format", "json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["url"] == "https://github.com/x/y"
    assert data["exit_code"] == 0


def test_cli_quiet_suppresses_clean_output():
    runner = CliRunner()
    with patch("repo_tester.cli.clone_repo", _mock_clone()), \
         patch("repo_tester.cli.SCANNERS", []):
        result = runner.invoke(main, ["https://github.com/x/y", "--quiet"])
    assert result.exit_code == 0
    assert result.output.strip() == ""


def test_cli_invalid_url_exit_two():
    runner = CliRunner()
    result = runner.invoke(main, ["https://notgithub.com/x/y"])
    assert result.exit_code == 2
