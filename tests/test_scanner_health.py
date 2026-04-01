import pytest
from unittest.mock import patch, MagicMock
from tests.conftest import make_file
from repo_tester.scanners.health import RepoHealthScanner


@pytest.fixture
def scanner():
    return RepoHealthScanner()


def _mock_github(data: dict):
    """Returns a mock requests.get that yields the given JSON."""
    mock = MagicMock()
    mock.ok = True
    mock.json.return_value = data
    return mock


def test_flags_stale_repo(scanner, tmp_repo):
    stale_data = {"pushed_at": "2020-01-01T00:00:00Z", "forks_count": 10, "stargazers_count": 50}
    with patch("repo_tester.scanners.health.requests.get", return_value=_mock_github(stale_data)):
        findings = scanner.scan(tmp_repo)
    assert any("not updated" in f.title.lower() for f in findings)


def test_flags_missing_license(scanner, tmp_repo):
    active_data = {"pushed_at": "2026-01-01T00:00:00Z", "forks_count": 5, "stargazers_count": 10}
    with patch("repo_tester.scanners.health.requests.get", return_value=_mock_github(active_data)):
        findings = scanner.scan(tmp_repo)
    assert any("LICENSE" in f.title for f in findings)


def test_no_license_flag_when_license_present(scanner, tmp_repo):
    make_file(tmp_repo, "LICENSE", "MIT License")
    active_data = {"pushed_at": "2026-01-01T00:00:00Z", "forks_count": 5, "stargazers_count": 10}
    with patch("repo_tester.scanners.health.requests.get", return_value=_mock_github(active_data)):
        findings = scanner.scan(tmp_repo)
    assert not any("LICENSE" in f.title for f in findings)


def test_flags_curl_pipe_in_ci(scanner, tmp_repo):
    make_file(tmp_repo, ".github/workflows/ci.yml",
              "- run: curl https://example.com/setup.sh | bash")
    with patch("repo_tester.scanners.health.requests.get", return_value=_mock_github(
        {"pushed_at": "2026-01-01T00:00:00Z", "forks_count": 5, "stargazers_count": 10}
    )):
        findings = scanner.scan(tmp_repo)
    assert any("curl" in f.title.lower() and "CI" in f.title for f in findings)


def test_flags_unpinned_action(scanner, tmp_repo):
    make_file(tmp_repo, ".github/workflows/ci.yml",
              "      - uses: actions/checkout@main")
    with patch("repo_tester.scanners.health.requests.get", return_value=_mock_github(
        {"pushed_at": "2026-01-01T00:00:00Z", "forks_count": 5, "stargazers_count": 10}
    )):
        findings = scanner.scan(tmp_repo)
    assert any("Unpinned" in f.title and "action" in f.title.lower() for f in findings)


def test_github_api_failure_is_silent(scanner, tmp_repo):
    with patch("repo_tester.scanners.health.requests.get", side_effect=Exception("timeout")):
        findings = scanner.scan(tmp_repo)  # Should not raise
    # Only file-based checks should run — no crash
    assert isinstance(findings, list)
