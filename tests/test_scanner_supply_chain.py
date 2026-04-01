import json
import pytest
from unittest.mock import patch, MagicMock
from tests.conftest import make_file
from repo_tester.scanners.supply_chain import SupplyChainScanner


@pytest.fixture
def scanner():
    return SupplyChainScanner()


def test_flags_unpinned_pypi_dep(scanner, tmp_repo):
    make_file(tmp_repo, "requirements.txt", "requests>=2.0\nnumpy\n")
    findings = scanner.scan(tmp_repo)
    titles = [f.title for f in findings]
    assert any("requests" in t for t in titles)
    assert any("numpy" in t for t in titles)


def test_pinned_dep_no_unpinned_finding(scanner, tmp_repo):
    make_file(tmp_repo, "requirements.txt", "requests==2.31.0\n")
    with patch("repo_tester.scanners.supply_chain.http.post") as mock_post:
        mock_post.return_value.ok = True
        mock_post.return_value.json.return_value = {"vulns": []}
        findings = scanner.scan(tmp_repo)
    unpinned = [f for f in findings if "Unpinned" in f.title]
    assert unpinned == []


def test_detects_osv_vulnerability(scanner, tmp_repo):
    make_file(tmp_repo, "requirements.txt", "requests==2.0.0\n")
    with patch("repo_tester.scanners.supply_chain.http.post") as mock_post:
        mock_post.return_value.ok = True
        mock_post.return_value.json.return_value = {
            "vulns": [{"id": "CVE-2023-1234"}, {"id": "CVE-2023-5678"}]
        }
        findings = scanner.scan(tmp_repo)
    assert any("CVE" in f.detail for f in findings)
    assert any(f.severity == "HIGH" for f in findings)


def test_osv_network_failure_silent(scanner, tmp_repo):
    make_file(tmp_repo, "requirements.txt", "requests==2.31.0\n")
    with patch("repo_tester.scanners.supply_chain.http.post",
               side_effect=Exception("network error")):
        findings = scanner.scan(tmp_repo)
    # Should not raise, unpinned finding only (requests is pinned here)
    assert all("network" not in f.detail.lower() for f in findings)


def test_detects_typosquatting(scanner, tmp_repo):
    # "requets" is distance 1 from "requests"
    make_file(tmp_repo, "requirements.txt", "requets==1.0.0\n")
    with patch("repo_tester.scanners.supply_chain.http.post") as mock_post:
        mock_post.return_value.ok = True
        mock_post.return_value.json.return_value = {"vulns": []}
        findings = scanner.scan(tmp_repo)
    assert any("typosquat" in f.title.lower() for f in findings)


def test_pkgbuild_raw_ip_source(scanner, tmp_repo):
    make_file(tmp_repo, "PKGBUILD",
              "source=('https://192.168.1.1/package.tar.gz')\n",
              is_install=True)
    findings = scanner.scan(tmp_repo)
    assert any("raw IP" in f.title for f in findings)


def test_parses_package_json_deps(scanner, tmp_repo):
    pkg = json.dumps({"dependencies": {"lodash": ">=4.0.0"}})
    make_file(tmp_repo, "package.json", pkg)
    with patch("repo_tester.scanners.supply_chain.http.post") as mock_post:
        mock_post.return_value.ok = True
        mock_post.return_value.json.return_value = {"vulns": []}
        findings = scanner.scan(tmp_repo)
    assert any("lodash" in f.title for f in findings)
