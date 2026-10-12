"""npm lock resolution and advisory attribution regressions."""

import json
from pathlib import Path
from unittest.mock import patch

from repo_tester.npm_lock import parse_npm_lock
from repo_tester.scanners.supply_chain import SupplyChainScanner
from tests.conftest import make_file


def _fixture(version: int = 3):
    manifest = {"dependencies": {"diff": "^8.0.2", "marked": "^15.0.4", "chalk": "^5.3.0"}}
    lock = {
        "lockfileVersion": version,
        "packages": {
            "": {"dependencies": manifest["dependencies"]},
            "node_modules/diff": {"version": "8.0.2"},
            "node_modules/marked": {"version": "15.0.4"},
            "node_modules/chalk": {"version": "5.3.0"},
            "node_modules/unreachable": {"version": "1.0.0"},
        },
    }
    return json.dumps(manifest), json.dumps(lock)


def test_v2_v3_resolve_only_reachable_entries():
    for version in (2, 3):
        manifest, lock = _fixture(version)
        packages, warnings = parse_npm_lock(manifest, lock)
        assert warnings == []
        assert {(p.name, p.version) for p in packages} == {("diff", "8.0.2"), ("marked", "15.0.4"), ("chalk", "5.3.0")}
        assert all(p.direct for p in packages)


def test_nested_transitive_chain_and_nearest_resolution():
    manifest = json.dumps({"dependencies": {"parent": "^1.0.0"}})
    lock = json.dumps(
        {
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"parent": "^1.0.0"}},
                "node_modules/parent": {"version": "1.0.0", "dependencies": {"diff": "^7.0.0"}},
                "node_modules/parent/node_modules/diff": {"version": "7.0.0"},
                "node_modules/diff": {"version": "8.0.3"},
            },
        }
    )
    packages, warnings = parse_npm_lock(manifest, lock)
    assert warnings == []
    assert [(p.name, p.version, p.chain) for p in packages] == [
        ("parent", "1.0.0", ("parent",)),
        ("diff", "7.0.0", ("parent", "diff")),
    ]


def test_versioned_npm_query_and_attribution_guard(tmp_repo):
    manifest, lock = _fixture()
    make_file(tmp_repo, "package.json", manifest)
    make_file(tmp_repo, "package-lock.json", lock)
    scanner = SupplyChainScanner()

    class Response:
        ok = True
        status_code = 200

        def __init__(self, payload):
            self.payload = payload

        def json(self):
            return self.payload

    diff_advisory = {
        "id": "GHSA-73rr-hh4g-fpgx",
        "database_specific": {"severity": "LOW"},
        "affected": [
            {
                "package": {"name": "diff", "ecosystem": "npm"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "6.0.0"}, {"fixed": "8.0.3"}]}],
            }
        ],
    }
    wrong_advisory = {
        "id": "MAL-2025-46760",
        "affected": [{"package": {"name": "yanti-getuk64-breki", "ecosystem": "npm"}}],
    }

    def post(_url, *, json, timeout):
        queries = json["queries"]
        assert all(q["version"] and q["package"]["ecosystem"] == "npm" for q in queries)
        return Response(
            {
                "results": [
                    {"vulns": [{"id": "GHSA-73rr-hh4g-fpgx"}]}
                    if q["package"]["name"] == "diff"
                    else {"vulns": [{"id": "MAL-2025-46760"}]}
                    if q["package"]["name"] == "chalk"
                    else {"vulns": []}
                    for q in queries
                ]
            }
        )

    def get(url, *, timeout):
        return Response(diff_advisory if url.endswith("GHSA-73rr-hh4g-fpgx") else wrong_advisory)

    with (
        patch("repo_tester.scanners.supply_chain.http.post", side_effect=post),
        patch("repo_tester.scanners.supply_chain.http.get", side_effect=get),
    ):
        findings = scanner.scan(tmp_repo)
    advisories = [f for f in findings if f.advisory]
    assert [(f.package, f.resolved_version, f.severity, f.verdict) for f in advisories] == [
        ("diff", "8.0.2", "LOW", "bad")
    ]
    assert advisories[0].advisory["fixed"] == ["8.0.3"]
    assert any("attribution mismatch" in f.detail.lower() and f.verdict == "warn" for f in findings)
    assert not any(f.package == "chalk" and f.verdict == "bad" for f in findings)


def test_stale_lock_is_disclosed():
    manifest, lock = _fixture()
    changed = json.loads(manifest)
    changed["dependencies"]["diff"] = "^9.0.0"
    _, warnings = parse_npm_lock(json.dumps(changed), lock)
    assert "stale" in warnings[0]


def test_npm_typosquat_requires_directional_registry_evidence():
    scanner = SupplyChainScanner()

    class Response:
        ok = True

        def __init__(self, payload):
            self.payload = payload

        def json(self):
            return self.payload

    def popular_get(url, *, timeout):
        return Response({"downloads": 125_000_000 if url.endswith("/vitest") else 195_000_000})

    with patch("repo_tester.scanners.supply_chain.http.get", side_effect=popular_get):
        assert scanner._check_typosquatting([{"name": "vitest", "ecosystem": "npm"}], Path("package.json")) == []

    def obscure_get(url, *, timeout):
        if "downloads" in url:
            return Response({"downloads": 7 if url.endswith("/chlak") else 400_000_000})
        return Response(
            {
                "time": {"created": "2026-01-01T00:00:00Z"},
                "maintainers": [{"name": "suspect" if url.endswith("/chlak") else "chalk-maintainer"}],
            }
        )

    with patch("repo_tester.scanners.supply_chain.http.get", side_effect=obscure_get):
        findings = scanner._check_typosquatting([{"name": "chlak", "ecosystem": "npm"}], Path("package.json"))
    assert len(findings) == 1
    assert findings[0].verdict == "warn"
    assert findings[0].evidence[0]["suspect_downloads"] == 7
    assert findings[0].evidence[0]["target_downloads"] == 400_000_000
