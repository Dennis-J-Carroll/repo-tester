from __future__ import annotations

import json
import re
import tomllib
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

import requests as http

from repo_tester.context import RepoContext
from repo_tester.npm_lock import LockedPackage, parse_npm_lock
from repo_tester.report import Finding
from repo_tester.scanners.base import BaseScanner

# ── Levenshtein distance with fallback ──────────────────────────────────────
try:
    from Levenshtein import distance as _lev_distance
except ImportError:
    try:
        from rapidfuzz.distance.Levenshtein import distance as _lev_distance
    except ImportError:
        _lev_distance = None


def levenshtein_distance(s1: str, s2: str) -> int:
    """Edit distance between two strings — C extension when available, else a
    pure-Python fallback (slower but always works)."""
    if _lev_distance is not None:
        return _lev_distance(s1, s2)
    if len(s1) < len(s2):
        s1, s2 = s2, s1
    if not s2:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, ca in enumerate(s1):
        curr = [i + 1]
        for j, cb in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]


_KNOWN_FILE = Path(__file__).parent.parent / "patterns" / "known_packages.json"
_OSV_API = "https://api.osv.dev/v1/query"
_OSV_BATCH_API = "https://api.osv.dev/v1/querybatch"
_OSV_VULN_API = "https://api.osv.dev/v1/vulns/"


def _package_identity(name: str, ecosystem: str) -> str:
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.lower()


# ── Fix 2: Popular packages with >1000 GitHub stars — whitelisted from typosquatting ──
# These are well-known, established packages. A new package with a similar name
# to one of these should still be flagged, but these packages themselves should NOT
# be flagged as typosquats of each other.
_POPULAR_PACKAGES = {
    "requests",
    "urllib3",
    "certifi",
    "charset-normalizer",
    "idna",
    "numpy",
    "pandas",
    "scipy",
    "matplotlib",
    "scikit-learn",
    "flask",
    "django",
    "fastapi",
    "tornado",
    "celery",
    "gunicorn",
    "uvicorn",
    "click",
    "black",
    "ruff",
    "mypy",
    "isort",
    "autopep8",
    "pytest",
    "unittest2",
    "nose2",
    "coverage",
    "tox",
    "sqlalchemy",
    "psycopg2",
    "pymongo",
    "redis",
    "boto3",
    "botocore",
    "aiohttp",
    "httpx",
    "pillow",
    "opencv-python",
    "scikit-image",
    "tensorflow",
    "torch",
    "keras",
    "jax",
    "transformers",
    "cryptography",
    "paramiko",
    "pyopenssl",
    "passlib",
    "jinja2",
    "markupsafe",
    "werkzeug",
    "itsdangerous",
    "setuptools",
    "wheel",
    "pip",
    "build",
    "hatchling",
    "flit-core",
    "pydantic",
    "rich",
    "typer",
    "loguru",
    "arrow",
    "attrs",
    "pyyaml",
    "toml",
    "tomli",
    "tomli-w",
    "six",
    "packaging",
    "filelock",
    "platformdirs",
    "virtualenv",
    "tqdm",
    "colorama",
    "pygments",
}


def _is_popular(name: str) -> bool:
    """Check if a package is well-known/popular (Fix 2)."""
    # Exact match
    if name.lower() in _POPULAR_PACKAGES:
        return True
    # Hyphen/underscore variants
    normalized = name.lower().replace("-", "").replace("_", "")
    for pkg in _POPULAR_PACKAGES:
        if pkg.replace("-", "").replace("_", "") == normalized:
            return True
    return False


def _short_name_safe(name: str) -> bool:
    """Short names (<= 4 chars) have naturally small Levenshtein distances.
    Only flag short names if the distance is 0 (exact match to known typosquat)."""
    return len(name) <= 4


class SupplyChainScanner(BaseScanner):
    name = "supply_chain"
    priority = 2

    def __init__(self) -> None:
        with open(_KNOWN_FILE) as f:
            data = json.load(f)
        self._known_pypi: list[str] = data["pypi"]
        self._known_npm: list[str] = data["npm"]

    def scan(self, repo: RepoContext) -> list[Finding]:
        findings: list[Finding] = []
        handlers = {
            "requirements.txt": self._parse_requirements_txt,
            "package.json": self._parse_package_json,
            "pyproject.toml": self._parse_pyproject_toml,
            "go.mod": self._parse_go_mod,
            "Cargo.toml": self._parse_cargo_toml,
            "PKGBUILD": self._parse_pkgbuild,
        }
        for path in repo.files:
            handler = handlers.get(path.name)
            if not handler:
                continue
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue
            deps = handler(text)
            if path.name == "package.json":
                lock_path = path.with_name("package-lock.json")
                if lock_path in repo.files:
                    try:
                        locked, warnings = parse_npm_lock(text, lock_path.read_text(errors="replace"))
                    except OSError as exc:
                        locked, warnings = [], [f"Cannot read npm lockfile: {exc}"]
                    for warning in warnings:
                        findings.append(self._lookup_warning(warning, lock_path))
                    if locked:
                        findings.extend(self._check_locked_npm(locked, lock_path))
                elif deps:
                    findings.append(
                        self._lookup_warning(
                            "No adjacent supported package-lock.json v2/v3; npm versions and "
                            "advisory applicability are unverified (yarn/pnpm locks are not parsed)",
                            path,
                        )
                    )
            else:
                findings.extend(self._check_pinning(deps, path))
                findings.extend(self._check_osv(deps, path))
                unresolved = sum(
                    dep["ecosystem"] == "PyPI"
                    and re.fullmatch(r"==\s*([A-Za-z0-9][A-Za-z0-9._+!-]*)", dep.get("version_spec", "")) is None
                    for dep in deps
                )
                if unresolved:
                    findings.append(
                        self._lookup_warning(
                            f"{unresolved} PyPI declarations have unresolved versions; OSV applicability not checked",
                            path,
                        )
                    )
            findings.extend(self._check_typosquatting(deps, path))
            if path.name == "PKGBUILD":
                findings.extend(self._check_source_urls(text, path))
        return findings

    # --- parsers (unchanged) ---

    def _parse_requirements_txt(self, text: str) -> list[dict]:
        deps = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "-")):
                continue
            m = re.match(r"^([A-Za-z0-9_\-\.]+)\s*([>=<!~^].+)?$", line)
            if m:
                deps.append({"name": m.group(1), "version_spec": (m.group(2) or "").strip(), "ecosystem": "PyPI"})
        return deps

    def _parse_package_json(self, text: str) -> list[dict]:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return []
        combined: dict[str, str] = {}
        combined.update(data.get("dependencies", {}))
        combined.update(data.get("devDependencies", {}))
        return [{"name": k, "version_spec": v, "ecosystem": "npm"} for k, v in combined.items()]

    def _parse_pyproject_toml(self, text: str) -> list[dict]:
        if tomllib is None:
            return []
        try:
            data = tomllib.loads(text)
        except Exception:
            return []
        deps: list[dict] = []
        for spec in data.get("project", {}).get("dependencies", []):
            m = re.match(r"^([A-Za-z0-9_\-\.]+)\s*([>=<!~^].+)?$", spec.strip())
            if m:
                deps.append({"name": m.group(1), "version_spec": (m.group(2) or "").strip(), "ecosystem": "PyPI"})
        for group in data.get("project", {}).get("optional-dependencies", {}).values():
            for spec in group:
                m = re.match(r"^([A-Za-z0-9_\-\.]+)\s*([>=<!~^].+)?$", spec.strip())
                if m:
                    deps.append({"name": m.group(1), "version_spec": (m.group(2) or "").strip(), "ecosystem": "PyPI"})
        return deps

    def _parse_go_mod(self, text: str) -> list[dict]:
        deps: list[dict] = []
        for line in text.splitlines():
            m = re.match(r"\s+(\S+)\s+v(\S+)", line)
            if m:
                deps.append({"name": m.group(1), "version_spec": m.group(2), "ecosystem": "Go"})
        return deps

    def _parse_cargo_toml(self, text: str) -> list[dict]:
        deps: list[dict] = []
        in_deps = False
        for line in text.splitlines():
            if line.strip() in ("[dependencies]", "[dev-dependencies]"):
                in_deps = True
                continue
            if line.startswith("[") and "dependencies" not in line:
                in_deps = False
            if in_deps:
                m = re.match(r'([a-z0-9_\-]+)\s*=\s*["{]?([^"}\n]+)', line)
                if m:
                    deps.append({"name": m.group(1), "version_spec": m.group(2).strip(), "ecosystem": "crates.io"})
        return deps

    def _parse_pkgbuild(self, text: str) -> list[dict]:
        deps: list[dict] = []
        m = re.search(r"depends=\(([^)]+)\)", text, re.DOTALL)
        if m:
            for item in re.findall(r"'([^']+)'", m.group(1)):
                name = re.split(r"[>=<]", item)[0]
                deps.append({"name": name, "version_spec": "", "ecosystem": "pacman"})
        return deps

    # --- checks ---

    def _lookup_warning(self, detail: str, path: Path) -> Finding:
        return Finding(
            severity="MEDIUM",
            title="Supply-chain verification incomplete",
            detail=detail,
            file_path=str(path),
            scanner=self.name,
            verdict="warn",
            evidence=[{"type": "verification_limit", "detail": detail}],
        )

    def _check_pinning(self, deps: list[dict], path: Path) -> list[Finding]:
        findings: list[Finding] = []
        for dep in deps:
            spec = dep["version_spec"]
            if not spec or spec.startswith(">=") or spec in ("*", "latest"):
                findings.append(
                    Finding(
                        severity="MEDIUM",
                        title=f"Unpinned dependency: {dep['name']}",
                        detail=f"Version '{spec or 'unspecified'}' allows unexpected upgrades that may introduce vulnerabilities",
                        file_path=str(path),
                        scanner=self.name,
                        verdict="warn",
                    )
                )
        return findings

    def _check_osv(self, deps: list[dict], path: Path) -> list[Finding]:
        """Check exact PyPI declarations; never query advisories by package name alone."""
        findings: list[Finding] = []
        for dep in deps:
            if dep["ecosystem"] != "PyPI":
                continue
            match = re.fullmatch(r"==\s*([A-Za-z0-9][A-Za-z0-9._+!-]*)", dep.get("version_spec", ""))
            if not match:
                continue
            version = match.group(1)
            try:
                resp = http.post(
                    _OSV_API,
                    json={"package": {"name": dep["name"], "ecosystem": "PyPI"}, "version": version},
                    timeout=10,
                )
                if not resp.ok:
                    findings.append(
                        self._lookup_warning(f"OSV returned HTTP {resp.status_code} for {dep['name']}", path)
                    )
                    continue
                for advisory in resp.json().get("vulns", []):
                    finding = self._advisory_finding(dep["name"], version, "PyPI", advisory, path, None)
                    if finding:
                        finding.verdict = "warn"  # Declaration is not proof of an installed environment.
                        finding.detail += " Declared version only; installed environment was not inspected."
                        findings.append(finding)
                    elif isinstance(advisory, dict) and advisory.get("id"):
                        findings.append(
                            self._lookup_warning(
                                f"OSV attribution mismatch: {advisory['id']} does not name {dep['name']}", path
                            )
                        )
            except Exception as exc:
                findings.append(self._lookup_warning(f"OSV lookup failed for {dep['name']}: {exc}", path))
        return findings

    def _check_locked_npm(self, locked: list[LockedPackage], path: Path) -> list[Finding]:
        findings: list[Finding] = []
        # OSV guarantees querybatch result order matches input order.
        for start in range(0, len(locked), 100):
            batch = locked[start : start + 100]
            pending = [
                (
                    package,
                    {"package": {"name": package.name, "ecosystem": "npm"}, "version": package.version},
                )
                for package in batch
            ]
            ids: list[tuple[LockedPackage, str]] = []
            for _ in range(10):  # Bound malformed or endless OSV pagination.
                if not pending:
                    break
                try:
                    response = http.post(_OSV_BATCH_API, json={"queries": [query for _, query in pending]}, timeout=20)
                    if not response.ok:
                        raise ValueError(f"HTTP {response.status_code}")
                    results = response.json().get("results")
                    if not isinstance(results, list) or len(results) != len(pending):
                        raise ValueError("OSV batch response length does not match request")
                except Exception as exc:
                    findings.append(self._lookup_warning(f"OSV npm lookup failed: {exc}", path))
                    pending = []
                    break
                next_pending = []
                for (package, query), result in zip(pending, results, strict=True):
                    if not isinstance(result, dict):
                        findings.append(self._lookup_warning("OSV batch result was malformed", path))
                        continue
                    vulns = result.get("vulns") or []
                    if not isinstance(vulns, list):
                        findings.append(self._lookup_warning("OSV batch vulnerabilities were malformed", path))
                        continue
                    for vuln in vulns:
                        if isinstance(vuln, dict) and isinstance(vuln.get("id"), str):
                            ids.append((package, vuln["id"]))
                    if result.get("next_page_token"):
                        next_pending.append((package, {**query, "page_token": result["next_page_token"]}))
                pending = next_pending
            if pending:
                findings.append(self._lookup_warning("OSV npm lookup pagination incomplete", path))

            details: dict[str, dict] = {}
            for _, advisory_id in ids:
                if advisory_id in details:
                    continue
                if not re.fullmatch(r"[A-Za-z0-9-]+", advisory_id):
                    findings.append(self._lookup_warning("OSV returned malformed advisory ID", path))
                    continue
                try:
                    response = http.get(_OSV_VULN_API + quote(advisory_id, safe=""), timeout=10)
                    if not response.ok:
                        raise ValueError(f"HTTP {response.status_code}")
                    details[advisory_id] = response.json()
                except Exception as exc:
                    findings.append(self._lookup_warning(f"OSV advisory fetch failed for {advisory_id}: {exc}", path))
            emitted: set[tuple[str, str]] = set()
            for package, advisory_id in ids:
                if advisory_id not in details or (package.lock_path, advisory_id) in emitted:
                    continue
                emitted.add((package.lock_path, advisory_id))
                finding = self._advisory_finding(
                    package.name, package.version, "npm", details[advisory_id], path, package
                )
                if finding:
                    findings.append(finding)
                else:
                    findings.append(
                        self._lookup_warning(
                            f"OSV attribution mismatch: {advisory_id} does not name {package.name}", path
                        )
                    )
        return findings

    def _advisory_finding(
        self,
        name: str,
        version: str,
        ecosystem: str,
        advisory: dict,
        path: Path,
        package: LockedPackage | None,
    ) -> Finding | None:
        if not isinstance(advisory, dict) or not isinstance(advisory.get("id"), str):
            return None
        affected = [
            item
            for item in (advisory.get("affected") or [])
            if isinstance(item, dict)
            and isinstance(item.get("package"), dict)
            and isinstance(item["package"].get("name"), str)
            and _package_identity(item["package"]["name"], ecosystem) == _package_identity(name, ecosystem)
            and item["package"].get("ecosystem") == ecosystem
        ]
        if not affected:
            return None
        ranges = [
            range_data for item in affected for range_data in (item.get("ranges") or []) if isinstance(range_data, dict)
        ]
        fixed = sorted(
            {
                event["fixed"]
                for range_data in ranges
                for event in (range_data.get("events") or [])
                if isinstance(event, dict) and isinstance(event.get("fixed"), str)
            }
        )
        database_specific = advisory.get("database_specific") or {}
        severity = database_specific.get("severity", "MEDIUM") if isinstance(database_specific, dict) else "MEDIUM"
        severity = {"MODERATE": "MEDIUM"}.get(str(severity).upper(), str(severity).upper())
        if severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            severity = "MEDIUM"
        advisory_id = advisory["id"]
        source_url = f"https://osv.dev/vulnerability/{quote(advisory_id, safe='')}"
        fixed_note = f"; published fixes: {', '.join(fixed)}" if fixed else "; no fixed version listed"
        scope = "lockfile" if package else "manifest"
        return Finding(
            severity=severity,
            title=f"OSV advisory {advisory_id} matches {name}@{version}",
            detail=f"OSV matched {name}@{version} in {scope}{fixed_note}. Reachability not checked.",
            file_path=str(path),
            scanner=self.name,
            verdict="bad" if package else "warn",
            package=name,
            resolved_version=version if package else None,
            advisory={"id": advisory_id, "source_url": source_url, "affected": ranges, "fixed": fixed},
            evidence=[
                {
                    "type": "osv_version_query",
                    "package": name,
                    "version": version,
                    "ecosystem": ecosystem,
                    "url": source_url,
                    "fetched_at": datetime.now(UTC).isoformat(),
                    "source": scope,
                    "lock_path": package.lock_path if package else None,
                    "direct": package.direct if package else None,
                }
            ],
            remediation=(
                f"Review fixes for {advisory_id}; update dependency and regenerate package-lock.json, "
                "then run npm audit."
                if package
                else "Verify the installed environment and upgrade the affected package."
            ),
            learn=["lockfiles", "osv-version-queries", "advisory-ranges"],
            dependency_chain=list(package.chain) if package else [],
        )

    def _check_typosquatting(self, deps: list[dict], path: Path) -> list[Finding]:
        findings: list[Finding] = []
        for dep in deps:
            name = dep["name"]
            name_norm = name.lower().replace("-", "").replace("_", "")

            known = self._known_pypi if dep["ecosystem"] == "PyPI" else self._known_npm
            # A known target cannot simultaneously be a typo of another target.
            if _is_popular(name) or name.lower() in {item.lower() for item in known}:
                continue

            # Fix 2: Skip very short names — they naturally have small distances
            if _short_name_safe(name) and len(name_norm) <= 4:
                continue

            for legit in known:
                legit_norm = legit.lower().replace("-", "").replace("_", "")
                distance = levenshtein_distance(name_norm, legit_norm)
                if name_norm != legit_norm and distance <= 2:
                    popularity = None
                    if dep["ecosystem"] == "npm":
                        popularity = self._npm_squat_evidence(name, legit)
                        if popularity is None:
                            continue
                    detail = (
                        f"Edit distance {distance} from curated package '{legit}'. "
                        "Name similarity alone cannot establish malicious intent; verify package identity."
                    )
                    evidence = {"type": "name_similarity", "candidate": legit, "distance": distance}
                    if popularity:
                        detail += (
                            f" Last-week npm downloads: {name} {popularity['suspect_downloads']:,}, "
                            f"{legit} {popularity['target_downloads']:,}; "
                            f"candidate created {popularity['created_at']}."
                        )
                        evidence.update(popularity)
                    findings.append(
                        Finding(
                            severity="MEDIUM",
                            title=f"Possible typosquat: '{name}' ≈ '{legit}'",
                            detail=detail,
                            file_path=str(path),
                            scanner=self.name,
                            verdict="warn",
                            package=name,
                            evidence=[evidence],
                            learn=["typosquatting"],
                        )
                    )
                    break
        return findings

    def _npm_squat_evidence(self, suspect: str, target: str) -> dict | None:
        """Require strong directional evidence before naming an npm typosquat candidate.

        npm counts HTTP tarball downloads, not distinct users. Thresholds are
        conservative triage gates, not a calibrated maliciousness score.
        """
        try:
            downloads = {}
            for name in (suspect, target):
                response = http.get(
                    f"https://api.npmjs.org/downloads/point/last-week/{quote(name, safe='')}", timeout=5
                )
                if not response.ok:
                    return None
                count = response.json().get("downloads")
                if not isinstance(count, int) or count < 0:
                    return None
                downloads[name] = count
            suspect_count, target_count = downloads[suspect], downloads[target]
            if target_count < 100_000 or suspect_count > 1_000 or suspect_count / target_count >= 0.01:
                return None

            metadata = {}
            for name in (suspect, target):
                response = http.get(f"https://registry.npmjs.org/{quote(name, safe='')}", timeout=5)
                if not response.ok:
                    return None
                metadata[name] = response.json()
            created_at = metadata[suspect].get("time", {}).get("created")
            if not isinstance(created_at, str):
                return None
            maintainers = [
                {
                    item["name"].lower()
                    for item in metadata[name].get("maintainers", [])
                    if isinstance(item, dict) and isinstance(item.get("name"), str) and item["name"]
                }
                for name in (suspect, target)
            ]
            if maintainers[0] & maintainers[1]:
                return None
            return {
                "suspect_downloads": suspect_count,
                "target_downloads": target_count,
                "created_at": created_at,
                "maintainer_overlap": False,
                "fetched_at": datetime.now(UTC).isoformat(),
                "source_url": f"https://api.npmjs.org/downloads/point/last-week/{quote(suspect, safe='')}",
            }
        except Exception:
            return None

    def _check_source_urls(self, text: str, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        for m in re.finditer(r'source\s*=\s*\(["\']?(https?://[^)"\']+)', text):
            url = m.group(1)
            if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url):
                findings.append(
                    Finding(
                        severity="HIGH",
                        title="PKGBUILD downloads from raw IP address",
                        detail=f"Source URL uses a raw IP: {url} — unexpected for legitimate packages",
                        file_path=str(path),
                        scanner=self.name,
                        verdict="bad",
                    )
                )
        return findings

    # ── Imp 9: Library practice targets ───────────────────────────────────────
    def library_targets(self, deps: list[dict]) -> list[dict]:
        """Rank libraries by repeated manifest declarations, not usage."""
        from collections import Counter

        name_counts = Counter(d["name"] for d in deps)
        targets = []
        for name, count in name_counts.most_common(10):
            if count >= 2:
                targets.append(
                    {
                        "name": name,
                        "count": count,
                        "note": f"declared {count} times in scanned manifests",
                    }
                )
        return targets
