from __future__ import annotations
import json
import re
from pathlib import Path
import requests as http
from repo_tester.scanners.base import BaseScanner
from repo_tester.context import RepoContext
from repo_tester.report import Finding

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

# ── Fix 2: Popular packages with >1000 GitHub stars — whitelisted from typosquatting ──
# These are well-known, established packages. A new package with a similar name
# to one of these should still be flagged, but these packages themselves should NOT
# be flagged as typosquats of each other.
_POPULAR_PACKAGES = {
    "requests", "urllib3", "certifi", "charset-normalizer", "idna",
    "numpy", "pandas", "scipy", "matplotlib", "scikit-learn",
    "flask", "django", "fastapi", "tornado", "celery", "gunicorn", "uvicorn",
    "click", "black", "ruff", "mypy", "isort", "autopep8",
    "pytest", "unittest2", "nose2", "coverage", "tox",
    "sqlalchemy", "psycopg2", "pymongo", "redis",
    "boto3", "botocore", "aiohttp", "httpx",
    "pillow", "opencv-python", "scikit-image",
    "tensorflow", "torch", "keras", "jax", "transformers",
    "cryptography", "paramiko", "pyopenssl", "passlib",
    "jinja2", "markupsafe", "werkzeug", "itsdangerous",
    "setuptools", "wheel", "pip", "build", "hatchling", "flit-core",
    "pydantic", "rich", "typer", "loguru", "arrow", "attrs",
    "pyyaml", "toml", "tomli", "tomli-w",
    "six", "packaging", "filelock", "platformdirs", "virtualenv",
    "tqdm", "colorama", "pygments",
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
            findings.extend(self._check_pinning(deps, path))
            findings.extend(self._check_osv(deps, path))
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
        deps: list[dict] = []
        in_deps = False
        for line in text.splitlines():
            if re.search(r"^\[?dependencies\]?", line):
                in_deps = True
            if in_deps:
                m = re.search(r'"([A-Za-z0-9_\-\.]+)\s*([>=<!~^][^"]*)?"', line)
                if m:
                    deps.append({"name": m.group(1), "version_spec": (m.group(2) or "").strip(), "ecosystem": "PyPI"})
                if line.strip().startswith("[") and "dependencies" not in line:
                    in_deps = False
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

    def _check_pinning(self, deps: list[dict], path: Path) -> list[Finding]:
        findings: list[Finding] = []
        for dep in deps:
            spec = dep["version_spec"]
            if not spec or spec.startswith(">=") or spec in ("*", "latest"):
                findings.append(Finding(
                    severity="MEDIUM",
                    title=f"Unpinned dependency: {dep['name']}",
                    detail=f"Version '{spec or 'unspecified'}' allows unexpected upgrades that may introduce vulnerabilities",
                    file_path=str(path),
                    scanner=self.name,
                    verdict="warn",
                ))
        return findings

    def _check_osv(self, deps: list[dict], path: Path) -> list[Finding]:
        findings: list[Finding] = []
        for dep in deps:
            if dep["ecosystem"] not in ("PyPI", "npm"):
                continue
            try:
                query_data = {"package": {"name": dep["name"], "ecosystem": dep["ecosystem"]}}
                version_spec = dep.get("version_spec", "")
                version = None
                if version_spec.startswith("=="):
                    version = version_spec[2:].strip()
                    query_data["version"] = version

                resp = http.post(
                    _OSV_API,
                    json=query_data,
                    timeout=10,
                )
                if resp.ok:
                    vulns = resp.json().get("vulns", [])
                    if vulns:
                        ids = ", ".join(v["id"] for v in vulns[:3])
                        suffix = f" (+{len(vulns) - 3} more)" if len(vulns) > 3 else ""
                        version_note = f" (v{version})" if version else ""
                        findings.append(Finding(
                            severity="HIGH",
                            title=f"Known CVEs in {dep['name']}{version_note}",
                            detail=f"{len(vulns)} vulnerabilities: {ids}{suffix}",
                            file_path=str(path),
                            scanner=self.name,
                            verdict="bad",
                        ))
            except Exception:
                pass
        return findings

    def _check_typosquatting(self, deps: list[dict], path: Path) -> list[Finding]:
        findings: list[Finding] = []
        for dep in deps:
            name = dep["name"]
            name_norm = name.lower().replace("-", "").replace("_", "")

            # Fix 2: Skip popular/established packages
            if _is_popular(name):
                continue

            # Fix 2: Skip very short names — they naturally have small distances
            if _short_name_safe(name) and len(name_norm) <= 4:
                continue

            known = self._known_pypi if dep["ecosystem"] == "PyPI" else self._known_npm
            for legit in known:
                legit_norm = legit.lower().replace("-", "").replace("_", "")
                if name_norm != legit_norm and levenshtein_distance(name_norm, legit_norm) <= 2:
                    findings.append(Finding(
                        severity="HIGH",
                        title=f"Possible typosquat: '{name}' ≈ '{legit}'",
                        detail=f"Package name is very close to popular package '{legit}' — verify this is intentional",
                        file_path=str(path),
                        scanner=self.name,
                        verdict="bad",
                    ))
                    break
        return findings

    def _check_source_urls(self, text: str, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        for m in re.finditer(r'source\s*=\s*\(["\']?(https?://[^)"\']+)', text):
            url = m.group(1)
            if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url):
                findings.append(Finding(
                    severity="HIGH",
                    title="PKGBUILD downloads from raw IP address",
                    detail=f"Source URL uses a raw IP: {url} — unexpected for legitimate packages",
                    file_path=str(path),
                    scanner=self.name,
                    verdict="bad",
                ))
        return findings

    # ── Imp 9: Library practice targets ───────────────────────────────────────
    def library_targets(self, deps: list[dict]) -> list[dict]:
        """Rank flagged libraries by how often they appear in the dep tree."""
        from collections import Counter
        name_counts = Counter(d["name"] for d in deps)
        targets = []
        for name, count in name_counts.most_common(10):
            if count >= 2:
                targets.append({
                    "name": name,
                    "count": count,
                    "note": f"appears {count}x in dependency tree",
                })
        return targets
