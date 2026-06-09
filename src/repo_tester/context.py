from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from contextlib import contextmanager
from typing import TYPE_CHECKING
import fnmatch
import json
import re
import subprocess
import tempfile
import shutil

if TYPE_CHECKING:
    from repo_tester.report import Finding

INSTALL_SCRIPT_NAMES = {
    "install.sh", "install.bash", "bootstrap.sh", "build.sh",
    "setup.py", "PKGBUILD", "Makefile",
}

# ── Fix 4: Ignore rule support ──────────────────────────────────────────────
@dataclass
class IgnoreRule:
    """A single ignore rule from .repo-tester-ignore"""
    pattern: str          # glob pattern for file path matching
    scanners: list[str]   # scanner names to suppress (empty = all)
    findings: list[str]   # finding title substrings to suppress (empty = all)
    severities: list[str] # severity levels to suppress (empty = all)


@dataclass
class IgnoreConfig:
    """Loaded .repo-tester-ignore configuration"""
    rules: list[IgnoreRule] = field(default_factory=list)

    def is_ignored(self, finding: "Finding") -> bool:
        """Check if a finding matches any ignore rule."""
        for rule in self.rules:
            # Check scanner match
            if rule.scanners and finding.scanner not in rule.scanners:
                continue
            # Check severity match
            if rule.severities and finding.severity not in rule.severities:
                continue
            # Check finding title match
            if rule.findings:
                if not any(f_sub in finding.title for f_sub in rule.findings):
                    continue
            # Check file path pattern
            if finding.file_path:
                # Normalize path for matching
                file_name = Path(finding.file_path).name
                rel_path = finding.file_path.replace("\\", "/")
                # Match against: basename, full path, or suffix of path
                # (e.g., ".github/workflows/ci.yml" matches "/tmp/repo/.github/workflows/ci.yml")
                matches = (
                    fnmatch.fnmatch(file_name, rule.pattern) or
                    fnmatch.fnmatch(rel_path, rule.pattern) or
                    fnmatch.fnmatch(finding.file_path, rule.pattern) or
                    rel_path.endswith(rule.pattern.lstrip("*/")) or
                    rel_path.endswith("/" + rule.pattern.lstrip("*/"))
                )
                if not matches:
                    continue
            # All matched criteria — this finding is ignored
            return True
        return False


def _load_ignore_config(repo_path: Path) -> IgnoreConfig:
    """Load .repo-tester-ignore from the cloned repository root."""
    config_file = repo_path / ".repo-tester-ignore"
    config = IgnoreConfig()
    if not config_file.exists():
        return config
    try:
        data = json.loads(config_file.read_text())
        for rule in data.get("rules", []):
            config.rules.append(IgnoreRule(
                pattern=rule.get("pattern", "*"),
                scanners=rule.get("scanners", []),
                findings=rule.get("findings", []),
                severities=rule.get("severities", []),
            ))
    except (json.JSONDecodeError, KeyError, TypeError):
        pass  # Malformed config — proceed without ignores
    return config


def _parse_github_url(url: str) -> tuple[str, str]:
    match = re.search(r"https?://github\.com/([^/]+)/([^/\s]+?)(?:\.git)?$", url)
    if not match:
        raise ValueError(f"Not a valid GitHub URL: {url}")
    return match.group(1), match.group(2)


@dataclass
class RepoContext:
    url: str
    owner: str
    repo: str
    local_path: Path
    files: list[Path] = field(default_factory=list)
    install_scripts: list[Path] = field(default_factory=list)
    ignore_config: IgnoreConfig = field(default_factory=IgnoreConfig)

    def _classify_files(self) -> None:
        for f in self.local_path.rglob("*"):
            if f.is_file() and ".git" not in f.parts:
                self.files.append(f)
                if f.name in INSTALL_SCRIPT_NAMES:
                    self.install_scripts.append(f)


@contextmanager
def clone_repo(url: str):
    """Shallow-clone a GitHub repo to a temp dir, yield RepoContext, always clean up."""
    owner, repo = _parse_github_url(url)
    tmpdir = tempfile.mkdtemp(prefix="repo-tester-")
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet", url, tmpdir],
            check=True,
            capture_output=True,
            timeout=180,
        )
        ctx = RepoContext(url=url, owner=owner, repo=repo, local_path=Path(tmpdir))
        ctx._classify_files()
        # Fix 4: Load ignore config
        ctx.ignore_config = _load_ignore_config(Path(tmpdir))
        yield ctx
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
