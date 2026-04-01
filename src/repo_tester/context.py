from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from contextlib import contextmanager
import re
import subprocess
import tempfile
import shutil

INSTALL_SCRIPT_NAMES = {
    "install.sh", "install.bash", "bootstrap.sh", "build.sh",
    "setup.py", "PKGBUILD", "Makefile",
}


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
        yield ctx
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
