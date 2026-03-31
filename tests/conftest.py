import pytest
from pathlib import Path
from repo_tester.context import RepoContext


@pytest.fixture
def tmp_repo(tmp_path):
    """Fake RepoContext backed by a temp directory. No git clone needed."""
    repo = RepoContext(
        url="https://github.com/test/repo",
        owner="test",
        repo="repo",
        local_path=tmp_path,
    )
    repo.files = []
    repo.install_scripts = []
    return repo


def make_file(repo: RepoContext, name: str, content: str, is_install: bool = False) -> Path:
    """Create a file in the fake repo and register it."""
    path = repo.local_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    repo.files.append(path)
    if is_install:
        repo.install_scripts.append(path)
    return path
