import pytest
from unittest.mock import patch
from pathlib import Path
from repo_tester.context import clone_repo, RepoContext, _parse_github_url


def test_parse_github_url_valid():
    owner, repo = _parse_github_url("https://github.com/Dennis-J-Carroll/claude-desktop-bin")
    assert owner == "Dennis-J-Carroll"
    assert repo == "claude-desktop-bin"


def test_parse_github_url_with_git_suffix():
    owner, repo = _parse_github_url("https://github.com/foo/bar.git")
    assert owner == "foo"
    assert repo == "bar"


def test_parse_github_url_invalid_raises():
    with pytest.raises(ValueError, match="Not a valid GitHub URL"):
        _parse_github_url("https://gitlab.com/foo/bar")


def test_clone_repo_cleans_up_on_exit(tmp_path):
    fake_tmpdir = str(tmp_path / "clone")
    Path(fake_tmpdir).mkdir()
    (Path(fake_tmpdir) / "README.md").write_text("hello")

    with patch("repo_tester.context.tempfile.mkdtemp", return_value=fake_tmpdir), \
         patch("repo_tester.context.subprocess.run"):
        with clone_repo("https://github.com/x/y") as ctx:
            assert ctx.owner == "x"
            assert ctx.repo == "y"
    # temp dir should be gone
    assert not Path(fake_tmpdir).exists()


def test_repo_context_classifies_install_scripts(tmp_path):
    ctx = RepoContext(
        url="https://github.com/x/y",
        owner="x",
        repo="y",
        local_path=tmp_path,
    )
    (tmp_path / "install.sh").write_text("#!/bin/bash")
    (tmp_path / "README.md").write_text("# readme")
    (tmp_path / "PKGBUILD").write_text("pkgname=foo")
    ctx._classify_files()

    names = [f.name for f in ctx.install_scripts]
    assert "install.sh" in names
    assert "PKGBUILD" in names
    assert "README.md" not in names
