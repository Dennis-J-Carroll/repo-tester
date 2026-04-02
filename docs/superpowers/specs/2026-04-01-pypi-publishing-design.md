# PyPI Publishing Design

**Date:** 2026-04-01  
**Author:** Dennis J. Carroll  
**Status:** Approved

## Overview

This document describes the design for publishing `repo-tester` to PyPI (Python Package Index) for the first time. The package will use modern Python packaging standards (PEP 621), trusted publishing via GitHub Actions OIDC, and a safety-gated workflow that tests on TestPyPI before releasing to production PyPI.

## Goals

1. Publish `repo-tester` to PyPI for public installation via `pip install repo-tester`
2. Ensure professional package presentation with complete metadata and visual README
3. Automate publishing via GitHub Actions with manual approval gates
4. Use secure trusted publishing (OIDC) instead of API tokens
5. Test releases on TestPyPI before production deployment

## Non-Goals

- Automated version bumping (versions are manually controlled in `pyproject.toml`)
- Conda/alternative package manager support
- Package signing beyond PyPI's built-in attestation

## Context

**Current state:**
- Package uses modern `pyproject.toml` with hatchling build backend
- Local build artifact exists (`dist/repo_tester-0.1.0.tar.gz`)
- Package installed locally in editable mode
- GitHub workflow references PyPI install but package not yet published
- Missing PyPI metadata (author, README, URLs, classifiers)
- Logo file exists: `logo.PNG` (1.7MB)

**User requirements:**
- Initial PyPI release (version 0.1.0)
- Test on TestPyPI before production publish
- Automated publishing via GitHub Actions
- Comprehensive README with logo, badges, screenshots
- Author: Dennis J. Carroll <denniscarrollj@gmail.com>
- License: MIT

## Design

### 1. PyPI Metadata Enhancement

**File:** `pyproject.toml`

Add complete PEP 621 metadata fields:

**Author Information:**
```toml
authors = [{name = "Dennis J. Carroll", email = "denniscarrollj@gmail.com"}]
```

**README Reference:**
```toml
readme = "README.md"
```
This makes PyPI display the README as the package's long description (main content on package page).

**License:**
```toml
license = {text = "MIT"}
```

**Project URLs:**
```toml
[project.urls]
Homepage = "https://github.com/Dennis-J-Carroll/repo-tester"
Repository = "https://github.com/Dennis-J-Carroll/repo-tester"
Issues = "https://github.com/Dennis-J-Carroll/repo-tester/issues"
```

**Keywords:**
```toml
keywords = ["security", "github", "scanner", "malicious-code", "repository", "safety", "supply-chain"]
```

**Classifiers:**
```toml
classifiers = [
    "Development Status :: 4 - Beta",
    "Intended Audience :: Developers",
    "Intended Audience :: System Administrators",
    "Topic :: Security",
    "Topic :: Software Development :: Quality Assurance",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Programming Language :: Python :: 3.13",
    "Operating System :: OS Independent",
    "Environment :: Console",
]
```

**Rationale:**
- Classifiers make the package discoverable via PyPI search filters
- URLs provide navigation to source code, documentation, and issue tracker
- Keywords improve search engine optimization on PyPI
- Author info is required metadata and builds trust

### 2. README.md Structure

**File:** `README.md` (root directory)

**Visual elements:**
1. **Logo banner** - `logo.PNG` displayed at top via Markdown image
2. **Badges row** - PyPI version, Python versions, MIT license, build status
3. **Screenshots** - Example CLI output showing scanner in action with colored severity levels
4. **Optional diagram** - Three-scanner architecture visualization

**Content structure:**
```markdown
# [Logo: logo.PNG]

# repo-tester

[Badges]

**GitHub repository safety scanner** - Detect malicious patterns, supply chain risks, and repository health issues

## Overview
2-3 sentence description of what repo-tester does and why users need it. Focus on security value proposition.

## Features
- 🔍 **Malicious Pattern Detection** - Obfuscated code, suspicious imports, credential theft patterns
- 🔗 **Supply Chain Analysis** - Typosquatting detection, dependency confusion checks
- 📊 **Repository Health Checks** - Outdated dependencies, missing CI/CD, security policies
- ⚡ **Fast Parallel Scanning** - Three scanners run concurrently via ThreadPoolExecutor
- 📋 **Flexible Output** - JSON for automation, text for human review

## Installation

```bash
pip install repo-tester
```

## Quick Start

```bash
# Scan a repository
repo-tester https://github.com/owner/repo

# JSON output for CI/CD integration
repo-tester https://github.com/owner/repo --format json

# Quiet mode (silent if clean, exit code 0/1)
repo-tester https://github.com/owner/repo --quiet
```

[Screenshot: Example output showing severity levels and findings]

## Usage Examples

### Basic Scan
Show example of text output with colored severity levels (CRITICAL, HIGH, MEDIUM, LOW, INFO)

### CI/CD Integration
Show JSON output example and how to parse it in CI pipelines

### Exit Codes
- `0` - Clean (no findings)
- `1` - Issues found
- `2` - Error (network, clone failure, etc.)

## How It Works

Brief explanation of the three-scanner architecture:
1. **MaliciousPatternScanner** (Priority 1) - Pattern matching against known malicious code signatures
2. **SupplyChainScanner** (Priority 2) - Dependency analysis and typosquatting detection
3. **RepoHealthScanner** (Priority 3) - GitHub API checks for security best practices

All scanners run in parallel for fast results.

[Optional: Architecture diagram]

## Development

See [CLAUDE.md](CLAUDE.md) for development setup, testing, and architecture details.

## Security

See [SECURITY.md](SECURITY.md) for security policy and vulnerability reporting.

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Contributing

Contributions welcome! Check [CLAUDE.md](CLAUDE.md) for:
- Development environment setup
- Running tests
- Adding new malicious patterns
- Creating new scanners

---

**Author:** Dennis J. Carroll  
**Repository:** https://github.com/Dennis-J-Carroll/repo-tester
```

**Badges to include:**
- `[![PyPI version](https://badge.fury.io/py/repo-tester.svg)](https://pypi.org/project/repo-tester/)`
- `[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)`
- `[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)`
- `[![Build Status](https://github.com/Dennis-J-Carroll/repo-tester/workflows/Security%20Scan/badge.svg)](https://github.com/Dennis-J-Carroll/repo-tester/actions)`

**Content tone:** Professional, security-focused, emphasizes speed and ease of use. Target audience: developers, security engineers, DevOps teams.

### 3. GitHub Actions Publishing Workflow

**File:** `.github/workflows/publish.yml`

**Trigger:**
```yaml
on:
  push:
    tags:
      - 'v*.*.*'
```

Workflow runs when version tags are pushed (e.g., `v0.1.0`, `v1.2.3`, `v0.2.0-beta.1`).

**Two-job structure:**

#### Job 1: `test-publish` (Automatic)

**Purpose:** Immediate publish to TestPyPI for verification

**Steps:**
1. Checkout code
2. Set up Python 3.11
3. Install build tools: `pip install build`
4. Build package: `python -m build`
5. Publish to TestPyPI using `pypa/gh-action-pypi-publish@release/v1`
   - Uses OIDC trusted publishing (no tokens)
   - `repository-url: https://test.pypi.org/legacy/`
   - Requires `id-token: write` permission

**Output:** Prints TestPyPI URL for verification: `https://test.pypi.org/project/repo-tester/`

**Verification command:**
```bash
pip install -i https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ repo-tester
```
(Extra index needed because dependencies live on production PyPI)

#### Job 2: `publish` (Manual Approval Required)

**Purpose:** Production PyPI release after TestPyPI verification

**Dependencies:**
- `needs: test-publish` (waits for TestPyPI job to complete)
- `environment: release` (triggers GitHub approval UI)

**Environment protection rule:**
GitHub repository settings will have a `release` environment configured with required reviewers (you). When the job reaches this step, GitHub pauses and sends notification. You click "Review deployments" → "Approve" in the Actions UI.

**Steps:**
1. Checkout code
2. Set up Python 3.11
3. Build package: `python -m build` (clean build, not reusing test-publish artifacts)
4. Publish to PyPI using `pypa/gh-action-pypi-publish@release/v1`
   - Uses OIDC trusted publishing
   - `repository-url: https://upload.pypi.org/legacy/` (production)
   - Requires `id-token: write` permission

**Output:** Prints PyPI URL: `https://pypi.org/project/repo-tester/`

**Workflow YAML structure:**
```yaml
name: Publish to PyPI

on:
  push:
    tags:
      - 'v*.*.*'

permissions:
  id-token: write  # Required for OIDC trusted publishing
  contents: read

jobs:
  test-publish:
    name: Publish to TestPyPI
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Build package
        run: |
          pip install build
          python -m build
      - name: Publish to TestPyPI
        uses: pypa/gh-action-pypi-publish@release/v1
        with:
          repository-url: https://test.pypi.org/legacy/

  publish:
    name: Publish to PyPI
    needs: test-publish
    runs-on: ubuntu-latest
    environment: release  # Triggers manual approval
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Build package
        run: |
          pip install build
          python -m build
      - name: Publish to PyPI
        uses: pypa/gh-action-pypi-publish@release/v1
```

**Safety gates:**
1. TestPyPI publishes first automatically
2. Manual verification step (test install from TestPyPI)
3. Manual approval required for PyPI publish
4. Trusted publishing eliminates token leak risk

### 4. Trusted Publishing (OIDC) Configuration

**What is trusted publishing?**
PyPI's OIDC-based authentication system allows GitHub Actions to publish packages without API tokens. GitHub proves its identity to PyPI using OpenID Connect, and PyPI verifies the workflow is authorized to publish.

**One-time setup required:**

#### TestPyPI Configuration (test.pypi.org)

**Timing:** Before first tag push

**Steps:**
1. Log in to https://test.pypi.org
2. Navigate to Account Settings → Publishing
3. Click "Add a new publisher"
4. Fill in form:
   - **PyPI Project Name:** `repo-tester`
   - **Owner:** `Dennis-J-Carroll`
   - **Repository name:** `repo-tester`
   - **Workflow name:** `publish.yml`
   - **Environment name:** (leave blank)
5. Click "Add"

**Result:** TestPyPI will trust the `test-publish` job in your `publish.yml` workflow to create and update the `repo-tester` package.

#### PyPI Configuration (pypi.org)

**Timing:** After successful TestPyPI publish (PyPI requires proof that project exists)

**Steps:**
1. Log in to https://pypi.org
2. Navigate to Account Settings → Publishing
3. Click "Add a new publisher"
4. Fill in form:
   - **PyPI Project Name:** `repo-tester`
   - **Owner:** `Dennis-J-Carroll`
   - **Repository name:** `repo-tester`
   - **Workflow name:** `publish.yml`
   - **Environment name:** `release`
5. Click "Add"

**Important:** The environment name `release` must match the `environment:` field in the `publish` job. This links the OIDC identity to the specific approval-gated job.

**Result:** PyPI will trust only the `publish` job (with `release` environment) to publish packages. The manual approval in GitHub creates an audit trail.

#### GitHub Environment Configuration

**Timing:** Before first tag push

**Steps:**
1. Go to repository Settings → Environments
2. Click "New environment"
3. Name: `release`
4. Check "Required reviewers"
5. Add yourself (Dennis-J-Carroll) as required reviewer
6. Click "Save protection rules"

**Result:** When the `publish` job runs, GitHub pauses and requires your approval before proceeding.

**Verification:**
After OIDC setup, the workflow will have:
- No secrets/tokens in repository settings
- No credentials in workflow YAML
- GitHub's identity system proves authorization to PyPI

### 5. Version Management and Release Process

**Current version:** `0.1.0` (in `pyproject.toml`)

**Version bump strategy:**
- Manual updates to `pyproject.toml` version field
- Follow semantic versioning: `MAJOR.MINOR.PATCH`
  - MAJOR: Breaking changes
  - MINOR: New features (backward compatible)
  - PATCH: Bug fixes
- Pre-release versions supported: `0.2.0-beta.1`, `1.0.0-rc.2`

**Git tag format:**
- Must match `v*.*.*` pattern
- Should match version in `pyproject.toml` (e.g., version `0.1.0` → tag `v0.1.0`)
- The workflow extracts version from git tag, but build uses `pyproject.toml` version
- **Important:** Keep git tag and `pyproject.toml` version in sync

**Release workflow (step-by-step):**

1. **Update version in code:**
   ```bash
   # Edit pyproject.toml, change version = "0.1.0" to version = "0.2.0"
   git add pyproject.toml
   git commit -m "chore: bump version to 0.2.0"
   git push origin master
   ```

2. **Create and push tag:**
   ```bash
   git tag v0.2.0
   git push origin v0.2.0
   ```

3. **Automatic TestPyPI publish:**
   - GitHub Actions workflow triggers
   - `test-publish` job runs automatically
   - Package builds and publishes to TestPyPI
   - Check Actions tab for TestPyPI URL

4. **Verify TestPyPI package:**
   ```bash
   # Create test virtualenv
   python -m venv test-env
   source test-env/bin/activate
   
   # Install from TestPyPI
   pip install -i https://test.pypi.org/simple/ \
       --extra-index-url https://pypi.org/simple/ \
       repo-tester
   
   # Test it works
   repo-tester --help
   repo-tester https://github.com/some/repo
   
   # Clean up
   deactivate
   rm -rf test-env
   ```

5. **Manual approval for PyPI:**
   - Go to repository Actions tab
   - Click on the running workflow
   - Click "Review deployments" button
   - Check "release" environment
   - Click "Approve and deploy"

6. **Automatic PyPI publish:**
   - `publish` job runs after approval
   - Package builds and publishes to production PyPI
   - Check Actions tab for PyPI URL

7. **Verify production install:**
   ```bash
   pip install repo-tester
   repo-tester --version  # Should show 0.2.0
   ```

**Rollback strategy:**
PyPI does not allow deleting or replacing published versions (security measure). If a bad release goes out:
1. Immediately publish a patch version (e.g., `0.2.1`)
2. Mark the broken version as "yanked" on PyPI web UI (prevents new installs but doesn't break existing ones)
3. Document the issue in GitHub releases

**Version constraints:**
- `requires-python = ">=3.11"` ensures package only installs on Python 3.11+
- Dependencies are pinned to exact versions in current `pyproject.toml` (good for security scanner)
- Future: Consider using `>=` constraints for libraries (e.g., `click>=8.1.7`) to avoid dependency conflicts

### 6. Build Configuration

**No changes to build system** - existing setup is correct.

**Current configuration:**
```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/repo_tester"]
```

**What this does:**
- Uses `hatchling` as PEP 517 build backend (modern, fast, minimal)
- Builds wheel and source distributions
- Packages `src/repo_tester/` directory (src-layout best practice)
- CLI entry point already configured: `repo-tester = "repo_tester.cli:main"`

**Build outputs:**
- `dist/repo_tester-0.1.0-py3-none-any.whl` (wheel - preferred install format)
- `dist/repo_tester-0.1.0.tar.gz` (source distribution - fallback)

**No changes needed because:**
- Hatchling automatically includes `README.md`, `LICENSE`, `SECURITY.md` in distributions
- Package structure follows best practices (src-layout)
- Entry points already configured
- Dependencies already declared

**Future considerations:**
- Add `[project.optional-dependencies]` for dev dependencies (pytest, pytest-mock)
- Consider adding `[tool.hatch.version]` for dynamic versioning from git tags (current manual approach is fine)

## Implementation Plan

Detailed implementation steps will be created in the next phase (writing-plans skill). High-level sequence:

1. Update `pyproject.toml` with metadata
2. Create `README.md` with logo, badges, content
3. Create `.github/workflows/publish.yml`
4. Configure OIDC on TestPyPI and PyPI websites
5. Configure GitHub `release` environment
6. Test workflow with first tag push (`v0.1.0`)
7. Verify TestPyPI install
8. Approve and publish to PyPI
9. Verify production install
10. Update existing `.github/workflows/security-scan.yml` to remove PyPI install (it will work after publishing)

## Testing Strategy

**Pre-publish validation:**
- Local build test: `python -m build`
- Check distribution contents: `tar -tzf dist/repo_tester-0.1.0.tar.gz`
- Test local install: `pip install dist/repo_tester-0.1.0-py3-none-any.whl`
- Run CLI: `repo-tester --help` and scan a test repo

**TestPyPI validation:**
- Install from TestPyPI with extra index for dependencies
- Verify CLI works
- Verify `--version` shows correct version
- Verify all scanners run (test scan against known malicious repo)

**Post-publish validation:**
- Install from PyPI: `pip install repo-tester`
- Verify package metadata on PyPI web page
- Verify README renders correctly
- Verify badges work
- Test CLI functionality

**Rollback plan:**
- If TestPyPI package broken: fix locally, push new tag with patch version
- If PyPI package broken: immediately publish patch version, yank broken version on PyPI UI

## Security Considerations

**Trusted publishing benefits:**
- No API tokens to leak or rotate
- OIDC authentication tied to specific repository + workflow + environment
- GitHub's identity system provides audit trail
- Manual approval creates human checkpoint

**Supply chain security:**
- Workflow pins action versions with SHA (e.g., `actions/checkout@v4`)
- Build process is reproducible (no custom scripts)
- All build artifacts generated in GitHub's infrastructure (not local machine)
- Dependencies declared explicitly in `pyproject.toml`

**Package integrity:**
- PyPI automatically generates attestations for packages published via trusted publishing
- Users can verify package provenance using `pip verify` (future feature)

**Risks and mitigations:**
- **Risk:** Compromised GitHub account could push malicious tag
  - **Mitigation:** Enable 2FA on GitHub account, use SSH keys, review changes before tagging
- **Risk:** Malicious dependency could be included
  - **Mitigation:** Pinned dependencies, security scanning in CI, careful dependency updates
- **Risk:** Typosquatting of our package name
  - **Mitigation:** Register package name quickly, monitor PyPI for similar names

## Open Questions

None - all questions resolved during brainstorming phase.

## Future Enhancements

**Not in scope for initial release, but noted for future:**
1. **Automated version bumping** - Use `commitizen` or `semantic-release` to auto-bump versions from commit messages
2. **Changelog generation** - Auto-generate `CHANGELOG.md` from git commits
3. **GitHub Releases** - Auto-create GitHub releases with changelog when tags are pushed
4. **Download stats badge** - Add PyPI downloads badge after package gets traction
5. **Read the Docs** - Set up documentation site if project grows
6. **conda-forge** - Publish to conda-forge for conda users
7. **Docker image** - Publish to Docker Hub for containerized usage
8. **Homebrew formula** - Create formula for macOS `brew install repo-tester`

## Success Criteria

Initial release is successful when:
1. ✅ Package appears on PyPI: https://pypi.org/project/repo-tester/
2. ✅ `pip install repo-tester` works from any machine
3. ✅ PyPI page shows complete metadata (author, license, links, classifiers)
4. ✅ README renders correctly with logo and badges
5. ✅ CLI command `repo-tester` available after install
6. ✅ GitHub Actions workflow completes successfully
7. ✅ Manual approval gate works as expected
8. ✅ TestPyPI → PyPI promotion process validated

## References

- [PEP 621 - Storing project metadata in pyproject.toml](https://peps.python.org/pep-0621/)
- [PyPI Trusted Publishers (OIDC)](https://docs.pypi.org/trusted-publishers/)
- [GitHub Actions Publishing Python Packages](https://docs.github.com/en/actions/automating-builds-and-tests/building-and-testing-python#publishing-to-package-registries)
- [Python Packaging User Guide](https://packaging.python.org/)
- [Hatchling Build Backend](https://hatch.pypa.io/latest/config/build/)
- [Semantic Versioning](https://semver.org/)
