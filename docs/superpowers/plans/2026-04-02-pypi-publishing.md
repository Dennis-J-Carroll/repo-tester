# PyPI Publishing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish repo-tester to PyPI with automated GitHub Actions workflow using trusted publishing (OIDC)

**Architecture:** Add complete PEP 621 metadata to pyproject.toml, create comprehensive README with logo/badges, implement two-stage GitHub Actions workflow (TestPyPI → manual approval → PyPI) using OIDC authentication

**Tech Stack:** pyproject.toml (PEP 621), GitHub Actions, PyPI trusted publishing (OIDC), hatchling build backend

---

## File Structure

**Files to modify:**
- `pyproject.toml` - Add author, README reference, license, URLs, keywords, classifiers

**Files to create:**
- `README.md` - Comprehensive documentation with logo, badges, usage examples
- `.github/workflows/publish.yml` - Two-job workflow for TestPyPI and PyPI publishing

**Manual configuration (documented in tasks):**
- TestPyPI OIDC publisher setup
- PyPI OIDC publisher setup
- GitHub environment configuration

---

### Task 1: Add PyPI Metadata to pyproject.toml

**Files:**
- Modify: `pyproject.toml:5-14` (project section)

- [ ] **Step 1: Add author information**

Edit `pyproject.toml`, add after line 9 (after `requires-python`):

```toml
authors = [{name = "Dennis J. Carroll", email = "denniscarrollj@gmail.com"}]
```

The `[project]` section should now look like:
```toml
[project]
name = "repo-tester"
version = "0.1.0"
description = "GitHub repository safety scanner"
requires-python = ">=3.11"
authors = [{name = "Dennis J. Carroll", email = "denniscarrollj@gmail.com"}]
dependencies = [
    "click==8.1.7",
    "requests==2.33.1",
    "python-Levenshtein==0.27.3",
]
```

- [ ] **Step 2: Add README and license references**

Add after the `authors` line:

```toml
readme = "README.md"
license = {text = "MIT"}
```

- [ ] **Step 3: Add keywords**

Add after the `license` line:

```toml
keywords = ["security", "github", "scanner", "malicious-code", "repository", "safety", "supply-chain"]
```

- [ ] **Step 4: Add classifiers**

Add after the `keywords` line:

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

- [ ] **Step 5: Add project URLs**

Add after the `[project.scripts]` section (around line 17):

```toml
[project.urls]
Homepage = "https://github.com/Dennis-J-Carroll/repo-tester"
Repository = "https://github.com/Dennis-J-Carroll/repo-tester"
Issues = "https://github.com/Dennis-J-Carroll/repo-tester/issues"
```

- [ ] **Step 6: Verify pyproject.toml syntax**

Run: `python -c "import tomllib; tomllib.load(open('pyproject.toml', 'rb'))"`

Expected: No output (success)

If error: Fix TOML syntax errors

- [ ] **Step 7: Commit metadata changes**

```bash
git add pyproject.toml
git commit -m "feat: add complete PyPI metadata to pyproject.toml

Add author, README reference, license, keywords, classifiers, and
project URLs for PyPI package page.

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Task 2: Create Comprehensive README.md

**Files:**
- Create: `README.md`

- [ ] **Step 1: Create README with logo and header**

Create `README.md`:

```markdown
<p align="center">
  <img src="logo.PNG" alt="repo-tester logo" width="600">
</p>

# repo-tester

[![PyPI version](https://badge.fury.io/py/repo-tester.svg)](https://pypi.org/project/repo-tester/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://github.com/Dennis-J-Carroll/repo-tester/workflows/Security%20Scan/badge.svg)](https://github.com/Dennis-J-Carroll/repo-tester/actions)

**GitHub repository safety scanner** - Detect malicious patterns, supply chain risks, and repository health issues

## Overview

`repo-tester` is a comprehensive security scanner for GitHub repositories that identifies malicious code patterns, supply chain vulnerabilities, and repository health issues. Built for security engineers, DevOps teams, and developers, it provides fast parallel scanning with actionable findings.

Perfect for vetting third-party repositories, auditing dependencies, and integrating security checks into CI/CD pipelines.

## Features

- 🔍 **Malicious Pattern Detection** - Identifies obfuscated code, suspicious imports, base64 encoding, credential theft patterns, and hidden backdoors
- 🔗 **Supply Chain Analysis** - Detects typosquatting attacks, dependency confusion risks, and suspicious package names
- 📊 **Repository Health Checks** - Analyzes GitHub metadata, checks for security policies, outdated dependencies, and missing CI/CD workflows
- ⚡ **Fast Parallel Scanning** - Three specialized scanners run concurrently via ThreadPoolExecutor for rapid results
- 📋 **Flexible Output** - JSON format for automation and CI/CD integration, human-readable text for manual review
- 🎯 **Priority-Based Findings** - Results organized by severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)

## Installation

```bash
pip install repo-tester
```

Requires Python 3.11 or higher.

## Quick Start

```bash
# Scan a repository
repo-tester https://github.com/owner/repo

# JSON output for CI/CD integration
repo-tester https://github.com/owner/repo --format json

# Quiet mode (silent if clean, exit code 0/1)
repo-tester https://github.com/owner/repo --quiet
```

### Example Output

```
🔍 Scanning repository: https://github.com/suspicious/package
📦 Cloning to temporary directory...

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Scan Results
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔴 CRITICAL: Base64-encoded exec() detected
   File: src/utils.py:42
   Pattern: exec(base64.b64decode(...))

🟠 HIGH: Typosquatting risk detected
   Package: requsts (similar to: requests)

🟡 MEDIUM: Missing SECURITY.md
   Repository has no security policy

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Summary: 3 findings (1 CRITICAL, 1 HIGH, 1 MEDIUM)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

## Usage Examples

### Basic Scan

Scan any public GitHub repository:

```bash
repo-tester https://github.com/owner/repo
```

Exit codes:
- `0` - Clean scan (no findings)
- `1` - Issues found
- `2` - Error (network failure, clone failure, invalid URL)

### CI/CD Integration

Use JSON output for automated processing:

```bash
repo-tester https://github.com/owner/repo --format json > results.json
```

Example JSON structure:

```json
{
  "repository_url": "https://github.com/owner/repo",
  "scan_timestamp": "2026-04-02T12:00:00Z",
  "summary": {
    "CRITICAL": 1,
    "HIGH": 1,
    "MEDIUM": 1,
    "LOW": 0,
    "INFO": 0
  },
  "findings": [
    {
      "severity": "CRITICAL",
      "scanner": "MaliciousPatternScanner",
      "title": "Base64-encoded exec() detected",
      "description": "Potentially malicious code execution",
      "file_path": "src/utils.py",
      "line_number": 42,
      "code_snippet": "exec(base64.b64decode(...))"
    }
  ]
}
```

Parse in CI workflows:

```bash
# GitHub Actions example
CRITICAL=$(jq -r '.summary.CRITICAL' results.json)
if [ "$CRITICAL" -gt 0 ]; then
  echo "::error::Critical security issues found!"
  exit 1
fi
```

### Quiet Mode

For scripts that only need exit codes:

```bash
if repo-tester https://github.com/owner/repo --quiet; then
  echo "Repository is clean"
else
  echo "Security issues detected"
fi
```

## How It Works

`repo-tester` uses a three-scanner architecture for comprehensive security analysis:

**1. MaliciousPatternScanner (Priority 1)**
- Pattern-matches against 50+ known malicious code signatures
- Detects obfuscation techniques (base64, hex encoding, unicode tricks)
- Identifies credential theft patterns (hardcoded tokens, API keys)
- Finds suspicious imports and dangerous function calls
- Configurable via `src/repo_tester/patterns/malicious_patterns.json`

**2. SupplyChainScanner (Priority 2)**
- Analyzes package dependencies for typosquatting attacks
- Uses Levenshtein distance to compare against popular packages
- Detects dependency confusion risks
- Checks for suspicious package naming patterns

**3. RepoHealthScanner (Priority 3)**
- Queries GitHub API for repository metadata
- Checks for security policies (SECURITY.md, branch protection)
- Identifies missing or outdated CI/CD workflows
- Analyzes repository age, activity, and maintenance status

All three scanners run in parallel via Python's `ThreadPoolExecutor`, with results aggregated and deduplicated by priority.

## Development

See [CLAUDE.md](CLAUDE.md) for development setup, testing, and architecture details.

**Quick start for contributors:**

```bash
# Install in dev mode
pip install -e .
pip install pytest pytest-mock

# Run tests
pytest -v

# Run a specific test
pytest tests/test_scanner_malicious.py::test_detects_base64_exec -v
```

## Security

See [SECURITY.md](SECURITY.md) for our security policy and vulnerability reporting process.

**Found a security issue in repo-tester itself?** Please report it responsibly via the SECURITY.md guidelines rather than opening a public issue.

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Areas where we especially appreciate help:

- **New malicious patterns** - Add to `src/repo_tester/patterns/malicious_patterns.json` with corresponding tests
- **Additional scanners** - Implement new `BaseScanner` subclasses for specialized security checks
- **Performance improvements** - Optimize pattern matching and GitHub API usage
- **Documentation** - Improve examples, tutorials, and usage guides

Check [CLAUDE.md](CLAUDE.md) for:
- Development environment setup
- Testing guidelines
- Architecture overview
- Adding new patterns and scanners

---

**Author:** Dennis J. Carroll  
**Repository:** https://github.com/Dennis-J-Carroll/repo-tester  
**PyPI:** https://pypi.org/project/repo-tester/
```

- [ ] **Step 2: Verify README renders locally**

Run: `python -c "import markdown; print(markdown.markdown(open('README.md').read())[:100])"`

Expected: HTML output starting with `<p align="center">`

Alternative verification: Preview README.md in any Markdown viewer

- [ ] **Step 3: Check logo file exists**

Run: `ls -lh logo.PNG`

Expected: File exists (~1.7MB)

- [ ] **Step 4: Commit README**

```bash
git add README.md
git commit -m "docs: create comprehensive README with logo and badges

Add professional PyPI-ready README including:
- Logo banner and status badges
- Feature overview and installation
- Usage examples with CLI output
- CI/CD integration guide with JSON parsing
- Architecture explanation (three-scanner system)
- Development and contributing guidelines

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Task 3: Create GitHub Actions Publishing Workflow

**Files:**
- Create: `.github/workflows/publish.yml`

- [ ] **Step 1: Create workflow file with header and trigger**

Create `.github/workflows/publish.yml`:

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
```

- [ ] **Step 2: Add test-publish job**

Append to `.github/workflows/publish.yml`:

```yaml
  test-publish:
    name: Publish to TestPyPI
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install build tools
        run: |
          python -m pip install --upgrade pip
          pip install build
      
      - name: Build package
        run: python -m build
      
      - name: Publish to TestPyPI
        uses: pypa/gh-action-pypi-publish@release/v1
        with:
          repository-url: https://test.pypi.org/legacy/
          print-hash: true

```

- [ ] **Step 3: Add publish job with manual approval**

Append to `.github/workflows/publish.yml`:

```yaml
  publish:
    name: Publish to PyPI
    needs: test-publish
    runs-on: ubuntu-latest
    environment: release  # Triggers manual approval gate
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install build tools
        run: |
          python -m pip install --upgrade pip
          pip install build
      
      - name: Build package
        run: python -m build
      
      - name: Publish to PyPI
        uses: pypa/gh-action-pypi-publish@release/v1
        with:
          print-hash: true
```

- [ ] **Step 4: Verify workflow syntax**

Run: `cat .github/workflows/publish.yml | python -c "import sys, yaml; yaml.safe_load(sys.stdin)"`

Expected: No output (valid YAML)

If `yaml` module not installed: `pip install pyyaml` first

Alternative: Use GitHub's workflow validator by pushing to a branch

- [ ] **Step 5: Commit workflow**

```bash
git add .github/workflows/publish.yml
git commit -m "ci: add PyPI publishing workflow with OIDC

Two-stage workflow:
- test-publish: Automatic publish to TestPyPI on version tags
- publish: Manual approval required for PyPI production release

Uses trusted publishing (OIDC) - no API tokens required.
Triggered by pushing tags matching v*.*.* pattern.

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Task 4: Local Build Validation

**Files:**
- Test: Local build artifacts in `dist/`

- [ ] **Step 1: Clean previous build artifacts**

Run: `rm -rf dist/ build/ src/repo_tester.egg-info/`

Expected: Directories removed (or don't exist)

- [ ] **Step 2: Install build tools**

Run: `pip install build`

Expected: `Successfully installed build ...` or `Requirement already satisfied`

- [ ] **Step 3: Build package**

Run: `python -m build`

Expected output:
```
* Creating venv isolated environment...
* Installing packages in isolated environment... (hatchling)
* Getting build dependencies for sdist...
* Building sdist...
* Building wheel from sdist
* Creating venv isolated environment...
* Installing packages in isolated environment... (hatchling)
* Getting build dependencies for wheel...
* Building wheel...
Successfully built repo_tester-0.1.0.tar.gz and repo_tester-0.1.0-py3-none-any.whl
```

- [ ] **Step 4: Verify build artifacts exist**

Run: `ls -lh dist/`

Expected:
```
repo_tester-0.1.0-py3-none-any.whl
repo_tester-0.1.0.tar.gz
```

- [ ] **Step 5: Inspect wheel contents**

Run: `python -m zipfile -l dist/repo_tester-0.1.0-py3-none-any.whl | head -20`

Expected: Should include:
- `repo_tester/` directory with `.py` files
- `repo_tester-0.1.0.dist-info/` with `METADATA`, `WHEEL`, `LICENSE`
- `README.md` referenced in METADATA

- [ ] **Step 6: Check source distribution contents**

Run: `tar -tzf dist/repo_tester-0.1.0.tar.gz | grep -E "(README|LICENSE|SECURITY|pyproject)" | head -10`

Expected: Should include:
```
repo_tester-0.1.0/README.md
repo_tester-0.1.0/LICENSE
repo_tester-0.1.0/SECURITY.md
repo_tester-0.1.0/pyproject.toml
```

- [ ] **Step 7: Test local installation in virtualenv**

Run:
```bash
python -m venv test-env
source test-env/bin/activate
pip install dist/repo_tester-0.1.0-py3-none-any.whl
```

Expected: `Successfully installed repo-tester-0.1.0 click-... requests-... python-Levenshtein-...`

- [ ] **Step 8: Verify CLI works**

Run: `repo-tester --help`

Expected: Help text showing usage, options (--format, --quiet)

- [ ] **Step 9: Test actual scan**

Run: `repo-tester https://github.com/Dennis-J-Carroll/repo-tester --quiet`

Expected: Exit code 0 or 1 (command completes without crash)

- [ ] **Step 10: Clean up test environment**

Run:
```bash
deactivate
rm -rf test-env
```

Expected: Virtual environment removed

- [ ] **Step 11: Commit build validation documentation**

Create `.github/RELEASE.md`:

```markdown
# Release Process

## Prerequisites

1. Accounts created on https://test.pypi.org and https://pypi.org
2. OIDC publishers configured (see below)
3. GitHub `release` environment configured with required reviewers

## OIDC Configuration

### TestPyPI Setup

1. Log in to https://test.pypi.org
2. Go to Account Settings → Publishing
3. Click "Add a new publisher"
4. Fill in:
   - **PyPI Project Name:** `repo-tester`
   - **Owner:** `Dennis-J-Carroll`
   - **Repository name:** `repo-tester`
   - **Workflow name:** `publish.yml`
   - **Environment name:** (leave blank)
5. Click "Add"

### PyPI Setup

**Important:** Do this AFTER first successful TestPyPI publish

1. Log in to https://pypi.org
2. Go to Account Settings → Publishing
3. Click "Add a new publisher"
4. Fill in:
   - **PyPI Project Name:** `repo-tester`
   - **Owner:** `Dennis-J-Carroll`
   - **Repository name:** `repo-tester`
   - **Workflow name:** `publish.yml`
   - **Environment name:** `release`
5. Click "Add"

### GitHub Environment Setup

1. Go to repository Settings → Environments
2. Click "New environment"
3. Name: `release`
4. Check "Required reviewers"
5. Add Dennis-J-Carroll as required reviewer
6. Click "Save protection rules"

## Release Workflow

### 1. Create Release

Version is already `0.1.0` in `pyproject.toml` for initial release.

For future releases:
```bash
# Edit pyproject.toml, update version field
git add pyproject.toml
git commit -m "chore: bump version to X.Y.Z"
git push origin master
```

### 2. Tag and Push

```bash
git tag v0.1.0
git push origin v0.1.0
```

### 3. Monitor TestPyPI Publish

1. Go to https://github.com/Dennis-J-Carroll/repo-tester/actions
2. Click on the "Publish to PyPI" workflow run
3. Wait for `test-publish` job to complete
4. Check output for TestPyPI URL

### 4. Verify TestPyPI Package

```bash
# Create test environment
python -m venv verify-env
source verify-env/bin/activate

# Install from TestPyPI
pip install -i https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ repo-tester

# Test functionality
repo-tester --help
repo-tester https://github.com/Dennis-J-Carroll/repo-tester

# Clean up
deactivate
rm -rf verify-env
```

Check TestPyPI page: https://test.pypi.org/project/repo-tester/
- Verify metadata displays correctly
- Verify README renders with logo
- Verify badges show

### 5. Approve PyPI Release

1. Go to https://github.com/Dennis-J-Carroll/repo-tester/actions
2. Click on the "Publish to PyPI" workflow run
3. Click "Review deployments" button
4. Check `release` environment
5. Click "Approve and deploy"

### 6. Verify PyPI Package

```bash
# In a fresh environment
pip install repo-tester
repo-tester --version
repo-tester https://github.com/Dennis-J-Carroll/repo-tester
```

Check PyPI page: https://pypi.org/project/repo-tester/
- Verify all metadata
- Verify README renders correctly
- Test installation works globally

## Rollback

PyPI doesn't allow deletion of published versions. If bad release:

1. Publish patch version immediately (e.g., 0.1.1)
2. Yank broken version on PyPI UI (prevents new installs)
3. Document issue in GitHub releases
```

```bash
git add .github/RELEASE.md
git commit -m "docs: add release process documentation

Complete step-by-step guide for:
- OIDC configuration on TestPyPI and PyPI
- GitHub environment setup
- Release workflow from tag to verification
- Rollback procedures

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Task 5: OIDC Configuration and GitHub Environment Setup

**Files:**
- Manual: TestPyPI, PyPI, GitHub web UI configuration

- [ ] **Step 1: Configure TestPyPI OIDC publisher**

**Action:** Manual web UI steps

1. Open browser to https://test.pypi.org
2. Log in with your account
3. Navigate to Account Settings → Publishing
4. Click "Add a new publisher"
5. Fill in form:
   - PyPI Project Name: `repo-tester`
   - Owner: `Dennis-J-Carroll`
   - Repository name: `repo-tester`
   - Workflow name: `publish.yml`
   - Environment name: (leave blank)
6. Click "Add"

**Verification:** Publisher appears in list with status "Pending first use"

**Note:** Do NOT configure PyPI OIDC yet - it requires TestPyPI publish first

- [ ] **Step 2: Configure GitHub release environment**

**Action:** Manual web UI steps

1. Open browser to https://github.com/Dennis-J-Carroll/repo-tester/settings/environments
2. Click "New environment"
3. Name: `release`
4. Check "Required reviewers"
5. Add yourself (Dennis-J-Carroll) as required reviewer
6. Optional: Set "Wait timer" to 0 minutes (immediate review)
7. Click "Save protection rules"

**Verification:** Environment appears at `/settings/environments` with protection rules enabled

- [ ] **Step 3: Document configuration completion**

Create a file to track OIDC setup status:

```bash
cat > .github/OIDC_STATUS.md <<'EOF'
# OIDC Configuration Status

## TestPyPI
- [x] Account created
- [x] Publisher configured for repo-tester
- [ ] First publish completed
- [ ] Package verified

## PyPI
- [x] Account created
- [ ] Publisher configured (requires TestPyPI publish first)
- [ ] First publish completed
- [ ] Package verified

## GitHub
- [x] Release environment created
- [x] Required reviewers configured (Dennis-J-Carroll)

## Next Steps
1. Push v0.1.0 tag to trigger workflow
2. Verify TestPyPI publish succeeds
3. Configure PyPI OIDC publisher
4. Approve and publish to PyPI
EOF
```

```bash
git add .github/OIDC_STATUS.md
git commit -m "docs: track OIDC configuration status

Checklist for TestPyPI, PyPI, and GitHub environment setup.

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Task 6: Initial Release to TestPyPI

**Files:**
- Test: GitHub Actions workflow, TestPyPI package

- [ ] **Step 1: Verify all changes are committed**

Run: `git status`

Expected: `nothing to commit, working tree clean`

If uncommitted changes: Commit them first

- [ ] **Step 2: Create v0.1.0 tag**

Run:
```bash
git tag -a v0.1.0 -m "Initial release

First public release of repo-tester security scanner.

Features:
- Malicious pattern detection (50+ patterns)
- Supply chain analysis (typosquatting detection)
- Repository health checks (GitHub API integration)
- Parallel scanning with ThreadPoolExecutor
- JSON and text output formats
- CLI with --format and --quiet options"
```

Expected: Tag created (no output)

- [ ] **Step 3: Verify tag exists**

Run: `git tag -l`

Expected: `v0.1.0` appears in list

- [ ] **Step 4: Push tag to trigger workflow**

Run: `git push origin v0.1.0`

Expected: 
```
Enumerating objects: 1, done.
...
To https://github.com/Dennis-J-Carroll/repo-tester.git
 * [new tag]         v0.1.0 -> v0.1.0
```

- [ ] **Step 5: Monitor GitHub Actions workflow**

**Action:** Manual browser check

1. Open https://github.com/Dennis-J-Carroll/repo-tester/actions
2. Click on "Publish to PyPI" workflow run (should start within 10 seconds)
3. Watch `test-publish` job progress
4. Check each step completes successfully:
   - Checkout code ✓
   - Set up Python ✓
   - Install build tools ✓
   - Build package ✓
   - Publish to TestPyPI ✓

**Expected:** All steps green, TestPyPI URL printed in "Publish to TestPyPI" step output

**If workflow fails:**
- Check error message in failed step
- Common issues: OIDC not configured, YAML syntax error, build failure
- Fix issue, delete tag (`git tag -d v0.1.0 && git push --delete origin v0.1.0`), recreate

- [ ] **Step 6: Verify package appears on TestPyPI**

**Action:** Manual browser check

1. Open https://test.pypi.org/project/repo-tester/
2. Verify package page loads
3. Check metadata displays:
   - Author: Dennis J. Carroll
   - License: MIT License
   - Classifiers: Development Status :: 4 - Beta, etc.
4. Check README renders with logo image
5. Check badges display (may show "not found" initially - this is OK)

- [ ] **Step 7: Test install from TestPyPI**

Run:
```bash
python -m venv testpypi-env
source testpypi-env/bin/activate
pip install -i https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ repo-tester
```

Expected: 
```
Looking in indexes: https://test.pypi.org/simple/, https://pypi.org/simple/
Collecting repo-tester
...
Successfully installed repo-tester-0.1.0 click-8.1.7 ...
```

- [ ] **Step 8: Verify installed CLI works**

Run: `repo-tester --help`

Expected: Help text with usage information

Run: `repo-tester https://github.com/Dennis-J-Carroll/repo-tester --quiet`

Expected: Command completes without crash (exit code 0 or 1)

- [ ] **Step 9: Clean up test environment**

Run:
```bash
deactivate
rm -rf testpypi-env
```

- [ ] **Step 10: Update OIDC status**

Edit `.github/OIDC_STATUS.md`, check off:
```markdown
- [x] First publish completed
- [x] Package verified
```

```bash
git add .github/OIDC_STATUS.md
git commit -m "docs: mark TestPyPI publish complete"
git push origin master
```

---

### Task 7: Configure PyPI OIDC and Publish to Production

**Files:**
- Manual: PyPI OIDC configuration
- Test: Production PyPI package

- [ ] **Step 1: Configure PyPI OIDC publisher**

**Action:** Manual web UI steps

1. Open browser to https://pypi.org
2. Log in with your account
3. Navigate to Account Settings → Publishing
4. Click "Add a new publisher"
5. Fill in form:
   - PyPI Project Name: `repo-tester`
   - Owner: `Dennis-J-Carroll`
   - Repository name: `repo-tester`
   - Workflow name: `publish.yml`
   - Environment name: `release` (IMPORTANT - must match workflow)
6. Click "Add"

**Verification:** Publisher appears in list

**Note:** This step requires TestPyPI publish to be complete first

- [ ] **Step 2: Return to GitHub Actions workflow**

**Action:** Manual browser check

1. Go back to https://github.com/Dennis-J-Carroll/repo-tester/actions
2. Click on the "Publish to PyPI" workflow run for v0.1.0
3. The `publish` job should show "Waiting" with "Review deployments" button

- [ ] **Step 3: Review and approve PyPI deployment**

**Action:** Manual GitHub UI steps

1. Click "Review deployments" button
2. Check the `release` environment checkbox
3. Review the deployment details
4. Add optional comment: "Verified on TestPyPI, approving production release"
5. Click "Approve and deploy"

**Expected:** `publish` job starts running

- [ ] **Step 4: Monitor PyPI publish job**

**Action:** Watch GitHub Actions

1. Watch `publish` job progress
2. Check each step completes successfully:
   - Checkout code ✓
   - Set up Python ✓
   - Install build tools ✓
   - Build package ✓
   - Publish to PyPI ✓

**Expected:** All steps green, PyPI URL printed in final step

**If publish fails:**
- Common issue: OIDC publisher environment name mismatch
- Verify PyPI publisher has environment name `release`
- Re-run job after fixing configuration

- [ ] **Step 5: Verify package on production PyPI**

**Action:** Manual browser check

1. Open https://pypi.org/project/repo-tester/
2. Verify package page loads
3. Check metadata:
   - Version: 0.1.0
   - Author: Dennis J. Carroll <denniscarrollj@gmail.com>
   - License: MIT License
   - Keywords: security, github, scanner, malicious-code, repository, safety, supply-chain
   - Classifiers: All classifiers from pyproject.toml
4. Check README renders with logo
5. Check badges display
6. Check project links work (Homepage, Repository, Issues)

- [ ] **Step 6: Test production install**

Run:
```bash
python -m venv pypi-env
source pypi-env/bin/activate
pip install repo-tester
```

Expected: 
```
Collecting repo-tester
  Downloading repo_tester-0.1.0-py3-none-any.whl ...
...
Successfully installed repo-tester-0.1.0 click-8.1.7 ...
```

- [ ] **Step 7: Verify production CLI**

Run: `repo-tester --help`

Expected: Help text displays

Run: `repo-tester --version` (if implemented, otherwise skip)

Run: `repo-tester https://github.com/Dennis-J-Carroll/repo-tester`

Expected: Scan completes successfully

- [ ] **Step 8: Clean up test environment**

Run:
```bash
deactivate
rm -rf pypi-env
```

- [ ] **Step 9: Update OIDC status**

Edit `.github/OIDC_STATUS.md`, check all remaining boxes:
```markdown
## PyPI
- [x] Account created
- [x] Publisher configured
- [x] First publish completed
- [x] Package verified
```

```bash
git add .github/OIDC_STATUS.md
git commit -m "docs: mark PyPI publish complete

Package successfully published to PyPI:
https://pypi.org/project/repo-tester/

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
git push origin master
```

- [ ] **Step 10: Verify workflow badge in README**

Open https://github.com/Dennis-J-Carroll/repo-tester in browser

Check that README displays with:
- Logo image renders
- All badges display (PyPI version, Python version, License, Build Status)
- Documentation is properly formatted

**If PyPI badge shows "not found":** Wait 5-10 minutes for PyPI CDN to update, then refresh

- [ ] **Step 11: Create GitHub Release**

**Action:** Manual GitHub UI steps

1. Go to https://github.com/Dennis-J-Carroll/repo-tester/releases
2. Click "Create a new release"
3. Tag: `v0.1.0` (select existing tag)
4. Release title: `v0.1.0 - Initial Release`
5. Description:
```markdown
## 🎉 Initial Public Release

First stable release of **repo-tester**, a GitHub repository safety scanner.

### Features

✅ **Malicious Pattern Detection** - 50+ patterns for obfuscated code, credential theft, backdoors  
✅ **Supply Chain Analysis** - Typosquatting detection using Levenshtein distance  
✅ **Repository Health Checks** - GitHub API integration for security policy analysis  
✅ **Parallel Scanning** - Fast results via ThreadPoolExecutor  
✅ **Flexible Output** - JSON and text formats for automation and manual review  

### Installation

```bash
pip install repo-tester
```

### Quick Start

```bash
# Scan any public repository
repo-tester https://github.com/owner/repo

# JSON output for CI/CD
repo-tester https://github.com/owner/repo --format json
```

### Links

📦 [PyPI Package](https://pypi.org/project/repo-tester/)  
📖 [Documentation](https://github.com/Dennis-J-Carroll/repo-tester#readme)  
🐛 [Report Issues](https://github.com/Dennis-J-Carroll/repo-tester/issues)

### What's Next

See the [project roadmap](https://github.com/Dennis-J-Carroll/repo-tester/issues) for planned features.
```
6. Check "Set as the latest release"
7. Click "Publish release"

**Expected:** Release appears at https://github.com/Dennis-J-Carroll/repo-tester/releases/tag/v0.1.0

---

## Testing and Validation

### Pre-Release Checklist

Before pushing any version tag, verify:

- [ ] All tests pass: `pytest -v`
- [ ] Local build succeeds: `python -m build`
- [ ] Local install works: `pip install dist/repo_tester-*.whl && repo-tester --help`
- [ ] Version in `pyproject.toml` matches tag (e.g., `0.1.0` → `v0.1.0`)
- [ ] README.md has no broken links or images
- [ ] All changes committed and pushed to master

### Post-Release Verification

After publishing to PyPI:

- [ ] Package appears on https://pypi.org/project/repo-tester/
- [ ] Metadata displays correctly (author, license, classifiers, URLs)
- [ ] README renders with logo and badges
- [ ] `pip install repo-tester` works in fresh environment
- [ ] CLI command `repo-tester --help` works
- [ ] Actual scan completes without errors
- [ ] GitHub Release created with changelog

## Rollback Procedures

If a bad release is published to PyPI:

1. **Immediate action:** Yank the version on PyPI web UI
   - Go to https://pypi.org/manage/project/repo-tester/releases/
   - Click on the version
   - Click "Options" → "Yank release"
   - Add reason: "Broken build, use vX.Y.Z instead"

2. **Publish fix:** Create patch version
   ```bash
   # Edit pyproject.toml: 0.1.0 → 0.1.1
   git add pyproject.toml
   git commit -m "chore: bump version to 0.1.1"
   git push origin master
   git tag v0.1.1
   git push origin v0.1.1
   ```

3. **Document:** Add note to GitHub Release explaining the issue

**Note:** Yanked versions prevent new installs but don't break existing installations. Never delete PyPI releases.

## Future Releases

For subsequent releases:

1. Update version in `pyproject.toml`
2. Commit version bump
3. Create and push tag: `git tag vX.Y.Z && git push origin vX.Y.Z`
4. Workflow automatically publishes to TestPyPI
5. Verify TestPyPI package
6. Approve PyPI deployment in GitHub UI
7. Create GitHub Release with changelog

Version number guidance:
- **Patch (0.1.X):** Bug fixes, security patches
- **Minor (0.X.0):** New features, backward compatible
- **Major (X.0.0):** Breaking changes

## Success Criteria

Initial release is complete when:

✅ Package published to https://pypi.org/project/repo-tester/  
✅ `pip install repo-tester` works globally  
✅ PyPI page shows complete metadata (author, license, URLs, classifiers)  
✅ README renders with logo and badges  
✅ CLI command available after install  
✅ GitHub Actions workflow completed successfully  
✅ Manual approval gate tested and working  
✅ TestPyPI → PyPI promotion validated  
✅ GitHub Release created with changelog  

---

**Plan Status:** Ready for implementation  
**Estimated Time:** 45-60 minutes for initial setup, 15 minutes for future releases  
**Dependencies:** TestPyPI account, PyPI account, GitHub repository access
