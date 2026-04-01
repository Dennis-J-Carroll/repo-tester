# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install in dev mode
pip install -e .
pip install pytest pytest-mock

# Run all tests
pytest -v

# Run a single test file
pytest tests/test_scanner_malicious.py -v

# Run a single test
pytest tests/test_scanner_malicious.py::test_detects_base64_exec -v

# Scan a repo
repo-tester https://github.com/owner/repo
repo-tester https://github.com/owner/repo --format json
repo-tester https://github.com/owner/repo --quiet   # silent if clean
```

## Architecture

Three scanner modules share a common `BaseScanner` interface and run in parallel via `ThreadPoolExecutor` in `cli.py`. Each scanner receives a `RepoContext` (a shallow-cloned temp directory) and returns a list of `Finding` objects.

**Scanner priority order:** `MaliciousPatternScanner (1)` → `SupplyChainScanner (2)` → `RepoHealthScanner (3)`. Priority is metadata only — all three always run.

**Pattern updates:** Add new patterns to `src/repo_tester/patterns/malicious_patterns.json` without touching Python. Each new pattern should have a corresponding test in `tests/test_scanner_malicious.py`.

**Adding a new scanner:** Subclass `BaseScanner`, implement `scan(repo) -> list[Finding]`, add to `SCANNERS` list in `cli.py`.

**Temp directories:** `clone_repo()` is a context manager that always cleans up. Never store paths from `RepoContext.local_path` outside the `with` block.

## Integration

- **Claude Code hook:** `.claude/settings.local.json` (gitignored) — fires on `UserPromptSubmit` when a GitHub URL is detected
- **OpenClaw skill:** `.claude-plugin/manifest.json` — registers as a ClawHub skill, calls the same CLI
- **GITHUB_TOKEN env var:** Set for higher GitHub API rate limits (60/hr unauth → 5000/hr auth)
