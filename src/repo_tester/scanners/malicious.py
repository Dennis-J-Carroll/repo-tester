from __future__ import annotations
import ast
import json
import re
from pathlib import Path
from typing import cast
from repo_tester.scanners.base import BaseScanner
from repo_tester.context import RepoContext
from repo_tester.report import Finding, Severity

_PATTERNS_FILE = Path(__file__).parent.parent / "patterns" / "malicious_patterns.json"

_INSTALL_EXTRA: list[tuple[str, Severity, str, str]] = [
    (r"curl\s+\S+.*\|\s*(bash|sh|python\d?)", "CRITICAL",
     "curl pipe shell in install script",
     "Downloads and executes code without verification"),
    (r"wget\s+.*-O\s*-\s*\|", "CRITICAL",
     "wget pipe shell in install script",
     "Downloads and pipes directly to a shell"),
    (r"curl\s+-s\s+\S+\s+>\s*/tmp/", "HIGH",
     "curl download to /tmp in install script",
     "Downloads file to /tmp — check what is executed afterward"),
]

# ── Fix 1: Test file detection ──────────────────────────────────────────────
TEST_FILE_PATTERNS = [
    r"^test_",           # test_*.py
    r"_test\.py$",       # *_test.py
    r"_tests?\.py$",     # *_tests.py, *_test.py
    r"^conftest\.py$",   # pytest conftest
]
TEST_FILE_RE = [re.compile(p) for p in TEST_FILE_PATTERNS]

# Patterns that are noisy in test files
TEST_NOISY_PATTERN_IDS = {"HARDCODED_IP"}

# ── Fix 3: Known-legitimate contexts for dynamic exec/compile ───────────────
LEGITIMATE_EXEC_CONTEXTS = {
    # Template engines
    "jinja2", "mako", "tornado.template", "django.template", "cheetah",
    # Build/packaging tools
    "setuptools", "distutils", "wheel", "build", "flit", "hatch",
    # REPL / interactive
    "IPython", "code", "ptpython", "bpython",
    # Testing frameworks (fixture loading, test discovery)
    "pytest", "unittest", "nose", "doctest",
    # ORMs (metaclass-based model definition)
    "django.db", "sqlalchemy", "peewee", "tortoise",
    # Compilers / transpilers
    "Cython", "mypyc", "numba",
}


def _is_test_file(path: Path) -> bool:
    """Check if a file path looks like a test file."""
    name = path.name
    if any(TEST_FILE_RE[i].search(name) for i in range(len(TEST_FILE_RE))):
        return True
    # Check if in tests/ or test/ directory
    parts = [p.lower() for p in path.parts]
    return "tests" in parts or "test" in parts


def _is_legitimate_exec_context(path: Path, surrounding_code: str) -> bool:
    """Check if exec/compile is in a known legitimate context (Fix 3)."""
    lower = surrounding_code.lower()
    for ctx in LEGITIMATE_EXEC_CONTEXTS:
        # Use word boundaries to avoid matching substrings like "code" in "decode"
        if re.search(rf"\b{re.escape(ctx.lower())}\b", lower):
            return True
    # Check if inside a decorator/metaclass pattern
    if "@" in surrounding_code and ("metaclass" in lower or "decorator" in lower):
        return True
    return False


class MaliciousPatternScanner(BaseScanner):
    name = "malicious"
    priority = 1

    def __init__(self) -> None:
        with open(_PATTERNS_FILE) as f:
            self._patterns = json.load(f)["regex"]

    def scan(self, repo: RepoContext) -> list[Finding]:
        findings: list[Finding] = []
        for path in repo.files:
            is_test = _is_test_file(path)
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue
            findings.extend(self._regex_scan(path, text, is_test))
            if path.suffix == ".py":
                findings.extend(self._ast_scan(path, text, is_test))

        for path in repo.install_scripts:
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue
            findings.extend(self._install_script_scan(path, text))

        return findings

    def _regex_scan(self, path: Path, text: str, is_test: bool) -> list[Finding]:
        findings: list[Finding] = []
        for pat in self._patterns:
            # Fix 1: Skip noisy patterns in test files
            if is_test and pat.get("id") in TEST_NOISY_PATTERN_IDS:
                continue
            for i, line in enumerate(text.splitlines(), 1):
                if re.search(pat["pattern"], line, re.IGNORECASE):
                    findings.append(Finding(
                        severity=pat["severity"],
                        title=pat["title"],
                        detail=pat["detail"],
                        file_path=str(path),
                        line_number=i,
                        scanner=self.name,
                        verdict="warn" if pat["severity"] == "MEDIUM" else "bad",
                    ))
        return findings

    def _ast_scan(self, path: Path, text: str, is_test: bool) -> list[Finding]:
        findings: list[Finding] = []
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return findings

        # Fix 3: Build a mapping of line ranges to surrounding context
        # (imports, class/function names near the exec/compile call)
        file_lines = text.splitlines()
        surrounding_context = text[:2000]  # First ~50 lines for context clues

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            # eval/exec/compile with non-literal argument
            if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec", "compile"):
                if node.args and not isinstance(node.args[0], ast.Constant):
                    # Fix 3: Check for legitimate context
                    # Get ~5 lines around the call for context
                    start_line = max(0, node.lineno - 6)
                    end_line = min(len(file_lines), node.lineno + 4)
                    local_context = "\n".join(file_lines[start_line:end_line])

                    # Check imports at top of file for legitimate contexts
                    if _is_legitimate_exec_context(path, surrounding_context + local_context):
                        continue  # Skip: known legitimate use

                    # Fix 3: Also skip if in a test file (tests often use exec for parametrize)
                    if is_test and node.func.id in ("compile",):
                        continue

                    findings.append(Finding(
                        severity="CRITICAL",
                        title=f"Dynamic {node.func.id}() call",
                        detail=f"{node.func.id}() called with non-literal argument — possible code injection",
                        file_path=str(path),
                        line_number=node.lineno,
                        scanner=self.name,
                        verdict="bad",
                    ))

            # subprocess with shell=True
            for kw in node.keywords:
                if (kw.arg == "shell"
                        and isinstance(kw.value, ast.Constant)
                        and kw.value.value is True):
                    findings.append(Finding(
                        severity="HIGH",
                        title="subprocess with shell=True",
                        detail="shell=True can enable shell injection if input is not sanitized",
                        file_path=str(path),
                        line_number=node.lineno,
                        scanner=self.name,
                        verdict="bad",
                    ))
                    break

        return findings

    def _install_script_scan(self, path: Path, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for pattern, severity, title, detail in _INSTALL_EXTRA:
            for i, line in enumerate(text.splitlines(), 1):
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        severity=cast(Severity, severity),
                        title=title,
                        detail=detail,
                        file_path=str(path),
                        line_number=i,
                        scanner=self.name,
                        verdict="bad" if severity == "CRITICAL" else "warn",
                    ))
        return findings
