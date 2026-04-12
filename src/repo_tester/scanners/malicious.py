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


class MaliciousPatternScanner(BaseScanner):
    name = "malicious"
    priority = 1

    def __init__(self) -> None:
        with open(_PATTERNS_FILE) as f:
            self._patterns = json.load(f)["regex"]

    def scan(self, repo: RepoContext) -> list[Finding]:
        findings: list[Finding] = []
        for path in repo.files:
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue
            findings.extend(self._regex_scan(path, text))
            if path.suffix == ".py":
                findings.extend(self._ast_scan(path, text))

        for path in repo.install_scripts:
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue
            findings.extend(self._install_script_scan(path, text))

        return findings

    def _regex_scan(self, path: Path, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for pat in self._patterns:
            for i, line in enumerate(text.splitlines(), 1):
                if re.search(pat["pattern"], line, re.IGNORECASE):
                    findings.append(Finding(
                        severity=pat["severity"],
                        title=pat["title"],
                        detail=pat["detail"],
                        file_path=str(path),
                        line_number=i,
                        scanner=self.name,
                    ))
        return findings

    def _ast_scan(self, path: Path, text: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            # eval/exec/compile with non-literal argument
            if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec", "compile"):
                if node.args and not isinstance(node.args[0], ast.Constant):
                    findings.append(Finding(
                        severity="CRITICAL",
                        title=f"Dynamic {node.func.id}() call",
                        detail=f"{node.func.id}() called with non-literal argument — possible code injection",
                        file_path=str(path),
                        line_number=node.lineno,
                        scanner=self.name,
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
                    ))
        return findings
