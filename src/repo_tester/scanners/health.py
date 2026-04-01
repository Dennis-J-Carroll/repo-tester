from __future__ import annotations
import os
import re
from datetime import datetime, timezone
import requests
from repo_tester.scanners.base import BaseScanner
from repo_tester.context import RepoContext
from repo_tester.report import Finding

_GITHUB_API = "https://api.github.com"


class RepoHealthScanner(BaseScanner):
    name = "health"
    priority = 3

    def scan(self, repo: RepoContext) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_github_api(repo))
        findings.extend(self._check_required_files(repo))
        findings.extend(self._check_ci_workflows(repo))
        return findings

    def _headers(self) -> dict[str, str]:
        h = {"Accept": "application/vnd.github+json"}
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            h["Authorization"] = f"Bearer {token}"
        return h

    def _check_github_api(self, repo: RepoContext) -> list[Finding]:
        findings: list[Finding] = []
        try:
            resp = requests.get(
                f"{_GITHUB_API}/repos/{repo.owner}/{repo.repo}",
                headers=self._headers(),
                timeout=10,
            )
            if not resp.ok:
                return findings
            data = resp.json()

            pushed = data.get("pushed_at", "")
            if pushed:
                age_days = (
                    datetime.now(timezone.utc)
                    - datetime.fromisoformat(pushed.replace("Z", "+00:00"))
                ).days
                if age_days > 730:
                    findings.append(Finding(
                        severity="LOW",
                        title=f"Repo not updated in {age_days} days",
                        detail="Abandoned repos may have unpatched vulnerabilities",
                        scanner=self.name,
                    ))

            if data.get("forks_count", 0) == 0 and data.get("stargazers_count", 0) < 5:
                findings.append(Finding(
                    severity="INFO",
                    title="Very low community activity",
                    detail="New or obscure repo — verify source and intent before installing",
                    scanner=self.name,
                ))
        except Exception:
            pass
        return findings

    def _check_required_files(self, repo: RepoContext) -> list[Finding]:
        findings: list[Finding] = []
        names = {f.name for f in repo.files}
        if "LICENSE" not in names and "LICENSE.md" not in names and "LICENSE.txt" not in names:
            findings.append(Finding(
                severity="LOW",
                title="No LICENSE file",
                detail="Repo has no license — unclear legal standing for use or distribution",
                scanner=self.name,
            ))
        if "SECURITY.md" not in names:
            findings.append(Finding(
                severity="INFO",
                title="No SECURITY.md",
                detail="No security policy or vulnerability disclosure process documented",
                scanner=self.name,
            ))
        return findings

    def _check_ci_workflows(self, repo: RepoContext) -> list[Finding]:
        findings: list[Finding] = []
        workflow_files = [f for f in repo.files if ".github/workflows" in str(f).replace("\\", "/")]
        for wf in workflow_files:
            try:
                text = wf.read_text(errors="replace")
            except OSError:
                continue
            for i, line in enumerate(text.splitlines(), 1):
                if re.search(r"curl\s+\S+.*\|\s*(bash|sh)", line):
                    findings.append(Finding(
                        severity="HIGH",
                        title="curl pipe shell in CI workflow",
                        detail="CI downloads and executes remote scripts without verification",
                        file_path=str(wf),
                        line_number=i,
                        scanner=self.name,
                    ))
                if re.search(r"uses:\s+[^@\s]+@(main|master|latest|HEAD)", line):
                    m = re.search(r"uses:\s+(\S+)", line)
                    action = m.group(1) if m else "unknown"
                    findings.append(Finding(
                        severity="MEDIUM",
                        title=f"Unpinned external action: {action}",
                        detail="Actions pinned to branch names can be silently modified — use SHA pins",
                        file_path=str(wf),
                        line_number=i,
                        scanner=self.name,
                    ))
                if re.search(r"echo\s+\$\{\{.*secrets\.", line):
                    findings.append(Finding(
                        severity="HIGH",
                        title="Secret echoed to CI log",
                        detail="Secrets printed to CI logs are visible to anyone with log access",
                        file_path=str(wf),
                        line_number=i,
                        scanner=self.name,
                    ))
        return findings
