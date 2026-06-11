from __future__ import annotations
import os
import re
from datetime import datetime, timezone
import requests
from repo_tester.scanners.base import BaseScanner
from repo_tester.context import RepoContext
from repo_tester.report import Finding

_GITHUB_API = "https://api.github.com"

# ── Imp 6: Thin-wrapper detection for CI steps ──────────────────────────────
# A CI step that is just `run: curl ... | bash` with no checksum verification
# is analogous to analyze.py's _is_thin_wrapper — a single delegating call
# that adds indirection without adding value.

# Steps that verify what they download (not thin wrappers)
_VERIFICATION_PATTERNS = [
    r"sha256sum", r"sha512sum", r"md5sum", r"gpg", r"gpgv",
    r"cosign", r"sigstore", r"verify", r"checksum", r"--verify",
]

# curl|bash patterns that indicate thin wrappers
_CURL_PIPE_PATTERNS = [
    r"curl\s+.*\|\s*(bash|sh)",
    r"wget\s+.*-O\s*-\s*\|",
    r"curl\s+.*\|\s*sudo",
]


def _is_verified_install(line: str) -> bool:
    """Check if a curl|bash line includes verification."""
    for pat in _VERIFICATION_PATTERNS:
        if re.search(pat, line, re.IGNORECASE):
            return True
    return False


def _is_thin_wrapper_step(step_text: str) -> bool:
    """
    Imp 6: Check if a CI workflow step is a thin wrapper around curl|bash.
    Returns True if the step ONLY does curl|bash WITHOUT verification.
    Analogous to analyze.py's _is_thin_wrapper().
    """
    has_curl_pipe = any(re.search(p, step_text, re.IGNORECASE) for p in _CURL_PIPE_PATTERNS)
    if not has_curl_pipe:
        return False
    # If it has verification, it's not a thin wrapper — it adds value
    return not _is_verified_install(step_text)


def _curl_pipe_flag_density(text: str) -> tuple[int, int, float]:
    """
    Imp 6: Calculate curl|bash flag density in a workflow file.
    Returns (thin_wrapper_count, total_run_steps, density).
    """
    total_run_steps = 0
    thin_wrappers = 0
    in_step = False
    step_buffer = ""

    for line in text.splitlines():
        if re.match(r"^\s*-\s*(name|run|uses):", line):
            # Check previous step
            if step_buffer and total_run_steps > 0:
                if _is_thin_wrapper_step(step_buffer):
                    thin_wrappers += 1
            in_step = True
            step_buffer = line
        elif in_step and (line.strip().startswith("- ") or line.strip() == ""):
            # New step or blank line ends current step
            if step_buffer and "run:" in step_buffer:
                total_run_steps += 1
                if _is_thin_wrapper_step(step_buffer):
                    thin_wrappers += 1
            in_step = bool(line.strip())
            step_buffer = line if in_step else ""
        elif in_step:
            step_buffer += "\n" + line

    # Check final step
    if step_buffer and "run:" in step_buffer:
        total_run_steps += 1
        if _is_thin_wrapper_step(step_buffer):
            thin_wrappers += 1

    density = (thin_wrappers / max(total_run_steps, 1)) * 100
    return thin_wrappers, total_run_steps, density


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
                        verdict="warn",
                    ))

            if data.get("forks_count", 0) == 0 and data.get("stargazers_count", 0) < 5:
                findings.append(Finding(
                    severity="INFO",
                    title="Very low community activity",
                    detail="New or obscure repo — verify source and intent before installing",
                    scanner=self.name,
                    verdict="ok",  # Imp 8: informational, not bad
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
                verdict="warn",
            ))
        if "SECURITY.md" not in names:
            findings.append(Finding(
                severity="INFO",
                title="No SECURITY.md",
                detail="No security policy or vulnerability disclosure process documented",
                scanner=self.name,
                verdict="ok",
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

            thin_count, total_steps, density = _curl_pipe_flag_density(text)

            # Build a line→step-buffer map so verification on adjacent lines is visible
            lines = text.splitlines()
            step_buffers: dict[int, str] = {}  # 1-based line → full step text
            current_step_lines: list[int] = []
            current_step_parts: list[str] = []
            for i, line in enumerate(lines, 1):
                if re.match(r"^\s*-\s*(name|run|uses):", line):
                    # Flush previous step
                    if current_step_parts:
                        buf = "\n".join(current_step_parts)
                        for ln in current_step_lines:
                            step_buffers[ln] = buf
                    current_step_lines = [i]
                    current_step_parts = [line]
                elif current_step_parts and not (line.strip().startswith("- ") and not line.strip().startswith("- name:") and not line.strip().startswith("- run:") and not line.strip().startswith("- uses:")):
                    current_step_lines.append(i)
                    current_step_parts.append(line)
                else:
                    if current_step_parts:
                        buf = "\n".join(current_step_parts)
                        for ln in current_step_lines:
                            step_buffers[ln] = buf
                    current_step_lines = []
                    current_step_parts = []
            if current_step_parts:
                buf = "\n".join(current_step_parts)
                for ln in current_step_lines:
                    step_buffers[ln] = buf

            for i, line in enumerate(lines, 1):
                if re.search(r"curl\s+\S+.*\|\s*(bash|sh)", line):
                    step_context = step_buffers.get(i, line)
                    if _is_thin_wrapper_step(step_context):
                        findings.append(Finding(
                            severity="HIGH",
                            title="curl pipe shell in CI workflow (thin wrapper, no verification)",
                            detail=f"CI downloads and executes remote scripts without checksum verification. "
                                   f"Flag density: {thin_count}/{total_steps} steps ({density:.0f}%). "
                                   f"Add sha256sum or gpg verification.",
                            file_path=str(wf),
                            line_number=i,
                            scanner=self.name,
                            verdict="bad",
                        ))
                    else:
                        findings.append(Finding(
                            severity="MEDIUM",
                            title="curl pipe shell in CI workflow (has verification)",
                            detail="CI downloads remote scripts but includes verification — review the verify step",
                            file_path=str(wf),
                            line_number=i,
                            scanner=self.name,
                            verdict="warn",
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
                        verdict="warn",
                    ))

                if re.search(r"echo\s+\$\{\{.*secrets\.", line):
                    findings.append(Finding(
                        severity="HIGH",
                        title="Secret echoed to CI log",
                        detail="Secrets printed to CI logs are visible to anyone with log access",
                        file_path=str(wf),
                        line_number=i,
                        scanner=self.name,
                        verdict="bad",
                    ))
        return findings
