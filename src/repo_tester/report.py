from __future__ import annotations
from dataclasses import dataclass, field
from typing import Literal
from datetime import UTC, datetime
import json

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
Verdict = Literal["ok", "warn", "bad"]
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
VERDICT_ORDER = {"bad": 0, "warn": 1, "ok": 2}
VERDICT_ICON = {"ok": "✓", "warn": "◆", "bad": "✗"}


@dataclass
class Finding:
    severity: Severity
    title: str
    detail: str
    file_path: str | None = None
    line_number: int | None = None
    scanner: str = ""
    verdict: Verdict = "warn"  # Imp 8: ok / warn / bad
    package: str | None = None
    resolved_version: str | None = None
    installed: str | None = None
    advisory: dict | None = None
    evidence: list[dict] = field(default_factory=list)
    remediation: str | None = None
    learn: list[str] = field(default_factory=list)
    dependency_chain: list[str] = field(default_factory=list)


@dataclass
class Report:
    url: str
    findings: list[Finding] = field(default_factory=list)
    scanned_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    repo_type: str = ""  # Imp 7: detected repo domain
    flag_density: float = 0.0  # Imp 7: findings per 100 files
    flag_density_raw: float = 0.0
    flag_density_baseline: float = 0.0
    library_targets: list[dict] = field(default_factory=list)  # Imp 9
    scan_warnings: list[str] = field(default_factory=list)

    @property
    def exit_code(self) -> int:
        return 0 if not self.findings and not self.scan_warnings else 1

    @property
    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    @property
    def verdict_summary(self) -> dict[str, int]:
        """Imp 8: Count findings by verdict level."""
        counts: dict[str, int] = {"ok": 0, "warn": 0, "bad": 0}
        for f in self.findings:
            counts[f.verdict] = counts.get(f.verdict, 0) + 1
        return counts

    def sorted_findings(self) -> list[Finding]:
        # Sort by severity first, then by verdict (bad before warn before ok)
        return sorted(
            self.findings,
            key=lambda f: (
                SEVERITY_ORDER.get(f.severity, 99),
                VERDICT_ORDER.get(f.verdict, 1),
            ),
        )

    def to_json(self) -> str:
        return json.dumps(
            {
                "url": self.url,
                "schema_version": 2,
                "scanned_at": self.scanned_at,
                "repo_type": self.repo_type,
                "flag_density": round(self.flag_density, 1),
                "flag_density_raw": round(self.flag_density_raw, 1),
                "flag_density_baseline": round(self.flag_density_baseline, 1),
                "exit_code": self.exit_code,
                "summary": self.summary,
                "verdict_summary": self.verdict_summary,
                "library_targets": self.library_targets,
                "scan_warnings": self.scan_warnings,
                "findings": [
                    {
                        "severity": f.severity,
                        "title": f.title,
                        "detail": f.detail,
                        "file_path": f.file_path,
                        "line_number": f.line_number,
                        "scanner": f.scanner,
                        "verdict": f.verdict,
                        "package": f.package,
                        "resolved_version": f.resolved_version,
                        "installed": f.installed,
                        "advisory": f.advisory,
                        "evidence": f.evidence,
                        "remediation": f.remediation,
                        "learn": f.learn,
                        "dependency_chain": f.dependency_chain,
                    }
                    for f in self.sorted_findings()
                ],
            },
            indent=2,
        )

    def to_terminal(self) -> str:
        lines: list[str] = []
        repo_name = self.url.replace("https://github.com/", "")
        lines.append(f"\nREPO SCAN: {repo_name}")
        if self.repo_type:
            lines.append(f"  repo type: {self.repo_type}")
        lines.append("━" * 50)

        if not self.findings:
            lines.append("Scan incomplete" if self.scan_warnings else "✓ No issues found")
        else:
            for f in self.sorted_findings():
                loc = f":{f.line_number}" if f.line_number else ""
                path = f" in {f.file_path}{loc}" if f.file_path else ""
                icon = VERDICT_ICON.get(f.verdict, "◆")
                lines.append(f"[{f.severity}] {icon} {f.verdict.upper()}{path}")
                lines.append(f"  {f.title}")
                lines.append(f"  {f.detail}")
                lines.append("")

        for warning in self.scan_warnings:
            lines.append(f"[SCAN WARNING] {warning}")

        lines.append("━" * 50)
        s = self.summary
        lines.append(
            f"{s['CRITICAL']} CRITICAL  {s['HIGH']} HIGH  {s['MEDIUM']} MEDIUM  {s['LOW']} LOW  {s.get('INFO', 0)} INFO"
        )
        # Imp 8: verdict footer
        v = self.verdict_summary
        lines.append(
            f"{v['bad']} BAD  {v['warn']} WARN  {v['ok']} OK  |  "
            f"adjusted flags: {self.flag_density:.1f}/100 files "
            f"(raw {self.flag_density_raw:.1f} - baseline {self.flag_density_baseline:.1f}; floor 0)"
        )
        # Imp 9: library practice targets
        if self.library_targets:
            lines.append("")
            lines.append("Repeated Dependency Declarations:")
            for t in self.library_targets[:5]:
                lines.append(f"  {t['count']:>3}x  {t['name']}  ({t['note']})")
        return "\n".join(lines)
