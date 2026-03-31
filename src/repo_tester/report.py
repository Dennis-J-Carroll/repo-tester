from __future__ import annotations
from dataclasses import dataclass, field
from typing import Literal
from datetime import datetime, timezone
import json

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


@dataclass
class Finding:
    severity: Severity
    title: str
    detail: str
    file_path: str | None = None
    line_number: int | None = None
    scanner: str = ""


@dataclass
class Report:
    url: str
    findings: list[Finding] = field(default_factory=list)
    scanned_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @property
    def exit_code(self) -> int:
        return 0 if not self.findings else 1

    @property
    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

    def to_json(self) -> str:
        return json.dumps(
            {
                "url": self.url,
                "scanned_at": self.scanned_at,
                "exit_code": self.exit_code,
                "summary": self.summary,
                "findings": [
                    {
                        "severity": f.severity,
                        "title": f.title,
                        "detail": f.detail,
                        "file_path": f.file_path,
                        "line_number": f.line_number,
                        "scanner": f.scanner,
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
        lines.append("━" * 45)
        if not self.findings:
            lines.append("✓ No issues found")
        else:
            for f in self.sorted_findings():
                loc = f":{f.line_number}" if f.line_number else ""
                path = f" in {f.file_path}{loc}" if f.file_path else ""
                lines.append(f"[{f.severity}]{path}")
                lines.append(f"  {f.title}")
                lines.append(f"  {f.detail}")
                lines.append("")
        lines.append("━" * 45)
        s = self.summary
        lines.append(
            f"{s['CRITICAL']} CRITICAL  {s['HIGH']} HIGH  "
            f"{s['MEDIUM']} MEDIUM  {s['LOW']} LOW  {s.get('INFO', 0)} INFO"
        )
        return "\n".join(lines)
