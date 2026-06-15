from __future__ import annotations
import sys
import concurrent.futures
from pathlib import Path
import click
from repo_tester.context import clone_repo
from repo_tester.report import Report
from repo_tester.repo_type import (
    detect_repo_type,
    normalized_flag_density,
    is_expected_finding,
)
from repo_tester.scanners.malicious import MaliciousPatternScanner
from repo_tester.scanners.supply_chain import SupplyChainScanner
from repo_tester.scanners.health import RepoHealthScanner

SCANNERS = [MaliciousPatternScanner(), SupplyChainScanner(), RepoHealthScanner()]


def run_scan(url: str) -> tuple[Report, int]:
    """Clone *url* and run all scanners. Returns (report, file_count).

    Raises ValueError for invalid URLs, Exception for scan failures.
    file_count is captured before the temp clone is deleted.
    """
    with clone_repo(url) as repo:
        file_count = len(repo.files)
        repo_type = detect_repo_type(repo.files)
        report = Report(url=url, repo_type=repo_type)
        all_deps: list[dict] = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(s.scan, repo) for s in SCANNERS]
            for future in concurrent.futures.as_completed(futures, timeout=90):
                try:
                    report.findings.extend(future.result())
                except Exception:
                    pass

        if repo_type:
            for f in report.findings:
                if is_expected_finding(repo_type, f.scanner, f.title):
                    f.verdict = "ok"

        sc = next((s for s in SCANNERS if isinstance(s, SupplyChainScanner)), None)
        if sc:
            handlers = {
                "requirements.txt": sc._parse_requirements_txt,
                "package.json": sc._parse_package_json,
                "pyproject.toml": sc._parse_pyproject_toml,
                "go.mod": sc._parse_go_mod,
                "Cargo.toml": sc._parse_cargo_toml,
            }
            for path in repo.files:
                handler = handlers.get(path.name)
                if handler:
                    try:
                        all_deps.extend(handler(path.read_text(errors="replace")))
                    except OSError:
                        pass
            report.library_targets = sc.library_targets(all_deps)

        if repo.ignore_config.rules:
            report.findings = [f for f in report.findings
                                if not repo.ignore_config.is_ignored(f)]

        # Rebase absolute clone paths to repo-relative so the temp dir
        # (/tmp/repo-tester-XXXX/...) never leaks into reports.
        for f in report.findings:
            if f.file_path:
                try:
                    f.file_path = str(Path(f.file_path).relative_to(repo.local_path))
                except ValueError:
                    pass  # path not under the clone root — leave as-is

        report.flag_density = normalized_flag_density(
            len(report.findings), max(file_count, 1), repo_type
        )

    return report, file_count


@click.command()
@click.argument("url")
@click.option("--format", "fmt", type=click.Choice(["terminal", "json"]), default="terminal",
              help="Output format")
@click.option("--quiet", is_flag=True, help="Suppress output when no findings")
def main(url: str, fmt: str, quiet: bool) -> None:
    """Scan a GitHub repository for security issues."""
    try:
        report, _ = run_scan(url)
    except ValueError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(2)
    except Exception as exc:
        click.echo(f"Scan failed: {exc}", err=True)
        sys.exit(2)

    if quiet and not report.findings:
        sys.exit(0)

    if fmt == "json":
        click.echo(report.to_json())
    else:
        click.echo(report.to_terminal())

    sys.exit(report.exit_code)
