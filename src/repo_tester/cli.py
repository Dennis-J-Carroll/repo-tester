from __future__ import annotations
import sys
import concurrent.futures
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


@click.command()
@click.argument("url")
@click.option("--format", "fmt", type=click.Choice(["terminal", "json"]), default="terminal",
              help="Output format")
@click.option("--quiet", is_flag=True, help="Suppress output when no findings")
def main(url: str, fmt: str, quiet: bool) -> None:
    """Scan a GitHub repository for security issues."""
    try:
        with clone_repo(url) as repo:
            # Imp 7: Detect repo type
            repo_type = detect_repo_type(repo.files)

            report = Report(url=url, repo_type=repo_type)
            all_deps: list[dict] = []

            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                futures = [executor.submit(s.scan, repo) for s in SCANNERS]
                for future in concurrent.futures.as_completed(futures, timeout=90):
                    try:
                        findings = future.result()
                        report.findings.extend(findings)
                    except Exception:
                        pass

            # Imp 7: Normalize verdicts by repo type
            # Expected patterns for this domain become "ok" instead of "warn"
            if repo_type:
                for f in report.findings:
                    if is_expected_finding(repo_type, f.scanner, f.title):
                        f.verdict = "ok"

            # Imp 9: Collect library practice targets
            sc = [s for s in SCANNERS if isinstance(s, SupplyChainScanner)]
            if sc:
                # Gather deps from all dep files
                handlers = {
                    "requirements.txt": sc[0]._parse_requirements_txt,
                    "package.json": sc[0]._parse_package_json,
                    "pyproject.toml": sc[0]._parse_pyproject_toml,
                    "go.mod": sc[0]._parse_go_mod,
                    "Cargo.toml": sc[0]._parse_cargo_toml,
                }
                for path in repo.files:
                    handler = handlers.get(path.name)
                    if handler:
                        try:
                            text = path.read_text(errors="replace")
                            all_deps.extend(handler(text))
                        except OSError:
                            pass
                report.library_targets = sc[0].library_targets(all_deps)

            # Fix 4: Apply ignore rules
            if repo.ignore_config.rules:
                before = len(report.findings)
                report.findings = [f for f in report.findings
                                   if not repo.ignore_config.is_ignored(f)]
                suppressed = before - len(report.findings)
                if suppressed > 0 and not quiet:
                    click.echo(f"  ({suppressed} finding(s) suppressed by .repo-tester-ignore)", err=True)

            # Imp 7: Compute flag density
            report.flag_density = normalized_flag_density(
                len(report.findings), max(len(repo.files), 1), repo_type
            )

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
