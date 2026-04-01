from __future__ import annotations
import sys
import concurrent.futures
import click
from repo_tester.context import clone_repo
from repo_tester.report import Report
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
            report = Report(url=url)
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                futures = [executor.submit(s.scan, repo) for s in SCANNERS]
                for future in concurrent.futures.as_completed(futures, timeout=90):
                    try:
                        report.findings.extend(future.result())
                    except Exception:
                        pass
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
