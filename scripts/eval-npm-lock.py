"""Compare locked OSV findings with npm audit on a local public npm repo.

This measures agreement between tools, not ground-truth precision or recall.
No dependencies are installed and package scripts are not run.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from collections import Counter
from pathlib import Path

from repo_tester.context import RepoContext
from repo_tester.scanners.supply_chain import SupplyChainScanner


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository", type=Path, help="Local npm repository with package.json and package-lock.json")
    parser.add_argument("--npm-audit", action="store_true", help="Compare with npm audit using current registry data")
    args = parser.parse_args()
    root = args.repository.resolve()
    paths = [root / "package.json", root / "package-lock.json"]
    if not all(path.is_file() for path in paths):
        parser.error("repository must contain package.json and package-lock.json")

    repo = RepoContext(url="", owner="", repo=root.name, local_path=root, files=paths)
    findings = SupplyChainScanner().scan(repo)
    matched = [finding for finding in findings if finding.advisory and finding.resolved_version]
    packages = sorted({finding.package for finding in matched})
    output = {
        "repository": str(root),
        "commit": subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"], cwd=root, capture_output=True, text=True, check=False
        ).stdout.strip(),
        "osv_advisory_matches": len(matched),
        "osv_packages": packages,
        "scanner_verdicts": dict(Counter(finding.verdict for finding in findings)),
        "scanner_warnings": [
            finding.detail for finding in findings if "verification incomplete" in finding.title.lower()
        ],
    }
    if args.npm_audit:
        result = subprocess.run(
            ["npm", "audit", "--json", "--ignore-scripts"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
        audit = json.loads(result.stdout)
        if audit.get("error"):
            raise RuntimeError(f"npm audit failed: {audit['error']}")
        audit_packages = set(audit.get("vulnerabilities", {}))
        output["npm_audit"] = {
            "severity_counts": audit.get("metadata", {}).get("vulnerabilities", {}),
            "package_count": len(audit_packages),
            "overlap": sorted(set(packages) & audit_packages),
            "osv_only": sorted(set(packages) - audit_packages),
            "audit_only": sorted(audit_packages - set(packages)),
        }
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
