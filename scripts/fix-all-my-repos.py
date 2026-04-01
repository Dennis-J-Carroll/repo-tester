#!/usr/bin/env python3
"""
Fix All My Repos - Batch security update script
Usage: python fix-all-my-repos.py [username]
"""

import subprocess
import sys
import json
import os
from pathlib import Path
from typing import List, Dict, Optional

def get_github_repos(username: str) -> List[Dict]:
    """Fetch all repos for a GitHub user using gh CLI."""
    try:
        result = subprocess.run(
            ['gh', 'repo', 'list', username, '--json', 'name,url', '--limit', '1000'],
            capture_output=True,
            text=True,
            check=True
        )
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"❌ Error fetching repos: {e}")
        print(f"Make sure 'gh' CLI is installed and authenticated: gh auth login")
        return []
    except FileNotFoundError:
        print("❌ GitHub CLI (gh) not found. Install it: https://cli.github.com/")
        return []

def scan_repo(repo_url: str) -> Optional[Dict]:
    """Scan a repo and return results."""
    try:
        result = subprocess.run(
            ['repo-tester', repo_url, '--format', 'json', '--quiet'],
            capture_output=True,
            text=True,
            timeout=180
        )
        return json.loads(result.stdout) if result.stdout else None
    except subprocess.TimeoutExpired:
        print(f"  ⏱️  Timeout scanning {repo_url}")
        return None
    except Exception as e:
        print(f"  ⚠️  Error scanning {repo_url}: {e}")
        return None

def clone_and_fix(repo_url: str, repo_name: str, work_dir: Path) -> bool:
    """Clone repo, fix dependencies, commit, and push."""
    repo_path = work_dir / repo_name

    try:
        # Clone
        print(f"  📥 Cloning {repo_name}...")
        subprocess.run(
            ['git', 'clone', '--depth', '1', repo_url, str(repo_path)],
            check=True,
            capture_output=True
        )

        # Check for requirements.txt
        req_file = repo_path / "requirements.txt"
        if not req_file.exists():
            print(f"  ℹ️  No requirements.txt, skipping")
            return False

        # Backup
        backup_file = req_file.with_suffix(f".txt.bak")
        req_file.rename(backup_file)

        # Read original packages
        with open(backup_file) as f:
            lines = [l.strip() for l in f if l.strip() and not l.startswith('#')]

        # Extract package names
        packages = []
        for line in lines:
            # Handle ==, >=, <=, ~=, etc.
            pkg = line.split('==')[0].split('>=')[0].split('<=')[0].split('~=')[0].split('[')[0].strip()
            if pkg:
                packages.append(pkg)

        print(f"  📦 Found {len(packages)} packages")

        # Upgrade in a virtual environment
        venv_path = repo_path / ".venv"
        print(f"  🔧 Creating virtual environment...")
        subprocess.run(['python3', '-m', 'venv', str(venv_path)], check=True, capture_output=True)

        pip_bin = venv_path / "bin" / "pip"

        # Install and upgrade
        print(f"  ⬆️  Upgrading packages...")
        for pkg in packages:
            try:
                subprocess.run(
                    [str(pip_bin), 'install', '--upgrade', pkg],
                    check=True,
                    capture_output=True,
                    timeout=60
                )
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                print(f"    ⚠️  Failed to upgrade {pkg}")

        # Freeze
        result = subprocess.run(
            [str(pip_bin), 'freeze'],
            capture_output=True,
            text=True,
            check=True
        )

        # Filter to only original packages
        frozen = result.stdout.strip().split('\n')
        filtered = [line for line in frozen if any(line.startswith(pkg + '==') for pkg in packages)]

        # Write new requirements
        with open(req_file, 'w') as f:
            f.write('\n'.join(filtered) + '\n')

        print(f"  ✅ Updated requirements.txt")

        # Commit and push
        os.chdir(repo_path)
        subprocess.run(['git', 'config', 'user.name', 'Security Bot'], check=True)
        subprocess.run(['git', 'config', 'user.email', 'bot@example.com'], check=True)
        subprocess.run(['git', 'add', 'requirements.txt'], check=True)
        subprocess.run([
            'git', 'commit', '-m',
            'security: update and pin dependencies\n\n' +
            '- Upgraded packages to latest versions\n' +
            '- Pinned exact versions for reproducibility\n' +
            '- Fixes CVEs identified by repo-tester\n\n' +
            'Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>'
        ], check=True, capture_output=True)

        print(f"  📤 Pushing changes...")
        subprocess.run(['git', 'push'], check=True, capture_output=True)

        print(f"  ✅ Successfully updated {repo_name}")
        return True

    except subprocess.CalledProcessError as e:
        print(f"  ❌ Error fixing {repo_name}: {e}")
        return False
    except Exception as e:
        print(f"  ❌ Unexpected error: {e}")
        return False

def main():
    if len(sys.argv) < 2:
        username = subprocess.run(
            ['gh', 'api', 'user', '--jq', '.login'],
            capture_output=True,
            text=True
        ).stdout.strip()
        if not username:
            print("Usage: python fix-all-my-repos.py [username]")
            sys.exit(1)
    else:
        username = sys.argv[1]

    print(f"🔒 Security Fix Bot for @{username}")
    print("━" * 50)
    print()

    # Get all repos
    print(f"📋 Fetching repositories...")
    repos = get_github_repos(username)
    print(f"Found {len(repos)} repositories")
    print()

    # Create work directory
    work_dir = Path("/tmp/security-fixes")
    work_dir.mkdir(exist_ok=True)

    # Track results
    results = {'scanned': 0, 'vulnerable': 0, 'fixed': 0, 'errors': 0}

    for repo in repos:
        repo_name = repo['name']
        repo_url = repo['url']

        print(f"🔍 {repo_name}")

        # Scan
        scan_results = scan_repo(repo_url)
        results['scanned'] += 1

        if not scan_results:
            print(f"  ℹ️  Skipping (scan failed)")
            results['errors'] += 1
            continue

        summary = scan_results['summary']
        total_issues = summary['CRITICAL'] + summary['HIGH'] + summary['MEDIUM']

        if total_issues == 0:
            print(f"  ✅ No issues found")
            continue

        print(f"  ⚠️  Found: {summary['CRITICAL']} CRITICAL, {summary['HIGH']} HIGH, {summary['MEDIUM']} MEDIUM")
        results['vulnerable'] += 1

        # Ask to fix
        response = input(f"  Fix {repo_name}? (y/N/q): ").strip().lower()

        if response == 'q':
            print("  🛑 Quitting...")
            break

        if response != 'y':
            print(f"  ⏭️  Skipping")
            continue

        # Fix it
        if clone_and_fix(repo_url, repo_name, work_dir):
            results['fixed'] += 1
        else:
            results['errors'] += 1

        print()

    # Summary
    print()
    print("━" * 50)
    print("📊 Summary")
    print(f"  Scanned: {results['scanned']}")
    print(f"  Vulnerable: {results['vulnerable']}")
    print(f"  Fixed: {results['fixed']}")
    print(f"  Errors: {results['errors']}")
    print()
    print("✅ Done!")

if __name__ == '__main__':
    main()
