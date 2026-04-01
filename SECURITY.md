# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in repo-tester, please report it by:

1. **DO NOT** open a public issue
2. Email: [Your contact email or use GitHub Security Advisories]
3. Or use GitHub's private vulnerability reporting: 
   https://github.com/Dennis-J-Carroll/repo-tester/security/advisories/new

## What to Include

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Response Timeline

- **Initial Response:** Within 48 hours
- **Status Update:** Within 1 week
- **Fix Timeline:** Depends on severity
  - Critical: 1-3 days
  - High: 1 week
  - Medium: 2 weeks
  - Low: Best effort

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Security Features

repo-tester is designed to help identify security issues in repositories. It:
- Uses shallow clones (depth=1) to minimize attack surface
- Always cleans up temporary directories
- Runs scanners in parallel with timeouts to prevent hanging
- Does not execute code from scanned repositories
- Does not require authentication (though GITHUB_TOKEN improves rate limits)

## Known Limitations

- Regex-based detection may have false positives/negatives
- OSV API calls require network access
- GitHub API rate limits apply (60/hr without token, 5000/hr with token)

## Attribution

We appreciate responsible disclosure and will credit reporters in:
- Security advisories
- Release notes
- CHANGELOG.md

Thank you for helping keep repo-tester secure!
