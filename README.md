<p align="center">
  <img src="logo.PNG" alt="repo-tester logo" width="400" />
</p>

<p align="center">
  <strong>GitHub Repository Safety Scanner</strong><br/>
  Automated security scanning for malicious code, supply chain risks, and repository health
</p>

<p align="center">
  <a href="https://pypi.org/project/repo-tester/">
    <img src="https://img.shields.io/pypi/v/repo-tester.svg" alt="PyPI version" />
  </a>
  <a href="https://www.python.org/downloads/release/python-311/">
    <img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python 3.11+" />
  </a>
  <a href="https://github.com/Dennis-J-Carroll/repo-tester/blob/master/LICENSE">
    <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License: MIT" />
  </a>
  <a href="https://github.com/Dennis-J-Carroll/repo-tester/actions">
    <img src="https://img.shields.io/github/actions/workflow/status/Dennis-J-Carroll/repo-tester/tests.yml?branch=master" alt="Build Status" />
  </a>
</p>

---

## Features

- **🔍 Malicious Pattern Detection** - Identifies common malicious code patterns including base64 execution, crypto miners, and obfuscated payloads
- **🔗 Supply Chain Risk Analysis** - Detects vulnerable dependencies, security advisories, and compromised packages using OSV database
- **📊 Repository Health Metrics** - Evaluates code quality, maintenance status, commit activity, and security best practices
- **⚡ Parallel Scanning** - All three scanners run concurrently for performance
- **📄 JSON & Terminal Output** - Flexible reporting formats for integration and human review
- **🔐 Security-First** - Designed with a defense-in-depth approach across multiple threat vectors

## Quick Start

### Installation

```bash
pip install repo-tester
```

### Basic Usage

```bash
# Scan a repository
repo-tester https://github.com/owner/repo

# Output as JSON
repo-tester https://github.com/owner/repo --format json

# Silent mode (exit code only, no output if clean)
repo-tester https://github.com/owner/repo --quiet
```

## Installation

### From PyPI (Recommended)

```bash
pip install repo-tester
```

### From Source (Development)

```bash
git clone https://github.com/Dennis-J-Carroll/repo-tester.git
cd repo-tester
pip install -e .
pip install pytest pytest-mock
```

## Usage Examples

### Basic Repository Scan

```bash
$ repo-tester https://github.com/owner/repo

REPO SCAN: owner/repo
═════════════════════════════════════════════
[HIGH] in setup.py:42
  Suspicious base64 execution detected
  Found base64 decode followed by exec() call

[MEDIUM] in requirements.txt
  Deprecated dependency
  Package uses outdated version with known vulnerabilities

═════════════════════════════════════════════
1 CRITICAL  0 HIGH  1 MEDIUM  2 LOW  0 INFO
```

### JSON Output for Integration

```bash
$ repo-tester https://github.com/owner/repo --format json
{
  "url": "https://github.com/owner/repo",
  "scanned_at": "2024-04-01T15:30:45.123456+00:00",
  "exit_code": 1,
  "summary": {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 1,
    "LOW": 2,
    "INFO": 0
  },
  "findings": [
    {
      "severity": "HIGH",
      "title": "Suspicious base64 execution detected",
      "detail": "Found base64 decode followed by exec() call",
      "file_path": "setup.py",
      "line_number": 42,
      "scanner": "MaliciousPatternScanner"
    },
    {
      "severity": "MEDIUM",
      "title": "Deprecated dependency",
      "detail": "Package uses outdated version with known vulnerabilities",
      "file_path": "requirements.txt",
      "line_number": null,
      "scanner": "SupplyChainScanner"
    }
  ]
}
```

### Quiet Mode (CI/CD Friendly)

```bash
# Returns exit code 0 if clean, 1 if issues found
# No output unless there are findings
$ repo-tester https://github.com/owner/repo --quiet
$ echo $?
0
```

### CI/CD Integration

#### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: pip install repo-tester
      - run: repo-tester https://github.com/${{ github.repository }}
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

#### Processing JSON Results

```bash
# Extract critical findings only
repo-tester https://github.com/owner/repo --format json | \
  jq '.findings[] | select(.severity == "CRITICAL")'

# Get count of high-severity issues
repo-tester https://github.com/owner/repo --format json | \
  jq '.summary.HIGH'

# Create markdown report
repo-tester https://github.com/owner/repo --format json | \
  jq -r '.findings[] | "- [\(.severity)] \(.title): \(.detail)"'
```

## How It Works

### Three-Scanner Architecture

The tool runs three independent scanners in parallel, each focusing on different security aspects:

#### 1. Malicious Pattern Scanner (Priority 1)
Searches for common code patterns used in malware and attacks:
- Base64 execution sequences (`base64.b64decode()` + `exec()`)
- Crypto mining code (references to mining pools and wallets)
- Command injection patterns
- Shell obfuscation techniques
- Pickle deserialization vulnerabilities

Patterns are defined in `patterns/malicious_patterns.json` for easy updates without code changes.

#### 2. Supply Chain Scanner (Priority 2)
Analyzes dependencies for security risks:
- Uses OSV (Open Source Vulnerabilities) database
- Checks for known CVEs in specific versions
- Identifies deprecated or unmaintained packages
- Detects high-risk dependencies
- Validates version pinning practices

#### 3. Repository Health Scanner (Priority 3)
Evaluates overall repository health:
- Commit frequency and activity patterns
- License presence and compliance
- README completeness
- Security policy files
- Branch protection rules
- Issue response times

All three scanners run concurrently via ThreadPoolExecutor for optimal performance.

## Development

### Running Tests

```bash
# Run all tests
pytest -v

# Run a single test file
pytest tests/test_scanner_malicious.py -v

# Run a specific test
pytest tests/test_scanner_malicious.py::test_detects_base64_exec -v
```

### Development Setup

```bash
git clone https://github.com/Dennis-J-Carroll/repo-tester.git
cd repo-tester
pip install -e .
pip install pytest pytest-mock
```

### Adding Custom Patterns

Edit `src/repo_tester/patterns/malicious_patterns.json`:

```json
{
  "pattern_name": {
    "regex": "your_pattern_here",
    "severity": "HIGH",
    "title": "Pattern Title",
    "detail": "What this pattern indicates"
  }
}
```

Add corresponding test in `tests/test_scanner_malicious.py`:

```python
def test_detects_your_pattern(self):
    code = "code containing pattern"
    findings = self.scanner.scan(self.repo)
    assert any("pattern_name" in f.title for f in findings)
```

### Project Structure

```
repo-tester/
├── src/repo_tester/
│   ├── cli.py                 # Command-line interface
│   ├── context.py             # Repository cloning and context
│   ├── report.py              # Finding report generation
│   ├── patterns/
│   │   └── malicious_patterns.json  # Malicious code patterns
│   └── scanners/
│       ├── base.py            # Scanner interface
│       ├── malicious.py       # Malicious pattern scanner
│       ├── supply_chain.py    # Dependency vulnerability scanner
│       └── health.py          # Repository health scanner
├── tests/                     # Test suite
├── pyproject.toml             # Project configuration
└── README.md                  # This file
```

## Security

### About This Tool

repo-tester is a **detection and analysis tool**, not a prevention tool. It helps identify potential security issues in repositories but should be used as part of a comprehensive security strategy.

### Safety Considerations

- **Shallow clones only** - Repository code is cloned to a temporary directory and immediately cleaned up
- **No package installation** - Dependencies are analyzed but not executed
- **Read-only scanning** - No modifications to the scanned repository
- **Network isolation** - Only makes API calls for vulnerability database lookups

### Responsible Disclosure

If you discover a vulnerability in repo-tester itself, please email security@example.com instead of using the issue tracker.

### What This Tool Is NOT

- Not a substitute for professional security audits
- Not a guarantee of safety
- Not a replacement for code review
- Not a source code obfuscation tool

## Contributing

We welcome contributions! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Write tests for your changes
4. Commit your changes (`git commit -m 'feat: add amazing feature'`)
5. Push to your branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

### Development Guidelines

- Write tests for all new features
- Maintain or improve code coverage
- Follow PEP 8 style guidelines
- Update documentation for new features
- Ensure all tests pass before submitting PR

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**Dennis J. Carroll**
- GitHub: [@Dennis-J-Carroll](https://github.com/Dennis-J-Carroll)
- Email: denniscarrollj@gmail.com

## Links

- **Repository:** [github.com/Dennis-J-Carroll/repo-tester](https://github.com/Dennis-J-Carroll/repo-tester)
- **Issues:** [github.com/Dennis-J-Carroll/repo-tester/issues](https://github.com/Dennis-J-Carroll/repo-tester/issues)
- **PyPI:** [pypi.org/project/repo-tester](https://pypi.org/project/repo-tester)

---

<p align="center">
  Made with ❤️ for safer open source
</p>
