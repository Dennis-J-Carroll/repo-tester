"""
Imp 7: Repo Type / Domain Detection

Detects the framework/domain of a repository so scanners can normalize
flag density. A Django repo with __import__ calls is less suspicious than
a CLI tool with __import__ calls — the domain context matters.

Inspired by analyze.py's context-aware abstraction detection and
CodeHealth's insight that equal complexity scores can hide very different
code quality.
"""
from __future__ import annotations
from pathlib import Path
from dataclasses import dataclass, field


# Domain signatures: key files that indicate a repo's primary framework
_DOMAIN_SIGNATURES: dict[str, list[str]] = {
    "django":     ["manage.py", "settings.py", "wsgi.py", "asgi.py", "urls.py"],
    "flask":      ["app.py", "wsgi.py"],  # + "flask" in requirements
    "fastapi":    ["main.py"],  # + "fastapi" in requirements
    "react":      ["src/App.js", "src/App.jsx", "src/App.tsx", "public/index.html"],
    "vue":        ["src/App.vue", "vue.config.js", "vite.config.ts"],
    "angular":    ["angular.json", "src/app/app.component.ts"],
    "nextjs":     ["next.config.js", "next.config.mjs", "pages/_app.js"],
    "data-science": ["notebook.ipynb", "notebooks/", "data/", "models/"],
    "go":         ["go.mod", "go.sum"],
    "rust":       ["Cargo.toml", "Cargo.lock"],
    "ruby":       ["Gemfile", "Gemfile.lock"],
}

# Domain-specific expected patterns: these findings are "ok" in this domain
_DOMAIN_EXPECTED_PATTERNS: dict[str, list[tuple[str, str]]] = {
    # (scanner, pattern_substring) -> these are expected/legitimate for this domain
    "django": [
        ("malicious", "__import__"),           # Django uses dynamic imports
        ("malicious", "Dynamic exec"),          # Django template compilation
        ("malicious", "Dynamic compile"),       # Django ORM metaclasses
        ("supply_chain", "django"),             # Django itself is a dep
        ("health", "No LICENSE"),               # Common oversight, not critical
    ],
    "flask": [
        ("malicious", "__import__"),
        ("malicious", "Dynamic exec"),
    ],
    "fastapi": [
        ("malicious", "__import__"),
        ("malicious", "Dynamic exec"),
    ],
    "react": [
        ("malicious", "eval"),                  # build tools use eval
        ("supply_chain", "react"),              # react-dom is expected
    ],
    "vue": [
        ("malicious", "eval"),
    ],
    "nextjs": [
        ("malicious", "eval"),
        ("malicious", "exec"),
    ],
    "data-science": [
        ("malicious", "Dynamic exec"),          # Jupyter uses exec
        ("malicious", "eval"),                  # notebooks use eval
        ("malicious", "__import__"),
    ],
    "go": [
        ("supply_chain", "unpinned"),           # Go modules don't pin like Python
    ],
    "rust": [
        ("supply_chain", "unpinned"),           # Cargo uses semver ranges
    ],
}


def detect_repo_type(files: list[Path]) -> str:
    """Detect the repo's primary framework/domain from file signatures."""
    file_strs = {str(f).replace("\\", "/") for f in files}
    file_names = {f.name for f in files}

    scores: dict[str, int] = {}
    for domain, signatures in _DOMAIN_SIGNATURES.items():
        score = 0
        for sig in signatures:
            if sig.endswith("/"):
                # Directory signature
                if any(sig in fs for fs in file_strs for f in [fs]):
                    score += 1
            else:
                if sig in file_names or any(sig in fs for fs in file_strs):
                    score += 1
        if score > 0:
            scores[domain] = score

    if not scores:
        return ""

    # Also check requirements for framework deps
    for f in files:
        if f.name in ("requirements.txt", "pyproject.toml", "package.json"):
            try:
                text = f.read_text(errors="replace").lower()
                if "django" in text and "django" in scores:
                    scores["django"] += 2
                if "flask" in text and "flask" in scores:
                    scores["flask"] += 2
                if "fastapi" in text and "fastapi" in scores:
                    scores["fastapi"] += 2
                if "react" in text and "react" in scores:
                    scores["react"] += 2
                if "vue" in text and "vue" in scores:
                    scores["vue"] += 2
                if "next" in text and "nextjs" in scores:
                    scores["nextjs"] += 2
                if "jupyter" in text or "notebook" in text:
                    scores.setdefault("data-science", 0)
                    scores["data-science"] += 2
            except OSError:
                pass

    best = max(scores, key=scores.get)
    return best if scores[best] >= 2 else ""


def is_expected_finding(repo_type: str, scanner: str, title: str) -> bool:
    """Check if a finding is expected/legitimate for this repo type."""
    if not repo_type or repo_type not in _DOMAIN_EXPECTED_PATTERNS:
        return False
    for expected_scanner, pattern in _DOMAIN_EXPECTED_PATTERNS[repo_type]:
        if expected_scanner == scanner and pattern.lower() in title.lower():
            return True
    return False


def normalized_flag_density(findings_count: int, files_count: int, repo_type: str) -> float:
    """Calculate flag density normalized by repo type."""
    if files_count == 0:
        return 0.0
    raw_density = (findings_count / files_count) * 100

    # Domain-specific baselines: these domains naturally produce more findings
    # This is the "expected noise floor" for each domain
    baselines: dict[str, float] = {
        "django": 8.0,        # Django repos: ORM, templates, dynamic imports
        "flask": 5.0,
        "fastapi": 5.0,
        "react": 4.0,
        "vue": 4.0,
        "angular": 4.0,
        "nextjs": 5.0,
        "data-science": 6.0,  # Jupyter, pandas, numpy patterns
        "go": 2.0,
        "rust": 2.0,
        "ruby": 3.0,
    }
    baseline = baselines.get(repo_type, 3.0)  # default baseline

    # Normalized: subtract the expected baseline so we're measuring
    # *excess* density above the domain's normal noise floor
    return max(0.0, raw_density - baseline)
