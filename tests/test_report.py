import json
from repo_tester.report import Finding, Report


def test_finding_fields():
    f = Finding(severity="CRITICAL", title="Bad thing", detail="It does bad")
    assert f.severity == "CRITICAL"
    assert f.title == "Bad thing"
    assert f.file_path is None
    assert f.line_number is None
    assert f.scanner == ""


def test_report_exit_code_zero_when_clean():
    r = Report(url="https://github.com/x/y")
    assert r.exit_code == 0


def test_report_exit_code_one_when_findings():
    r = Report(url="https://github.com/x/y", findings=[
        Finding(severity="HIGH", title="t", detail="d")
    ])
    assert r.exit_code == 1


def test_report_summary_counts():
    r = Report(url="https://github.com/x/y", findings=[
        Finding(severity="CRITICAL", title="t", detail="d"),
        Finding(severity="CRITICAL", title="t", detail="d"),
        Finding(severity="HIGH", title="t", detail="d"),
        Finding(severity="MEDIUM", title="t", detail="d"),
    ])
    s = r.summary
    assert s["CRITICAL"] == 2
    assert s["HIGH"] == 1
    assert s["MEDIUM"] == 1
    assert s["LOW"] == 0


def test_sorted_findings_critical_first():
    r = Report(url="https://github.com/x/y", findings=[
        Finding(severity="LOW", title="low", detail="d"),
        Finding(severity="CRITICAL", title="crit", detail="d"),
        Finding(severity="HIGH", title="high", detail="d"),
    ])
    severities = [f.severity for f in r.sorted_findings()]
    assert severities == ["CRITICAL", "HIGH", "LOW"]


def test_to_json_structure():
    r = Report(url="https://github.com/x/y", findings=[
        Finding(severity="HIGH", title="Test", detail="Detail", file_path="foo.py", line_number=3)
    ])
    data = json.loads(r.to_json())
    assert data["url"] == "https://github.com/x/y"
    assert data["exit_code"] == 1
    assert data["summary"]["HIGH"] == 1
    assert data["findings"][0]["title"] == "Test"
    assert data["findings"][0]["file_path"] == "foo.py"
    assert data["findings"][0]["line_number"] == 3


def test_terminal_clean_repo():
    r = Report(url="https://github.com/x/y")
    assert "No issues found" in r.to_terminal()


def test_terminal_shows_severity_and_title():
    r = Report(url="https://github.com/x/y", findings=[
        Finding(severity="CRITICAL", title="Obfuscated exec", detail="base64 in eval")
    ])
    out = r.to_terminal()
    assert "CRITICAL" in out
    assert "Obfuscated exec" in out
    assert "base64 in eval" in out
