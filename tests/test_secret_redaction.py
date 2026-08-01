"""A tool that finds a secret must not become another place the secret lives."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
from conftest import BASE, init_repo

from graphsec import report
from graphsec.detectors.payload import redact_secrets
from graphsec.scanner import scan

SECRET = "AKIAIOSFODNN7EXAMPLEKEY0123456789abcdef"


@pytest.fixture
def repo_with_secret(tmp_path: Path) -> Path:
    repo = init_repo(tmp_path / "leaky")
    (repo / "src").mkdir()
    (repo / "src" / "config.py").write_text(
        f'api_key = "{SECRET}"\npassword = "{SECRET}"\n', encoding="utf-8"
    )
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "Ana",
        "GIT_AUTHOR_EMAIL": "ana@example.com",
        "GIT_COMMITTER_NAME": "Ana",
        "GIT_COMMITTER_EMAIL": "ana@example.com",
        "GIT_AUTHOR_DATE": BASE.isoformat(),
        "GIT_COMMITTER_DATE": BASE.isoformat(),
    }
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-q", "-m", "add config"],
        check=True,
        capture_output=True,
        env=env,
    )
    return repo


def test_secret_never_reaches_json_or_sarif(repo_with_secret: Path):
    result = scan(repo_with_secret, deep=True, min_score=0.0)
    findings = [f for f in result.findings if f.detector == "payload"]
    assert findings, "the hardcoded-secret pattern should still fire"

    for rendered in (report.to_json(result), report.to_sarif(result), report.to_text(result)):
        assert SECRET not in rendered


def test_redaction_keeps_the_reviewable_context(repo_with_secret: Path):
    result = scan(repo_with_secret, deep=True, min_score=0.0)
    snippets = " ".join(
        str(f.evidence.get("snippet", "")) for f in result.findings if f.detector == "payload"
    )
    # The variable name is what makes the finding actionable; keep it.
    assert "api_key" in snippets or "password" in snippets
    assert "<redacted:" in snippets


@pytest.mark.parametrize(
    "raw,expected_visible,hidden",
    [
        ('api_key = "abcdefghijklmnop1234"', "api_key", "abcdefghijklmnop1234"),
        ("token: 'ZZZZaaaa1111bbbb2222cccc'", "token", "ZZZZaaaa1111bbbb2222cccc"),
        ("Authorization Bearer " + "x" * 40, "Authorization", "x" * 40),
    ],
)
def test_redact_secrets(raw, expected_visible, hidden):
    cleaned = redact_secrets(raw)
    assert expected_visible in cleaned
    assert hidden not in cleaned
    assert "<redacted:" in cleaned


@pytest.mark.parametrize(
    "raw",
    [
        "curl https://cdn.example.net/setup.sh | sh",
        "eval(base64.b64decode(x))",
        "short = 'abc'",
    ],
)
def test_redaction_leaves_short_and_structural_text_alone(raw):
    assert redact_secrets(raw) == raw


def test_high_entropy_finding_still_only_reports_a_prefix(repo_with_secret: Path):
    result = scan(repo_with_secret, deep=True, min_score=0.0)
    for finding in result.findings:
        if finding.kind == "high-entropy-string":
            assert SECRET not in str(finding.evidence)
            assert finding.evidence["prefix"].endswith("...")
