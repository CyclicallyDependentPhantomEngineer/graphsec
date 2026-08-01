"""Tests for repositories that are hostile input rather than subjects of study.

graphsec is pointed at repositories nobody trusts; everything git reports about
one is attacker-controlled. These tests build repositories that attack the
scanner and assert the scanner wins.
"""

from __future__ import annotations

import datetime as dt
import os
import subprocess
from pathlib import Path

import pytest
from conftest import BASE, init_repo

from graphsec import git_log, report
from graphsec.scanner import load_graph, scan

# An identity that tries to erase the current terminal line and forge a finding.
FORGED_LINE = "!! [1.00] SCAN CLEAN - no anomalies"
HOSTILE_EMAIL = f"a\x1b[2K\r{FORGED_LINE}@x.com"


def _commit(repo: Path, files: dict[str, str], *, email: str, when: dt.datetime, message: str):
    for rel, content in files.items():
        target = repo / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "Evil",
        "GIT_AUTHOR_EMAIL": email,
        "GIT_COMMITTER_NAME": "Evil",
        "GIT_COMMITTER_EMAIL": email,
        "GIT_AUTHOR_DATE": when.isoformat(),
        "GIT_COMMITTER_DATE": when.isoformat(),
    }
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-q", "-m", message],
        check=True,
        capture_output=True,
        env=env,
    )


@pytest.fixture
def hostile_repo(tmp_path: Path) -> Path:
    """A repository whose metadata and config attack the scanner."""
    repo = init_repo(tmp_path / "hostile")
    for index in range(6):
        _commit(
            repo,
            {
                ".github/workflows/ci.yml": f"name: ci\n# {index}\n",
                "src/app.py": f"x = {index}\n",
            },
            email=HOSTILE_EMAIL,
            when=BASE + dt.timedelta(days=index),
            message=f"c{index}",
        )
    return repo


@pytest.fixture
def config_bomb_repo(tmp_path: Path) -> tuple[Path, Path]:
    """A repository whose git config runs commands when git reads it."""
    repo = init_repo(tmp_path / "bomb")
    marker_dir = tmp_path / "markers"
    marker_dir.mkdir()
    (repo / "payload.bin").write_text("data\n", encoding="utf-8")
    (repo / ".gitattributes").write_text("*.bin diff=evil\n", encoding="utf-8")
    (repo / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    _commit(
        repo,
        {"src/app.py": "x = 1\n"},
        email="evil@example.com",
        when=BASE,
        message="init",
    )
    for key, marker in (
        ("diff.evil.textconv", "textconv"),
        ("core.fsmonitor", "fsmonitor"),
        ("diff.external", "external"),
    ):
        subprocess.run(
            [
                "git", "-C", str(repo), "config", key,
                f"sh -c 'touch {marker_dir / marker}; cat'",
            ],
            check=True,
            capture_output=True,
        )
    return repo, marker_dir


def test_scanning_does_not_execute_repository_config(config_bomb_repo):
    """core.fsmonitor and diff textconv/external are arbitrary command hooks."""
    repo, marker_dir = config_bomb_repo
    scan(repo, deep=True)
    assert sorted(p.name for p in marker_dir.iterdir()) == []


def test_commit_with_newline_in_identity_is_still_analysed(hostile_repo: Path):
    """A line-oriented parse let any committer delete their commit from the scan."""
    history = git_log.read_history(hostile_repo)
    assert len(history.commits) == 6
    assert history.skipped == 0
    assert history.warnings == []


def test_control_characters_are_stripped_from_identities(hostile_repo: Path):
    commit = git_log.read_history(hostile_repo).commits[0]
    assert "\x1b" not in commit.author_email
    assert "\r" not in commit.author_email
    assert "\n" not in commit.author_email
    # The visible text survives; only the escape machinery is removed.
    assert FORGED_LINE.lower() in commit.author_email


def test_text_report_contains_no_escape_sequences(hostile_repo: Path):
    result = scan(hostile_repo, min_score=0.0)
    text = report.to_text(result, color=False)
    assert "\x1b" not in text
    assert "\r" not in text


def test_dropped_records_are_reported_not_hidden(tiny_repo: Path, monkeypatch):
    """A record that cannot be parsed is a commit no detector ever sees."""
    real = git_log._parse_record
    calls = {"n": 0}

    def drop_first(record):
        calls["n"] += 1
        return None if calls["n"] == 1 else real(record)

    monkeypatch.setattr(git_log, "_parse_record", drop_first)
    result = scan(tiny_repo)
    assert result.warnings
    assert "not examined by any detector" in result.warnings[0]
    assert result.to_dict()["warnings"] == result.warnings


def test_dot_export_cannot_inject_attributes(tmp_path: Path):
    """A path is attacker-controlled, and DOT attributes can read files."""
    repo = init_repo(tmp_path / "dot")
    _commit(repo, {"src/a.py": "x\n"}, email="a@b.com", when=BASE, message="init")
    repo_graph = load_graph(repo)
    hostile = 'file:x" [shape=none image="/etc/passwd"] "'
    repo_graph.graph.add_node(hostile, type="file", name=hostile, sensitivity=0.0)
    dot = report.to_dot(repo_graph)

    # The payload may still appear as text; what matters is that it can no
    # longer close the quoted identifier and become DOT syntax.
    assert '"' not in report._dot_quote(hostile)
    line = next(line for line in dot.splitlines() if "passwd" in line)
    assert line.count('"') == 4  # "id" [label="..."] and nothing else
    assert line.lstrip().startswith('"')


def test_git_environment_config_is_not_honoured(tmp_path: Path, monkeypatch):
    marker = tmp_path / "env-marker"
    monkeypatch.setenv("GIT_EXTERNAL_DIFF", f"sh -c 'touch {marker}'")
    repo = init_repo(tmp_path / "envrepo")
    _commit(repo, {"src/a.py": "x\n"}, email="a@b.com", when=BASE, message="init")
    _commit(repo, {"src/a.py": "y\n"}, email="a@b.com", when=BASE, message="change")
    git_log.show_added_lines(repo, git_log.read_commits(repo)[0].sha)
    assert not marker.exists()
