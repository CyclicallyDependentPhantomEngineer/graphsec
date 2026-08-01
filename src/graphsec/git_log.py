"""Read commit history out of a git repository.

Uses plain ``git`` subprocess calls rather than a binding so the only hard
requirement is a ``git`` executable on PATH.
"""

from __future__ import annotations

import datetime as dt
import logging
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .models import Commit, FileChange

RECORD_SEP = "\x1e"
FIELD_SEP = "\x1f"

# The trailing separator terminates the subject, so a record can be split on
# FIELD_SEP alone. Without it the header had to be taken as the first line of
# the record, and an author identity containing a newline silently destroyed
# the record -- which let a commit hide itself from every detector.
_PRETTY = (
    f"{RECORD_SEP}%H{FIELD_SEP}%an{FIELD_SEP}%ae{FIELD_SEP}%aI{FIELD_SEP}%s{FIELD_SEP}"
)
_HEADER_FIELDS = 5

_SHA = re.compile(r"^[0-9a-fA-F]{7,64}$")

# "src/{old => new}/file.py" or "old.py => new.py"
_BRACE_RENAME = re.compile(r"^(.*)\{(.*?) => (.*?)\}(.*)$")

# "+0530" / "-08" rather than the "+05:30" that fromisoformat wants pre-3.11.
_COMPACT_OFFSET = re.compile(r"([+-])(\d{2})(\d{2})$")

# C0 controls and DEL. Tab and newline are stripped too: every field these are
# applied to is rendered as a single line in reports.
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")

# Repository-local configuration that git would otherwise execute on our
# behalf. A scanned repository is untrusted input by definition, and several of
# these keys are arbitrary command hooks: core.fsmonitor and
# diff.<driver>.textconv both run during a plain `git log`/`git show`.
_SAFE_CONFIG = (
    "core.fsmonitor=",
    "core.alternateRefsCommand=",
    "core.sshCommand=",
    "core.pager=cat",
    "core.quotePath=true",
    "diff.external=",
    "uploadpack.packObjectsHook=",
    "protocol.ext.allow=never",
)

# Diff-producing commands must also be told not to shell out per-file.
NO_DIFF_PROGRAMS = ("--no-textconv", "--no-ext-diff")

log = logging.getLogger("graphsec.git")


class GitError(RuntimeError):
    """Raised when git is missing, or the path is not a repository."""


def sanitize(text: str) -> str:
    """Drop control characters from repository-supplied text.

    Author names, emails, subjects and paths are attacker-controlled whenever
    the scanned repository is untrusted. Left intact they can rewrite a
    terminal report with ANSI escapes or forge whole lines with newlines.
    """
    return _CONTROL.sub("", text)


def _git_env() -> dict[str, str]:
    env = dict(os.environ)
    # Config from the environment is as dangerous as config from the repository.
    for name in list(env):
        if name.startswith("GIT_CONFIG") or name in {
            "GIT_EXTERNAL_DIFF",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_PROXY_COMMAND",
            "GIT_SSH",
            "GIT_SSH_COMMAND",
        }:
            del env[name]
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_OPTIONAL_LOCKS"] = "0"
    return env


def _run(repo: Path, args: list[str]) -> str:
    command = ["git", "-C", str(repo)]
    for setting in _SAFE_CONFIG:
        command += ["-c", setting]
    command += args
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            env=_git_env(),
        )
    except FileNotFoundError as exc:  # pragma: no cover - environment dependent
        raise GitError("git executable not found on PATH") from exc
    if proc.returncode != 0:
        raise GitError(proc.stderr.strip() or f"git {' '.join(args)} failed")
    return proc.stdout


def is_git_repo(path: str | Path) -> bool:
    path = Path(path)
    if not path.is_dir():
        return False
    try:
        return _run(path, ["rev-parse", "--is-inside-work-tree"]).strip() == "true"
    except GitError:
        return False


def repo_root(path: str | Path) -> Path:
    return Path(_run(Path(path), ["rev-parse", "--show-toplevel"]).strip())


def _split_rename(spec: str) -> tuple[str, str | None]:
    """Return ``(new_path, old_path)`` for a numstat path column."""
    match = _BRACE_RENAME.match(spec)
    if match:
        prefix, old, new, suffix = match.groups()
        old_path = f"{prefix}{old}{suffix}".replace("//", "/")
        new_path = f"{prefix}{new}{suffix}".replace("//", "/")
        return new_path, old_path
    if " => " in spec:
        old, new = spec.split(" => ", 1)
        return new.strip(), old.strip()
    return spec, None


def _parse_numstat(line: str) -> FileChange | None:
    parts = line.split("\t")
    if len(parts) < 3:
        return None
    ins_raw, del_raw, spec = parts[0], parts[1], "\t".join(parts[2:])
    binary = ins_raw == "-" or del_raw == "-"
    insertions = 0 if binary else int(ins_raw or 0)
    deletions = 0 if binary else int(del_raw or 0)
    path, old_path = _split_rename(sanitize(spec))
    if not path:
        return None
    return FileChange(
        path=path,
        insertions=insertions,
        deletions=deletions,
        binary=binary,
        old_path=old_path,
    )


def parse_timestamp(value: str) -> dt.datetime | None:
    """Parse a git ``%aI`` timestamp on every supported Python version.

    ``datetime.fromisoformat`` only learned to accept the ``Z`` suffix and
    colon-less UTC offsets in 3.11, and git prints UTC commits as
    ``2024-01-08T10:00:00Z``. Without this normalisation every commit in a
    UTC repository is unparseable on 3.10.
    """
    text = value.strip()
    if not text:
        return None
    if text[-1] in "Zz":
        text = f"{text[:-1]}+00:00"
    else:
        text = _COMPACT_OFFSET.sub(r"\1\2:\3", text)
    try:
        return dt.datetime.fromisoformat(text)
    except ValueError:
        return None


def _parse_record(record: str) -> Commit | None:
    """Parse one ``RECORD_SEP``-delimited record, or return None if malformed.

    Splitting on the field separator rather than on lines is what makes this
    robust: git accepts a carriage return inside an author identity and renders
    it as a newline, so a line-oriented parse can be broken by any committer.
    """
    fields = record.split(FIELD_SEP, _HEADER_FIELDS)
    if len(fields) <= _HEADER_FIELDS:
        return None
    sha, name, email, when, subject, body = fields
    if not _SHA.match(sha.strip()):
        return None
    authored_at = parse_timestamp(when)
    if authored_at is None:
        return None

    changes = []
    for line in body.split("\n"):
        if not line.strip():
            continue
        change = _parse_numstat(line)
        if change is not None:
            changes.append(change)

    return Commit(
        sha=sha.strip(),
        author_name=sanitize(name),
        author_email=sanitize(email).lower(),
        authored_at=authored_at,
        subject=sanitize(subject),
        changes=tuple(changes),
    )


@dataclass(frozen=True)
class History:
    """Parsed history plus what had to be discarded to produce it."""

    commits: list[Commit]
    skipped: int = 0

    @property
    def warnings(self) -> list[str]:
        if not self.skipped:
            return []
        return [
            f"{self.skipped} commit record(s) could not be parsed and were excluded "
            "from the analysis; those commits were not examined by any detector"
        ]


def read_history(
    repo: str | Path,
    *,
    max_commits: int | None = None,
    since: str | None = None,
    include_merges: bool = False,
) -> History:
    """Read commits newest-first, reporting how many records were unusable."""
    repo = Path(repo)
    if not is_git_repo(repo):
        raise GitError(f"{repo} is not a git repository")

    args = [
        "log",
        "--numstat",
        "--date=iso-strict",
        f"--pretty=format:{_PRETTY}",
        *NO_DIFF_PROGRAMS,
    ]
    if not include_merges:
        args.append("--no-merges")
    if max_commits:
        args.append(f"--max-count={max_commits}")
    if since:
        args.append(f"--since={since}")

    raw = _run(repo, args)
    commits = []
    skipped = 0
    for record in raw.split(RECORD_SEP):
        if not record.strip():
            continue
        commit = _parse_record(record)
        if commit is None:
            skipped += 1
            continue
        commits.append(commit)

    if skipped:
        # A dropped record is a commit no detector ever sees, so this is never
        # merely cosmetic: it is exactly what an evasive commit would produce.
        if not commits:
            raise GitError(
                f"read {skipped} commit record(s) from {repo} but could not parse any; "
                "the git log format is not what this version expects"
            )
        log.warning("skipped %d unparseable commit record(s) in %s", skipped, repo)
    return History(commits=commits, skipped=skipped)


def read_commits(
    repo: str | Path,
    *,
    max_commits: int | None = None,
    since: str | None = None,
    include_merges: bool = False,
) -> list[Commit]:
    """Return commits newest-first with per-file insertion/deletion counts."""
    return read_history(
        repo,
        max_commits=max_commits,
        since=since,
        include_merges=include_merges,
    ).commits


def list_files(repo: str | Path) -> list[str]:
    """Return tracked paths at HEAD.

    ``-z`` disables git's own path quoting, so these arrive as raw bytes and
    are sanitised here rather than trusted.
    """
    try:
        raw = _run(Path(repo), ["ls-files", "-z"])
    except GitError:
        return []
    return [sanitize(p) for p in raw.split("\0") if p]


def show_added_lines(
    repo: str | Path,
    sha: str,
    *,
    path: str | None = None,
    max_bytes: int = 400_000,
) -> str:
    """Return the added-line text of a commit, truncated for safety."""
    args = ["show", "--format=", "--unified=0", "--no-color", *NO_DIFF_PROGRAMS, sha]
    if path:
        args += ["--", path]
    try:
        diff = _run(Path(repo), args)
    except GitError:
        return ""
    added = [
        line[1:]
        for line in diff.split("\n")
        if line.startswith("+") and not line.startswith("+++")
    ]
    text = "\n".join(added)
    return text[:max_bytes]


def added_lines_by_file(
    repo: str | Path, sha: str, *, max_bytes_per_file: int = 200_000
) -> dict[str, str]:
    """Split one commit's diff into ``path -> added line text``.

    A single ``git show`` is cheaper than one call per changed file, so the
    diff is parsed here rather than re-fetched.
    """
    try:
        diff = _run(
            Path(repo),
            ["show", "--format=", "--unified=0", "--no-color", *NO_DIFF_PROGRAMS, sha],
        )
    except GitError:
        return {}

    out: dict[str, list[str]] = {}
    current: str | None = None
    for line in diff.split("\n"):
        if line.startswith("+++ "):
            target = sanitize(line[4:].strip())
            current = None if target == "/dev/null" else target[2:] if target.startswith("b/") else target
            continue
        if line.startswith("--- ") or line.startswith("@@"):
            continue
        if current and line.startswith("+"):
            out.setdefault(current, []).append(line[1:])
    return {path: "\n".join(lines)[:max_bytes_per_file] for path, lines in out.items()}


def file_blob(repo: str | Path, sha: str, path: str, *, max_bytes: int = 200_000) -> str:
    """Return file contents at a revision, or an empty string if unavailable."""
    try:
        return _run(
            Path(repo), ["show", *NO_DIFF_PROGRAMS, f"{sha}:{path}"]
        )[:max_bytes]
    except GitError:
        return ""
