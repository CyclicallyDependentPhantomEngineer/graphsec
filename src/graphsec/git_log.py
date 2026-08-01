"""Read commit history out of a git repository.

Uses plain ``git`` subprocess calls rather than a binding so the only hard
requirement is a ``git`` executable on PATH.
"""

from __future__ import annotations

import datetime as dt
import re
import subprocess
from pathlib import Path

from .models import Commit, FileChange

RECORD_SEP = "\x1e"
FIELD_SEP = "\x1f"

_PRETTY = f"{RECORD_SEP}%H{FIELD_SEP}%an{FIELD_SEP}%ae{FIELD_SEP}%aI{FIELD_SEP}%s"

# "src/{old => new}/file.py" or "old.py => new.py"
_BRACE_RENAME = re.compile(r"^(.*)\{(.*?) => (.*?)\}(.*)$")


class GitError(RuntimeError):
    """Raised when git is missing, or the path is not a repository."""


def _run(repo: Path, args: list[str]) -> str:
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            check=False,
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
    path, old_path = _split_rename(spec)
    if not path:
        return None
    return FileChange(
        path=path,
        insertions=insertions,
        deletions=deletions,
        binary=binary,
        old_path=old_path,
    )


def _parse_record(record: str) -> Commit | None:
    lines = record.split("\n")
    header = lines[0]
    fields = header.split(FIELD_SEP)
    if len(fields) < 5:
        return None
    sha, name, email, when, subject = fields[0], fields[1], fields[2], fields[3], fields[4]
    try:
        authored_at = dt.datetime.fromisoformat(when)
    except ValueError:
        return None
    changes = []
    for line in lines[1:]:
        line = line.strip("\n")
        if not line.strip():
            continue
        change = _parse_numstat(line)
        if change is not None:
            changes.append(change)
    return Commit(
        sha=sha,
        author_name=name,
        author_email=email.lower(),
        authored_at=authored_at,
        subject=subject,
        changes=tuple(changes),
    )


def read_commits(
    repo: str | Path,
    *,
    max_commits: int | None = None,
    since: str | None = None,
    include_merges: bool = False,
) -> list[Commit]:
    """Return commits newest-first with per-file insertion/deletion counts."""
    repo = Path(repo)
    if not is_git_repo(repo):
        raise GitError(f"{repo} is not a git repository")

    args = ["log", "--numstat", "--date=iso-strict", f"--pretty=format:{_PRETTY}"]
    if not include_merges:
        args.append("--no-merges")
    if max_commits:
        args.append(f"--max-count={max_commits}")
    if since:
        args.append(f"--since={since}")

    raw = _run(repo, args)
    commits = []
    for record in raw.split(RECORD_SEP):
        if not record.strip():
            continue
        commit = _parse_record(record)
        if commit is not None:
            commits.append(commit)
    return commits


def list_files(repo: str | Path) -> list[str]:
    """Return tracked paths at HEAD."""
    try:
        raw = _run(Path(repo), ["ls-files", "-z"])
    except GitError:
        return []
    return [p for p in raw.split("\0") if p]


def show_added_lines(
    repo: str | Path,
    sha: str,
    *,
    path: str | None = None,
    max_bytes: int = 400_000,
) -> str:
    """Return the added-line text of a commit, truncated for safety."""
    args = ["show", "--format=", "--unified=0", "--no-color", sha]
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
            Path(repo), ["show", "--format=", "--unified=0", "--no-color", sha]
        )
    except GitError:
        return {}

    out: dict[str, list[str]] = {}
    current: str | None = None
    for line in diff.split("\n"):
        if line.startswith("+++ "):
            target = line[4:].strip()
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
        return _run(Path(repo), ["show", f"{sha}:{path}"])[:max_bytes]
    except GitError:
        return ""
