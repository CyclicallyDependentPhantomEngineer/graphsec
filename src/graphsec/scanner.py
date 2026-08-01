"""Top-level scan orchestration."""

from __future__ import annotations

import logging
from pathlib import Path

from . import git_log
from .detectors import DetectorContext, build_detectors
from .graph import RepoGraph, build_graph, build_import_graph
from .models import ScanResult

log = logging.getLogger("graphsec")


def load_graph(
    repo: str | Path,
    *,
    max_commits: int | None = None,
    since: str | None = None,
    with_imports: bool = True,
) -> RepoGraph:
    """Read history and build the repository graph."""
    root = git_log.repo_root(repo)
    commits = git_log.read_commits(root, max_commits=max_commits, since=since)
    tracked = set(git_log.list_files(root))

    imports = None
    if with_imports and tracked:
        head = "HEAD"
        imports = build_import_graph(
            root, tracked, lambda path: git_log.file_blob(root, head, path)
        )

    return build_graph(commits, tracked_files=tracked, imports=imports)


def scan(
    repo: str | Path,
    *,
    max_commits: int | None = None,
    since: str | None = None,
    deep: bool = False,
    detectors: list[str] | None = None,
    min_score: float = 0.5,
    with_imports: bool = True,
) -> ScanResult:
    """Run the full pipeline against ``repo`` and return the findings."""
    root = git_log.repo_root(repo)
    repo_graph = load_graph(
        root, max_commits=max_commits, since=since, with_imports=with_imports
    )

    result = ScanResult(
        repo=str(root),
        commit_count=len(repo_graph.commits),
        file_count=len(repo_graph.files),
        author_count=len(repo_graph.authors),
        graph_stats=repo_graph.stats(),
    )

    ctx = DetectorContext(repo=root, repo_graph=repo_graph, deep=deep)
    for detector in build_detectors(detectors, min_score=min_score):
        try:
            found = list(detector.run(ctx))
        except Exception:  # a broken detector must not sink the whole scan
            log.exception("detector %s failed", detector.name)
            continue
        log.debug("detector %s produced %d finding(s)", detector.name, len(found))
        result.extend(found)

    return result
