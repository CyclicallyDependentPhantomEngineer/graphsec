"""Supply-chain anomalies in dependency manifests.

Builds a small bipartite graph of ``dependency -> manifest -> author`` from the
history of every dependency manifest, then flags the introductions that do not
look like ordinary maintenance.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

import networkx as nx

from .. import git_log
from .. import paths as pathutil
from ..models import Finding
from .base import Detector, DetectorContext

# Package names common enough that a near-miss is worth a second look.
POPULAR_PACKAGES = frozenset(
    """
    requests urllib3 numpy pandas scipy flask django fastapi pydantic sqlalchemy
    boto3 botocore click typer rich pytest setuptools wheel pip cryptography
    pyyaml jinja2 werkzeug certifi colorama attrs six python-dateutil idna
    charset-normalizer packaging protobuf grpcio pillow matplotlib scikit-learn
    torch tensorflow transformers openai anthropic httpx aiohttp redis celery
    react react-dom lodash axios express chalk commander debug moment webpack
    typescript eslint prettier jest babel vue angular next rollup vite uuid
    """.split()
)

_URL_DEP = re.compile(r"(git\+|https?://|file:|ssh://|@github|\.tar\.gz|\.whl)", re.I)

_PY_REQ = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*([<>=!~;].*)?$")
_JSON_DEP = re.compile(r'^\s*"([^"]+)"\s*:\s*"([^"]*)"\s*,?\s*$')
_TOML_DEP = re.compile(r'^\s*"?([A-Za-z0-9][A-Za-z0-9._-]*)"?\s*[=<>~^]+\s*"?([^",]*)"?')
_GO_DEP = re.compile(r"^\s*([\w./-]+/[\w./-]+)\s+v[\w.+-]+")


def edit_distance(a: str, b: str, cap: int = 3) -> int:
    """Optimal string alignment distance, short-circuited once it exceeds ``cap``.

    Adjacent transpositions cost 1, not 2: ``reqeusts`` is one slip away from
    ``requests``, and that is exactly the typosquat shape worth flagging.
    """
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    rows = [list(range(len(b) + 1))]
    for i, ca in enumerate(a, start=1):
        row = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            row[j] = min(
                rows[-1][j] + 1,
                row[j - 1] + 1,
                rows[-1][j - 1] + (ca != cb),
            )
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                row[j] = min(row[j], rows[-2][j - 2] + 1)
        if min(row) > cap:
            return cap + 1
        rows.append(row)
    return rows[-1][-1]


def parse_added_dependencies(manifest: str, added: str) -> list[tuple[str, str]]:
    """Extract ``(name, version_spec)`` pairs from added manifest lines."""
    base = manifest.rsplit("/", 1)[-1].lower()
    found: list[tuple[str, str]] = []
    for line in added.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//", "[")):
            continue
        if base.endswith(".json"):
            match = _JSON_DEP.match(line)
            if match and "/" not in match.group(1)[:1]:
                found.append((match.group(1), match.group(2)))
            continue
        if base in {"go.mod", "go.sum"}:
            match = _GO_DEP.match(line)
            if match:
                found.append((match.group(1), ""))
            continue
        if base.endswith(".toml") or base == "cargo.toml":
            match = _TOML_DEP.match(stripped)
            if match:
                found.append((match.group(1), match.group(2)))
            continue
        match = _PY_REQ.match(stripped)
        if match:
            found.append((match.group(1), (match.group(3) or "").strip()))
    return [(name.strip(), spec.strip()) for name, spec in found if name.strip()]


class DependencyAnomalyDetector(Detector):
    """Flags suspicious dependency introductions across manifest history."""

    name = "dependency"
    description = "Supply-chain anomalies in dependency manifests"

    def __init__(self, max_manifest_commits: int = 400, min_score: float = 0.5) -> None:
        self.max_manifest_commits = max_manifest_commits
        self.min_score = min_score
        self.dep_graph = nx.DiGraph()

    def run(self, ctx: DetectorContext) -> Iterable[Finding]:
        manifest_commits = [
            commit
            for commit in ctx.commits
            if any(pathutil.is_dependency_manifest(c.path) for c in commit.changes)
        ][: self.max_manifest_commits]
        if not manifest_commits:
            return []

        seen: set[str] = set()
        author_manifest_history: dict[str, int] = {}
        findings: list[Finding] = []

        for commit in sorted(manifest_commits, key=lambda c: c.authored_at):
            touches_execution = any(
                pathutil.is_execution_surface(c.path) for c in commit.changes
            )
            prior_manifest_commits = author_manifest_history.get(commit.author_email, 0)
            author_manifest_history[commit.author_email] = prior_manifest_commits + 1

            for change in commit.changes:
                if not pathutil.is_dependency_manifest(change.path):
                    continue
                added = git_log.show_added_lines(ctx.repo, commit.sha, path=change.path)
                if not added:
                    continue
                for name, spec in parse_added_dependencies(change.path, added):
                    key = name.lower()
                    self.dep_graph.add_node(f"dep:{key}", type="dependency", name=name)
                    self.dep_graph.add_edge(
                        f"dep:{key}", f"file:{change.path}", kind="declared_in"
                    )
                    self.dep_graph.add_edge(
                        f"author:{commit.author_email}",
                        f"dep:{key}",
                        kind="introduced",
                        sha=commit.sha,
                    )
                    if key in seen:
                        continue
                    seen.add(key)

                    finding = self._score_dependency(
                        name=name,
                        spec=spec,
                        manifest=change.path,
                        commit=commit,
                        touches_execution=touches_execution,
                        first_manifest_commit=prior_manifest_commits == 0,
                    )
                    if finding is not None:
                        findings.append(finding)

        findings.sort(key=lambda f: -f.score)
        return findings

    def _score_dependency(
        self,
        *,
        name: str,
        spec: str,
        manifest: str,
        commit,
        touches_execution: bool,
        first_manifest_commit: bool,
    ) -> Finding | None:
        key = name.lower()
        reasons: list[str] = []
        score = 0.0

        if _URL_DEP.search(spec) or _URL_DEP.search(name):
            score += 0.55
            reasons.append(f"resolved from a URL or VCS ref rather than a registry: {spec or name}")

        if key not in POPULAR_PACKAGES:
            near = [
                popular
                for popular in POPULAR_PACKAGES
                if abs(len(popular) - len(key)) <= 2 and edit_distance(key, popular, 2) <= 1
            ]
            if near:
                score += 0.5
                reasons.append(f"name is one edit away from popular package(s): {sorted(near)}")

        if touches_execution:
            score += 0.3
            reasons.append("introduced in a commit that also modifies CI or build scripts")

        if first_manifest_commit:
            score += 0.15
            reasons.append(f"first manifest change ever made by {commit.author_email}")

        if not reasons:
            return None
        score = min(score, 1.0)
        if score < self.min_score:
            return None

        return Finding(
            detector=self.name,
            kind="suspicious-dependency",
            subject=name,
            score=score,
            message=f"dependency '{name}' added to {manifest}: " + "; ".join(reasons),
            evidence={
                "manifest": manifest,
                "version_spec": spec,
                "sha": commit.sha,
                "author": commit.author_email,
                "authored_at": commit.authored_at.isoformat(),
                "reasons": reasons,
            },
        )
