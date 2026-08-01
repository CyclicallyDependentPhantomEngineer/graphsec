"""Build the heterogeneous repository graph the detectors run on.

Nodes are namespaced strings: ``file:src/a.py``, ``author:a@b.com``,
``dir:src``. Edges carry a ``kind`` so detectors can filter:

* ``touched``   author  -- file, weight = number of commits
* ``cochange``  file    -- file, weight = number of shared commits
* ``contains``  dir     -- file/dir

Import edges live in a separate directed graph because they connect the same
node pair as co-change edges and must not be conflated with them.
"""

from __future__ import annotations

import datetime as dt
import posixpath
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from itertools import combinations
from pathlib import Path

import networkx as nx

from . import paths as pathutil
from .models import Commit

# Commits touching more than this many files would add a quadratic number of
# co-change edges; they are almost always merges, vendoring or reformatting.
MAX_COCHANGE_FANOUT = 40

_PY_IMPORT = re.compile(r"^\s*(?:from\s+([\w\.]+)\s+import|import\s+([\w\.]+))", re.M)
_JS_IMPORT = re.compile(r"""(?:from|require\()\s*['"]([^'"]+)['"]""")


def file_node(path: str) -> str:
    return f"file:{pathutil.normalise(path)}"


def author_node(email: str) -> str:
    return f"author:{email.lower()}"


def dir_node(path: str) -> str:
    return f"dir:{path}"


def node_name(node: str) -> str:
    return node.split(":", 1)[1] if ":" in node else node


@dataclass
class RepoGraph:
    """The built graph plus the indexes detectors need."""

    graph: nx.Graph
    imports: nx.DiGraph
    commits: list[Commit]
    file_commits: dict[str, list[str]] = field(default_factory=dict)
    author_commits: dict[str, list[str]] = field(default_factory=dict)
    commit_by_sha: dict[str, Commit] = field(default_factory=dict)
    tracked_files: set[str] = field(default_factory=set)

    @property
    def files(self) -> list[str]:
        return [n for n, d in self.graph.nodes(data=True) if d.get("type") == "file"]

    @property
    def authors(self) -> list[str]:
        return [n for n, d in self.graph.nodes(data=True) if d.get("type") == "author"]

    def stats(self) -> dict[str, object]:
        kinds = Counter(d.get("kind") for _, _, d in self.graph.edges(data=True))
        return {
            "nodes": self.graph.number_of_nodes(),
            "edges": self.graph.number_of_edges(),
            "files": len(self.files),
            "authors": len(self.authors),
            "import_edges": self.imports.number_of_edges(),
            "edge_kinds": dict(kinds),
        }


def _add_directory_chain(graph: nx.Graph, path: str) -> None:
    parts = pathutil.normalise(path).split("/")
    if len(parts) == 1:
        parent = dir_node(".")
        graph.add_node(parent, type="dir", name=".")
        graph.add_edge(parent, file_node(path), kind="contains", weight=1.0)
        return
    chain = []
    for index in range(len(parts) - 1):
        chain.append(dir_node("/".join(parts[: index + 1])))
    for index, node in enumerate(chain):
        graph.add_node(node, type="dir", name=node_name(node))
        if index:
            graph.add_edge(chain[index - 1], node, kind="contains", weight=1.0)
    graph.add_edge(chain[-1], file_node(path), kind="contains", weight=1.0)


def _bump(graph: nx.Graph, a: str, b: str, kind: str) -> None:
    if graph.has_edge(a, b):
        edge = graph[a][b]
        if edge.get("kind") == kind:
            edge["weight"] = edge.get("weight", 0.0) + 1.0
            return
    graph.add_edge(a, b, kind=kind, weight=1.0)


def _resolve_python_import(module: str, source: str, tracked: set[str]) -> str | None:
    parts = module.split(".")
    for depth in range(len(parts), 0, -1):
        stem = "/".join(parts[:depth])
        for candidate in (f"{stem}.py", f"{stem}/__init__.py"):
            if candidate in tracked:
                return candidate
        # Try relative to the importing file's package root.
        base = posixpath.dirname(source)
        while base:
            for candidate in (f"{base}/{stem}.py", f"{base}/{stem}/__init__.py"):
                if candidate in tracked:
                    return candidate
            base = posixpath.dirname(base)
    return None


def _resolve_js_import(spec: str, source: str, tracked: set[str]) -> str | None:
    if not spec.startswith("."):
        return None
    base = posixpath.normpath(posixpath.join(posixpath.dirname(source), spec))
    for suffix in ("", ".ts", ".tsx", ".js", ".jsx", "/index.ts", "/index.js"):
        candidate = f"{base}{suffix}"
        if candidate in tracked:
            return candidate
    return None


def build_import_graph(repo: Path, tracked: set[str], read_file) -> nx.DiGraph:
    """Best-effort static import graph for Python and JS/TS sources."""
    graph = nx.DiGraph()
    for path in tracked:
        low = path.lower()
        if not (low.endswith(".py") or low.endswith((".js", ".jsx", ".ts", ".tsx"))):
            continue
        text = read_file(path)
        if not text:
            continue
        graph.add_node(file_node(path), type="file", name=path)
        if low.endswith(".py"):
            targets = (
                _resolve_python_import(m.group(1) or m.group(2), path, tracked)
                for m in _PY_IMPORT.finditer(text)
            )
        else:
            targets = (
                _resolve_js_import(m.group(1), path, tracked)
                for m in _JS_IMPORT.finditer(text)
            )
        for target in targets:
            if target and target != path:
                graph.add_node(file_node(target), type="file", name=target)
                graph.add_edge(file_node(path), file_node(target), kind="imports")
    return graph


def build_graph(
    commits: list[Commit],
    *,
    tracked_files: set[str] | None = None,
    imports: nx.DiGraph | None = None,
    max_cochange_fanout: int = MAX_COCHANGE_FANOUT,
) -> RepoGraph:
    """Turn commit history into the co-change / ownership graph."""
    graph = nx.Graph()
    file_commits: dict[str, list[str]] = defaultdict(list)
    author_commits: dict[str, list[str]] = defaultdict(list)
    commit_by_sha: dict[str, Commit] = {}

    for commit in commits:
        commit_by_sha[commit.sha] = commit
        author = author_node(commit.author_email)
        if author not in graph:
            graph.add_node(
                author,
                type="author",
                name=commit.author_email,
                display=commit.author_name,
                commits=0,
                churn=0,
                first_seen=commit.authored_at,
                last_seen=commit.authored_at,
            )
        adata = graph.nodes[author]
        adata["commits"] += 1
        adata["churn"] += commit.churn
        adata["first_seen"] = min(adata["first_seen"], commit.authored_at)
        adata["last_seen"] = max(adata["last_seen"], commit.authored_at)
        author_commits[author].append(commit.sha)

        touched: list[str] = []
        for change in commit.changes:
            path = pathutil.normalise(change.path)
            node = file_node(path)
            if node not in graph:
                graph.add_node(
                    node,
                    type="file",
                    name=path,
                    commits=0,
                    churn=0,
                    insertions=0,
                    deletions=0,
                    binary_touches=0,
                    sensitivity=pathutil.sensitivity(path),
                    label=pathutil.label(path),
                    first_seen=commit.authored_at,
                    last_seen=commit.authored_at,
                )
            fdata = graph.nodes[node]
            fdata["commits"] += 1
            fdata["churn"] += change.churn
            fdata["insertions"] += change.insertions
            fdata["deletions"] += change.deletions
            fdata["binary_touches"] += int(change.binary)
            fdata["first_seen"] = min(fdata["first_seen"], commit.authored_at)
            fdata["last_seen"] = max(fdata["last_seen"], commit.authored_at)
            file_commits[node].append(commit.sha)
            _add_directory_chain(graph, path)
            _bump(graph, author, node, "touched")
            touched.append(node)

        if 1 < len(touched) <= max_cochange_fanout:
            for left, right in combinations(sorted(set(touched)), 2):
                _bump(graph, left, right, "cochange")

    for _node, data in graph.nodes(data=True):
        if data.get("type") in {"file", "author"}:
            for key in ("first_seen", "last_seen"):
                value = data.get(key)
                if isinstance(value, dt.datetime):
                    data[key] = value.isoformat()

    return RepoGraph(
        graph=graph,
        imports=imports if imports is not None else nx.DiGraph(),
        commits=commits,
        file_commits=dict(file_commits),
        author_commits=dict(author_commits),
        commit_by_sha=commit_by_sha,
        tracked_files=set(tracked_files or ()),
    )
