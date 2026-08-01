from __future__ import annotations

from pathlib import Path

import networkx as nx
import pytest

from graphsec import features, git_log
from graphsec.graph import author_node, build_graph, build_import_graph, file_node
from graphsec.scanner import load_graph


def test_graph_nodes_and_edges(planted_repo: Path):
    repo_graph = load_graph(planted_repo)
    graph = repo_graph.graph

    assert file_node("src/api/routes.py") in graph
    assert author_node("contractor@vendor.example") in graph
    assert graph.nodes[file_node(".github/workflows/release.yml")]["label"] == "execution-surface"
    assert graph.nodes[file_node("requirements.txt")]["label"] == "dependency-manifest"

    routes = graph.nodes[file_node("src/api/routes.py")]
    assert routes["commits"] >= 15
    assert routes["type"] == "file"


def test_cochange_edges_have_weights(planted_repo: Path):
    repo_graph = load_graph(planted_repo)
    edge = repo_graph.graph[file_node("src/api/routes.py")][file_node("vendor/tracker.js")]
    assert edge["kind"] == "cochange"
    assert edge["weight"] >= 4


def test_ownership_edges(planted_repo: Path):
    repo_graph = load_graph(planted_repo)
    edge = repo_graph.graph[author_node("ben@example.com")][file_node("src/core/util.py")]
    assert edge["kind"] == "touched"
    assert edge["weight"] >= 12


def test_fanout_cap_blocks_quadratic_blowup(planted_repo: Path):
    commits = git_log.read_commits(planted_repo)
    capped = build_graph(commits, max_cochange_fanout=1)
    cochange = [
        (u, v) for u, v, d in capped.graph.edges(data=True) if d.get("kind") == "cochange"
    ]
    assert cochange == []


def test_import_graph_resolves_python_imports(tmp_path: Path):
    tracked = {"pkg/__init__.py", "pkg/a.py", "pkg/b.py"}
    sources = {
        "pkg/__init__.py": "",
        "pkg/a.py": "from pkg.b import thing\n",
        "pkg/b.py": "thing = 1\n",
    }
    imports = build_import_graph(tmp_path, tracked, sources.get)
    assert imports.has_edge(file_node("pkg/a.py"), file_node("pkg/b.py"))


def test_pagerank_is_a_distribution_and_ranks_the_hub_first():
    star = nx.Graph()
    star.add_weighted_edges_from(
        [("hub", "a", 1.0), ("hub", "b", 1.0), ("hub", "c", 1.0), ("a", "b", 1.0)]
    )
    ranks = features.pagerank(star)
    assert pytest.approx(sum(ranks.values()), abs=1e-9) == 1.0
    assert max(ranks, key=ranks.get) == "hub"


def test_pagerank_handles_empty_and_edgeless_graphs():
    assert features.pagerank(nx.Graph()) == {}
    isolated = nx.Graph()
    isolated.add_nodes_from(["a", "b"])
    assert features.pagerank(isolated) == {"a": 0.5, "b": 0.5}


def test_pagerank_matches_networkx_when_scipy_is_available():
    pytest.importorskip("scipy")
    graph = nx.Graph()
    graph.add_weighted_edges_from(
        [("a", "b", 2.0), ("b", "c", 1.0), ("c", "d", 3.0), ("d", "a", 1.0), ("a", "c", 1.0)]
    )
    ours = features.pagerank(graph)
    theirs = nx.pagerank(graph, weight="weight")
    for node, value in theirs.items():
        assert ours[node] == pytest.approx(value, abs=1e-6)


def test_feature_extraction_needs_no_scipy(monkeypatch, planted_repo: Path):
    """The declared dependency set is networkx + numpy; scipy must stay optional."""
    import builtins

    real_import = builtins.__import__

    def blocked(name, *args, **kwargs):
        if name == "scipy" or name.startswith("scipy."):
            raise ImportError("scipy is not installed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked)
    nodes, matrix = features.extract(load_graph(planted_repo))
    assert matrix.shape == (len(nodes), len(features.FEATURE_NAMES))


def test_feature_matrix_shape(planted_repo: Path):
    repo_graph = load_graph(planted_repo)
    nodes, matrix = features.extract(repo_graph)
    assert len(nodes) == matrix.shape[0]
    assert matrix.shape[1] == len(features.FEATURE_NAMES)
    assert matrix.min() >= 0.0  # all features are non-negative by construction


def test_graph_stats(planted_repo: Path):
    stats = load_graph(planted_repo).stats()
    assert stats["files"] >= 8
    assert stats["authors"] == 3
    assert stats["edge_kinds"]["cochange"] > 0
