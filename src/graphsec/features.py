"""Per-file feature extraction from the repository graph.

The features are deliberately structural: they describe a file's position in
the co-change / ownership topology rather than its contents, which is what
lets the same model run against any repository without tuning.
"""

from __future__ import annotations

import math
import posixpath

import networkx as nx
import numpy as np

from .graph import RepoGraph, node_name

FEATURE_NAMES = (
    "commits",
    "churn",
    "churn_per_commit",
    "author_count",
    "ownership_concentration",
    "cochange_degree",
    "cochange_weight",
    "external_coupling",
    "clustering",
    "pagerank",
    "core_number",
    "betweenness",
    "import_in",
    "import_out",
    "coupling_without_imports",
    "sensitivity",
)

# Betweenness is O(V*E); sample pivots once the graph gets large.
BETWEENNESS_SAMPLE = 96


def cochange_subgraph(repo_graph: RepoGraph) -> nx.Graph:
    """The file-file co-change projection, with edge weights preserved."""
    edges = [
        (u, v, data.get("weight", 1.0))
        for u, v, data in repo_graph.graph.edges(data=True)
        if data.get("kind") == "cochange"
    ]
    sub = nx.Graph()
    sub.add_nodes_from(repo_graph.files)
    sub.add_weighted_edges_from(edges)
    return sub


def _betweenness(graph: nx.Graph) -> dict[str, float]:
    if graph.number_of_nodes() == 0:
        return {}
    if graph.number_of_nodes() <= BETWEENNESS_SAMPLE:
        return nx.betweenness_centrality(graph, normalized=True)
    return nx.betweenness_centrality(
        graph, k=BETWEENNESS_SAMPLE, normalized=True, seed=17
    )


def _ownership(repo_graph: RepoGraph, file_node: str) -> tuple[int, float]:
    """Return ``(author_count, share_of_the_top_author)``."""
    weights = [
        data.get("weight", 1.0)
        for _, _, data in repo_graph.graph.edges(file_node, data=True)
        if data.get("kind") == "touched"
    ]
    total = sum(weights)
    if not weights or total <= 0:
        return 0, 0.0
    return len(weights), max(weights) / total


def extract(repo_graph: RepoGraph) -> tuple[list[str], np.ndarray]:
    """Return ``(file_nodes, matrix)`` with one row per file, in a stable order."""
    files = sorted(repo_graph.files)
    if not files:
        return [], np.zeros((0, len(FEATURE_NAMES)), dtype=float)

    sub = cochange_subgraph(repo_graph)
    pagerank = nx.pagerank(sub, weight="weight") if sub.number_of_edges() else {}
    clustering = nx.clustering(sub, weight="weight") if sub.number_of_edges() else {}
    core = nx.core_number(sub) if sub.number_of_edges() else {}
    betweenness = _betweenness(sub) if sub.number_of_edges() else {}
    imports = repo_graph.imports

    rows = []
    for node in files:
        data = repo_graph.graph.nodes[node]
        path = node_name(node)
        own_dir = posixpath.dirname(path)

        neighbours = list(sub.edges(node, data=True)) if node in sub else []
        total_weight = sum(d.get("weight", 1.0) for _, _, d in neighbours)
        external_weight = sum(
            d.get("weight", 1.0)
            for _, other, d in neighbours
            if posixpath.dirname(node_name(other)) != own_dir
        )
        import_neighbours = set()
        if node in imports:
            import_neighbours = set(imports.successors(node)) | set(
                imports.predecessors(node)
            )
        non_import_weight = sum(
            d.get("weight", 1.0)
            for _, other, d in neighbours
            if other not in import_neighbours
        )

        commits = float(data.get("commits", 0))
        churn = float(data.get("churn", 0))
        author_count, concentration = _ownership(repo_graph, node)

        rows.append(
            [
                commits,
                math.log1p(churn),
                churn / commits if commits else 0.0,
                float(author_count),
                concentration,
                float(len(neighbours)),
                math.log1p(total_weight),
                external_weight / total_weight if total_weight else 0.0,
                float(clustering.get(node, 0.0)),
                float(pagerank.get(node, 0.0)),
                float(core.get(node, 0)),
                float(betweenness.get(node, 0.0)),
                float(imports.in_degree(node)) if node in imports else 0.0,
                float(imports.out_degree(node)) if node in imports else 0.0,
                non_import_weight / total_weight if total_weight else 0.0,
                float(data.get("sensitivity", 0.0)),
            ]
        )

    return files, np.asarray(rows, dtype=float)


def robust_z(matrix: np.ndarray) -> np.ndarray:
    """Median/MAD standardisation — outliers must not move the scale."""
    if matrix.size == 0:
        return matrix
    median = np.median(matrix, axis=0)
    mad = np.median(np.abs(matrix - median), axis=0)
    scale = np.where(mad > 1e-9, mad * 1.4826, 1.0)
    return (matrix - median) / scale
