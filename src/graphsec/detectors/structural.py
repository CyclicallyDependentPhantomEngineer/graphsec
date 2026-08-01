"""Unsupervised outlier detection over graph-topology features.

Uses scikit-learn's IsolationForest when it is installed, and falls back to a
robust-z composite so the package stays usable with only networkx + numpy.
"""

from __future__ import annotations

from collections.abc import Iterable

import numpy as np

from .. import features as featmod
from ..graph import node_name
from ..models import Finding
from .base import Detector, DetectorContext, squash

MIN_FILES = 8


def _isolation_scores(matrix: np.ndarray) -> tuple[np.ndarray, str] | None:
    try:
        from sklearn.ensemble import IsolationForest
    except ImportError:
        return None
    model = IsolationForest(
        n_estimators=200,
        contamination="auto",
        random_state=17,
    ).fit(matrix)
    # score_samples is higher for inliers; flip so larger means more anomalous.
    return -model.score_samples(matrix), "isolation-forest"


def _fallback_scores(matrix: np.ndarray) -> tuple[np.ndarray, str]:
    z = featmod.robust_z(matrix)
    # Aggregate deviation across features, damping any single runaway column.
    clipped = np.clip(np.abs(z), 0.0, 12.0)
    return clipped.mean(axis=1) + clipped.max(axis=1) / 2.0, "robust-z"


class StructuralAnomalyDetector(Detector):
    """Flags files whose position in the change graph is unlike its peers."""

    name = "structural"
    description = "Graph-topology outliers among tracked files"

    def __init__(self, top_k: int = 15, min_score: float = 0.5) -> None:
        self.top_k = top_k
        self.min_score = min_score

    def run(self, ctx: DetectorContext) -> Iterable[Finding]:
        nodes, matrix = featmod.extract(ctx.repo_graph)
        if len(nodes) < MIN_FILES:
            return []

        result = _isolation_scores(matrix)
        if result is None:
            raw, model = _fallback_scores(matrix)
        else:
            raw, model = result

        # Normalise the model's raw scores against their own distribution so
        # severities are comparable between repositories and between models.
        median = float(np.median(raw))
        mad = float(np.median(np.abs(raw - median))) * 1.4826
        spread = mad if mad > 1e-9 else float(np.std(raw)) or 1.0
        z = (raw - median) / spread

        z_features = featmod.robust_z(matrix)
        order = np.argsort(-z)[: self.top_k]

        findings = []
        for index in order:
            node = nodes[index]
            data = ctx.graph.nodes[node]
            sensitivity = float(data.get("sensitivity", 0.0))
            score = squash(float(z[index]), midpoint=3.0, steepness=0.9)
            # A structurally odd file matters more when it is also on an
            # execution or dependency surface.
            score = min(1.0, score * (0.75 + 0.5 * sensitivity))
            if score < self.min_score:
                continue
            drivers = sorted(
                zip(featmod.FEATURE_NAMES, z_features[index], strict=True),
                key=lambda pair: -abs(pair[1]),
            )[:3]
            findings.append(
                Finding(
                    detector=self.name,
                    kind="structural-outlier",
                    subject=node_name(node),
                    score=score,
                    message=(
                        f"{node_name(node)} sits far outside the normal change "
                        f"topology ({model} z={z[index]:.2f})"
                    ),
                    evidence={
                        "model": model,
                        "z": round(float(z[index]), 3),
                        "path_class": data.get("label"),
                        "commits": data.get("commits"),
                        "churn": data.get("churn"),
                        "top_features": {
                            name: round(float(value), 2) for name, value in drivers
                        },
                    },
                )
            )
        return findings
