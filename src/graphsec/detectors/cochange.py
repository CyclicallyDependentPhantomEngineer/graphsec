"""Hidden coupling between files that have no structural reason to be linked.

A file pair that keeps changing together while living in unrelated directories
and sharing no import edge is either undocumented coupling or a change that is
being smuggled alongside unrelated work. Both are worth a human look.
"""

from __future__ import annotations

import math
import posixpath
from collections.abc import Iterable

from .. import paths as pathutil
from ..graph import node_name
from ..models import Finding
from .base import Detector, DetectorContext, squash


def _path_distance(left: str, right: str) -> float:
    """0.0 when two files share a directory, 1.0 when they share no prefix."""
    a = posixpath.dirname(left).split("/") if posixpath.dirname(left) else []
    b = posixpath.dirname(right).split("/") if posixpath.dirname(right) else []
    if not a and not b:
        return 0.0
    shared = 0
    for x, y in zip(a, b, strict=False):  # the shorter path bounds the shared prefix
        if x != y:
            break
        shared += 1
    return 1.0 - (2 * shared) / (len(a) + len(b) or 1)


def is_expected_pair(left: str, right: str) -> bool:
    """True when the coupling has an obvious, benign explanation.

    Tests track the code they exercise, and files sharing a stem (``foo.c`` /
    ``foo.h``, ``Widget.tsx`` / ``Widget.test.tsx``) are two halves of one unit.
    Reporting those buries the interesting pairs.
    """
    if pathutil.is_test(left) or pathutil.is_test(right):
        return True
    left_stem, right_stem = pathutil.stem(left), pathutil.stem(right)
    return bool(left_stem) and left_stem == right_stem


class HiddenCouplingDetector(Detector):
    """Flags high-lift co-change pairs that span unrelated parts of the tree."""

    name = "cochange"
    description = "Unexplained co-change coupling across distant modules"

    def __init__(
        self,
        min_support: int = 3,
        min_lift: float = 2.0,
        min_confidence: float = 0.6,
        min_distance: float = 0.5,
        top_k: int = 20,
        min_score: float = 0.5,
    ) -> None:
        self.min_support = min_support
        self.min_lift = min_lift
        self.min_confidence = min_confidence
        self.min_distance = min_distance
        self.top_k = top_k
        self.min_score = min_score

    def run(self, ctx: DetectorContext) -> Iterable[Finding]:
        graph = ctx.graph
        total = max(len(ctx.commits), 1)
        imports = ctx.repo_graph.imports

        candidates = []
        for left, right, data in graph.edges(data=True):
            if data.get("kind") != "cochange":
                continue
            support = float(data.get("weight", 0.0))
            if support < self.min_support:
                continue
            left_commits = graph.nodes[left].get("commits", 0)
            right_commits = graph.nodes[right].get("commits", 0)
            if not left_commits or not right_commits:
                continue
            expected = left_commits * right_commits / total
            if expected <= 0:
                continue
            lift = support / expected
            # Confidence is the stronger of the two conditional probabilities:
            # "whenever the rarer file changes, the other one changes too".
            confidence = support / min(left_commits, right_commits)
            if lift < self.min_lift and confidence < self.min_confidence:
                continue

            left_path, right_path = node_name(left), node_name(right)
            distance = _path_distance(left_path, right_path)
            if distance < self.min_distance:
                continue
            if imports.has_edge(left, right) or imports.has_edge(right, left):
                continue  # An import explains the coupling.
            if is_expected_pair(left_path, right_path):
                continue

            sensitivity = max(
                float(graph.nodes[left].get("sensitivity", 0.0)),
                float(graph.nodes[right].get("sensitivity", 0.0)),
            )
            statistic = (2.0 * confidence + math.log2(max(lift, 1.0))) * (0.5 + distance)
            score = squash(statistic, midpoint=2.0, steepness=1.1)
            score = min(1.0, score * (0.55 + 0.75 * sensitivity))
            if score < self.min_score:
                continue

            candidates.append(
                Finding(
                    detector=self.name,
                    kind="hidden-coupling",
                    subject=f"{left_path} <-> {right_path}",
                    score=score,
                    message=(
                        f"{left_path} and {right_path} changed together "
                        f"{int(support)}x ({confidence:.0%} of the rarer file's commits, "
                        f"{lift:.1f}x the expected rate) despite living in unrelated "
                        "directories with no import between them"
                    ),
                    evidence={
                        "support": int(support),
                        "expected": round(expected, 2),
                        "lift": round(lift, 2),
                        "confidence": round(confidence, 3),
                        "path_distance": round(distance, 2),
                        "sensitivity": round(sensitivity, 2),
                        "shared_commits": sorted(
                            set(ctx.repo_graph.file_commits.get(left, []))
                            & set(ctx.repo_graph.file_commits.get(right, []))
                        )[:5],
                    },
                )
            )

        candidates.sort(key=lambda f: -f.score)
        return candidates[: self.top_k]
