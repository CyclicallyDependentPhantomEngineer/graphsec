"""Detector interface and shared scoring helpers."""

from __future__ import annotations

import math
from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from ..graph import RepoGraph
from ..models import Finding


@dataclass
class DetectorContext:
    """Everything a detector is allowed to look at."""

    repo: Path
    repo_graph: RepoGraph
    deep: bool = False
    options: dict[str, object] = field(default_factory=dict)

    @property
    def commits(self):
        return self.repo_graph.commits

    @property
    def graph(self):
        return self.repo_graph.graph


class Detector(ABC):
    """Base class for all anomaly detectors."""

    name: str = "detector"
    description: str = ""

    @abstractmethod
    def run(self, ctx: DetectorContext) -> Iterable[Finding]:
        """Yield findings for the given repository graph."""

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<{type(self).__name__} {self.name}>"


def squash(value: float, midpoint: float = 3.0, steepness: float = 1.0) -> float:
    """Map an unbounded anomaly statistic into a (0, 1) severity."""
    try:
        return 1.0 / (1.0 + math.exp(-steepness * (value - midpoint)))
    except OverflowError:  # pragma: no cover - extreme inputs only
        return 0.0 if value < midpoint else 1.0
