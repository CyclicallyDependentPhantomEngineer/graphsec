"""Detector registry."""

from __future__ import annotations

from .author import OwnershipAnomalyDetector
from .base import Detector, DetectorContext
from .cochange import HiddenCouplingDetector
from .commit import CommitRiskDetector
from .dependency import DependencyAnomalyDetector
from .payload import PayloadDetector
from .structural import StructuralAnomalyDetector

DETECTOR_CLASSES: tuple[type[Detector], ...] = (
    StructuralAnomalyDetector,
    HiddenCouplingDetector,
    OwnershipAnomalyDetector,
    CommitRiskDetector,
    DependencyAnomalyDetector,
    PayloadDetector,
)

DETECTOR_NAMES: tuple[str, ...] = tuple(cls.name for cls in DETECTOR_CLASSES)


def build_detectors(
    names: list[str] | None = None, *, min_score: float = 0.5
) -> list[Detector]:
    """Instantiate detectors, optionally restricted to ``names``."""
    wanted = set(names) if names else None
    unknown = (wanted or set()) - set(DETECTOR_NAMES)
    if unknown:
        raise ValueError(
            f"unknown detector(s): {sorted(unknown)}; available: {list(DETECTOR_NAMES)}"
        )
    return [
        cls(min_score=min_score)
        for cls in DETECTOR_CLASSES
        if wanted is None or cls.name in wanted
    ]


__all__ = [
    "Detector",
    "DetectorContext",
    "DETECTOR_CLASSES",
    "DETECTOR_NAMES",
    "build_detectors",
    "StructuralAnomalyDetector",
    "HiddenCouplingDetector",
    "OwnershipAnomalyDetector",
    "CommitRiskDetector",
    "DependencyAnomalyDetector",
    "PayloadDetector",
]
