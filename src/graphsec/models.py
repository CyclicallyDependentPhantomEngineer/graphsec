"""Core data structures shared across the scanner."""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class FileChange:
    """A single file touched by a commit."""

    path: str
    insertions: int
    deletions: int
    binary: bool = False
    old_path: str | None = None

    @property
    def churn(self) -> int:
        return self.insertions + self.deletions


@dataclass(frozen=True)
class Commit:
    """One non-merge commit with its file-level numstat."""

    sha: str
    author_name: str
    author_email: str
    authored_at: dt.datetime
    subject: str
    changes: tuple[FileChange, ...] = ()

    @property
    def short_sha(self) -> str:
        return self.sha[:10]

    @property
    def churn(self) -> int:
        return sum(c.churn for c in self.changes)

    @property
    def paths(self) -> tuple[str, ...]:
        return tuple(c.path for c in self.changes)


@dataclass(frozen=True)
class Finding:
    """A single anomaly reported by a detector.

    ``score`` is a normalised severity in [0, 1]; ``evidence`` holds the raw
    numbers that produced it so a reviewer can audit the verdict.
    """

    detector: str
    kind: str
    subject: str
    score: float
    message: str
    evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def severity(self) -> str:
        if self.score >= 0.75:
            return "high"
        if self.score >= 0.5:
            return "medium"
        return "low"

    def to_dict(self) -> dict[str, Any]:
        return {
            "detector": self.detector,
            "kind": self.kind,
            "subject": self.subject,
            "score": round(self.score, 4),
            "severity": self.severity,
            "message": self.message,
            "evidence": self.evidence,
        }


@dataclass
class ScanResult:
    """Everything a scan produced, ready for serialisation."""

    repo: str
    commit_count: int
    file_count: int
    author_count: int
    findings: list[Finding] = field(default_factory=list)
    graph_stats: dict[str, Any] = field(default_factory=dict)
    # Conditions that limited the scan. Anything here means the report covers
    # less than the whole repository, which a reader has to know about.
    warnings: list[str] = field(default_factory=list)

    def extend(self, findings: Iterable[Finding]) -> None:
        self.findings.extend(findings)

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-f.score, f.detector, f.subject))

    def to_dict(self) -> dict[str, Any]:
        return {
            "repo": self.repo,
            "summary": {
                "commits": self.commit_count,
                "files": self.file_count,
                "authors": self.author_count,
                "findings": len(self.findings),
                "high": sum(1 for f in self.findings if f.severity == "high"),
                "medium": sum(1 for f in self.findings if f.severity == "medium"),
                "low": sum(1 for f in self.findings if f.severity == "low"),
            },
            "graph": self.graph_stats,
            "warnings": list(self.warnings),
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }
