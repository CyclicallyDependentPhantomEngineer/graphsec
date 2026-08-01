"""Commit-level anomalies: timing, size and dangerous file combinations."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable

import numpy as np

from .. import paths as pathutil
from ..models import Commit, Finding
from .base import Detector, DetectorContext, squash

MIN_COMMITS_FOR_BASELINE = 12


def _hour_rarity(hours: Counter[int], hour: int) -> float:
    """How unusual an hour is for one author, smoothed over a +/-1h window."""
    total = sum(hours.values())
    if total < 4:
        return 0.0
    local = sum(hours.get((hour + offset) % 24, 0) for offset in (-1, 0, 1))
    return 1.0 - (local / total)


class CommitRiskDetector(Detector):
    """Scores individual commits on timing, size and the surfaces they touch."""

    name = "commit"
    description = "Timing, churn and surface anomalies at commit level"

    def __init__(self, top_k: int = 25, min_score: float = 0.5) -> None:
        self.top_k = top_k
        self.min_score = min_score

    def run(self, ctx: DetectorContext) -> Iterable[Finding]:
        commits = ctx.commits
        if not commits:
            return []

        churns = np.asarray([c.churn for c in commits], dtype=float)
        median = float(np.median(churns))
        mad = float(np.median(np.abs(churns - median))) * 1.4826
        spread = mad if mad > 1e-9 else max(float(np.std(churns)), 1.0)

        hours_by_author: dict[str, Counter[int]] = defaultdict(Counter)
        for commit in commits:
            hours_by_author[commit.author_email][commit.authored_at.hour] += 1

        first_commit_seen: dict[str, str] = {}
        for commit in sorted(commits, key=lambda c: c.authored_at):
            first_commit_seen.setdefault(commit.author_email, commit.sha)

        findings = []
        for commit in commits:
            reasons: list[str] = []
            risk = 0.0

            churn_z = (commit.churn - median) / spread
            if churn_z > 6.0 and commit.churn > 400:
                risk += min(churn_z / 12.0, 1.2)
                reasons.append(f"churn {commit.churn} lines (z={churn_z:.1f})")

            surfaces = {pathutil.label(c.path) for c in commit.changes}
            sensitivity = max(
                (pathutil.sensitivity(c.path) for c in commit.changes), default=0.0
            )
            if "execution-surface" in surfaces and "dependency-manifest" in surfaces:
                risk += 0.9
                reasons.append("changes CI/build scripts and dependency manifests together")
            if "secret-material" in surfaces:
                risk += 1.1
                reasons.append("touches key or credential material")

            binaries = [c.path for c in commit.changes if c.binary]
            if binaries and sensitivity >= 0.7:
                risk += 0.7
                reasons.append(f"adds/edits binary blobs next to sensitive paths: {binaries[:3]}")

            if len(commits) >= MIN_COMMITS_FOR_BASELINE:
                rarity = _hour_rarity(hours_by_author[commit.author_email], commit.authored_at.hour)
                if rarity > 0.9 and sensitivity >= 0.7:
                    risk += 0.8
                    reasons.append(
                        f"authored at {commit.authored_at:%H:%M}, outside this "
                        "author's normal window, on a sensitive surface"
                    )

            if (
                first_commit_seen.get(commit.author_email) == commit.sha
                and sensitivity >= 0.8
            ):
                risk += 0.8
                reasons.append("author's first ever commit lands on a high-value surface")

            if not reasons:
                continue
            score = squash(risk * 2.2, midpoint=2.6, steepness=1.0)
            if score < self.min_score:
                continue
            findings.append(
                Finding(
                    detector=self.name,
                    kind="risky-commit",
                    subject=commit.short_sha,
                    score=score,
                    message=(
                        f"{commit.short_sha} by {commit.author_email}: "
                        + "; ".join(reasons)
                    ),
                    evidence={
                        "sha": commit.sha,
                        "author": commit.author_email,
                        "authored_at": commit.authored_at.isoformat(),
                        "subject": commit.subject,
                        "churn": commit.churn,
                        "files": list(commit.paths)[:12],
                        "surfaces": sorted(surfaces),
                        "reasons": reasons,
                    },
                )
            )

        findings.sort(key=lambda f: -f.score)
        return findings[: self.top_k]


def commit_surfaces(commit: Commit) -> set[str]:
    """Public helper: the set of path classes a commit touches."""
    return {pathutil.label(change.path) for change in commit.changes}
