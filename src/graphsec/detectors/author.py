"""Ownership anomalies: who touches what, and who has no business doing so."""

from __future__ import annotations

import posixpath
from collections import Counter, defaultdict
from collections.abc import Iterable

from ..graph import node_name
from ..models import Finding
from .base import Detector, DetectorContext, squash


class OwnershipAnomalyDetector(Detector):
    """Territory excursions, sole ownership and identity inconsistencies."""

    name = "ownership"
    description = "Author/file ownership anomalies"

    def __init__(
        self,
        familiarity_threshold: float = 0.08,
        min_sensitivity: float = 0.7,
        sole_owner_min_commits: int = 4,
        min_score: float = 0.5,
    ) -> None:
        self.familiarity_threshold = familiarity_threshold
        self.min_sensitivity = min_sensitivity
        self.sole_owner_min_commits = sole_owner_min_commits
        self.min_score = min_score

    def run(self, ctx: DetectorContext) -> Iterable[Finding]:
        graph = ctx.graph
        findings: list[Finding] = []

        touches: dict[str, list[tuple[str, float]]] = defaultdict(list)
        for author in ctx.repo_graph.authors:
            for _, target, data in graph.edges(author, data=True):
                if data.get("kind") == "touched":
                    touches[author].append((target, float(data.get("weight", 1.0))))

        total_commits = max(len(ctx.commits), 1)

        for author, edges in touches.items():
            dir_weights: Counter[str] = Counter()
            for node, weight in edges:
                dir_weights[posixpath.dirname(node_name(node))] += weight
            total_weight = sum(dir_weights.values()) or 1.0
            author_commits = graph.nodes[author].get("commits", 0)
            tenure_share = author_commits / total_commits

            for node, weight in edges:
                data = graph.nodes[node]
                sensitivity = float(data.get("sensitivity", 0.0))
                if sensitivity < self.min_sensitivity:
                    continue
                directory = posixpath.dirname(node_name(node))
                # Familiarity with this directory, ignoring this file's own touches.
                familiarity = max(dir_weights[directory] - weight, 0.0) / total_weight
                if familiarity > self.familiarity_threshold:
                    continue

                statistic = (
                    (1.0 - familiarity) * sensitivity * (1.0 - min(tenure_share, 0.9))
                )
                score = squash(statistic * 4.0, midpoint=2.0, steepness=2.2)
                if score < self.min_score:
                    continue
                findings.append(
                    Finding(
                        detector=self.name,
                        kind="territory-excursion",
                        subject=f"{node_name(author)} -> {node_name(node)}",
                        score=score,
                        message=(
                            f"{node_name(author)} touched {node_name(node)} "
                            f"({data.get('label')}) with almost no prior history in "
                            f"{directory or 'the repository root'}"
                        ),
                        evidence={
                            "author_commits": author_commits,
                            "author_share_of_history": round(tenure_share, 3),
                            "directory_familiarity": round(familiarity, 4),
                            "file_sensitivity": round(sensitivity, 2),
                            "touches": int(weight),
                            "path_class": data.get("label"),
                        },
                    )
                )

        findings.extend(self._sole_owners(ctx))
        findings.extend(self._identity_conflicts(ctx))
        return findings

    def _sole_owners(self, ctx: DetectorContext) -> list[Finding]:
        graph = ctx.graph
        out = []
        for node in ctx.repo_graph.files:
            data = graph.nodes[node]
            sensitivity = float(data.get("sensitivity", 0.0))
            if sensitivity < self.min_sensitivity:
                continue
            owners = [
                (other, float(edata.get("weight", 1.0)))
                for _, other, edata in graph.edges(node, data=True)
                if edata.get("kind") == "touched"
            ]
            if len(owners) != 1:
                continue
            owner, weight = owners[0]
            if weight < self.sole_owner_min_commits:
                continue
            score = min(1.0, 0.45 + 0.35 * sensitivity)
            if score < self.min_score:
                continue
            out.append(
                Finding(
                    detector=self.name,
                    kind="sole-ownership",
                    subject=node_name(node),
                    score=score,
                    message=(
                        f"{node_name(node)} ({data.get('label')}) has been modified "
                        f"only by {node_name(owner)} across {int(weight)} commits"
                    ),
                    evidence={
                        "owner": node_name(owner),
                        "commits": int(weight),
                        "path_class": data.get("label"),
                    },
                )
            )
        return out

    def _identity_conflicts(self, ctx: DetectorContext) -> list[Finding]:
        by_email: dict[str, set[str]] = defaultdict(set)
        by_name: dict[str, set[str]] = defaultdict(set)
        for commit in ctx.commits:
            by_email[commit.author_email].add(commit.author_name)
            by_name[commit.author_name.strip().lower()].add(commit.author_email)

        out = []
        for email, names in by_email.items():
            if len(names) > 1:
                out.append(
                    Finding(
                        detector=self.name,
                        kind="identity-conflict",
                        subject=email,
                        score=0.5,
                        message=(
                            f"{email} has authored commits under {len(names)} "
                            "different display names"
                        ),
                        evidence={"names": sorted(names)},
                    )
                )
        for name, emails in by_name.items():
            if len(emails) > 1:
                out.append(
                    Finding(
                        detector=self.name,
                        kind="identity-conflict",
                        subject=name,
                        score=0.5,
                        message=(
                            f"display name '{name}' maps to {len(emails)} "
                            "different author emails"
                        ),
                        evidence={"emails": sorted(emails)},
                    )
                )
        return out
