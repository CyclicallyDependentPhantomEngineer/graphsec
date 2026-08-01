from __future__ import annotations

from pathlib import Path

import pytest

from graphsec.detectors import (
    DETECTOR_NAMES,
    DependencyAnomalyDetector,
    DetectorContext,
    HiddenCouplingDetector,
    OwnershipAnomalyDetector,
    PayloadDetector,
    StructuralAnomalyDetector,
    build_detectors,
)
from graphsec.detectors.cochange import _path_distance, is_expected_pair
from graphsec.detectors.dependency import edit_distance, parse_added_dependencies
from graphsec.detectors.payload import shannon_entropy
from graphsec.scanner import load_graph, scan


@pytest.fixture
def ctx(planted_repo: Path) -> DetectorContext:
    return DetectorContext(repo=planted_repo, repo_graph=load_graph(planted_repo), deep=True)


def test_build_detectors_rejects_unknown_name():
    with pytest.raises(ValueError, match="unknown detector"):
        build_detectors(["nope"])


def test_build_detectors_filters():
    detectors = build_detectors(["structural", "commit"])
    assert {d.name for d in detectors} == {"structural", "commit"}
    assert set(DETECTOR_NAMES) >= {"structural", "commit", "payload"}


def test_hidden_coupling_finds_planted_pair(ctx: DetectorContext):
    findings = list(HiddenCouplingDetector(min_support=3).run(ctx))
    subjects = {f.subject for f in findings}
    assert any("vendor/tracker.js" in s and "src/api/routes.py" in s for s in subjects)


def test_hidden_coupling_ignores_same_directory_pairs(ctx: DetectorContext):
    findings = list(HiddenCouplingDetector(min_support=3).run(ctx))
    for finding in findings:
        left, right = finding.subject.split(" <-> ")
        assert left.rsplit("/", 1)[0] != right.rsplit("/", 1)[0]


@pytest.mark.parametrize(
    "left,right,expected",
    [
        ("tests/test_orm.py", "src/model.py", True),
        ("src/widget.ts", "ui/widget.tsx", True),
        ("src/api/routes.py", "vendor/tracker.js", False),
        (".github/workflows/ci.yml", "src/auth/session.py", False),
    ],
)
def test_is_expected_pair(left, right, expected):
    assert is_expected_pair(left, right) is expected


def test_path_distance():
    assert _path_distance("src/a.py", "src/b.py") == 0.0
    assert _path_distance("src/api/a.py", "vendor/b.js") == 1.0
    assert 0.0 < _path_distance("src/api/a.py", "src/core/b.py") < 1.0


def test_ownership_flags_outsider_touching_sensitive_paths(ctx: DetectorContext):
    findings = list(OwnershipAnomalyDetector().run(ctx))
    excursions = [f for f in findings if f.kind == "territory-excursion"]
    assert any(
        "contractor@vendor.example" in f.subject and "auth/session.py" in f.subject
        for f in excursions
    )


def test_ownership_flags_sole_owner_of_execution_surface(ctx: DetectorContext):
    findings = [f for f in OwnershipAnomalyDetector().run(ctx) if f.kind == "sole-ownership"]
    assert findings == [] or all(f.score >= 0.5 for f in findings)


def test_commit_detector_flags_the_planted_commit(planted_repo: Path):
    result = scan(planted_repo, detectors=["commit"])
    messages = " ".join(f.message for f in result.findings)
    assert "contractor@vendor.example" in messages
    assert any(f.severity in {"medium", "high"} for f in result.findings)


def test_dependency_detector_flags_typosquat(ctx: DetectorContext):
    findings = list(DependencyAnomalyDetector().run(ctx))
    assert any(f.subject == "reqeusts" for f in findings)
    squat = next(f for f in findings if f.subject == "reqeusts")
    assert "requests" in str(squat.evidence["reasons"])


def test_dependency_graph_is_populated(ctx: DetectorContext):
    detector = DependencyAnomalyDetector()
    list(detector.run(ctx))
    assert detector.dep_graph.has_node("dep:flask")
    assert detector.dep_graph.has_edge("dep:reqeusts", "file:requirements.txt")


@pytest.mark.parametrize(
    "manifest,line,expected",
    [
        ("requirements.txt", "+requests==2.31.0", ("requests", "==2.31.0")),
        ("package.json", '+    "lodash": "^4.17.21",', ("lodash", "^4.17.21")),
        ("go.mod", "+\tgithub.com/pkg/errors v0.9.1", ("github.com/pkg/errors", "")),
    ],
)
def test_parse_added_dependencies(manifest, line, expected):
    parsed = parse_added_dependencies(manifest, line.lstrip("+"))
    assert expected in parsed


def test_edit_distance_counts_transposition_as_one():
    assert edit_distance("requests", "reqeusts") == 1
    assert edit_distance("abc", "abd") == 1
    assert edit_distance("abc", "abc") == 0
    assert edit_distance("short", "a-very-long-name", cap=2) == 3  # short-circuited


def test_payload_detector_requires_deep_mode(planted_repo: Path):
    shallow = DetectorContext(repo=planted_repo, repo_graph=load_graph(planted_repo), deep=False)
    assert list(PayloadDetector().run(shallow)) == []


def test_payload_detector_finds_piped_shell_and_eval(ctx: DetectorContext):
    findings = list(PayloadDetector().run(ctx))
    by_kind = {f.kind: f for f in findings}
    assert "remote-script-execution" in by_kind
    assert "dynamic-eval" in by_kind
    assert by_kind["remote-script-execution"].evidence["file"] == (
        ".github/workflows/release.yml"
    )
    assert by_kind["dynamic-eval"].evidence["file"] == "src/auth/session.py"


def test_shannon_entropy():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("abcd") == pytest.approx(2.0)


def test_structural_detector_returns_scored_findings(ctx: DetectorContext):
    findings = list(StructuralAnomalyDetector(min_score=0.0, top_k=5).run(ctx))
    assert findings
    assert all(0.0 <= f.score <= 1.0 for f in findings)
    assert all("top_features" in f.evidence for f in findings)


def test_structural_detector_falls_back_without_sklearn(ctx: DetectorContext, monkeypatch):
    from graphsec.detectors import structural

    monkeypatch.setattr(structural, "_isolation_scores", lambda matrix: None)
    findings = list(structural.StructuralAnomalyDetector(min_score=0.0, top_k=5).run(ctx))
    assert findings
    assert {f.evidence["model"] for f in findings} == {"robust-z"}


def test_structural_detector_skips_tiny_repos(tiny_repo: Path):
    ctx = DetectorContext(repo=tiny_repo, repo_graph=load_graph(tiny_repo))
    assert list(StructuralAnomalyDetector().run(ctx)) == []
