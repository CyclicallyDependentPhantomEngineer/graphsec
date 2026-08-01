from __future__ import annotations

import json
from pathlib import Path

import pytest

from graphsec import report
from graphsec.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main
from graphsec.scanner import load_graph, scan


def test_scan_text_output(planted_repo: Path, capsys):
    assert main(["scan", str(planted_repo)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "graphsec scan of" in out
    assert "findings:" in out


def test_scan_json_output_is_valid(planted_repo: Path, capsys):
    assert main(["scan", str(planted_repo), "--format", "json"]) == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["commits"] > 20
    assert payload["graph"]["files"] >= 8
    assert isinstance(payload["findings"], list)
    scores = [f["score"] for f in payload["findings"]]
    assert scores == sorted(scores, reverse=True)


def test_scan_sarif_output(planted_repo: Path, capsys):
    assert main(["scan", str(planted_repo), "--format", "sarif"]) == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["tool"]["driver"]["name"] == "graphsec"


def test_scan_writes_output_file(planted_repo: Path, tmp_path: Path):
    target = tmp_path / "out.json"
    assert main(["scan", str(planted_repo), "-f", "json", "-o", str(target)]) == EXIT_OK
    assert json.loads(target.read_text())["repo"]


def test_fail_on_medium_exits_nonzero(planted_repo: Path, capsys):
    code = main(["scan", str(planted_repo), "--deep", "--fail-on", "medium"])
    capsys.readouterr()
    assert code == EXIT_FINDINGS


def test_fail_on_never_exits_zero(planted_repo: Path, capsys):
    assert main(["scan", str(planted_repo), "--deep"]) == EXIT_OK
    capsys.readouterr()


def test_scan_non_repo_reports_error(tmp_path: Path, capsys):
    assert main(["scan", str(tmp_path / "missing")]) == EXIT_ERROR
    assert "graphsec:" in capsys.readouterr().err


def test_detectors_command(capsys):
    assert main(["detectors"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "structural" in out
    assert "dependency" in out


def test_graph_command_emits_dot(planted_repo: Path, capsys):
    assert main(["graph", str(planted_repo)]) == EXIT_OK
    out = capsys.readouterr().out
    assert out.startswith("graph repo {")
    assert '"src/api/routes.py"' in out


def test_single_detector_selection(planted_repo: Path, capsys):
    assert main(["scan", str(planted_repo), "-d", "cochange", "-f", "json"]) == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert {f["detector"] for f in payload["findings"]} <= {"cochange"}


def test_min_score_filters(planted_repo: Path):
    high = scan(planted_repo, min_score=0.95)
    low = scan(planted_repo, min_score=0.1)
    assert len(high.findings) <= len(low.findings)


def test_report_text_handles_empty_result(tiny_repo: Path):
    result = scan(tiny_repo, min_score=0.99)
    text = report.to_text(result)
    assert "no anomalies above threshold" in text


def test_dot_highlights_requested_files(planted_repo: Path):
    dot = report.to_dot(load_graph(planted_repo), highlight={"src/api/routes.py"})
    assert 'color="red"' in dot


@pytest.mark.parametrize("fmt", ["text", "json", "sarif"])
def test_formats_render_without_error(tiny_repo: Path, fmt: str, capsys):
    assert main(["scan", str(tiny_repo), "-f", fmt]) == EXIT_OK
    capsys.readouterr()
