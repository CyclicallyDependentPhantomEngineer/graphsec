"""Rendering of scan results: text, JSON and DOT."""

from __future__ import annotations

import json
from collections.abc import Iterable

from .git_log import sanitize
from .graph import RepoGraph, node_name
from .models import ScanResult

SEVERITY_MARK = {"high": "!!", "medium": "! ", "low": "  "}

# Attributes injected through a crafted path would otherwise change how
# Graphviz renders -- and what it reads -- when the DOT file is processed.
_DOT_UNSAFE = str.maketrans({'"': "'", "\\": "/"})


def _dot_quote(name: str) -> str:
    return sanitize(name).translate(_DOT_UNSAFE)


def to_json(result: ScanResult, *, indent: int = 2) -> str:
    return json.dumps(result.to_dict(), indent=indent, sort_keys=False, default=str)


def to_sarif(result: ScanResult) -> str:
    """Minimal SARIF 2.1.0 output so findings can be uploaded to code scanning."""
    rules: dict[str, dict] = {}
    results = []
    for finding in result.sorted_findings():
        rule_id = f"graphsec/{finding.detector}/{finding.kind}"
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": finding.kind,
                "shortDescription": {"text": finding.kind.replace("-", " ")},
                "defaultConfiguration": {"level": "warning"},
            },
        )
        location_path = finding.evidence.get("manifest") or finding.subject
        results.append(
            {
                "ruleId": rule_id,
                "level": "error" if finding.severity == "high" else "warning",
                "message": {"text": finding.message},
                "properties": {"score": round(finding.score, 4), **finding.evidence},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": str(location_path)},
                        }
                    }
                ],
            }
        )
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "graphsec",
                        "informationUri": "https://github.com/graphsec/graphsec",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2, default=str)


def to_text(result: ScanResult, *, limit: int = 40, color: bool = False) -> str:
    summary = result.to_dict()["summary"]
    lines = [
        f"graphsec scan of {result.repo}",
        f"  commits={summary['commits']} files={summary['files']} "
        f"authors={summary['authors']}",
        f"  graph: {result.graph_stats.get('nodes', 0)} nodes / "
        f"{result.graph_stats.get('edges', 0)} edges",
        f"  findings: {summary['findings']} "
        f"(high={summary['high']} medium={summary['medium']} low={summary['low']})",
        "",
    ]
    for warning in result.warnings:
        lines.insert(-1, f"  WARNING: {sanitize(warning)}")

    findings = result.sorted_findings()[:limit]
    if not findings:
        lines.append("  no anomalies above threshold")
        return "\n".join(lines)

    for finding in findings:
        mark = SEVERITY_MARK[finding.severity]
        head = f"{mark} [{finding.score:.2f}] {finding.detector}/{finding.kind}"
        if color:
            shade = {"high": "31", "medium": "33", "low": "37"}[finding.severity]
            head = f"\033[{shade}m{head}\033[0m"
        lines.append(head)
        # Messages and evidence embed repository-controlled text; escape
        # sequences in it would otherwise rewrite the operator's report.
        lines.append(f"     {sanitize(finding.message)}")
        for key, value in list(finding.evidence.items())[:4]:
            lines.append(f"     - {sanitize(str(key))}: {sanitize(str(value))}")
        lines.append("")

    hidden = len(result.findings) - len(findings)
    if hidden > 0:
        lines.append(f"  ... {hidden} more finding(s) not shown")
    return "\n".join(lines)


def to_dot(repo_graph: RepoGraph, *, highlight: Iterable[str] = ()) -> str:
    """Export the co-change graph for visual inspection with Graphviz."""
    highlight = {h for h in highlight}
    lines = ["graph repo {", '  node [shape=box fontsize=9];']
    for node, data in repo_graph.graph.nodes(data=True):
        if data.get("type") != "file":
            continue
        name = node_name(node)
        safe = _dot_quote(name)
        attrs = [f'label="{safe}"']
        if name in highlight:
            attrs.append('color="red"')
            attrs.append('penwidth=2')
        elif data.get("sensitivity", 0.0) >= 0.7:
            attrs.append('color="orange"')
        lines.append(f'  "{safe}" [{" ".join(attrs)}];')
    for left, right, data in repo_graph.graph.edges(data=True):
        if data.get("kind") != "cochange":
            continue
        weight = data.get("weight", 1.0)
        lines.append(
            f'  "{_dot_quote(node_name(left))}" -- "{_dot_quote(node_name(right))}" '
            f'[penwidth={min(1 + weight / 4, 6):.1f}];'
        )
    lines.append("}")
    return "\n".join(lines)
