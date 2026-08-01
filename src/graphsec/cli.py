"""Command line interface for graphsec."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from . import __version__, report
from .detectors import DETECTOR_NAMES
from .git_log import GitError
from .scanner import load_graph, scan

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="graphsec",
        description=(
            "Graph-based anomaly detection for security analysis of any git repository."
        ),
    )
    parser.add_argument("--version", action="version", version=f"graphsec {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_cmd = sub.add_parser("scan", help="scan a repository for anomalies")
    scan_cmd.add_argument("repo", nargs="?", default=".", help="path to a git repository")
    scan_cmd.add_argument(
        "-f",
        "--format",
        choices=("text", "json", "sarif"),
        default="text",
        help="output format (default: text)",
    )
    scan_cmd.add_argument("-o", "--output", help="write the report to this file")
    scan_cmd.add_argument(
        "-n", "--max-commits", type=int, default=None, help="only read the N most recent commits"
    )
    scan_cmd.add_argument(
        "--since", default=None, help="only read commits newer than this git date expression"
    )
    scan_cmd.add_argument(
        "-d",
        "--detector",
        action="append",
        dest="detectors",
        choices=list(DETECTOR_NAMES),
        help="run only this detector (repeatable)",
    )
    scan_cmd.add_argument(
        "--deep",
        action="store_true",
        help="also scan commit contents (slower; enables the payload detector)",
    )
    scan_cmd.add_argument(
        "--min-score", type=float, default=0.5, help="drop findings below this score (default: 0.5)"
    )
    scan_cmd.add_argument(
        "--no-imports", action="store_true", help="skip static import graph construction"
    )
    scan_cmd.add_argument("--limit", type=int, default=40, help="max findings in text output")
    scan_cmd.add_argument(
        "--fail-on",
        choices=("never", "low", "medium", "high"),
        default="never",
        help="exit non-zero when a finding of this severity or higher is present",
    )
    scan_cmd.add_argument("-v", "--verbose", action="store_true", help="log detector progress")

    graph_cmd = sub.add_parser("graph", help="export the co-change graph as Graphviz DOT")
    graph_cmd.add_argument("repo", nargs="?", default=".", help="path to a git repository")
    graph_cmd.add_argument("-o", "--output", help="write DOT to this file")
    graph_cmd.add_argument("-n", "--max-commits", type=int, default=None)
    graph_cmd.add_argument("--since", default=None)

    sub.add_parser("detectors", help="list available detectors")
    return parser


def _emit(text: str, output: str | None) -> None:
    if output:
        Path(output).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text + ("\n" if not text.endswith("\n") else ""))


def _cmd_scan(args: argparse.Namespace) -> int:
    result = scan(
        args.repo,
        max_commits=args.max_commits,
        since=args.since,
        deep=args.deep,
        detectors=args.detectors,
        min_score=args.min_score,
        with_imports=not args.no_imports,
    )

    if args.format == "json":
        text = report.to_json(result)
    elif args.format == "sarif":
        text = report.to_sarif(result)
    else:
        text = report.to_text(result, limit=args.limit, color=sys.stdout.isatty())
    _emit(text, args.output)

    if args.fail_on != "never":
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f.severity] >= threshold for f in result.findings):
            return EXIT_FINDINGS
    return EXIT_OK


def _cmd_graph(args: argparse.Namespace) -> int:
    repo_graph = load_graph(args.repo, max_commits=args.max_commits, since=args.since)
    _emit(report.to_dot(repo_graph), args.output)
    return EXIT_OK


def _cmd_detectors(_: argparse.Namespace) -> int:
    from .detectors import DETECTOR_CLASSES

    for cls in DETECTOR_CLASSES:
        sys.stdout.write(f"{cls.name:<12} {cls.description}\n")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if getattr(args, "verbose", False) else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )
    handlers = {"scan": _cmd_scan, "graph": _cmd_graph, "detectors": _cmd_detectors}
    try:
        return handlers[args.command](args)
    except GitError as exc:
        sys.stderr.write(f"graphsec: {exc}\n")
        return EXIT_ERROR
    except ValueError as exc:
        sys.stderr.write(f"graphsec: {exc}\n")
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
