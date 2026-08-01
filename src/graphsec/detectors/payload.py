"""Content scan of added lines for execution and exfiltration primitives.

Only runs in deep mode: it fetches diffs, so its cost scales with history.
Findings here are pattern-based and meant to be triaged, not trusted blindly.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Iterable

from .. import git_log
from .. import paths as pathutil
from ..models import Finding
from .base import Detector, DetectorContext

PATTERNS: tuple[tuple[str, re.Pattern[str], float], ...] = (
    (
        "remote-script-execution",
        re.compile(r"curl[^\n|]{0,200}\|\s*(ba)?sh|wget[^\n|]{0,200}\|\s*(ba)?sh", re.I),
        0.9,
    ),
    (
        "dynamic-eval",
        re.compile(r"\b(eval|exec)\s*\(\s*(base64|atob|bytes\.fromhex|codecs\.decode|__import__)", re.I),
        0.9,
    ),
    (
        "encoded-payload",
        re.compile(r"(base64\.b64decode|atob|Buffer\.from\s*\([^)]*base64)", re.I),
        0.5,
    ),
    (
        "reverse-shell",
        re.compile(r"(socket\.socket\([^)]*\)[\s\S]{0,120}connect\(|/dev/tcp/|nc\s+-e\s)", re.I),
        0.95,
    ),
    (
        "credential-exfiltration",
        re.compile(
            r"(AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|NPM_TOKEN|\.ssh/id_[a-z]+|~/\.aws/credentials)"
            r"[\s\S]{0,120}(curl|requests\.(post|get)|fetch\(|http)",
            re.I,
        ),
        0.95,
    ),
    (
        "history-rewrite",
        re.compile(r"git\s+(push\s+--force|filter-branch|update-ref\s+-d)", re.I),
        0.5,
    ),
    (
        "hardcoded-secret",
        re.compile(
            r"(?:api[_-]?key|secret|password|token)\s*[:=]\s*[\"'][A-Za-z0-9/+_\-]{16,}[\"']",
            re.I,
        ),
        0.7,
    ),
)

_CANDIDATE_TOKEN = re.compile(r"[A-Za-z0-9+/=_\-]{32,}")

# A quoted literal long enough to be a credential, and a bare token long enough
# to be one. Everything around them -- the variable name, the surrounding call --
# is what makes a finding reviewable, so only the value itself is removed.
_QUOTED_VALUE = re.compile(r"(['\"])([A-Za-z0-9+/=_\-]{16,})\1")
_BARE_TOKEN = re.compile(r"(?<![A-Za-z0-9+/=_\-])([A-Za-z0-9+/=_\-]{28,})")


def redact_secrets(text: str) -> str:
    """Strip credential-shaped values out of text that will be reported.

    A finding travels into JSON and SARIF artifacts, and the documented CI
    recipe uploads SARIF to code scanning. Copying the secret we just found
    into that artifact would move it somewhere new rather than protect it.
    """

    quoted = _QUOTED_VALUE.sub(
        lambda m: f"{m.group(1)}<redacted:{len(m.group(2))} chars>{m.group(1)}", text
    )
    return _BARE_TOKEN.sub(lambda m: f"<redacted:{len(m.group(1))} chars>", quoted)


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


class PayloadDetector(Detector):
    """Scans added lines for execution, obfuscation and exfiltration markers."""

    name = "payload"
    description = "Suspicious added content (deep mode only)"

    def __init__(
        self,
        max_commits: int = 300,
        entropy_threshold: float = 4.6,
        min_score: float = 0.5,
    ) -> None:
        self.max_commits = max_commits
        self.entropy_threshold = entropy_threshold
        self.min_score = min_score

    def run(self, ctx: DetectorContext) -> Iterable[Finding]:
        if not ctx.deep:
            return []

        findings: list[Finding] = []
        for commit in ctx.commits[: self.max_commits]:
            for path, added in git_log.added_lines_by_file(ctx.repo, commit.sha).items():
                if not added:
                    continue
                sensitivity = pathutil.sensitivity(path)
                base = {
                    "sha": commit.sha,
                    "file": path,
                    "author": commit.author_email,
                    "subject": commit.subject,
                    "path_class": pathutil.label(path),
                }

                for kind, pattern, weight in PATTERNS:
                    match = pattern.search(added)
                    if not match:
                        continue
                    score = min(1.0, weight * (0.8 + 0.3 * sensitivity))
                    if score < self.min_score:
                        continue
                    findings.append(
                        Finding(
                            detector=self.name,
                            kind=kind,
                            subject=f"{commit.short_sha}:{path}",
                            score=score,
                            message=(
                                f"{commit.short_sha} adds content matching {kind} "
                                f"in {path} ({commit.author_email})"
                            ),
                            evidence={
                                **base,
                                "snippet": redact_secrets(match.group(0)[:160]),
                            },
                        )
                    )

                secret = None if pathutil.is_lockfile(path) else self._high_entropy_token(added)
                if secret is not None:
                    token, entropy = secret
                    findings.append(
                        Finding(
                            detector=self.name,
                            kind="high-entropy-string",
                            subject=f"{commit.short_sha}:{path}",
                            score=min(
                                1.0, 0.5 + (entropy - self.entropy_threshold) / 2.0
                            ),
                            message=(
                                f"{commit.short_sha} adds a {len(token)}-char "
                                f"high-entropy string (H={entropy:.2f}) to {path}, "
                                "possible embedded credential"
                            ),
                            evidence={
                                **base,
                                "entropy": round(entropy, 3),
                                "prefix": token[:12] + "...",
                            },
                        )
                    )

        findings.sort(key=lambda f: -f.score)
        return findings

    def _high_entropy_token(self, text: str) -> tuple[str, float] | None:
        best: tuple[str, float] | None = None
        for match in _CANDIDATE_TOKEN.finditer(text):
            token = match.group(0)
            # Hashes and lockfile digests are long but uniform; require mixed case
            # or symbols so we do not flag every checksum in a lockfile.
            if token.islower() or token.isupper() or token.isdigit():
                continue
            entropy = shannon_entropy(token)
            if entropy >= self.entropy_threshold and (best is None or entropy > best[1]):
                best = (token, entropy)
        return best
