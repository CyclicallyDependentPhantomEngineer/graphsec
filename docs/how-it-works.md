# How graphsec works

This document explains the whole pipeline: what is read out of the repository,
what graph is built from it, which numbers are computed, and how those numbers
turn into a score between 0 and 1. Every threshold quoted here is the actual
default in the source, and each section links to the file that implements it.

If you only want to run the thing, the README's TL;DR is enough. Read this when
you want to know why a finding fired, or you want to change a threshold and need
to know what it will move.

## The pipeline

```
git log --numstat          →  Commit / FileChange records      git_log.py
        ↓
build the repository graph →  files, authors, dirs + edges     graph.py
        ↓
extract per-file features  →  16-dimensional vectors           features.py
        ↓
run six detectors          →  Finding objects with evidence    detectors/
        ↓
render                     →  text / JSON / SARIF / DOT        report.py
```

Nothing is cached and nothing is written to the repository. A scan is a pure
function of the commit history plus the file tree at `HEAD`.

## Stage 1 — reading history

[`git_log.py`](../src/graphsec/git_log.py) shells out to `git` rather than using
a binding, so the only hard requirement is a `git` executable.

```
git log --no-merges --numstat --date=iso-strict --pretty=format:<record>
```

Records are separated by `0x1E` and fields within the header by `0x1F`, so a
commit subject containing newlines, tabs or pipes cannot corrupt the parse. Each
record yields a `Commit` with a tuple of `FileChange` entries carrying
insertions, deletions, a binary flag and, for renames, the previous path.

Three details matter:

- **Merges are excluded.** A merge commit's numstat re-reports changes that
  already appeared on the branch, which would double-count churn and inflate
  co-change edges.
- **Renames are unfolded.** git writes `src/{old => new}/file.py`; both the old
  and new path are recovered so history is not silently split in two.
- **Timestamps are normalised before parsing.** git prints UTC commits as
  `2024-01-08T10:00:00Z`, and `datetime.fromisoformat` only accepts the `Z`
  suffix from Python 3.11 onward. `parse_timestamp` rewrites `Z` and colon-less
  offsets (`+0530`) first. If *every* record fails to parse, `read_commits`
  raises rather than returning an empty list — a scanner that reports "no
  findings" because it could not read the log is worse than one that crashes.

## Stage 2 — the graph

[`graph.py`](../src/graphsec/graph.py) builds one undirected heterogeneous graph
plus a separate directed import graph.

| Node | Example | Attributes |
| --- | --- | --- |
| `file:` | `file:src/auth/session.py` | commits, churn, insertions, deletions, binary touches, sensitivity, label, first/last seen |
| `author:` | `author:ana@example.com` | commits, churn, first/last seen, display name |
| `dir:` | `dir:src/auth` | name |

| Edge | Between | Weight |
| --- | --- | --- |
| `touched` | author – file | number of commits by that author on that file |
| `cochange` | file – file | number of commits containing both files |
| `contains` | dir – file, dir – dir | 1 |
| `imports` | file → file | separate `DiGraph`, unweighted |

Import edges live in their own graph on purpose: they connect the same node pair
as co-change edges, and conflating "these two files reference each other" with
"these two files change together" would destroy the signal that matters most —
coupling that imports *cannot* explain.

Import resolution is best-effort and static: Python `import`/`from ... import`
statements are matched against tracked paths (including package-relative
lookups), and relative JS/TS specifiers are resolved through the usual
`.ts/.tsx/.js/.jsx/index.*` suffix list. Unresolvable imports are dropped rather
than guessed.

**The fan-out cap.** A commit touching more than `MAX_COCHANGE_FANOUT = 40`
files contributes no co-change edges. Such commits are almost always merges,
vendoring, reformatting or a license header sweep; including them would add
`n(n-1)/2` meaningless edges each and drown every real coupling signal.

## Stage 3 — per-file features

[`features.py`](../src/graphsec/features.py) turns each file node into a
16-dimensional vector. The whole point is that these describe a file's *position
in the change topology*, not its contents — which is what lets the same model run
against any repository, in any language, without tuning.

| # | Feature | Definition | What an outlier means |
| --- | --- | --- | --- |
| 1 | `commits` | commits touching the file | churned constantly, or touched once and never again |
| 2 | `churn` | `log1p(insertions + deletions)` | log-scaled so one vendored blob does not dominate the axis |
| 3 | `churn_per_commit` | churn ÷ commits | large rewrites rather than incremental edits |
| 4 | `author_count` | distinct authors | a file everyone edits, or nobody but one person |
| 5 | `ownership_concentration` | top author's share of touches | 1.0 means a single person owns it outright |
| 6 | `cochange_degree` | number of co-change neighbours | isolated file, or a hub that moves with everything |
| 7 | `cochange_weight` | `log1p(total co-change weight)` | strength, not just breadth, of coupling |
| 8 | `external_coupling` | fraction of coupling weight to files in *other* directories | a file whose real dependencies live elsewhere |
| 9 | `clustering` | weighted clustering coefficient | whether its neighbours also change together |
| 10 | `pagerank` | weighted PageRank over the co-change graph | structural centrality in the change process |
| 11 | `core_number` | k-core index | membership in a densely co-changing core |
| 12 | `betweenness` | betweenness centrality | a bridge between otherwise separate modules |
| 13 | `import_in` | incoming import edges | how many files depend on it |
| 14 | `import_out` | outgoing import edges | how many files it depends on |
| 15 | `coupling_without_imports` | fraction of co-change weight to non-import neighbours | coupling with no code-level explanation |
| 16 | `sensitivity` | path sensitivity, see below | how much a silent change here would matter |

Two performance notes: betweenness switches to sampled pivots
(`BETWEENNESS_SAMPLE = 96`, fixed seed 17) above 96 nodes, and PageRank is
computed by power iteration over the edge list with numpy — `O(E)` per iteration
and no dense matrix. networkx delegates `pagerank` to scipy, which is not a
dependency here; computing it directly also means scores do not shift depending
on which optional packages happen to be installed.

## Path sensitivity

[`paths.py`](../src/graphsec/paths.py) gives every path a weight in `[0, 1]`.
This is the only place where domain knowledge, rather than topology, enters the
scoring, and it is what makes "unusual" become "unusual *and worth waking someone
up for*".

| Class | Sensitivity | Examples |
| --- | --- | --- |
| `secret-material` | 1.0 | `.env`, `*.pem`, `*.key`, `*.p12`, keystores |
| `execution-surface` | 0.9 | `.github/workflows/`, `Dockerfile`, `Makefile`, `setup.py`, `scripts/`, `.husky/` |
| `dependency-manifest` | 0.8 | `requirements.txt`, `package.json`, `go.mod`, `Cargo.toml`, lockfiles |
| `security-relevant` | 0.7 | path matching `auth`, `token`, `crypto`, `permission`, `iam`, `sanitiz`, `cert`, … |
| `source` | 0.3 | any recognised source extension |
| `other` | 0.0 | docs, assets, everything else |

The highest matching class wins. Sensitivity never *creates* a finding on its
own — it only multiplies a score that some statistical signal already produced.

## Stage 4 — the detectors

Every detector returns `Finding` objects carrying a `score`, a human-readable
`message`, and an `evidence` dictionary holding the raw numbers that produced
the score. The evidence exists so a reviewer can overrule the tool.

### `structural` — topology outliers

[`detectors/structural.py`](../src/graphsec/detectors/structural.py)

Runs `IsolationForest` (200 trees, `contamination="auto"`, seed 17) over the
feature matrix; the raw scores are then standardised against their own
median/MAD so severities are comparable across repositories and across models.
`squash(z, midpoint=3.0, steepness=0.9)` maps that to `(0, 1)`, multiplied by
`0.75 + 0.5 × sensitivity`.

Without scikit-learn it falls back to a robust-z composite (mean of clipped
per-feature deviations plus half the maximum). Findings report which model ran
under `evidence.model`, and the three features that deviated most under
`evidence.top_features`.

Repositories with fewer than `MIN_FILES = 8` files produce nothing: there is no
distribution to be an outlier in. Reports the top 15 by default.

### `cochange` — hidden coupling

[`detectors/cochange.py`](../src/graphsec/detectors/cochange.py)

For every co-change edge with support ≥ 3:

```
expected   = commits(a) × commits(b) / total_commits
lift       = support / expected
confidence = support / min(commits(a), commits(b))
statistic  = (2 × confidence + log2(lift)) × (0.5 + path_distance)
```

Confidence is the stronger of the two conditional probabilities — "whenever the
rarer of the two files changes, the other changes too". It carries the load
because lift alone punishes hot files: a module touched in 17 of 30 commits has a
high expected co-change rate with everything, so a genuine coupling to a file
touched 5 times scores only 1.8× lift while its confidence is 100%.

`path_distance` is 0.0 for files in the same directory and 1.0 for files sharing
no path prefix. A pair is dropped when:

- both `lift < 2.0` **and** `confidence < 0.6`
- `path_distance < 0.5` — same-neighbourhood coupling is just cohesion
- an import edge exists in either direction — the coupling is explained
- the pair is "expected": either side is a test file, or the two share a stem
  (`foo.c`/`foo.h`, `Widget.tsx`/`Widget.test.tsx`)

That last rule matters more than it sounds. On a real 174-commit repository,
suppressing test-to-source and same-stem pairs took the finding count from 22 to
7, and every survivor was worth reading.

### `ownership` — who touches what

[`detectors/author.py`](../src/graphsec/detectors/author.py)

Three separate signals:

**Territory excursion.** For each author, their touch weight is bucketed by
directory. For any file with sensitivity ≥ 0.7, familiarity is that author's
weight in the file's directory *excluding this file's own touches*, over their
total. Below `familiarity_threshold = 0.08` it fires, scored by
`(1 − familiarity) × sensitivity × (1 − min(tenure_share, 0.9))`. Excluding the
file's own touches is what makes it work: otherwise the very act of touching the
file makes the author look at home there.

**Sole ownership.** A file with sensitivity ≥ 0.7 modified across ≥ 4 commits by
exactly one author. Not an attack signal on its own — a bus-factor and
unreviewed-surface signal.

**Identity conflict.** One email committing under multiple display names, or one
display name mapping to multiple emails. Usually a misconfigured `git config`;
occasionally not.

### `commit` — risky commits

[`detectors/commit.py`](../src/graphsec/detectors/commit.py)

Additive risk over one commit, then `squash(risk × 2.2, midpoint=2.6,
steepness=1.0)`:

| Signal | Risk |
| --- | --- |
| Touches key or credential material | +1.1 |
| Changes CI/build scripts **and** dependency manifests together | +0.9 |
| Off-hours for *that author*, on a sensitive surface | +0.8 |
| Author's first ever commit lands on a high-value surface | +0.8 |
| Binary blobs alongside sensitive paths | +0.7 |
| Extreme churn (`z > 6` and > 400 lines) | up to +1.2 |

"Off-hours" is computed per author, not per clock: each author's commit-hour
histogram is smoothed over a ±1 hour window, and rarity above 0.9 counts. Someone
who always commits at 02:00 is never flagged for committing at 02:00. This
requires `MIN_COMMITS_FOR_BASELINE = 12` commits of history before it activates.

### `dependency` — supply chain

[`detectors/dependency.py`](../src/graphsec/detectors/dependency.py)

Walks every commit that touched a dependency manifest, oldest first, parses the
*added* lines per manifest format, and builds a small
`dependency → manifest → author` graph. The first appearance of each dependency
name is scored:

| Signal | Score |
| --- | --- |
| Resolved from a URL, VCS ref or archive rather than a registry | +0.55 |
| Name within one edit of a popular package | +0.5 |
| Introduced in a commit that also modifies CI or build scripts | +0.3 |
| First manifest change ever made by this author | +0.15 |

The edit distance is *optimal string alignment*, not plain Levenshtein, so an
adjacent transposition costs 1 rather than 2 — `reqeusts` is one slip from
`requests`, which is precisely the typosquat shape worth flagging. Plain
Levenshtein scores it 2 and misses it.

### `payload` — content patterns (deep mode only)

[`detectors/payload.py`](../src/graphsec/detectors/payload.py)

Only runs under `--deep`, because it fetches diffs and its cost scales with
history rather than with tree size. Each commit's diff is fetched once and split
per file, so a finding names the file that introduced the content, not just the
commit.

Patterns: remote script execution (`curl … | sh`), dynamic eval of encoded data,
reverse shells, credential exfiltration, `base64` decoding, history rewriting,
hardcoded secrets. Plus a Shannon-entropy check on long tokens (threshold 4.6
bits/char), skipped inside lockfiles, whose checksums are high-entropy by nature.

Credential-shaped values are redacted out of the reported snippet before it
reaches a finding: a quoted literal of 16 or more characters, or a bare token of
28 or more, becomes `<redacted:N chars>`. The surrounding context — the variable
name, the call it sits in — is what makes the finding reviewable and is kept.
Findings travel into JSON and SARIF, and the documented CI recipe uploads SARIF
to code scanning, so copying a discovered secret into one would move it
somewhere new rather than protect it.

These are regex patterns. They are the least clever part of the tool and the most
prone to false positives — graphsec's own source matches several of its own
rules, correctly, because those strings really are in the diff.

## Stage 5 — scoring

Detectors produce unbounded statistics; `squash` maps them to `(0, 1)` with a
logistic curve:

```python
1 / (1 + exp(-steepness × (value - midpoint)))
```

Severity bands: **high** ≥ 0.75, **medium** ≥ 0.5, **low** below. `--min-score`
drops findings under a threshold (default 0.5) *inside* each detector, so raising
it makes scans faster as well as quieter.

Scores are calibrated per repository, not absolute. A 0.9 means "this is an
outlier relative to the rest of *this* repository", which is exactly what you
want for triage and exactly wrong for comparing two repositories to each other.

## What this cannot do

- **It reads history, not code.** Logic bugs, injection flaws and unsafe
  deserialisation are invisible here. Run a SAST tool as well.
- **Squashed or rewritten history erases the signal.** Every timing, authorship
  and co-change feature comes from commit granularity.
- **Shallow clones produce nothing.** Use `fetch-depth: 0` in CI.
- **Bots look like attackers.** Dependabot is, structurally, a low-familiarity
  author who only ever touches dependency manifests. Filter by detector or score.
- **Unusual ≠ malicious.** A monorepo migration, a code freeze, a contractor
  onboarding and a genuine supply-chain attack can produce identical shapes. The
  evidence block exists so you can tell them apart; the score cannot.

## Extending it

A detector is a class with a `name`, a `description` and a `run(ctx)` returning
`Finding` objects. `ctx` carries the repo path, the built `RepoGraph`, and the
`deep` flag.

```python
from graphsec.detectors.base import Detector, DetectorContext, squash
from graphsec.models import Finding


class MyDetector(Detector):
    name = "mine"
    description = "What it looks for"

    def __init__(self, min_score: float = 0.5) -> None:
        self.min_score = min_score

    def run(self, ctx: DetectorContext):
        for node in ctx.repo_graph.files:
            ...
            yield Finding(
                detector=self.name,
                kind="my-anomaly",
                subject=node,
                score=squash(statistic),
                message="...",
                evidence={"statistic": statistic},
            )
```

Register it in `DETECTOR_CLASSES` in
[`detectors/__init__.py`](../src/graphsec/detectors/__init__.py). It is then
available to `-d mine` and to `graphsec detectors` automatically. A detector that
raises is logged and skipped rather than sinking the whole scan, so a broken
addition degrades the scan instead of breaking it.
