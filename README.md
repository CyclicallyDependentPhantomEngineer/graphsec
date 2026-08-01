# graphsec

Graph-based anomaly detection for security analysis of **any** git repository.

`graphsec` reads a repository's history, builds a heterogeneous graph of files,
authors and directories, and then looks for structure that does not fit: files
that sit in an odd position in the change topology, modules that keep changing
together for no visible reason, people editing code they have never touched
before, commits that land on CI and dependency manifests at 03:00, and packages
whose names are one keystroke away from something popular.

It needs nothing but `git` and the repository itself — no build, no language
server, no network, no prior training data. Point it at a checkout and it works.

```
pip install graphsec
graphsec scan /path/to/repo
```

```
graphsec scan of /path/to/repo
  commits=174 files=76 authors=4
  graph: 95 nodes / 580 edges
  findings: 7 (high=4 medium=3 low=0)

!! [0.88] commit/risky-commit
     73cc1a5a1d by contractor@vendor.example: changes CI/build scripts and
     dependency manifests together; authored at 03:12, outside this author's
     normal window, on a sensitive surface
     - sha: 73cc1a5a1d8f23776b72acdb9873f21b704201e4
     - files: ['.github/workflows/release.yml', 'requirements.txt', ...]
```

## Why a graph

Most repository security tooling looks at one artifact at a time: this file has
a secret in it, this dependency has a CVE. That misses the class of problem
where every individual change looks fine and only the *relationships* are wrong
— an unrelated file riding along in every release commit, a first-time
contributor whose opening move is the deploy pipeline, a vendored blob that only
ever changes alongside the auth module.

Those are relational properties, so `graphsec` models the repository as a graph
and scores nodes and edges rather than lines of code.

### The graph

| Node | Example | Meaning |
| --- | --- | --- |
| `file:` | `file:src/auth/session.py` | a tracked path |
| `author:` | `author:ana@example.com` | a commit author identity |
| `dir:` | `dir:src/auth` | a directory, for containment |

| Edge | Between | Weight |
| --- | --- | --- |
| `touched` | author – file | number of commits |
| `cochange` | file – file | number of shared commits |
| `contains` | dir – file/dir | 1 |
| `imports` | file → file | static import edges (separate directed graph) |

Commits touching more than 40 files are excluded from co-change edges: they are
almost always merges, vendoring or reformatting, and they would add a quadratic
number of meaningless edges.

## Detectors

| Name | What it flags |
| --- | --- |
| `structural` | Files whose graph-topology feature vector is an outlier (IsolationForest, or a robust-z composite when scikit-learn is not installed) |
| `cochange` | High-confidence co-change between files in unrelated directories with no import to explain it |
| `ownership` | Territory excursions onto sensitive paths, sole ownership of execution surfaces, and author identity inconsistencies |
| `commit` | Commits combining CI/build and dependency changes, off-hours work on sensitive surfaces, extreme churn, first-ever commits landing on high-value paths |
| `dependency` | New dependencies pulled from URLs or VCS refs, names one edit away from popular packages, dependencies introduced alongside CI changes |
| `payload` | Added content matching remote-script execution, dynamic eval of encoded data, reverse shells, credential exfiltration, high-entropy strings (**deep mode only**) |

List them at runtime with `graphsec detectors`.

### Structural features

Each file becomes a 16-dimensional vector describing its position in the graph:
commit count, log churn, churn per commit, author count, ownership
concentration, co-change degree and weight, fraction of coupling that leaves its
own directory, weighted clustering, PageRank, k-core number, betweenness,
import in/out degree, fraction of coupling unexplained by imports, and path
sensitivity. Betweenness switches to pivot sampling above 96 nodes so large
repositories stay fast.

## Usage

```bash
graphsec scan .                        # text report
graphsec scan . -f json -o out.json    # machine-readable
graphsec scan . -f sarif -o out.sarif  # upload to GitHub code scanning
graphsec scan . --deep                 # also scan commit contents
graphsec scan . -d cochange -d commit  # pick detectors
graphsec scan . -n 2000 --since '1 year ago'
graphsec scan . --min-score 0.7 --fail-on high
graphsec graph . -o repo.dot && dot -Tsvg repo.dot -o repo.svg
```

`--fail-on {low,medium,high}` makes the process exit `1` when a finding at that
severity or above is present, which is what you want in CI. Exit codes: `0` no
qualifying findings, `1` findings, `2` error.

Scores are normalised to `[0, 1]`; `>= 0.75` is reported as high, `>= 0.5` as
medium. Every finding carries an `evidence` block with the raw numbers that
produced the score, so a reviewer can audit the verdict rather than trust it.

### As a library

```python
from graphsec import scan, load_graph

result = scan("/path/to/repo", deep=True, min_score=0.6)
for finding in result.sorted_findings():
    print(finding.severity, finding.detector, finding.subject, finding.message)

repo_graph = load_graph("/path/to/repo")
print(repo_graph.stats())
```

### In CI

```yaml
- name: graphsec
  run: |
    pip install graphsec
    graphsec scan . -f sarif -o graphsec.sarif --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: graphsec.sarif
```

Fetch full history (`actions/checkout` with `fetch-depth: 0`) — a shallow clone
has no topology to analyse.

## Interpreting results

`graphsec` is a triage tool, not an oracle. It reports *unusual*, and unusual is
not the same as *malicious*: a monorepo migration, a code freeze, a contractor
onboarding and an actual supply-chain attack can all produce the same shape.
Treat findings as questions to ask, and read the evidence block before acting.

Known sources of noise:

- Repositories with fewer than ~8 files or ~12 commits give the statistical
  detectors nothing to work with; they stay quiet by design.
- Squashed or rewritten history destroys authorship and timing signal.
- Bot accounts (dependabot, release automation) look exactly like a
  low-familiarity author touching manifests. Filter them with `-d` or by score.
- Test files couple to everything, so test-to-source pairs and same-stem pairs
  are suppressed in the `cochange` detector.

## Install

```bash
pip install graphsec          # networkx + numpy only
pip install 'graphsec[ml]'    # adds scikit-learn for IsolationForest
```

Python 3.10+. Without scikit-learn the `structural` detector falls back to a
median/MAD composite score; findings then report `"model": "robust-z"`.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev,ml]'
pytest
ruff check .
```

The test-suite builds synthetic git repositories with planted anomalies — a
first-time author committing to CI, auth and requirements at 03:12, a
typosquatted `reqeusts` dependency, and an unexplained coupling between an API
module and a vendored script — and asserts that each detector finds its own
signal.

## License

MIT
