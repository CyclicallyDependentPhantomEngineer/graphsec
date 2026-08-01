"""Path classification helpers.

The detectors care about *where* a change lands, not just how big it is.
These predicates give every file a coarse security weight.
"""

from __future__ import annotations

import posixpath
import re

# Paths whose contents execute during build, test, release or deploy.
EXECUTION_SURFACE = (
    ".github/workflows/",
    ".github/actions/",
    ".gitlab-ci.yml",
    ".circleci/",
    "azure-pipelines.yml",
    "jenkinsfile",
    "makefile",
    "dockerfile",
    "docker-compose",
    "setup.py",
    "conftest.py",
    "gradlew",
    "build.gradle",
    "pom.xml",
    ".husky/",
    "scripts/",
)

# Files that declare third-party code pulled into the build.
DEPENDENCY_MANIFESTS = (
    "requirements.txt",
    "requirements-dev.txt",
    "pyproject.toml",
    "setup.cfg",
    "pipfile",
    "poetry.lock",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "go.mod",
    "go.sum",
    "cargo.toml",
    "cargo.lock",
    "gemfile",
    "pom.xml",
    "build.gradle",
)

# Lockfiles are wall-to-wall checksums; entropy tells you nothing there.
LOCKFILES = (
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "cargo.lock",
    "go.sum",
    "gemfile.lock",
    "composer.lock",
)

_SENSITIVE_TOKENS = re.compile(
    r"(auth|login|session|token|jwt|oauth|saml|password|passwd|credential|secret|"
    r"crypto|cipher|encrypt|decrypt|hash|signature|verify|permission|policy|acl|"
    r"rbac|iam|admin|sudo|privile|sanitiz|escape|validat|firewall|tls|ssl|cert|key)"
)

_CONFIG_SUFFIXES = (".env", ".pem", ".key", ".p12", ".pfx", ".keystore", ".jks")

_SOURCE_SUFFIXES = (
    ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java", ".rb", ".php",
    ".c", ".h", ".cc", ".cpp", ".hpp", ".cs", ".kt", ".swift", ".scala", ".sh",
)


def normalise(path: str) -> str:
    cleaned = posixpath.normpath(path.replace("\\", "/"))
    # Strip a leading "./" only — a bare lstrip would eat the dot of ".github".
    if cleaned.startswith("./"):
        cleaned = cleaned[2:]
    return cleaned.lstrip("/")


def directory(path: str) -> str:
    parent = posixpath.dirname(normalise(path))
    return parent or "."


_TEST_COMPONENT = re.compile(r"(^|/)(tests?|spec|specs|__tests__|e2e|testdata|fixtures)(/|$)")
_TEST_BASENAME = re.compile(r"(^|[._-])(test|tests|spec)([._-]|$)")


def is_test(path: str) -> bool:
    """True for test code, which couples to everything by design."""
    low = normalise(path).lower()
    return bool(_TEST_COMPONENT.search(low) or _TEST_BASENAME.search(posixpath.basename(low)))


def stem(path: str) -> str:
    """Basename without extension and without test/spec decoration."""
    base = posixpath.basename(normalise(path)).lower()
    base = base.split(".", 1)[0]
    return _TEST_BASENAME.sub(lambda m: m.group(1) or "", base).strip("._-")


def is_source(path: str) -> bool:
    return normalise(path).lower().endswith(_SOURCE_SUFFIXES)


def is_execution_surface(path: str) -> bool:
    low = normalise(path).lower()
    base = posixpath.basename(low)
    return any(marker in low or base == marker for marker in EXECUTION_SURFACE)


def is_dependency_manifest(path: str) -> bool:
    base = posixpath.basename(normalise(path)).lower()
    return base in DEPENDENCY_MANIFESTS


def is_lockfile(path: str) -> bool:
    return posixpath.basename(normalise(path)).lower() in LOCKFILES


def is_secret_material(path: str) -> bool:
    low = normalise(path).lower()
    base = posixpath.basename(low)
    return low.endswith(_CONFIG_SUFFIXES) or base.startswith(".env")


def is_security_relevant(path: str) -> bool:
    return bool(_SENSITIVE_TOKENS.search(normalise(path).lower()))


def sensitivity(path: str) -> float:
    """Score a path in [0, 1] by how much a silent change there would matter."""
    score = 0.0
    if is_execution_surface(path):
        score = max(score, 0.9)
    if is_dependency_manifest(path):
        score = max(score, 0.8)
    if is_secret_material(path):
        score = max(score, 1.0)
    if is_security_relevant(path):
        score = max(score, 0.7)
    if is_source(path):
        score = max(score, 0.3)
    return score


def label(path: str) -> str:
    if is_secret_material(path):
        return "secret-material"
    if is_execution_surface(path):
        return "execution-surface"
    if is_dependency_manifest(path):
        return "dependency-manifest"
    if is_security_relevant(path):
        return "security-relevant"
    if is_source(path):
        return "source"
    return "other"
