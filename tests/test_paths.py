from __future__ import annotations

import pytest

from graphsec import paths


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("./src/a.py", "src/a.py"),
        (".github/workflows/ci.yml", ".github/workflows/ci.yml"),
        ("src\\win\\a.py", "src/win/a.py"),
        ("src/./b/../a.py", "src/a.py"),
    ],
)
def test_normalise(raw, expected):
    assert paths.normalise(raw) == expected


@pytest.mark.parametrize(
    "path,expected",
    [
        (".github/workflows/ci.yml", "execution-surface"),
        ("Dockerfile", "execution-surface"),
        ("requirements.txt", "dependency-manifest"),
        (".env", "secret-material"),
        ("certs/server.pem", "secret-material"),
        ("src/auth/session.py", "security-relevant"),
        ("src/api/routes.py", "source"),
        ("docs/guide.md", "other"),
    ],
)
def test_label(path, expected):
    assert paths.label(path) == expected


def test_sensitivity_ordering():
    assert paths.sensitivity(".env") > paths.sensitivity(".github/workflows/ci.yml")
    assert paths.sensitivity(".github/workflows/ci.yml") > paths.sensitivity("src/a.py")
    assert paths.sensitivity("docs/guide.md") == 0.0


@pytest.mark.parametrize(
    "path,expected",
    [
        ("tests/test_a.py", True),
        ("src/__tests__/widget.spec.ts", True),
        ("pkg/widget_test.go", True),
        ("src/app/testing_utils.py", False),
        ("src/api/routes.py", False),
    ],
)
def test_is_test(path, expected):
    assert paths.is_test(path) is expected


@pytest.mark.parametrize(
    "path,expected",
    [
        ("tests/test_widget.py", "widget"),
        ("src/Widget.tsx", "widget"),
        ("src/widget.test.ts", "widget"),
        ("pkg/widget_test.go", "widget"),
    ],
)
def test_stem_strips_test_decoration(path, expected):
    assert paths.stem(path) == expected


def test_directory():
    assert paths.directory("src/a/b.py") == "src/a"
    assert paths.directory("README.md") == "."
