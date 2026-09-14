"""Shared test fixtures.

Nothing here touches a real user profile. Every input a test needs is constructed inside a
temporary directory, because the project rule is that real agent data never reaches the
repository, a fixture, a test or a log line.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    """An empty git repository with a deterministic identity.

    The identity is set locally rather than relying on the developer's global config, so
    the tests behave the same on a machine that has never configured git, such as a CI
    runner.
    """
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=tmp_path, check=True)
    for key, value in (
        ("user.name", "Test"),
        ("user.email", "test@example.org"),
        ("commit.gpgsign", "false"),
    ):
        subprocess.run(["git", "config", key, value], cwd=tmp_path, check=True)

    # The same ignore rules the real repository has. Without them `git add -A` would track
    # the denylist, and the guard under test would correctly refuse to run at all, which
    # would make every other assertion fail for the wrong reason.
    (tmp_path / ".gitignore").write_text(".opsec-denylist\n.opsec-allowlist\n", encoding="utf-8")
    return tmp_path
