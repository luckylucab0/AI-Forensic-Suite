"""Shared test fixtures, and the switch that reproduces Windows here.

Nothing here touches a real user profile. Every input a test needs is constructed inside a
temporary directory, because the project rule is that real agent data never reaches the
repository, a fixture, a test or a log line.

`--windows-newlines` exists because three Windows-only defects reached CI in three
consecutive commits and each was found by the one runner nobody watches. One of the three
was this: `Path.write_text` opens in text mode, so on Windows a "\n" in a fixture becomes
CRLF on disk, and a test that compares bytes or text exactly then fails there while passing
on five other runners. The option makes every text-mode write in the suite behave the way
Windows behaves, so that failure happens locally, in seconds, instead of eight minutes into
a CI run. A test that passes both ways does not depend on the platform's newline
translation, which is the property worth having.

It patches `Path.write_text` only, and only when the caller did not say what it wanted:
a call that passes `newline=` explicitly has already made the decision and is left alone.
"""

from __future__ import annotations

import subprocess
from collections.abc import Iterator
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


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--windows-newlines",
        action="store_true",
        help="write text-mode fixtures the way Windows does, to reproduce a "
        "platform-dependent expectation on any machine",
    )


@pytest.fixture(autouse=True, scope="session")
def _windows_newlines(request: pytest.FixtureRequest) -> Iterator[None]:
    """Make Path.write_text translate newlines, as it does on Windows."""
    if not request.config.getoption("--windows-newlines"):
        yield
        return

    original = Path.write_text

    def translating(
        self: Path,
        data: str,
        encoding: str | None = None,
        errors: str | None = None,
        newline: str | None = None,
    ) -> int:
        # newline="\r\n" is what a Windows text-mode write does to every "\n". A caller
        # that passed newline itself gets exactly what it asked for, on every platform,
        # which is the whole point of passing it.
        return original(self, data, encoding, errors, newline if newline is not None else "\r\n")

    Path.write_text = translating  # type: ignore[method-assign]
    try:
        yield
    finally:
        Path.write_text = original  # type: ignore[method-assign]
