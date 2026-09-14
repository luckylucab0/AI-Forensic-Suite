"""Tests for the bilingual documentation drift guard.

The guard's value is entirely in its ability to fail at the right moment, so that is what
is tested: an English edit with no corresponding confirmation must break the build.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "check_translations.py"
REPO_ROOT = Path(__file__).resolve().parents[2]


def run(cwd: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=cwd,
        capture_output=True,
        text=True,
    )


def setup_pair(repo: Path, english: str = "# Title\n\nHello.\n") -> None:
    (repo / "docs").mkdir(exist_ok=True)
    (repo / "GUIDE.md").write_text(english, encoding="utf-8")
    (repo / "GUIDE.de.md").write_text("# Titel\n\nHallo.\n", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)


def test_repository_itself_is_current() -> None:
    assert run(REPO_ROOT, "--check").returncode == 0


def test_update_then_check_passes(git_repo: Path) -> None:
    setup_pair(git_repo)
    assert run(git_repo, "--update").returncode == 0
    assert run(git_repo, "--check").returncode == 0


def test_english_edit_without_confirmation_fails(git_repo: Path) -> None:
    setup_pair(git_repo)
    assert run(git_repo, "--update").returncode == 0
    (git_repo / "GUIDE.md").write_text("# Title\n\nHello, and something new.\n", encoding="utf-8")
    result = run(git_repo, "--check")
    assert result.returncode == 1
    assert "GUIDE.md changed" in result.stderr
    assert "GUIDE.de.md" in result.stderr


def test_missing_german_sibling_fails(git_repo: Path) -> None:
    (git_repo / "ALONE.md").write_text("# Alone\n", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=git_repo, check=True)
    result = run(git_repo, "--check")
    assert result.returncode == 1
    assert "no German sibling" in result.stderr


def test_missing_german_sibling_can_be_allowed(git_repo: Path) -> None:
    setup_pair(git_repo)
    (git_repo / "ALONE.md").write_text("# Alone\n", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=git_repo, check=True)
    assert run(git_repo, "--update").returncode == 0
    assert run(git_repo, "--check", "--allow-untranslated").returncode == 0


def test_untracked_documents_are_ignored(git_repo: Path) -> None:
    """A local, gitignored note is nobody's translation obligation."""
    setup_pair(git_repo)
    assert run(git_repo, "--update").returncode == 0
    (git_repo / "PRIVATE.md").write_text("# Local only\n", encoding="utf-8")
    assert run(git_repo, "--check").returncode == 0
