"""Tests for the OpSec guard.

A guard nobody tested is worse than no guard, because it produces a false sense of
safety: the failure mode is that it silently finds nothing and everyone believes the
repository is clean. So every path is exercised, including the ones that are supposed to
pass quietly.

The denied strings used here are obvious placeholders. Real ones are never committed, which
is the whole point of the mechanism under test.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "opsec_check.py"

EXIT_CLEAN = 0
EXIT_HIT = 1
EXIT_ERROR = 2

DENIED = "acme-internal-codename"


def run(cwd: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=cwd,
        capture_output=True,
        text=True,
    )


def write_denylist(repo: Path, *terms: str, name: str = ".opsec-denylist") -> Path:
    path = repo / name
    path.write_text(
        "# a comment that must be ignored\n\n" + "\n".join(terms) + "\n", encoding="utf-8"
    )
    return path


def commit(repo: Path, message: str = "initial") -> None:
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "commit", "-q", "-m", message],
        cwd=repo,
        check=True,
    )


def test_missing_denylist_passes_quietly(git_repo: Path) -> None:
    """A fresh clone and a CI run without the secret both look like this.

    Failing here would teach contributors to bypass the hook, which costs more than it
    buys.
    """
    (git_repo / "a.txt").write_text("harmless\n", encoding="utf-8")
    commit(git_repo)
    result = run(git_repo, "--mode", "both")
    assert result.returncode == EXIT_CLEAN
    assert "skipped" in result.stderr


def test_missing_denylist_can_be_required(git_repo: Path) -> None:
    result = run(git_repo, "--mode", "both", "--require-denylist")
    assert result.returncode == EXIT_ERROR


def test_clean_repository_passes(git_repo: Path) -> None:
    write_denylist(git_repo, DENIED)
    (git_repo / "a.txt").write_text("nothing to see\n", encoding="utf-8")
    commit(git_repo)
    result = run(git_repo, "--mode", "both")
    assert result.returncode == EXIT_CLEAN
    assert "clean" in result.stderr


def test_hit_in_tracked_file(git_repo: Path) -> None:
    write_denylist(git_repo, DENIED)
    (git_repo / "notes.md").write_text(f"see {DENIED} for details\n", encoding="utf-8")
    commit(git_repo)
    result = run(git_repo, "--mode", "tracked")
    assert result.returncode == EXIT_HIT
    assert "notes.md:1" in result.stderr


def test_hit_is_case_insensitive(git_repo: Path) -> None:
    write_denylist(git_repo, DENIED)
    (git_repo / "notes.md").write_text(DENIED.upper() + "\n", encoding="utf-8")
    commit(git_repo)
    assert run(git_repo, "--mode", "tracked").returncode == EXIT_HIT


def test_the_matched_string_is_never_printed(git_repo: Path) -> None:
    """The output of this check ends up in terminals, CI logs and screenshots.

    Printing the secret to prove the secret was found would defeat the purpose.
    """
    write_denylist(git_repo, DENIED)
    (git_repo / "notes.md").write_text(DENIED + "\n", encoding="utf-8")
    commit(git_repo)
    result = run(git_repo, "--mode", "tracked")
    assert result.returncode == EXIT_HIT
    assert DENIED not in result.stdout
    assert DENIED not in result.stderr
    assert "denylist entry #" in result.stderr


def test_hit_only_in_staged_content(git_repo: Path) -> None:
    """The working tree can be clean while the index is not, for example after an edit
    that was staged and then reverted on disk."""
    write_denylist(git_repo, DENIED)
    target = git_repo / "notes.md"
    target.write_text(DENIED + "\n", encoding="utf-8")
    subprocess.run(["git", "add", "notes.md"], cwd=git_repo, check=True)
    target.write_text("clean again\n", encoding="utf-8")

    assert run(git_repo, "--mode", "tracked").returncode == EXIT_CLEAN
    assert run(git_repo, "--mode", "staged").returncode == EXIT_HIT


def test_hit_in_commit_message(git_repo: Path) -> None:
    write_denylist(git_repo, DENIED)
    (git_repo / "a.txt").write_text("fine\n", encoding="utf-8")
    commit(git_repo)
    msg = git_repo / "msg.txt"
    msg.write_text(f"fix: adjust the {DENIED} handling\n", encoding="utf-8")
    result = run(git_repo, "--mode", "none", "--commit-msg", str(msg))
    assert result.returncode == EXIT_HIT
    assert "commit-msg:1" in result.stderr


def test_tracked_denylist_is_a_hard_error(git_repo: Path) -> None:
    """A committed denylist publishes exactly what it protects, so the check refuses to
    run at all rather than reporting a clean result."""
    write_denylist(git_repo, DENIED)
    subprocess.run(["git", "add", "-f", ".opsec-denylist"], cwd=git_repo, check=True)
    commit(git_repo)
    result = run(git_repo, "--mode", "tracked")
    assert result.returncode == EXIT_ERROR
    assert "must never be committed" in result.stderr


def test_allow_line_marker(git_repo: Path) -> None:
    write_denylist(git_repo, DENIED)
    (git_repo / "t.py").write_text(
        f'SAMPLE = "{DENIED}"  # opsec-check: allow-line\n', encoding="utf-8"
    )
    commit(git_repo)
    assert run(git_repo, "--mode", "tracked").returncode == EXIT_CLEAN


def test_allowlist_path(git_repo: Path) -> None:
    write_denylist(git_repo, DENIED)
    (git_repo / ".opsec-allowlist").write_text("fixtures/*\n", encoding="utf-8")
    (git_repo / "fixtures").mkdir()
    (git_repo / "fixtures" / "sample.txt").write_text(DENIED + "\n", encoding="utf-8")
    commit(git_repo)
    assert run(git_repo, "--mode", "tracked").returncode == EXIT_CLEAN


def test_binary_file_is_reported_as_skipped_not_ignored(git_repo: Path) -> None:
    """Skipping silently is how a check starts lying about its coverage."""
    write_denylist(git_repo, DENIED)
    (git_repo / "blob.bin").write_bytes(b"\x00\x01\x02" + DENIED.encode())
    commit(git_repo)
    result = run(git_repo, "--mode", "tracked")
    assert result.returncode == EXIT_CLEAN
    assert "skipped" in result.stderr
    assert "binary" in result.stderr


def test_oversized_file_is_reported_as_skipped(git_repo: Path) -> None:
    write_denylist(git_repo, DENIED)
    (git_repo / "big.txt").write_text("a" * 4096, encoding="utf-8")
    commit(git_repo)
    result = run(git_repo, "--mode", "tracked", "--max-bytes", "1024")
    assert result.returncode == EXIT_CLEAN
    assert "larger than" in result.stderr


def test_comments_and_blank_lines_in_the_denylist_are_ignored(git_repo: Path) -> None:
    (git_repo / ".opsec-denylist").write_text("# only a comment\n\n", encoding="utf-8")
    (git_repo / "a.txt").write_text("# only a comment\n", encoding="utf-8")
    commit(git_repo)
    result = run(git_repo, "--mode", "tracked")
    assert result.returncode == EXIT_CLEAN
    assert "no entries" in result.stderr


def test_outside_a_git_repository(tmp_path: Path) -> None:
    write_denylist(tmp_path, DENIED)
    result = run(tmp_path, "--mode", "tracked")
    assert result.returncode == EXIT_ERROR


@pytest.mark.parametrize("mode", ["tracked", "staged", "both", "none"])
def test_every_mode_is_accepted(git_repo: Path, mode: str) -> None:
    write_denylist(git_repo, DENIED)
    (git_repo / "a.txt").write_text("fine\n", encoding="utf-8")
    commit(git_repo)
    assert run(git_repo, "--mode", mode).returncode == EXIT_CLEAN
