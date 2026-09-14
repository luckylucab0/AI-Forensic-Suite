"""Tests for the generated artifact documentation.

The generator's contract is narrow and worth pinning: the committed files must match the
catalogue, regeneration must be idempotent, and the Markdown must not be broken by free
text from the catalogue. That last one is the interesting case, because an unescaped pipe
in a note silently shifts every later cell of that row under the wrong heading, which in a
forensic reference is a wrong answer rather than a cosmetic defect.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "gen_artifact_docs.py"
DOCS = REPO_ROOT / "docs"


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )


def test_committed_docs_match_the_catalogue() -> None:
    result = run("--check")
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("name", ["ARTIFACTS.md", "ARTIFACTS.de.md"])
def test_generated_files_exist_and_say_they_are_generated(name: str) -> None:
    text = (DOCS / name).read_text(encoding="utf-8")
    assert "Generated file. Do not edit." in text
    assert "claude_code." in text


@pytest.mark.parametrize("name", ["ARTIFACTS.md", "ARTIFACTS.de.md"])
def test_every_table_row_has_the_same_column_count(name: str) -> None:
    """Catches an unescaped pipe from a catalogue note."""
    lines = (DOCS / name).read_text(encoding="utf-8").splitlines()
    expected: int | None = None
    for i, line in enumerate(lines, start=1):
        if not line.startswith("|"):
            expected = None
            continue
        # Count real separators, ignoring escaped ones.
        cells = line.replace("\\|", "\x00").count("|")
        if expected is None:
            expected = cells
        assert cells == expected, f"{name}:{i} has {cells} pipes, expected {expected}"


@pytest.mark.parametrize("name", ["ARTIFACTS.md", "ARTIFACTS.de.md"])
def test_language_switcher_points_at_the_other_language(name: str) -> None:
    text = (DOCS / name).read_text(encoding="utf-8")
    other = "ARTIFACTS.md" if name.endswith(".de.md") else "ARTIFACTS.de.md"
    assert other in text.splitlines()[2]


def test_unverified_entries_are_marked_in_the_output() -> None:
    """An analyst reading the reference must be able to see which paths are not confirmed."""
    text = (DOCS / "ARTIFACTS.md").read_text(encoding="utf-8")
    assert "**unverified**" in text
    assert "inconclusive" in text


def test_priority_groups_are_ordered_most_volatile_first() -> None:
    """Within each agent, the groups run from what vanishes first to what lasts.

    The check is per agent rather than over the whole document: with many agents the
    sections repeat, so a global index comparison would compare one agent's durable group
    against a later agent's live_only group and fail for no reason.
    """
    text = (DOCS / "ARTIFACTS.md").read_text(encoding="utf-8")
    sections = text.split("\n## ")[1:]
    assert sections, "the document should contain at least one agent section"
    expected = ["live_only", "first", "normal", "durable"]
    for section in sections:
        agent = section.splitlines()[0]
        seen = [
            line[len("### ") :].strip()
            for line in section.splitlines()
            if line.startswith("### ") and line[len("### ") :].strip() in expected
        ]
        assert seen == [p for p in expected if p in seen], agent
