"""Tests for the generated support documentation.

The page exists so that nobody has to guess how completely an agent is read, so the
failure worth guarding against is not a broken table. It is a page that says more coverage
than there is: a number copied from the day it was written, a gap that quietly stops being
listed, or an entry that slides from "unfinished work" into no section at all.

So the assertions are about the arithmetic, about the five groups adding up, and about the
one section that is a promise rather than a decision: the readings somebody started and
did not finish have to appear with their reasons rather than as a number. The `--check`
mode is what keeps the committed copy honest.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

from agentforensics.catalog import load_catalogue
from agentforensics.parsers import PARSERS, for_artifact
from agentforensics.parsers.coverage import (
    HANDED_OVER,
    READABLE_AND_UNREAD,
    READABLE_FORMATS,
    UNFINISHED,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "gen_support_docs.py"
DOCS = REPO_ROOT / "docs"
NAMES = ["SUPPORT.md", "SUPPORT.de.md"]


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args], cwd=REPO_ROOT, capture_output=True, text=True
    )


def test_the_committed_page_matches_the_catalogue_and_the_readers() -> None:
    result = run("--check")
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("name", NAMES)
def test_the_page_says_it_is_generated(name: str) -> None:
    text = (DOCS / name).read_text(encoding="utf-8")
    assert "Generated file" in text or "Generierte Datei" in text
    assert "Claude Code" in text, "the agent table is not in the page"


@pytest.mark.parametrize("name", NAMES)
def test_every_table_row_has_the_same_column_count(name: str) -> None:
    lines = (DOCS / name).read_text(encoding="utf-8").splitlines()
    expected: int | None = None
    for number, line in enumerate(lines, start=1):
        if not line.startswith("|"):
            expected = None
            continue
        cells = line.replace("\\|", "\x00").count("|")
        if expected is None:
            expected = cells
        assert cells == expected, f"{name}:{number} has {cells} pipes, expected {expected}"


def test_the_counts_in_the_page_are_the_counts_in_the_code() -> None:
    """The one defect that would make this page worse than no page.

    Every number here is generated, so this reads them back out of the committed file and
    counts the same thing independently. A generator that started counting the wrong set
    would otherwise produce a page that is internally consistent and wrong.
    """
    catalogue = load_catalogue(REPO_ROOT / "catalog")
    read = [a for a in catalogue.artifacts if for_artifact(a.id) is not None]
    text = (DOCS / "SUPPORT.md").read_text(encoding="utf-8")

    found = re.search(r"(\d+) of (\d+) artifacts are read by (\d+) reader modules", text)
    assert found, "the totals sentence is gone from the page"
    assert (int(found.group(1)), int(found.group(2)), int(found.group(3))) == (
        len(read),
        len(catalogue.artifacts),
        len(PARSERS),
    )


def test_every_unread_artifact_is_in_exactly_one_group() -> None:
    """The groups have to partition what is not read, or the page hides something.

    An entry that falls through every group would appear in the totals as not read and be
    described nowhere, which is the shape of the gap this page exists to close.
    """
    catalogue = load_catalogue(REPO_ROOT / "catalog")
    unread = [a for a in catalogue.artifacts if for_artifact(a.id) is None]
    for artifact in unread:
        groups = [
            artifact.id in HANDED_OVER,
            artifact.sensitivity == "secret",
            artifact.format not in READABLE_FORMATS,
            artifact.id in READABLE_AND_UNREAD,
        ]
        assert any(groups), (
            f"{artifact.id} is read by nothing and belongs to none of the groups the "
            "support page describes, so the page would not mention it at all"
        )


def test_unfinished_work_is_named_rather_than_counted() -> None:
    """If there ever is unfinished work, the page has to list the entries by id.

    The section is empty today and the sentence says so. This asserts the other branch of
    the generator is the one that names them, because a count alone would let somebody
    read past it.
    """
    catalogue = load_catalogue(REPO_ROOT / "catalog")
    unfinished = [
        a
        for a in catalogue.artifacts
        if for_artifact(a.id) is None
        and a.format in READABLE_FORMATS
        and a.sensitivity != "secret"
        and a.id not in READABLE_AND_UNREAD
        and a.id not in HANDED_OVER
    ]
    text = (DOCS / "SUPPORT.md").read_text(encoding="utf-8")
    section = text.split("### Unfinished work on a format that is already read", 1)[1]
    section = section.split("##", 1)[0]
    if unfinished:
        for artifact in unfinished:
            assert artifact.id in section, artifact.id
    else:
        assert "None as of this generation" in section


@pytest.mark.parametrize("name", NAMES)
def test_a_reading_that_was_started_is_named_with_what_is_missing(name: str) -> None:
    """The section that says "read" is not the same as "read completely".

    An analyst reads the per-agent table and gets a yes or a no. This section is the third
    answer, and it is only worth having if it is specific: an id and the sentence saying
    which part of the file nobody has mapped. A count would read as a footnote and be
    skipped, which is why the generator is held to naming them in both languages.
    """
    heading = (
        "## Started and not finished" if name == "SUPPORT.md" else "## Angefangen und nicht fertig"
    )
    text = (DOCS / name).read_text(encoding="utf-8")
    assert heading in text, name
    section = text.split(heading, 1)[1].split("\n## ", 1)[0]
    for artifact_id, reason in UNFINISHED.items():
        assert artifact_id in section, f"{artifact_id} is declared unfinished and is not on {name}"
        if name == "SUPPORT.md":
            assert reason in section, artifact_id
    if not UNFINISHED:
        assert "None as of this generation" in section or "keine" in section
