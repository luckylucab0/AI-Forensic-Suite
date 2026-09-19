"""Tests for the generic text log reader.

A debug log is written whether or not the conversation was kept, so it outlives a deleted
transcript and is for several products the only artifact with a clock in it. The failures
that matter here are the two a log reader can have quietly: a line that never reaches the
case, and a time on an event that the line does not actually carry.
"""

from __future__ import annotations

from pathlib import Path

from agentforensics.catalog import load_catalogue
from agentforensics.model import UNINTERPRETED_MARK
from agentforensics.parsers import for_artifact
from agentforensics.parsers.base import ParseContext
from agentforensics.parsers.text_log import LOGS, MAX_LINES

CATALOG_DIR = Path(__file__).resolve().parents[2] / "catalog"
LOG = "claude_code.debug_logs"


def parse(path: Path, artifact: str = LOG) -> list:
    parser = for_artifact(artifact)
    assert parser is not None, artifact
    return list(
        parser.parse(
            ParseContext(
                bundle_uuid="b",
                original_path=f"/home/alice/.claude/logs/{path.name}",
                local_path=path,
                sha256="f" * 64,
                artifact_id=artifact,
                agent="claude_code",
                user="alice",
            )
        )
    )


def write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8", newline="")
    return path


def test_every_line_reaches_the_case_and_says_it_is_unread(tmp_path: Path) -> None:
    events = parse(
        write(
            tmp_path / "debug.log",
            "2026-09-07T12:00:00.123Z starting session\nno time on this line\n",
        )
    )
    assert [event.payload["text"] for event in events] == [
        "2026-09-07T12:00:00.123Z starting session",
        "no time on this line",
    ]
    assert all(UNINTERPRETED_MARK in (event.parse_problem or "") for event in events)
    assert [event.provenance.locator for event in events] == ["line:1", "line:2"]


def test_a_line_that_starts_with_a_time_is_dated_by_it(tmp_path: Path) -> None:
    events = parse(write(tmp_path / "debug.log", "2026-09-07T12:00:00.123Z connecting\n"))
    assert events[0].ts_utc == "2026-09-07T12:00:00.123000Z"
    assert events[0].ts_source == "the timestamp at the start of the line"


def test_the_other_spellings_are_read_too(tmp_path: Path) -> None:
    """The bracketed form and the one with a space and a comma, which is what one standard
    library writes by default. A reader that took only the ISO form would leave most of
    these files undated and an analyst would read that as logs without times."""
    events = parse(
        write(
            tmp_path / "debug.log",
            "[2026-09-07 12:00:00] one\n2026-09-07 12:00:01,500 two\n",
        )
    )
    assert [event.ts_utc for event in events] == [
        "2026-09-07T12:00:00.000000Z",
        "2026-09-07T12:00:01.500000Z",
    ]


def test_a_date_in_the_middle_of_a_line_is_not_read_as_its_time(tmp_path: Path) -> None:
    """A line that mentions a date is not a line that happened then, and a timeline built
    from the dates a log talks about is worse than one with gaps in it."""
    events = parse(write(tmp_path / "debug.log", "deleting sessions before 2026-01-01 00:00:00\n"))
    assert events[0].ts_utc is None
    assert events[0].ts_precision == "absent"


def test_a_continuation_line_is_its_own_undated_record(tmp_path: Path) -> None:
    """A stack trace belongs to the line above it in a way no reader can prove, so the
    lines are carried as they are rather than glued to a timestamp they do not have."""
    events = parse(
        write(
            tmp_path / "debug.log",
            "2026-09-07T12:00:00Z error while running the tool\n  at handler (index.js:12)\n",
        )
    )
    assert [event.ts_utc is None for event in events] == [False, True]
    assert events[1].payload["text"] == "  at handler (index.js:12)"


def test_a_blank_line_is_not_a_record(tmp_path: Path) -> None:
    events = parse(write(tmp_path / "debug.log", "one\n\n\ntwo\n"))
    assert len(events) == 2


def test_a_line_that_did_not_decode_is_kept_and_said_to_be_inexact(tmp_path: Path) -> None:
    path = tmp_path / "debug.log"
    path.write_bytes(b"ok line\nbroken \xff\xfe line\n")
    events = parse(path)
    assert len(events) == 2
    assert "did not decode" in (events[1].parse_problem or "")


def test_a_log_longer_than_the_limit_says_where_the_reading_stopped(tmp_path: Path) -> None:
    """The one thing a truncating reader must never do quietly. A report resting on a log
    that was read to the middle is the failure this project exists to avoid."""
    from agentforensics.parsers import text_log

    original = text_log.MAX_LINES
    text_log.MAX_LINES = 3
    try:
        events = parse(write(tmp_path / "debug.log", "".join(f"line {n}\n" for n in range(10))))
    finally:
        text_log.MAX_LINES = original
    assert len(events) == 4
    assert "not in the case" in (events[-1].parse_problem or "")
    assert events[-1].provenance.locator == "line:4"


def test_the_limit_is_high_enough_for_a_real_session() -> None:
    """A guard on the constant rather than on behaviour: lowering it to a number a long
    session exceeds would truncate real evidence and every test above would still pass."""
    assert MAX_LINES >= 100_000


def test_the_reader_claims_every_text_log_in_the_catalogue() -> None:
    catalogue = load_catalogue(CATALOG_DIR)
    logs = {
        a.id
        for a in catalogue.artifacts
        if a.category == "log" and a.format in ("text", "markdown")
    }
    assert logs == LOGS
