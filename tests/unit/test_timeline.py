"""Tests for the timeline export.

A timeline is the view an analyst reads first and questions least, so these are mostly
about what it must not imply: that an undated event did not happen, that two events in the
same second are ordered, or that the sequence is of what happened rather than of what was
collected.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

import pytest

from agentforensics.model import BundleRecord, Case, Event, Provenance, unparsed
from agentforensics.timeline import COLUMNS, FORMATS, Filters, header_notes, write


def event(kind: str, ts: str | None, locator: str, **fields: object) -> Event:
    return Event(
        kind=kind,
        provenance=Provenance(
            "b1", "/home/alice/.claude/p/s.jsonl", "aa", "claude_code.transcripts", locator
        ),
        agent=fields.pop("agent", "claude_code"),  # type: ignore[arg-type]
        raw={"line": locator},
        ts_utc=ts,
        ts_precision="second" if ts else "absent",
        ts_source="timestamp" if ts else None,
        **fields,  # type: ignore[arg-type]
    )


@pytest.fixture
def case(tmp_path: Path) -> Case:
    opened = Case.open(tmp_path / "case.sqlite")
    with opened.transaction():
        opened.add_bundle(BundleRecord("b1", "native", "/tmp/b"))
        opened.add_events(
            [
                event("user.prompt", "2026-09-05T08:00:02Z", "line:2", payload={"text": "second"}),
                event("user.prompt", "2026-09-05T08:00:01Z", "line:1", payload={"text": "first"}),
                event("assistant.text", None, "line:3", payload={"text": "no clock"}),
                event(
                    "command.exec",
                    "2026-09-05T08:00:03Z",
                    "line:4",
                    payload={"commands": [{"command": "rm -rf /tmp/x"}]},
                    agent="codex",
                ),
                unparsed(
                    Provenance(
                        "b1",
                        "/home/alice/.claude/p/s.jsonl",
                        "aa",
                        "claude_code.transcripts",
                        "line:5",
                    ),
                    "claude_code",
                    "{trunca",
                    "not valid JSON",
                ),
            ]
        )
    return opened


def read_csv(case: Case, filters: Filters | None = None) -> list[dict[str, str]]:
    buffer = io.StringIO()
    write(case, buffer, "csv", filters)
    buffer.seek(0)
    return list(csv.DictReader(buffer))


def test_an_undated_event_is_first_not_missing(case: Case) -> None:
    """Its position is unknown, not early.

    Omitting it would make it invisible in the one view an analyst reads first, which for
    an artifact with no internal timestamps is every event it has.
    """
    rows = read_csv(case)
    assert rows[0]["ts_utc"] == ""
    assert {row["ts_utc"] for row in rows[2:]} == {
        "2026-09-05T08:00:01Z",
        "2026-09-05T08:00:02Z",
        "2026-09-05T08:00:03Z",
    }
    assert len(rows) == 5, "nothing is dropped"


def test_the_dated_events_are_in_order(case: Case) -> None:
    dated = [row["ts_utc"] for row in read_csv(case) if row["ts_utc"]]
    assert dated == sorted(dated)


def test_every_row_carries_its_precision_and_source(case: Case) -> None:
    """Two events in the same second cannot be ordered against each other, and a timeline
    that presented them as ordered would invite a conclusion the evidence does not support."""
    for row in read_csv(case):
        assert row["ts_precision"] in ("second", "absent", "exact", "minute", "filesystem")
        if row["ts_utc"]:
            assert row["ts_source"], row


def test_every_row_carries_its_provenance(case: Case) -> None:
    """A timeline row that cannot be traced back to a file and a line is an assertion."""
    for row in read_csv(case):
        assert row["original_path"]
        assert row["file_sha256"]
        assert row["locator"]
        assert row["event_id"]


def test_an_unreadable_record_appears_as_a_row(case: Case) -> None:
    rows = [row for row in read_csv(case) if row["kind"] == "unparsed.record"]
    assert len(rows) == 1
    assert "not valid JSON" in rows[0]["summary"]


def test_the_summary_is_not_truncated(case: Case) -> None:
    """A prompt cut off at eighty characters is how a timeline hides the half that mattered."""
    long = "x" * 500
    with case.transaction():
        case.add_events(
            [event("user.prompt", "2026-09-05T09:00:00Z", "line:9", payload={"text": long})]
        )
    assert any(row["summary"] == long for row in read_csv(case))


def test_a_command_becomes_readable_in_the_summary(case: Case) -> None:
    assert any(row["summary"] == "rm -rf /tmp/x" for row in read_csv(case))


def test_filters_narrow_without_dropping_undated_events(case: Case) -> None:
    """Excluding them from a time-bounded query would turn "what happened that week" into
    "what happened that week, minus whatever had no clock"."""
    rows = read_csv(case, Filters(since="2026-09-05T08:00:02Z"))
    assert "" in {row["ts_utc"] for row in rows}
    assert "2026-09-05T08:00:01Z" not in {row["ts_utc"] for row in rows}


def test_filtering_by_agent_and_kind(case: Case) -> None:
    assert {row["agent"] for row in read_csv(case, Filters(agents=("codex",)))} == {"codex"}
    assert {row["kind"] for row in read_csv(case, Filters(kinds=("user.prompt",)))} == {
        "user.prompt"
    }


def test_a_filter_value_that_looks_like_a_column_name_is_still_a_value(case: Case) -> None:
    """The first version built the where clause with string replacement, which works until
    a value happens to contain a column name."""
    assert read_csv(case, Filters(agents=("agent",))) == []
    assert read_csv(case, Filters(session_id="ts_utc")) == []


def test_the_csv_columns_are_the_declared_ones(case: Case) -> None:
    buffer = io.StringIO()
    write(case, buffer, "csv")
    assert buffer.getvalue().splitlines()[0] == ",".join(COLUMNS)


def test_the_jsonl_export_carries_the_original_record(case: Case) -> None:
    """This format is read by tools, and a tool that has the original does not have to
    trust the mapping."""
    buffer = io.StringIO()
    write(case, buffer, "jsonl")
    records = [json.loads(line) for line in buffer.getvalue().splitlines()]
    assert all("raw" in record for record in records)


def test_timesketch_omits_undated_events_and_says_so(case: Case) -> None:
    """The format requires a datetime, and inventing one would put a wrong time in front
    of a reader, which is worse than an honest gap."""
    buffer = io.StringIO()
    written, undated = write(case, buffer, "timesketch")
    # Two of the five have no timestamp: the assistant turn whose record carried none, and
    # the unreadable line, which by definition has nothing to read a time out of.
    assert undated == 2
    assert written == 3
    records = [json.loads(line) for line in buffer.getvalue().splitlines()]
    assert all(record["datetime"] for record in records)
    assert all("timestamp_desc" in record for record in records)
    notes = " ".join(header_notes(case, written, undated, "timesketch"))
    assert "NOT in this file" in notes


def test_the_notes_qualify_the_timeline(case: Case) -> None:
    """They travel with the export rather than living in another command's output."""
    notes = " ".join(header_notes(case, 5, 1, "csv"))
    assert "no timestamp" in notes
    assert "could not be parsed" in notes


def test_two_exports_produce_identical_bytes(case: Case) -> None:
    """A timeline gets hashed, attached to a report and diffed against another run."""
    first, second = io.StringIO(), io.StringIO()
    write(case, first, "csv")
    write(case, second, "csv")
    assert first.getvalue() == second.getvalue()


def test_an_unknown_format_is_refused(case: Case) -> None:
    with pytest.raises(ValueError, match="unknown timeline format"):
        write(case, io.StringIO(), "xlsx")


def test_every_declared_format_writes_something(case: Case) -> None:
    for fmt in FORMATS:
        buffer = io.StringIO()
        written, _ = write(case, buffer, fmt)
        assert written > 0, fmt
        assert buffer.getvalue(), fmt
