"""Tests for the reading of last resort for a line-delimited log.

What is being asserted here is mostly a negative: that this parser does not decide what a
record means. The positive half is one property, and it is the reason the module exists. A
log nobody has mapped used to reach a case as a file name with nothing behind it, while the
endpoint query returned every record of the same file. A case that shows nothing is read by
an analyst as a file that held nothing.

So: every record comes back, only the fields a record plainly names are read out of it, and
every event says it has not been interpreted.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentforensics.catalog import load_catalogue
from agentforensics.model import BundleRecord, Case
from agentforensics.parsers import PARSERS, for_artifact
from agentforensics.parsers.base import ParseContext
from agentforensics.parsers.jsonl_generic import (
    LOGS,
    PROJECT_FIELDS,
    SESSION_FIELDS,
    TEXT_FIELDS,
    TIME_FIELDS,
)

CATALOG_DIR = Path(__file__).resolve().parents[2] / "catalog"

# One of the logs with no verified mapping, used wherever the test is about the reading
# rather than about which artifact it was. Chosen because its format is the ordinary one: a
# transcript of an agent this suite has never read against a vendor source.
ARTIFACT = "windsurf.cascade_transcripts"


def write(path: Path, *records: object) -> Path:
    lines = [r if isinstance(r, str) else json.dumps(r) for r in records]
    # newline="" so the file holds the bytes this test says it does, on every platform.
    path.write_text("".join(f"{line}\n" for line in lines), encoding="utf-8", newline="")
    return path


def parse(path: Path, artifact: str = ARTIFACT, agent: str = "windsurf") -> list:
    parser = for_artifact(artifact)
    assert parser is not None, artifact
    return list(
        parser.parse(
            ParseContext(
                bundle_uuid="b",
                original_path=f"/home/alice/{path.name}",
                local_path=path,
                sha256="f" * 64,
                artifact_id=artifact,
                agent=agent,
                user="alice",
            )
        )
    )


# ------------------------------------------------------------- the reason it exists


def test_every_record_of_an_unmapped_log_reaches_the_case(tmp_path: Path) -> None:
    """The defect this module closes, asserted at its plainest.

    Before it, this file produced one `artifact.fs` event saying it existed, while the
    generated endpoint query returned all three of its records. An analyst comparing a fleet
    hunt against the case built from a collection of the same endpoint would have found the
    conversation in one and a file name in the other.
    """
    path = write(
        tmp_path / "cascade.jsonl",
        {"role": "user", "text": "why is the build red"},
        {"role": "assistant", "text": "the lockfile is stale"},
        {"role": "user", "text": "fix it"},
    )

    events = parse(path)

    assert len(events) == 3
    assert [event.kind for event in events] == ["unparsed.record"] * 3
    assert [event.provenance.locator for event in events] == ["line:1", "line:2", "line:3"]


def test_the_record_is_in_raw_whole(tmp_path: Path) -> None:
    """Everything this parser does not read is still in the case.

    That is the whole bargain: the reading is thin because nobody has verified the format,
    and it costs nothing because the record itself is carried.
    """
    record = {"kind": "tool", "detail": {"argv": ["rm", "-rf", "build"]}, "n": 7}
    path = write(tmp_path / "cascade.jsonl", record)

    assert parse(path)[0].raw == record


def test_every_event_says_it_has_not_been_interpreted(tmp_path: Path) -> None:
    """Without it, a thin reading looks like a complete one.

    A record showing a timestamp and nothing else reads as a record that contained a
    timestamp and nothing else, which for most of these logs is the opposite of the truth.
    """
    path = write(tmp_path / "cascade.jsonl", {"timestamp": "2026-09-05T08:00:00Z"})

    problem = parse(path)[0].parse_problem or ""

    assert "no verified mapping" in problem
    assert "in raw" in problem
    assert "once a parser for it exists" in problem


# --------------------------------------------------------------- only what it says


def test_a_field_named_as_a_time_is_read_and_the_event_names_it(tmp_path: Path) -> None:
    """A name is the only evidence there is here, so the event carries the name.

    A case has to be able to tell a time this suite verified to be the agent's own clock
    from one that was picked up because a field happened to be called `ts`.
    """
    path = write(tmp_path / "cascade.jsonl", {"ts": "2026-09-05T08:00:00Z", "text": "hello"})

    event = parse(path)[0]

    assert event.ts_utc == "2026-09-05T08:00:00.000000Z"
    assert event.ts_source == "the field named ts"


def test_epoch_milliseconds_are_read_as_such_and_the_event_says_so(tmp_path: Path) -> None:
    """The analyzer is more precise about the same field than the endpoint query, which
    calls every time it finds a second. The reading it made is on the event, so a wrong one
    is visible rather than silent."""
    path = write(tmp_path / "cascade.jsonl", {"createdAt": 1788000000000})

    event = parse(path)[0]

    assert event.ts_utc is not None
    assert event.ts_precision == "second"
    assert "epoch milliseconds" in (event.parse_problem or "")
    assert "no verified mapping" in (event.parse_problem or "")


def test_a_field_that_is_not_a_time_leaves_the_event_undated(tmp_path: Path) -> None:
    """An unreadable value under a time-like name is a gap, and a gap is shown as one.

    Filing it under the ingest time or under zero would put an event on the timeline at a
    moment nothing happened, which is the one thing worse than an undated event.
    """
    path = write(tmp_path / "cascade.jsonl", {"time": "just now"})

    event = parse(path)[0]

    assert event.ts_utc is None
    assert event.ts_precision == "absent"
    assert "unrecognised timestamp format" in (event.parse_problem or "")


def test_text_is_carried_where_the_record_holds_text(tmp_path: Path) -> None:
    """A string under a field named as text is text, in both producers of this format."""
    path = write(tmp_path / "cascade.jsonl", {"content": "delete the old migrations"})

    assert parse(path)[0].payload["text"] == "delete the old migrations"


def test_typed_blocks_nobody_has_mapped_are_not_flattened_into_text(tmp_path: Path) -> None:
    """The line between reading and guessing, on the field most likely to be quoted.

    A content list whose blocks each carry text is text. A list of blocks of some type this
    suite has never read is not, and rendering it would put a string into the field an
    analyst quotes in a report. It stays in raw, so nothing is lost either way.
    """
    mapped = write(tmp_path / "a.jsonl", {"content": [{"text": "one"}, {"text": " two"}]})
    unmapped = write(tmp_path / "b.jsonl", {"content": [{"type": "redacted_thinking"}]})

    assert parse(mapped)[0].payload["text"] == "one two"
    assert parse(unmapped)[0].payload == {}
    assert parse(unmapped)[0].raw == {"content": [{"type": "redacted_thinking"}]}


def test_a_session_and_a_project_are_read_only_where_they_are_plain(tmp_path: Path) -> None:
    """These two are columns a case groups by, so a rendered object in one of them would
    show up as a conversation or a working copy that never existed."""
    plain = write(tmp_path / "a.jsonl", {"sessionId": "s-1", "cwd": "/home/alice/src/app"})
    structured = write(tmp_path / "b.jsonl", {"sessionId": {"id": "s-1"}, "cwd": ["/tmp"]})

    assert parse(plain)[0].session_id == "s-1"
    assert parse(plain)[0].project_path == "/home/alice/src/app"
    assert parse(structured)[0].session_id is None
    assert parse(structured)[0].project_path is None


def test_nothing_else_in_the_record_becomes_a_field(tmp_path: Path) -> None:
    """A name this parser does not read is a name nobody has verified.

    `user` here is the agent's own field and not the account the collection ran as, and the
    two are different questions. Reading it would attribute a record to whoever the log
    happened to call a user.
    """
    path = write(
        tmp_path / "cascade.jsonl",
        {"user": "bob", "branch": "main", "model": "some-model", "workspaceId": "w-9"},
    )

    event = parse(path)[0]

    assert event.user == "alice", "the account the collection ran as, not the record's field"
    assert event.git_branch is None
    assert event.payload == {}


# ------------------------------------------------------------------ the bad lines


def test_a_line_that_is_not_json_is_kept_with_the_reason(tmp_path: Path) -> None:
    """A half-written line is the shape a killed process leaves, and it is evidence."""
    path = write(tmp_path / "cascade.jsonl", {"text": "fine"}, '{"text": "cut off', {"text": "ok"})

    events = parse(path)

    assert len(events) == 3
    assert events[1].raw == '{"text": "cut off'
    assert "not valid JSON" in (events[1].parse_problem or "")


def test_a_line_that_is_not_an_object_is_kept_too(tmp_path: Path) -> None:
    """Every format in this suite writes one object per line, so a bare value is a surprise
    worth showing rather than a line to pass over."""
    path = write(tmp_path / "cascade.jsonl", "[1, 2, 3]")

    event = parse(path)[0]

    assert event.raw == "[1, 2, 3]"
    assert "where an object was expected" in (event.parse_problem or "")


def test_an_empty_log_produces_nothing_rather_than_failing(tmp_path: Path) -> None:
    """An agent that was installed and never used leaves this file empty. The file's own
    existence is already in the case as an artifact.fs event."""
    assert parse(write(tmp_path / "cascade.jsonl")) == []


# --------------------------------------------- the catalogue staying in step


def test_the_parser_claims_every_line_delimited_artifact_in_the_catalogue() -> None:
    """The omission no other test would catch.

    An unclaimed log is collected, passes ingest as unsupported, and produces a case where
    nothing looks wrong. So the committed set is compared against the catalogue itself:
    adding a log there fails here until somebody decides how it is read.
    """
    catalogue = load_catalogue(CATALOG_DIR)
    in_catalogue = {
        artifact.id
        for agent in catalogue.agents
        for artifact in agent.artifacts
        if artifact.format == "jsonl"
    }

    assert in_catalogue == LOGS


@pytest.mark.parametrize("artifact_id", sorted(LOGS))
def test_every_claimed_log_is_read_by_something(artifact_id: str) -> None:
    """Either by this parser or by one with a verified mapping placed ahead of it.

    The set does not shrink when one is taken over, which is the point: this parser goes on
    claiming every line-delimited artifact, so the drift test above keeps working, while a
    verified parser decides what a record means. What must never happen is a log that
    neither reads.
    """
    parser = for_artifact(artifact_id)
    assert parser is not None
    if parser.name != "jsonl_generic":
        generic = next(p for p in PARSERS if p.name == "jsonl_generic")
        assert generic.handles(artifact_id), (
            f"{artifact_id} was taken over by {parser.name} and dropped out of the generic "
            "reader's set, so adding a log to the catalogue would stop failing here"
        )


def test_the_fields_read_here_are_the_ones_the_endpoint_query_reads() -> None:
    """The two producers of this format have to agree about an unmapped record.

    They are allowed to differ in how much they say about a value, and they do: the query
    calls every time it finds a second and this parser works out the unit. What they may not
    differ about is which field is the timestamp, because then a fleet hunt and the case
    built from the same endpoint would date one record two ways and an analyst would have no
    way to tell which was right.
    """
    from agentforensics.exporters import velociraptor_unified as unified

    block = "\n".join(unified._generic())

    for name in TIME_FIELDS + SESSION_FIELDS + PROJECT_FIELDS + TEXT_FIELDS:
        assert f"Rec.{name}" in block, name


def test_a_case_counts_these_apart_from_the_records_nothing_could_read(tmp_path: Path) -> None:
    """The end of the chain, and the reason the events say what they say.

    Both populations are `unparsed.record`, and a case that reported one number would call
    a log of intact records unreadable. That matters as soon as a case holds a store nobody
    has a schema for: the handful of genuinely broken lines, which is what an analyst has
    to look at before quoting anything, disappears among rows that are perfectly fine and
    merely unread.
    """
    path = write(tmp_path / "cascade.jsonl", {"text": "fine"}, '{"text": "cut off')

    case = Case.open(tmp_path / "case.sqlite")
    with case.transaction():
        case.add_bundle(BundleRecord("b", "native", "/tmp/b"))
        case.add_events(parse(path))
    counts = case.counts()

    assert counts["events_unparsed"] == 2
    assert counts["events_uninterpreted"] == 1
