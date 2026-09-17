"""The vendor-neutral log format.

The tests that matter here are the two guarantees the format is sold on: an event survives
the round trip with nothing lost, and reading is total, so no line of a log can go missing
however malformed it is.
"""

from __future__ import annotations

import dataclasses
import io
import json
from typing import Any

import pytest

from agentforensics.model.event import EVENT_KINDS, Event, Provenance
from agentforensics.unified import (
    FORMAT_VERSION,
    from_record,
    read,
    schema,
    to_line,
    to_record,
    validator,
    write,
)

LOG = {"bundle_uuid": "b1", "original_path": "/tmp/agents.jsonl", "sha256": "00"}

PROVENANCE = Provenance(
    bundle_uuid="b1",
    original_path="/Users/alice/.claude/projects/-src-app/s1.jsonl",
    sha256="ab" * 32,
    artifact_id="claude_code.transcripts",
    locator="line:12",
)


def event(**overrides: Any) -> Event:
    """An event with every optional field filled, so the round trip proves something.

    A round trip over an event whose fields are mostly None would pass while losing them
    all, which is the failure this format has to rule out.
    """
    fields: dict[str, Any] = {
        "kind": "tool.call",
        "provenance": PROVENANCE,
        "agent": "claude_code",
        "raw": {"type": "assistant", "message": {"content": [{"type": "tool_use"}]}},
        "ts_utc": "2026-09-06T09:00:00.000Z",
        "ts_precision": "exact",
        "ts_source": "timestamp",
        "actor": "assistant",
        "client": "cli",
        "host": "endpoint-1",
        "user": "alice",
        "session_id": "s1",
        "project_path": "/src/app",
        "git_branch": "main",
        "payload": {
            "tool": "Bash",
            "tool_use_id": "t1",
            "input": {"command": "npm ci"},
            "output": "ok",
            "is_error": False,
            "commands": [{"command": "npm ci", "executable": "npm", "cwd": "/src/app"}],
            "models": [{"model": "example-model", "input_tokens": 10, "output_tokens": 20}],
        },
        "parse_problem": None,
    }
    fields.update(overrides)
    return Event(**fields)


# ------------------------------------------------------------------ round trip


def test_an_event_survives_the_round_trip_field_for_field() -> None:
    """The format's one promise. Compared field by field rather than by a summary, because
    a comparison that only looked at a few fields would pass while losing the rest."""
    original = event()
    restored = from_record(to_record(original), provenance_fallback=PROVENANCE)
    assert dataclasses.asdict(restored) == dataclasses.asdict(original)
    assert restored.event_id == original.event_id


def test_the_agent_name_is_never_lost() -> None:
    """Which the format requires of every record: an event that cannot be attributed to an
    agent is worth less than no event, because it gets counted all the same."""
    record = to_record(event())
    assert record["agent"] == "claude_code"
    assert "agent" in schema()["required"]


def test_the_working_directory_and_the_tool_input_and_output_survive() -> None:
    """Named explicitly because these are the three an analyst is asked about, and the
    three a lossy normalizer drops first."""
    restored = from_record(to_record(event()), provenance_fallback=PROVENANCE)
    assert restored.project_path == "/src/app"
    assert restored.payload["input"] == {"command": "npm ci"}
    assert restored.payload["output"] == "ok"


def test_the_original_record_travels_with_the_event() -> None:
    """The guarantee that a mapping mistake costs interpretation and not evidence."""
    original = event()
    record = to_record(original)
    assert record["raw"] == original.raw


def test_every_event_kind_the_build_knows_is_in_the_schema() -> None:
    """Otherwise a producer could write a kind this build emits and a reader would refuse
    it, which is a split in the format that nothing else would catch."""
    allowed = set(schema()["properties"]["kind"]["enum"])
    assert allowed == set(EVENT_KINDS)


def test_a_record_this_build_writes_satisfies_its_own_schema() -> None:
    for kind in EVENT_KINDS:
        record = to_record(event(kind=kind))
        validator()(record)


def test_the_line_is_one_line_of_json_with_the_version_on_it() -> None:
    """Every record carries the version because a row-based producer has nowhere to put a
    header, and because two logs have to concatenate into a valid third one."""
    line = to_line(event())
    assert "\n" not in line
    assert json.loads(line)["v"] == FORMAT_VERSION


def test_two_logs_concatenate() -> None:
    first = io.StringIO()
    second = io.StringIO()
    write([event()], first)
    write([event(kind="user.prompt", actor="user")], second)
    merged = first.getvalue() + second.getvalue()
    events = list(read(merged.splitlines(), **LOG))
    assert [e.kind for e in events] == ["tool.call", "user.prompt"]
    assert all(e.parse_problem is None for e in events)


# ---------------------------------------------------------------- total reading


def test_a_line_that_is_not_json_becomes_an_event_and_keeps_its_text() -> None:
    """A reader that skipped the line would let a tampered log look clean."""
    events = list(read(['{"v": 1, "agent"', ""], **LOG))
    assert [e.kind for e in events] == ["unparsed.record"]
    assert events[0].raw == '{"v": 1, "agent"'
    assert "not valid JSON" in (events[0].parse_problem or "")
    assert events[0].provenance.locator == "line:1"


def test_a_line_that_is_not_an_object_is_kept() -> None:
    events = list(read(["42"], **LOG))
    assert events[0].kind == "unparsed.record"
    assert events[0].raw == 42


def test_an_unknown_event_kind_is_kept_with_its_identity() -> None:
    """A kind from a newer producer. The event keeps its time, session and agent, so it
    still sorts into a timeline and is still attributable: only the interpretation is
    missing, not the evidence."""
    record = to_record(event())
    record["kind"] = "something.new"
    restored = from_record(record, provenance_fallback=PROVENANCE)
    assert restored.kind == "unparsed.record"
    assert restored.agent == "claude_code"
    assert restored.session_id == "s1"
    assert restored.ts_utc == "2026-09-06T09:00:00.000Z"
    assert "something.new" in (restored.parse_problem or "")


def test_a_record_with_no_agent_is_kept_as_unattributed() -> None:
    record = to_record(event())
    del record["agent"]
    restored = from_record(record, provenance_fallback=PROVENANCE)
    assert restored.kind == "unparsed.record"
    assert restored.agent == "unknown"
    assert "names no agent" in (restored.parse_problem or "")


def test_a_record_with_no_provenance_is_attributed_to_the_log_file() -> None:
    """An event has to be traceable to something, and the file it was read from is the
    honest answer when the record does not say."""
    events = list(read([json.dumps({"v": 1, "agent": "codex", "kind": "user.prompt"})], **LOG))
    assert events[0].provenance.original_path == "/tmp/agents.jsonl"
    assert events[0].provenance.locator == "line:1"
    assert "carries no provenance" in (events[0].parse_problem or "")


def test_a_payload_that_is_not_an_object_is_kept_under_a_key() -> None:
    record = to_record(event())
    record["payload"] = ["not", "an", "object"]
    restored = from_record(record, provenance_fallback=PROVENANCE)
    assert restored.payload["payload"] == ["not", "an", "object"]
    assert "not an object" in (restored.parse_problem or "")


def test_a_record_with_no_raw_field_falls_back_to_itself() -> None:
    """Something has to stand in for the original, and the record is the closest there is."""
    record = to_record(event())
    del record["raw"]
    restored = from_record(record, provenance_fallback=PROVENANCE)
    assert restored.raw == record


# ------------------------------------------------------- inconsistency reported


def test_an_event_id_the_producer_got_wrong_is_reported_not_corrected() -> None:
    """Which producer read a file, and whether it agrees with us, is itself evidence."""
    record = to_record(event())
    record["event_id"] = "f" * 32
    restored = from_record(record, provenance_fallback=PROVENANCE)
    assert restored.kind == "tool.call", "the event is kept"
    assert "does not match" in (restored.parse_problem or "")


def test_a_precision_without_a_timestamp_is_downgraded_and_said_so() -> None:
    """The event model refuses the pair outright, which is right for a parser writing new
    events and wrong for a reader: the record already exists."""
    record = to_record(event())
    record["ts_utc"] = None
    restored = from_record(record, provenance_fallback=PROVENANCE)
    assert restored.ts_utc is None
    assert restored.ts_precision == "absent"
    assert "precision" in (restored.parse_problem or "")


def test_an_unknown_precision_is_downgraded_rather_than_believed() -> None:
    record = to_record(event())
    record["ts_precision"] = "nanosecond"
    restored = from_record(record, provenance_fallback=PROVENANCE)
    assert restored.ts_precision == "second"
    assert restored.ts_utc == "2026-09-06T09:00:00.000Z"


def test_an_unknown_actor_reads_as_unknown_and_is_reported() -> None:
    record = to_record(event())
    record["actor"] = "daemon"
    restored = from_record(record, provenance_fallback=PROVENANCE)
    assert restored.actor == "unknown"
    assert "daemon" in (restored.parse_problem or "")


def test_a_producers_own_complaint_comes_first() -> None:
    """It read the original file and we did not, so what it could not map matters more than
    what we could not map about its record."""
    record = to_record(event(parse_problem="the tool input was truncated on disk"))
    record["actor"] = "daemon"
    restored = from_record(record, provenance_fallback=PROVENANCE)
    assert (restored.parse_problem or "").startswith("the tool input was truncated on disk")


def test_a_session_id_written_as_a_number_is_still_a_session_id() -> None:
    record = to_record(event())
    record["session_id"] = 12345
    restored = from_record(record, provenance_fallback=PROVENANCE)
    assert restored.session_id == "12345"


@pytest.mark.parametrize("field", ["v", "agent", "kind", "payload", "provenance", "raw"])
def test_the_schema_requires_the_fields_a_consumer_cannot_work_without(field: str) -> None:
    assert field in schema()["required"]
