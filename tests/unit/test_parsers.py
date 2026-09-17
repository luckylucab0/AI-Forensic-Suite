"""Tests for the parsers and the shared reading helpers.

Weighted towards the failure paths, because those are where a forensic parser is judged. A
parser that reads a clean transcript is table stakes; a parser that meets a truncated line,
a record type from next year's version or a timestamp in a format nobody documented and
still produces a usable, honest timeline is the actual requirement.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentforensics.parsers import for_artifact
from agentforensics.parsers.base import ParseContext, iter_lines, normalise_ts, text_of


def context(path: Path, artifact_id: str = "claude_code.transcripts") -> ParseContext:
    return ParseContext(
        bundle_uuid="b1",
        original_path="/home/alice/.claude/projects/p/s.jsonl",
        local_path=path,
        sha256="aa",
        artifact_id=artifact_id,
        agent="claude_code",
        user="alice",
    )


def parse(path: Path, artifact_id: str = "claude_code.transcripts") -> list:
    parser = for_artifact(artifact_id)
    assert parser is not None, artifact_id
    return list(parser.parse(context(path, artifact_id)))


# ---------------------------------------------------------------- the line reader


def test_every_line_is_yielded_including_the_broken_ones(tmp_path: Path) -> None:
    """The rule the whole project turns on, at the lowest level it applies.

    A reader that skipped the unreadable lines would make a truncated transcript look like
    a short one, and a short transcript looks like a short conversation.
    """
    path = tmp_path / "t.jsonl"
    path.write_text(
        '{"a": 1}\n'
        "\n"  # a blank line is not a record
        "{not json\n"
        "42\n"
        '{"b": 2}\n',
        encoding="utf-8",
    )
    lines = list(iter_lines(path))
    assert [line.number for line in lines] == [1, 3, 4, 5]
    assert [line.ok for line in lines] == [True, False, False, True]
    assert "not valid JSON" in (lines[1].problem or "")
    assert "where an object was expected" in (lines[2].problem or "")
    assert lines[1].text == "{not json", "the original text has to survive"


def test_a_byte_order_mark_does_not_eat_the_first_record(tmp_path: Path) -> None:
    """Written by a Windows tool, and it makes an otherwise fine first line unparseable."""
    path = tmp_path / "t.jsonl"
    path.write_bytes(b'\xef\xbb\xbf{"type": "user"}\n')
    lines = list(iter_lines(path))
    assert len(lines) == 1
    assert lines[0].ok


def test_a_line_that_does_not_decode_is_reported_not_dropped(tmp_path: Path) -> None:
    path = tmp_path / "t.jsonl"
    path.write_bytes(b'{"a": "\xff\xfe"}\n{"b": 1}\n')
    lines = list(iter_lines(path))
    assert [line.ok for line in lines] == [False, True]
    assert "did not decode" in (lines[0].problem or "")


def test_a_file_that_cannot_be_read_yields_one_problem(tmp_path: Path) -> None:
    lines = list(iter_lines(tmp_path / "missing.jsonl"))
    assert len(lines) == 1
    assert "could not be read" in (lines[0].problem or "")


def test_a_line_limit_says_it_stopped(tmp_path: Path) -> None:
    """A silently truncated read is the same defect as a silently skipped line."""
    path = tmp_path / "t.jsonl"
    path.write_text('{"a":1}\n{"a":2}\n{"a":3}\n', encoding="utf-8")
    lines = list(iter_lines(path, limit=2))
    assert "the rest of it has not been read" in (lines[-1].problem or "")


# ------------------------------------------------------------------- timestamps


@pytest.mark.parametrize(
    ("value", "expected", "precision"),
    [
        ("2026-09-05T08:00:00.123Z", "2026-09-05T08:00:00.123000Z", "exact"),
        ("2026-09-05T08:00:00Z", "2026-09-05T08:00:00.000000Z", "second"),
        ("2026-09-05T10:00:00+02:00", "2026-09-05T08:00:00.000000Z", "second"),
        ("2026-09-05 08:00", "2026-09-05T08:00:00.000000Z", "minute"),
        (1788912000, "2026-09-09T00:00:00.000000Z", "second"),
        (1788912000000, "2026-09-09T00:00:00.000000Z", "second"),
    ],
)
def test_a_timestamp_is_normalised_with_its_precision(
    value: object, expected: str, precision: str
) -> None:
    got, got_precision, _ = normalise_ts(value)
    assert (got, got_precision) == (expected, precision)


@pytest.mark.parametrize("value", [0, "", None, True, "not a date", "2026-02-30T00:00:00Z"])
def test_an_unusable_timestamp_comes_back_absent(value: object) -> None:
    """Never the ingest time, never zero, never the analyst's own timezone.

    A 1970 date on a timeline reads as evidence and is not one.
    """
    got, precision, _ = normalise_ts(value)
    assert got is None
    assert precision == "absent"


def test_a_naive_timestamp_says_it_was_assumed_to_be_utc() -> None:
    _, _, note = normalise_ts("2026-09-05T08:00:00")
    assert note is not None and "UTC" in note


def test_an_epoch_reading_is_recorded() -> None:
    """Agents write seconds and milliseconds and label neither, so the reading is a guess
    and the guess has to be visible."""
    _, _, note = normalise_ts(1788912000000)
    assert note == "read as epoch milliseconds"


def test_flattening_content_never_silently_drops_a_block() -> None:
    """A prompt shown half is worse than one shown untidily."""
    flattened = text_of([{"type": "text", "text": "one"}, {"type": "invented", "x": 1}])
    assert "one" in flattened
    assert "invented" in flattened, "an unmapped block type still has to reach the analyst"


# ------------------------------------------------------- the Claude Code parser


def transcript(tmp_path: Path, records: list[object], extra: str = "") -> Path:
    path = tmp_path / "s.jsonl"
    body = "".join(json.dumps(record) + "\n" for record in records) + extra
    path.write_text(body, encoding="utf-8")
    return path


BASE = {
    "cwd": "/home/alice/src/app",
    "gitBranch": "main",
    "sessionId": "s1",
    "timestamp": "2026-09-05T08:00:00.000Z",
    "entrypoint": "cli",
}


def test_a_user_turn_becomes_a_prompt(tmp_path: Path) -> None:
    events = parse(transcript(tmp_path, [{**BASE, "type": "user", "message": {"content": "hi"}}]))
    assert [e.kind for e in events] == ["user.prompt"]
    assert events[0].actor == "user"
    assert events[0].payload["text"] == "hi"
    assert events[0].session_id == "s1"
    assert events[0].project_path == "/home/alice/src/app"
    assert events[0].client == "cli"


def test_a_tool_result_is_not_attributed_to_the_user(tmp_path: Path) -> None:
    """The harness reports a tool's output back in a record typed as the user.

    Reading that as the person typing would put the output of every command into the list
    of what the user asked for, which is a wrong answer to the question the list exists to
    answer.
    """
    events = parse(
        transcript(
            tmp_path,
            [
                {
                    **BASE,
                    "type": "user",
                    "message": {
                        "content": [{"type": "tool_result", "tool_use_id": "t1", "content": "out"}]
                    },
                }
            ],
        )
    )
    assert [e.kind for e in events] == ["tool.result"]
    assert events[0].actor == "tool"


def test_one_assistant_record_produces_several_events(tmp_path: Path) -> None:
    """A turn that thinks, answers and calls a tool is four events sharing a line."""
    events = parse(
        transcript(
            tmp_path,
            [
                {
                    **BASE,
                    "type": "assistant",
                    "message": {
                        "id": "m1",
                        "model": "a-model",
                        "content": [
                            {"type": "thinking", "thinking": "hmm"},
                            {"type": "text", "text": "reading it"},
                            {
                                "type": "tool_use",
                                "id": "t1",
                                "name": "Bash",
                                "input": {"command": "ls -la"},
                            },
                        ],
                    },
                }
            ],
        )
    )
    kinds = [e.kind for e in events]
    assert kinds == ["assistant.thinking", "assistant.text", "tool.call", "command.exec"]
    assert len({e.event_id for e in events}) == 4, "they share a locator and need distinct ids"
    assert events[-1].payload["commands"][0]["executable"] == "ls"


def test_a_tool_with_an_effect_produces_the_effect_too(tmp_path: Path) -> None:
    """Two events because an analyst asks two questions: what did it try, what got touched."""
    records = [
        {
            **BASE,
            "type": "assistant",
            "message": {
                "content": [
                    {
                        "type": "tool_use",
                        "id": "a",
                        "name": "Write",
                        "input": {"file_path": "/src/a.py", "content": "x"},
                    },
                    {
                        "type": "tool_use",
                        "id": "b",
                        "name": "Read",
                        "input": {"file_path": "/src/b.py"},
                    },
                    {
                        "type": "tool_use",
                        "id": "c",
                        "name": "WebFetch",
                        "input": {"url": "https://example.org/p"},
                    },
                ]
            },
        }
    ]
    kinds = [e.kind for e in parse(transcript(tmp_path, records))]
    assert kinds.count("tool.call") == 3
    assert "file.write" in kinds and "file.read" in kinds and "network.request" in kinds


def test_an_mcp_tool_is_recognised_as_one(tmp_path: Path) -> None:
    """So that "which external servers did this agent reach" is an indexed query."""
    events = parse(
        transcript(
            tmp_path,
            [
                {
                    **BASE,
                    "type": "assistant",
                    "message": {
                        "content": [
                            {"type": "tool_use", "id": "t", "name": "mcp__files__read", "input": {}}
                        ]
                    },
                }
            ],
        )
    )
    assert events[0].kind == "mcp.call"
    assert events[0].payload["mcp"] == [{"server": "files", "tool": "read"}]


def test_a_record_type_from_a_newer_version_is_kept(tmp_path: Path) -> None:
    """The reason the mapping is written the other way round from the usual.

    The vendor adds a record type when it adds a feature. A transcript from next year's
    version has to produce a readable timeline with visible holes, not an empty one, and
    the unknown record keeps its timestamp so it still sorts into the right place.
    """
    events = parse(
        transcript(tmp_path, [{**BASE, "type": "some-future-thing", "payload": {"a": 1}}])
    )
    assert [e.kind for e in events] == ["unparsed.record"]
    assert "not one this parser maps" in (events[0].parse_problem or "")
    assert events[0].ts_utc is not None, "it still has to sort into the timeline"
    assert events[0].session_id == "s1"
    assert events[0].raw["payload"] == {"a": 1}


def test_an_unknown_content_block_is_kept(tmp_path: Path) -> None:
    events = parse(
        transcript(
            tmp_path,
            [{**BASE, "type": "assistant", "message": {"content": [{"type": "invented", "x": 1}]}}],
        )
    )
    assert [e.kind for e in events] == ["unparsed.record"]
    assert "content block type" in (events[0].parse_problem or "")


def test_a_broken_line_does_not_stop_the_rest_of_the_file(tmp_path: Path) -> None:
    """One truncated write must not cost the conversation around it."""
    path = transcript(
        tmp_path,
        [{**BASE, "type": "user", "message": {"content": "first"}}],
        extra='{"type": "assistant", "message": {"conte\n'
        + json.dumps({**BASE, "type": "user", "message": {"content": "third"}})
        + "\n",
    )
    events = parse(path)
    assert [e.kind for e in events] == ["user.prompt", "unparsed.record", "user.prompt"]
    assert [e.payload.get("text") for e in events if e.kind == "user.prompt"] == ["first", "third"]


def test_a_permission_mode_change_is_recorded(tmp_path: Path) -> None:
    """The record the question "were safety controls bypassed" turns on."""
    events = parse(
        transcript(tmp_path, [{**BASE, "type": "permission-mode", "mode": "acceptEdits"}])
    )
    assert events[0].kind == "permission.decision"
    assert events[0].payload["permissions"][0]["mode"] == "acceptEdits"


def test_the_prompt_history_is_parsed_from_its_own_artifact(tmp_path: Path) -> None:
    """It outlives the transcripts, which makes a prompt with no matching session
    one of the more interesting things a case can hold."""
    path = tmp_path / "history.jsonl"
    path.write_text(
        json.dumps({"display": "why is it red", "project": "/src/app", "timestamp": 1788912000000})
        + "\n",
        encoding="utf-8",
    )
    events = parse(path, "claude_code.history_jsonl")
    assert [e.kind for e in events] == ["prompt.history"]
    assert events[0].payload["text"] == "why is it red"
    assert events[0].ts_utc is not None


def test_every_transcript_artifact_the_catalogue_has_is_claimed() -> None:
    """Four places hold conversations, and leaving one out would drop a conversation.

    The live session, one set aside when it was superseded, a subagent's own transcript and
    a workflow run's journal are all the same format.
    """
    for artifact_id in (
        "claude_code.transcripts",
        "claude_code.transcripts_set_aside",
        "claude_code.subagent_transcripts",
        "claude_code.workflow_runs",
        "claude_code.history_jsonl",
    ):
        assert for_artifact(artifact_id) is not None, artifact_id


def test_a_file_with_no_parser_returns_none() -> None:
    """Which is recorded as unsupported rather than hidden."""
    assert for_artifact("windsurf.cascade_trajectories") is None
    assert for_artifact(None) is None
