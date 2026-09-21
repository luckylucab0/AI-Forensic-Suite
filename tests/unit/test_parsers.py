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

from agentforensics.model import UNINTERPRETED_MARK
from agentforensics.parsers import PARSERS, for_artifact
from agentforensics.parsers.base import ParseContext, iter_lines, normalise_ts, text_of
from agentforensics.parsers.coverage import (
    GENERIC_READERS,
    HANDED_OVER,
    READABLE_AND_UNREAD,
    READABLE_FORMATS,
    UNFINISHED,
)
from agentforensics.parsers.jsonl_generic import UNINTERPRETED as JSONL_UNINTERPRETED


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
    """The record the question "were safety controls bypassed" turns on.

    A change to the rules rather than a decision made under them. The distinction is the
    whole point of the kind: one says what happened to a request, the other says who moved
    the goalposts and when, and only the second one answers the bypass question.
    """
    events = parse(
        transcript(tmp_path, [{**BASE, "type": "permission-mode", "mode": "acceptEdits"}])
    )
    assert events[0].kind == "permission.change"
    assert events[0].payload["permissions"][0]["mode"] == "acceptEdits"
    assert events[0].payload["permissions"][0]["scope"] == "session"


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
    """Which is recorded as unsupported rather than hidden.

    The artifact used here is a credential store, which nothing reads on purpose: the
    collector does not copy its content by default and a token in an event payload is not
    what --include-secrets was for. It is a stable example precisely because the narrowing
    is deliberate rather than a gap somebody will close.
    """
    assert for_artifact("windsurf.auth_credentials") is None
    assert for_artifact(None) is None


# ------------------------------------------------------------- the Codex parser

CODEX_BASE = {"timestamp": "2026-09-06T09:00:00.000Z"}


def codex(tmp_path: Path, records: list[object], extra: str = "") -> Path:
    path = tmp_path / "rollout-2026-09-06T09-00-00-s1.jsonl"
    path.write_text(
        "".join(json.dumps(record) + "\n" for record in records) + extra, encoding="utf-8"
    )
    return path


def parse_codex(path: Path, artifact_id: str = "codex.rollouts") -> list:
    parser = for_artifact(artifact_id)
    assert parser is not None
    return list(
        parser.parse(
            ParseContext(
                bundle_uuid="b1",
                original_path="/home/alice/.codex/sessions/2026/09/06/" + path.name,
                local_path=path,
                sha256="aa",
                artifact_id=artifact_id,
                agent="codex",
                user="alice",
            )
        )
    )


SESSION_META = {
    **CODEX_BASE,
    "type": "session_meta",
    "payload": {"id": "s1", "cwd": "/src/app", "model": "m", "git": {"branch": "main"}},
}


def test_codex_session_metadata_sets_the_context_for_the_rest(tmp_path: Path) -> None:
    """Those facts arrive once and apply to everything after them, so they are carried
    forward rather than looked up per event."""
    events = parse_codex(
        codex(
            tmp_path,
            [
                SESSION_META,
                {
                    **CODEX_BASE,
                    "type": "response_item",
                    "payload": {"type": "message", "role": "user", "content": "hi"},
                },
            ],
        )
    )
    assert [e.kind for e in events] == ["session.start", "user.prompt"]
    assert events[1].session_id == "s1"
    assert events[1].project_path == "/src/app"
    assert events[1].git_branch == "main"
    assert events[1].payload["models"] == [{"model": "m"}]


def test_codex_event_msg_is_kept_as_a_record_not_as_a_turn(tmp_path: Path) -> None:
    """It mirrors response_item, so mapping it as a turn would double every turn.

    It is still a line on disk, so it gets an event of its own at a kind the conversation
    views do not read from. One event per record, with the line in raw: an earlier version
    of this parser counted the records and threw their content away, which the differential
    against the endpoint query in scripts/check_velociraptor_vql.py is what caught.
    """
    events = parse_codex(
        codex(
            tmp_path,
            [
                SESSION_META,
                {
                    **CODEX_BASE,
                    "type": "event_msg",
                    "payload": {"type": "agent_message", "message": "the mirrored text"},
                },
                {**CODEX_BASE, "type": "event_msg", "payload": {"type": "token_count"}},
            ],
        )
    )
    kinds = [e.kind for e in events]
    assert kinds.count("assistant.text") == 0, "the mirror must not become a turn"

    mirrors = [e for e in events if e.payload.get("mirrored_event_msg")]
    assert len(mirrors) == 2, "one event per record, so nothing is only counted"
    assert [e.kind for e in mirrors] == ["config.snapshot", "config.snapshot"]
    assert [e.provenance.locator for e in mirrors] == ["line:2", "line:3"]
    assert [e.payload["item_type"] for e in mirrors] == ["agent_message", "token_count"]
    # The content has to survive, not just the tally. A subtype that mirrors nothing would
    # otherwise exist in the case as a number and nowhere as evidence.
    assert "the mirrored text" in mirrors[0].payload["text"]
    assert mirrors[0].raw == {
        **CODEX_BASE,
        "type": "event_msg",
        "payload": {"type": "agent_message", "message": "the mirrored text"},
    }
    assert mirrors[1].session_id == SESSION_META["payload"]["id"]


def test_codex_compaction_is_an_event_not_a_gap(tmp_path: Path) -> None:
    """It is the usual explanation for an apparent hole in a transcript."""
    events = parse_codex(
        codex(
            tmp_path,
            [SESSION_META, {**CODEX_BASE, "type": "compacted", "payload": {"message": "x"}}],
        )
    )
    compaction = [e for e in events if e.payload.get("compaction")]
    assert len(compaction) == 1
    assert "compacted" in compaction[0].payload["text"]


def test_codex_a_shell_call_produces_the_command(tmp_path: Path) -> None:
    """The command can be argv rather than a string, which is how the sandbox spells it."""
    events = parse_codex(
        codex(
            tmp_path,
            [
                SESSION_META,
                {
                    **CODEX_BASE,
                    "type": "response_item",
                    "payload": {
                        "type": "local_shell_call",
                        "call_id": "c1",
                        "action": {"command": ["npm", "ci"], "workdir": "/src/app"},
                    },
                },
            ],
        )
    )
    command = next(e for e in events if e.kind == "command.exec")
    assert command.payload["commands"][0]["command"] == "npm ci"
    assert command.payload["commands"][0]["executable"] == "npm"


def test_codex_truncated_arguments_are_kept_as_evidence(tmp_path: Path) -> None:
    """A killed process leaves a valid line with an invalid argument list.

    A partial argument list is still evidence of what the agent was about to do, so it is
    kept and the parse problem is recorded rather than the call being discarded.
    """
    path = codex(
        tmp_path,
        [SESSION_META],
        extra='{"timestamp": "2026-09-06T09:00:09.000Z", "type": "response_item", "payload": '
        '{"type": "function_call", "call_id": "c2", "name": "apply_patch", '
        '"arguments": "{\\"path\\": \\"/src/pkg"}}\n',
    )
    call = next(e for e in parse_codex(path) if e.kind == "tool.call")
    assert "/src/pkg" in str(call.payload["input"])
    assert "did not parse" in (call.parse_problem or "")


def test_codex_unknown_types_are_kept_at_both_levels(tmp_path: Path) -> None:
    """The record envelope and the item inside it can each be a type from a newer version."""
    events = parse_codex(
        codex(
            tmp_path,
            [
                SESSION_META,
                {**CODEX_BASE, "type": "future_record", "payload": {}},
                {**CODEX_BASE, "type": "response_item", "payload": {"type": "future_item"}},
            ],
        )
    )
    problems = [e.parse_problem for e in events if e.kind == "unparsed.record"]
    assert any("record type" in (p or "") for p in problems)
    assert any("response_item type" in (p or "") for p in problems)
    assert all(e.ts_utc for e in events if e.kind == "unparsed.record"), (
        "an unknown record still has to sort into the timeline"
    )


def test_codex_prompt_history_is_its_own_artifact(tmp_path: Path) -> None:
    path = tmp_path / "history.jsonl"
    path.write_text(
        json.dumps({"session_id": "s1", "ts": 1788912000, "text": "hi"}) + "\n", encoding="utf-8"
    )
    events = parse_codex(path, "codex.prompt_history")
    assert [e.kind for e in events] == ["prompt.history"]
    assert events[0].ts_utc is not None


# ----------------------------------------------------------- the Copilot parser


def copilot(tmp_path: Path, records: list[object]) -> Path:
    directory = tmp_path / "session-state" / "sess-1"
    directory.mkdir(parents=True)
    path = directory / "events.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
    return path


def parse_copilot(path: Path) -> list:
    parser = for_artifact("copilot.session_event_log")
    assert parser is not None
    return list(
        parser.parse(
            ParseContext(
                bundle_uuid="b1",
                original_path="/home/alice/.copilot/session-state/sess-1/events.jsonl",
                local_path=path,
                sha256="aa",
                artifact_id="copilot.session_event_log",
                agent="copilot",
                user="alice",
            )
        )
    )


def test_copilot_takes_the_session_id_from_the_directory(tmp_path: Path) -> None:
    """The records do not always carry it, and the directory name is the session id.

    Reading it from the path is what keeps two sessions in one case apart.
    """
    events = parse_copilot(
        copilot(
            tmp_path,
            [
                {
                    "type": "user.message",
                    "timestamp": "2026-09-06T10:00:00Z",
                    "data": {"content": "hi"},
                }
            ],
        )
    )
    assert events[0].session_id == "sess-1"


def test_copilot_carries_the_model_forward(tmp_path: Path) -> None:
    """The model is announced once and applies to everything after it, so a case that wants
    to know which model wrote a turn has to carry that state rather than read the turn."""
    events = parse_copilot(
        copilot(
            tmp_path,
            [
                {
                    "type": "session.model_change",
                    "timestamp": "2026-09-06T10:00:00Z",
                    "data": {"newModel": "m2"},
                },
                {
                    "type": "assistant.message",
                    "timestamp": "2026-09-06T10:00:01Z",
                    "data": {"content": "done"},
                },
            ],
        )
    )
    turn = next(e for e in events if e.kind == "assistant.text")
    assert turn.payload["models"] == [{"model": "m2"}]


def test_copilot_names_the_mcp_server_from_its_own_field(tmp_path: Path) -> None:
    """Which is better than the prefix convention the other agents use: no parsing, and no
    ambiguity about where the server name ends."""
    events = parse_copilot(
        copilot(
            tmp_path,
            [
                {
                    "type": "tool.execution_start",
                    "timestamp": "2026-09-06T10:00:00Z",
                    "data": {
                        "toolCallId": "t1",
                        "toolName": "read_file",
                        "mcpServerName": "filesystem",
                        "mcpToolName": "read",
                        "arguments": {"path": "/src/a.py"},
                    },
                }
            ],
        )
    )
    assert events[0].kind == "mcp.call"
    assert events[0].payload["mcp"] == [{"server": "filesystem", "tool": "read"}]


def test_copilot_a_shell_tool_produces_the_command(tmp_path: Path) -> None:
    events = parse_copilot(
        copilot(
            tmp_path,
            [
                {
                    "type": "tool.execution_start",
                    "timestamp": "2026-09-06T10:00:00Z",
                    "data": {
                        "toolCallId": "t1",
                        "toolName": "bash",
                        "arguments": {"command": "rm -rf /tmp/x"},
                    },
                }
            ],
        )
    )
    assert [e.kind for e in events] == ["tool.call", "command.exec"]
    assert events[1].payload["commands"][0]["executable"] == "rm"


def test_copilot_a_subagent_is_recorded(tmp_path: Path) -> None:
    """Its own work may never appear in this file, so the case has to know to look."""
    events = parse_copilot(
        copilot(
            tmp_path,
            [
                {
                    "type": "subagent.started",
                    "timestamp": "2026-09-06T10:00:00Z",
                    "data": {"agentName": "reviewer"},
                }
            ],
        )
    )
    assert events[0].payload["subagent"] == "reviewer"


def test_copilot_an_unknown_event_type_is_kept(tmp_path: Path) -> None:
    events = parse_copilot(
        copilot(
            tmp_path,
            [{"type": "some.future.event", "timestamp": "2026-09-06T10:00:00Z", "data": {}}],
        )
    )
    assert [e.kind for e in events] == ["unparsed.record"]
    assert "event type" in (events[0].parse_problem or "")
    assert events[0].ts_utc is not None


def test_the_three_formats_the_viewer_knows_all_have_parsers() -> None:
    for artifact_id in (
        "claude_code.transcripts",
        "codex.rollouts",
        "codex.archived_sessions",
        "copilot.session_event_log",
    ):
        assert for_artifact(artifact_id) is not None, artifact_id


def test_a_refusal_is_its_own_event(tmp_path: Path) -> None:
    """The model declining, as opposed to the harness denying a permission.

    The API reports it as a stop reason on a normal 200 response, so nothing else in the
    transcript marks the turn as refused. The question "was anything refused, and what"
    has to be answerable without reading every assistant turn in a case.
    """
    events = parse(
        transcript(
            tmp_path,
            [
                {
                    **BASE,
                    "type": "assistant",
                    "message": {
                        "id": "msg_1",
                        "role": "assistant",
                        "model": "example-model",
                        "stop_reason": "refusal",
                        "stop_details": {"type": "example_policy"},
                        "content": [{"type": "text", "text": "I cannot help with that."}],
                    },
                }
            ],
        )
    )
    refusals = [e for e in events if e.kind == "safety.refusal"]
    assert len(refusals) == 1
    assert refusals[0].payload["refusal"] == "example_policy"
    assert "cannot help" in refusals[0].payload["text"]
    assert any(e.kind == "assistant.text" for e in events), (
        "the wording of a refusal is what tells manipulation apart from an ordinary "
        "decline, so the turn is kept as well"
    )


def test_a_refusal_with_no_category_still_reads_as_a_refusal(tmp_path: Path) -> None:
    """A null there would read as 'no refusal' to anything filtering on the field."""
    events = parse(
        transcript(
            tmp_path,
            [
                {
                    **BASE,
                    "type": "assistant",
                    "message": {
                        "id": "msg_1",
                        "role": "assistant",
                        "stop_reason": "refusal",
                        "content": [{"type": "text", "text": "no"}],
                    },
                }
            ],
        )
    )
    refusal = next(e for e in events if e.kind == "safety.refusal")
    assert refusal.payload["refusal"] == "refusal"


# ------------------------------------- the Gemini CLI and Qwen Code parser


def jsonl_file(tmp_path: Path, name: str, records: list[object]) -> Path:
    path = tmp_path / name
    path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
    return path


def parse_as(path: Path, artifact_id: str, agent: str) -> list:
    """Parse one file as a named artifact of a named agent.

    The agent is a parameter because three of the parsers serve several agents, and an
    event attributed to the wrong one is worse than an event nobody parsed: a case would
    then say an agent was used that never was.
    """
    parser = for_artifact(artifact_id)
    assert parser is not None, artifact_id
    return list(
        parser.parse(
            ParseContext(
                bundle_uuid="b1",
                original_path=f"/home/alice/{name_of(artifact_id)}/{path.name}",
                local_path=path,
                sha256="aa",
                artifact_id=artifact_id,
                agent=agent,
                user="alice",
            )
        )
    )


def name_of(artifact_id: str) -> str:
    return artifact_id.split(".")[0]


def test_gemini_records_are_told_apart_by_which_key_they_carry(tmp_path: Path) -> None:
    """The service's own discrimination order, and the reason to test it is that the
    records overlap: a message record has a timestamp and so does the header, so a reader
    testing in the wrong order reads one as the other."""
    events = parse_as(
        jsonl_file(
            tmp_path,
            "session-s1.jsonl",
            [
                {
                    "sessionId": "s1",
                    "projectHash": "abc123",
                    "startTime": "2026-09-08T10:00:00.000Z",
                    "kind": "main",
                },
                {
                    "id": "m1",
                    "timestamp": "2026-09-08T10:00:01.000Z",
                    "type": "user",
                    "content": "hi",
                },
                {"$set": {"summary": "a summary"}},
                {"$rewindTo": "m1"},
            ],
        ),
        "gemini_cli.chats",
        "gemini_cli",
    )
    kinds = [event.kind for event in events]
    assert kinds == ["session.start", "user.prompt", "config.snapshot", "session.end"]
    assert all(event.agent == "gemini_cli" for event in events)


def test_gemini_does_not_present_a_project_hash_as_a_working_directory(tmp_path: Path) -> None:
    """The header records a hash of the directory, not the directory. A path nobody can
    find is worse than an absent one, because an analyst will go looking for it."""
    events = parse_as(
        jsonl_file(
            tmp_path,
            "session-s1.jsonl",
            [{"sessionId": "s1", "projectHash": "abc123", "startTime": "2026-09-08T10:00:00.000Z"}],
        ),
        "gemini_cli.chats",
        "gemini_cli",
    )
    assert events[0].project_path is None
    assert events[0].payload["project_hash"] == "abc123"


def test_gemini_a_rewind_is_an_event_not_a_gap(tmp_path: Path) -> None:
    """The turns it discards are still in the file. Without this event a reader sees turns
    the model never saw again and has nothing telling them so."""
    events = parse_as(
        jsonl_file(tmp_path, "session-s1.jsonl", [{"$rewindTo": "m2"}]),
        "gemini_cli.chats",
        "gemini_cli",
    )
    assert events[0].kind == "session.end"
    assert events[0].payload["rewind_to"] == "m2"
    assert "still in this file" in events[0].payload["text"]


def test_gemini_a_thought_part_is_not_mixed_into_the_answer(tmp_path: Path) -> None:
    """A plan the model formed and an answer it gave are different claims."""
    events = parse_as(
        jsonl_file(
            tmp_path,
            "session-s1.jsonl",
            [
                {
                    "id": "m1",
                    "timestamp": "2026-09-08T10:00:02.000Z",
                    "type": "gemini",
                    "content": [
                        {"text": "let me think", "thought": True},
                        {"text": "the answer"},
                    ],
                }
            ],
        ),
        "gemini_cli.chats",
        "gemini_cli",
    )
    thinking = next(e for e in events if e.kind == "assistant.thinking")
    text = next(e for e in events if e.kind == "assistant.text")
    assert thinking.payload["text"] == "let me think"
    assert text.payload["text"] == "the answer"


def test_gemini_a_shell_tool_produces_the_command(tmp_path: Path) -> None:
    events = parse_as(
        jsonl_file(
            tmp_path,
            "session-s1.jsonl",
            [
                {
                    "id": "m1",
                    "timestamp": "2026-09-08T10:00:02.000Z",
                    "type": "gemini",
                    "toolCalls": [
                        {
                            "id": "c1",
                            "name": "run_shell_command",
                            "args": {"command": "rm -rf build", "directory": "/srv/app"},
                            "status": "Success",
                            "result": [{"text": "done"}],
                        }
                    ],
                }
            ],
        ),
        "gemini_cli.chats",
        "gemini_cli",
    )
    command = next(e for e in events if e.kind == "command.exec")
    assert command.payload["commands"][0]["command"] == "rm -rf build"
    assert command.payload["commands"][0]["executable"] == "rm"
    assert command.payload["commands"][0]["cwd"] == "/srv/app"
    assert any(e.kind == "tool.result" for e in events)


def test_gemini_an_unknown_tool_still_records_its_arguments(tmp_path: Path) -> None:
    """A facet nobody mapped costs an index. Guessing from the name would write a command
    into a case that nothing ran."""
    events = parse_as(
        jsonl_file(
            tmp_path,
            "session-s1.jsonl",
            [
                {
                    "id": "m1",
                    "timestamp": "2026-09-08T10:00:02.000Z",
                    "type": "gemini",
                    "toolCalls": [
                        {"id": "c1", "name": "some_new_tool", "args": {"command": "rm -rf /"}}
                    ],
                }
            ],
        ),
        "gemini_cli.chats",
        "gemini_cli",
    )
    assert not [e for e in events if e.kind == "command.exec"]
    call = next(e for e in events if e.kind == "tool.call")
    assert call.payload["input"]["command"] == "rm -rf /"


def test_gemini_a_record_with_no_known_key_is_kept(tmp_path: Path) -> None:
    events = parse_as(
        jsonl_file(tmp_path, "session-s1.jsonl", [{"unexpected": True}]),
        "gemini_cli.chats",
        "gemini_cli",
    )
    assert events[0].kind == "unparsed.record"
    assert "told apart by" in (events[0].parse_problem or "")


def test_qwen_keeps_the_writers_own_view_of_who_typed_a_prompt(tmp_path: Path) -> None:
    """`provenance` is the writer saying whether a person typed this. That is exactly the
    question an analyst has about a prompt, so it travels rather than being flattened."""
    events = parse_as(
        jsonl_file(
            tmp_path,
            "s1.jsonl",
            [
                {
                    "uuid": "q1",
                    "sessionId": "s1",
                    "timestamp": "2026-09-08T11:00:00.000Z",
                    "type": "user",
                    "provenance": "assistant_output",
                    "cwd": "/srv/app",
                    "gitBranch": "main",
                    "message": {"role": "user", "parts": [{"text": "/compress"}]},
                }
            ],
        ),
        "qwen_code.conversation_transcript",
        "qwen_code",
    )
    assert events[0].kind == "user.prompt"
    assert events[0].payload["provenance_class"] == "assistant_output"
    assert events[0].project_path == "/srv/app"
    assert events[0].git_branch == "main"


def test_qwen_a_compression_is_an_event_not_a_gap(tmp_path: Path) -> None:
    events = parse_as(
        jsonl_file(
            tmp_path,
            "s1.jsonl",
            [
                {
                    "uuid": "q1",
                    "sessionId": "s1",
                    "timestamp": "2026-09-08T11:00:00.000Z",
                    "type": "system",
                    "subtype": "chat_compression",
                    "message": {"role": "user", "parts": [{"text": "summarised"}]},
                }
            ],
        ),
        "qwen_code.conversation_transcript",
        "qwen_code",
    )
    assert events[0].kind == "session.end"
    assert events[0].payload["compaction"] is True


def test_qwen_a_function_response_is_a_tool_result(tmp_path: Path) -> None:
    events = parse_as(
        jsonl_file(
            tmp_path,
            "s1.jsonl",
            [
                {
                    "uuid": "q1",
                    "sessionId": "s1",
                    "timestamp": "2026-09-08T11:00:00.000Z",
                    "type": "tool_result",
                    "message": {
                        "role": "user",
                        "parts": [
                            {
                                "functionResponse": {
                                    "id": "t1",
                                    "name": "run_shell_command",
                                    "response": {"output": "ok"},
                                }
                            }
                        ],
                    },
                }
            ],
        ),
        "qwen_code.conversation_transcript",
        "qwen_code",
    )
    assert events[0].kind == "tool.result"
    assert events[0].actor == "tool"
    assert events[0].payload["tool"] == "run_shell_command"


def test_qwen_prompt_history_is_a_json_array_not_a_log(tmp_path: Path) -> None:
    """logs.json is rewritten whole on every append, so it is read as one document. Reading
    it line by line would produce nothing at all from a valid file."""
    path = tmp_path / "logs.json"
    path.write_text(
        json.dumps(
            [
                {
                    "sessionId": "s1",
                    "messageId": 0,
                    "timestamp": "2026-09-08T11:00:00.000Z",
                    "type": "user",
                    "message": "bump the lockfile",
                }
            ],
            indent=2,
        ),
        encoding="utf-8",
    )
    events = parse_as(path, "qwen_code.prompt_history_log", "qwen_code")
    assert [event.kind for event in events] == ["prompt.history"]
    assert events[0].payload["text"] == "bump the lockfile"
    assert events[0].provenance.locator == "index:0"


def test_the_upstream_writes_the_same_prompt_log_and_is_read_the_same_way(
    tmp_path: Path,
) -> None:
    """One file of shared code, and for a while only the fork's copy of it was read.

    Gemini CLI writes logs.json from packages/core/src/core/logger.ts and Qwen Code, which
    is a fork of it, writes the same array of the same records. The catalogue carried the
    fork's path and not the original's, so every prompt a Gemini CLI user typed was
    collected under a directory glob and read by nothing. This asserts the reading, in the
    direction that was missing.
    """
    path = tmp_path / "logs.json"
    path.write_text(
        json.dumps(
            [
                {
                    "sessionId": "s1",
                    "messageId": 0,
                    "timestamp": "2026-09-08T11:00:00.000Z",
                    "type": "user",
                    "message": "summarise the failing test",
                },
                {
                    "sessionId": "s2",
                    "messageId": 0,
                    "timestamp": "2026-09-08T12:00:00.000Z",
                    "type": "user",
                    "message": "now open a pull request",
                },
            ]
        ),
        encoding="utf-8",
    )

    events = parse_as(path, "gemini_cli.prompt_history_log", "gemini_cli")

    assert [event.kind for event in events] == ["prompt.history", "prompt.history"]
    assert [event.payload["text"] for event in events] == [
        "summarise the failing test",
        "now open a pull request",
    ]
    # The session id and the agent's own clock, which is what lets a prompt whose
    # conversation the thirty-day sweep has deleted still be attributed to a session.
    assert [event.session_id for event in events] == ["s1", "s2"]
    assert events[0].ts_utc == "2026-09-08T11:00:00.000000Z"


def test_qwen_a_prompt_history_that_is_not_an_array_is_reported(tmp_path: Path) -> None:
    path = tmp_path / "logs.json"
    path.write_text('{"not": "an array"}', encoding="utf-8")
    events = parse_as(path, "qwen_code.prompt_history_log", "qwen_code")
    assert events[0].kind == "unparsed.record"
    assert "not the array this format writes" in (events[0].parse_problem or "")


# ------------------------------------------------------------- the Pi parser


def test_pi_the_header_supplies_the_working_directory_for_the_file(tmp_path: Path) -> None:
    events = parse_as(
        jsonl_file(
            tmp_path,
            "2026-09-09T12-00-00_s1.jsonl",
            [
                {
                    "type": "session",
                    "version": 3,
                    "id": "s1",
                    "timestamp": "2026-09-09T12:00:00.000Z",
                    "cwd": "/srv/app",
                },
                {
                    "type": "message",
                    "id": "p1",
                    "timestamp": "2026-09-09T12:00:01.000Z",
                    "message": {"role": "user", "content": "hello"},
                },
            ],
        ),
        "pi.sessions",
        "pi",
    )
    assert events[1].kind == "user.prompt"
    assert events[1].session_id == "s1"
    assert events[1].project_path == "/srv/app"


def test_pi_a_forked_session_says_so(tmp_path: Path) -> None:
    """The turns it continues from are in another file. A conversation that starts
    mid-thought is a fork, not a truncated collection, and only this says which."""
    events = parse_as(
        jsonl_file(
            tmp_path,
            "s.jsonl",
            [
                {
                    "type": "session",
                    "id": "s1",
                    "timestamp": "2026-09-09T12:00:00.000Z",
                    "cwd": "/srv/app",
                    "parentSession": "s0",
                }
            ],
        ),
        "pi.sessions",
        "pi",
    )
    assert events[0].payload["parent_session"] == "s0"
    assert "forked from s0" in events[0].payload["text"]


def test_pi_a_tool_result_carries_its_failure(tmp_path: Path) -> None:
    """A failed tool call and a successful one are different evidence, and this format is
    one of the few that says which without the reader inferring it from the output."""
    events = parse_as(
        jsonl_file(
            tmp_path,
            "s.jsonl",
            [
                {
                    "type": "message",
                    "id": "p1",
                    "timestamp": "2026-09-09T12:00:04.000Z",
                    "message": {
                        "role": "toolResult",
                        "toolCallId": "tc1",
                        "toolName": "bash",
                        "isError": True,
                        "content": [{"type": "text", "text": "fatal: not a git repository"}],
                    },
                }
            ],
        ),
        "pi.sessions",
        "pi",
    )
    assert events[0].kind == "tool.result"
    assert events[0].payload["is_error"] is True
    assert "not a git repository" in events[0].payload["text"]


def test_pi_a_namespaced_tool_is_an_external_server(tmp_path: Path) -> None:
    events = parse_as(
        jsonl_file(
            tmp_path,
            "s.jsonl",
            [
                {
                    "type": "message",
                    "id": "p1",
                    "timestamp": "2026-09-09T12:00:03.000Z",
                    "message": {
                        "role": "assistant",
                        "content": [
                            {
                                "type": "toolCall",
                                "id": "tc1",
                                "name": "search_issues",
                                "namespace": "example-tracker",
                                "arguments": {"query": "x"},
                            }
                        ],
                    },
                }
            ],
        ),
        "pi.sessions",
        "pi",
    )
    call = next(e for e in events if e.kind == "mcp.call")
    assert call.payload["mcp"] == [{"server": "example-tracker", "tool": "search_issues"}]


def test_pi_redacted_reasoning_is_distinguished_from_none(tmp_path: Path) -> None:
    """The provider withholding the reasoning and the model not having reasoned are
    different facts, and a case that conflated them would understate what happened."""
    events = parse_as(
        jsonl_file(
            tmp_path,
            "s.jsonl",
            [
                {
                    "type": "message",
                    "id": "p1",
                    "timestamp": "2026-09-09T12:00:03.000Z",
                    "message": {
                        "role": "assistant",
                        "content": [
                            {"type": "thinking", "thinking": "hidden", "redacted": True},
                            {"type": "text", "text": "done"},
                        ],
                    },
                }
            ],
        ),
        "pi.sessions",
        "pi",
    )
    thinking = next(e for e in events if e.kind == "assistant.thinking")
    assert thinking.payload["redacted"] is True


def test_pi_a_system_message_records_what_the_agent_could_do(tmp_path: Path) -> None:
    """Tools handed to or taken from the model mid-session are the answer to what this
    agent was able to do at that moment."""
    events = parse_as(
        jsonl_file(
            tmp_path,
            "s.jsonl",
            [
                {
                    "type": "message",
                    "id": "p1",
                    "timestamp": "2026-09-09T12:00:05.000Z",
                    "message": {
                        "role": "system",
                        "content": "",
                        "sections": {"preamble": "p", "tools": "t"},
                        "toolsRemoved": [{"name": "write"}],
                    },
                }
            ],
        ),
        "pi.sessions",
        "pi",
    )
    assert events[0].kind == "config.snapshot"
    assert events[0].payload["sections"] == ["preamble", "tools"]
    assert events[0].payload["tools_removed"] == [{"name": "write"}]


def test_pi_an_unknown_entry_type_is_kept(tmp_path: Path) -> None:
    events = parse_as(
        jsonl_file(
            tmp_path,
            "s.jsonl",
            [{"type": "some_future_entry", "id": "p1", "timestamp": "2026-09-09T12:00:07.000Z"}],
        ),
        "pi.sessions",
        "pi",
    )
    assert events[0].kind == "unparsed.record"
    assert "some_future_entry" in (events[0].parse_problem or "")


# ------------------------- the Cline, Roo Code and Kilo Code parser


def cline_task(tmp_path: Path, name: str, document: object) -> Path:
    task = tmp_path / "tasks" / "t1"
    task.mkdir(parents=True, exist_ok=True)
    path = task / name
    path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    return path


def parse_task(path: Path, agent: str = "cline") -> list:
    """Parse one file of a task directory, with the path the session id comes from.

    The original path matters here: none of the four files carries a session id inside, so
    it comes from the directory name, and a test that passed a flat path would be testing
    a situation the collector never produces.
    """
    parser = for_artifact("cline.vscode_task_transcripts")
    assert parser is not None
    return list(
        parser.parse(
            ParseContext(
                bundle_uuid="b1",
                original_path=f"/home/alice/.config/Code/User/globalStorage/x/tasks/t1/{path.name}",
                local_path=path,
                sha256="aa",
                artifact_id="cline.vscode_task_transcripts",
                agent=agent,
                user="alice",
            )
        )
    )


def test_cline_the_session_id_comes_from_the_task_directory(tmp_path: Path) -> None:
    events = parse_task(
        cline_task(tmp_path, "api_conversation_history.json", [{"role": "user", "content": "hi"}])
    )
    assert events[0].session_id == "t1"


def test_cline_a_tool_result_in_a_user_entry_is_not_a_prompt(tmp_path: Path) -> None:
    """The provider's API expects tool results under the user role, so a reader going by
    role alone attributes the agent's own tool output to the person at the keyboard."""
    events = parse_task(
        cline_task(
            tmp_path,
            "api_conversation_history.json",
            [
                {
                    "role": "user",
                    "content": [
                        {"type": "tool_result", "tool_use_id": "u1", "content": "3 matches"}
                    ],
                }
            ],
        )
    )
    assert [event.kind for event in events] == ["tool.result"]
    assert events[0].actor == "tool"


def test_cline_the_api_history_has_no_timestamps_and_says_so(tmp_path: Path) -> None:
    """Filling them in from the file's mtime would date every turn in a task to the moment
    it last changed, which reads as evidence and is not."""
    events = parse_task(
        cline_task(tmp_path, "api_conversation_history.json", [{"role": "user", "content": "hi"}])
    )
    assert events[0].ts_utc is None
    assert events[0].ts_precision == "absent"


def test_cline_an_ask_is_a_permission_event_with_no_answer_assumed(tmp_path: Path) -> None:
    """An assumed approval would be the worst defect this field could have: it is the
    difference between an agent that was allowed to act and one that acted unasked."""
    events = parse_task(
        cline_task(
            tmp_path,
            "ui_messages.json",
            [{"ts": 1789041601000, "type": "ask", "ask": "command", "text": "rm -rf build"}],
        )
    )
    assert events[0].kind == "permission.decision"
    assert events[0].payload["permissions"][0]["decision"] == "asked"
    assert events[0].payload["permissions"][0]["subject"] == "command"
    assert events[0].ts_utc is not None


def test_cline_user_feedback_in_the_ui_log_is_a_prompt(tmp_path: Path) -> None:
    events = parse_task(
        cline_task(
            tmp_path,
            "ui_messages.json",
            [{"ts": 1789041605000, "type": "say", "say": "user_feedback", "text": "go ahead"}],
        )
    )
    assert events[0].kind == "user.prompt"
    assert events[0].actor == "user"


def test_cline_a_file_in_context_is_not_recorded_as_a_read(tmp_path: Path) -> None:
    """A file can enter the context through a mention or an open editor tab. Claiming it
    was read would put a tool call in the case that nothing made."""
    events = parse_task(
        cline_task(
            tmp_path,
            "task_metadata.json",
            {
                "files_in_context": [{"path": "src/app/index.js"}],
                "model_usage": {"example-model-6": {"requests": 1}},
            },
        )
    )
    assert events[0].kind == "config.snapshot"
    assert events[0].payload["files"] == [{"path": "src/app/index.js", "operation": "unknown"}]


def test_cline_a_truncated_document_is_reported_as_one(tmp_path: Path) -> None:
    """These files are whole JSON documents, so a killed write costs the file rather than
    its last record. A task whose history will not parse while its siblings do is that."""
    task = tmp_path / "tasks" / "t1"
    task.mkdir(parents=True)
    path = task / "api_conversation_history.json"
    path.write_text('[{"role": "user", ', encoding="utf-8")
    events = parse_task(path)
    assert events[0].kind == "unparsed.record"
    assert "not valid JSON" in (events[0].parse_problem or "")


def test_cline_an_unknown_file_in_a_task_directory_is_reported(tmp_path: Path) -> None:
    """One catalogue entry claims four files, so the parser dispatches on the name. A name
    it does not know has to be said out loud rather than read as one of the four."""
    events = parse_task(cline_task(tmp_path, "something_new.json", {"a": 1}))
    assert events[0].kind == "unparsed.record"
    assert "not a file this parser maps" in (events[0].parse_problem or "")


def test_cline_serves_three_agents_without_mislabelling_them() -> None:
    """A fork's events must carry the fork's name. An event attributed to the wrong agent
    would have a case say an agent was used that never was."""
    for artifact_id in (
        "cline.vscode_task_transcripts",
        "cline.data_tasks",
        "roo_code.tasks",
        "kilo_code.extension_id_legacy_tree",
    ):
        assert for_artifact(artifact_id) is not None, artifact_id


def test_the_agent_of_an_event_is_the_catalogues_not_the_parsers(tmp_path: Path) -> None:
    events = parse_task(
        cline_task(tmp_path, "api_conversation_history.json", [{"role": "user", "content": "hi"}]),
        agent="roo_code",
    )
    assert events[0].agent == "roo_code"


def test_only_the_generic_readers_say_a_record_is_uninterpreted() -> None:
    """The mark is what tells the two populations of `unparsed.record` apart.

    One is a record nothing could read, which is a defect in the evidence. The other is a
    record that was read out of a store or a log nobody has mapped, which is intact evidence
    with no reading yet. The case counts them separately by looking for this phrase, so a
    parser that used the words for a record it actually failed on would file a broken line
    among the hundred thousand rows an analyst is not expected to open.
    """
    package = Path(__file__).resolve().parents[2] / "src" / "agentforensics" / "parsers"
    # By the name rather than by the phrase, because both readers build their sentence out
    # of the constant, which is the point: one place says the words and everything else
    # that has to recognise them, the case counts included, reads them from there.
    writers = sorted(
        module.name
        for module in package.glob("*.py")
        if "UNINTERPRETED_MARK" in module.read_text(encoding="utf-8")
    )

    # structured_generic is where the whole-document reading lives, so the three document
    # formats that use it (JSON, YAML and TOML) say the words through it rather than each
    # spelling them out, and the list below is shorter than the number of readers by
    # design.
    assert writers == [
        "jsonl_generic.py",
        "leveldb_store.py",
        "lmdb_generic.py",
        "prose_document.py",
        # Not a generic reader. It maps the three declarations a shell script states
        # unambiguously and says the mark on every other line, because a reader that
        # decided what an arbitrary line of shell means would be writing a shell.
        "shell_script.py",
        "sqlite_generic.py",
        "structured_generic.py",
        "text_log.py",
        "windsurf_cascade.py",
    ], writers
    assert UNINTERPRETED_MARK in JSONL_UNINTERPRETED


def test_every_parser_claims_at_least_one_artifact_the_catalogue_has() -> None:
    """A reader that claims nothing is a reader that was never reached.

    This is the sharp end of the check below it, and the case that one cannot see: a set
    with one name in it, misspelled, claims nothing at all and looks exactly like a set
    that happens to name no catalogue entry. Asking the parser rather than reading its set
    needs no rule about which sets are which and no guess about shapes, because handles()
    is the same question the ingest asks.

    What goes wrong when this fails is quiet in the way this project must not be: the
    artifact the reader meant to read falls through to a generic floor or to no parser at
    all, its file arrives in the case as an inventory row, and the reader sits in PARSERS
    looking as though it were doing something.
    """
    from agentforensics.catalog import load_catalogue

    catalogue = load_catalogue(Path(__file__).resolve().parents[2] / "catalog")
    idle = [
        parser.name
        for parser in PARSERS
        if not any(parser.handles(artifact.id) for artifact in catalogue.artifacts)
    ]
    assert not idle, (
        "these readers are in PARSERS and claim no catalogue entry, so nothing reaches "
        f"them and nothing says so: {idle}"
    )


def test_no_parser_declares_an_artifact_the_catalogue_does_not_have() -> None:
    """A typo in one of these sets is silent in exactly the way this project must not be.

    Every reader here is handed an artifact id and decides from a set written out in its
    own module, which is how a parser can be read without the catalogue open. The cost is
    that a name which no longer exists, or never did, claims nothing at all: the artifact
    it meant to read falls through to a generic floor or to no parser, the file arrives in
    the case as an inventory row, and nothing anywhere says a reader was pointed at a name
    that is not there. Twenty-two sets across nineteen modules are in that position.

    The opposite direction is already covered: the catalogue's parser field is asserted
    against the readers that claim each entry. This is the half that was missing, and it is
    found by walking the package rather than by listing the sets, so a set somebody adds
    tomorrow is covered without anybody remembering this test.
    """
    import importlib
    import pkgutil

    import agentforensics.parsers as package
    from agentforensics.catalog import load_catalogue

    catalogue = Path(__file__).resolve().parents[2] / "catalog"
    known = {artifact.id for artifact in load_catalogue(catalogue).artifacts}
    wrong: list[str] = []
    for module_info in sorted(pkgutil.iter_modules(package.__path__), key=lambda m: m.name):
        module = importlib.import_module(f"agentforensics.parsers.{module_info.name}")
        for name in dir(module):
            if not name.isupper():
                continue
            value = getattr(module, name)
            if not isinstance(value, (frozenset, set, dict, tuple)):
                continue
            items = list(value.keys() if isinstance(value, dict) else value)
            if not items or not all(isinstance(item, str) for item in items):
                continue
            # Which sets are artifact-id sets is decided by the catalogue rather than by a
            # shape rule. An event kind is spelled the same way an artifact id is, so a
            # rule about dots would have flagged every kind in the package; a set that
            # names no catalogue entry at all is not one of these sets and is passed over.
            # The cost is that a set whose every name is wrong goes unnoticed here, and
            # the alternative was a test that cried wolf on its first run. That case is
            # the one the test above catches, by asking the parser instead of its set.
            if not any(item in known for item in items):
                continue
            missing = sorted(item for item in items if item not in known)
            wrong.extend(f"{module_info.name}.{name}: {item}" for item in missing)

    assert not wrong, (
        "these readers name an artifact the catalogue does not have, so they claim nothing "
        f"and nothing says so: {wrong}"
    )


def test_every_generic_reader_named_is_a_reader_that_ships() -> None:
    """The set that says which readings are thin, held against the readers there are.

    It is read by the generated support page, which tells somebody how completely an
    agent is read before they conclude anything from an empty result. A name that has
    been renamed away would quietly move an agent from "read at the floor" to "read",
    which is the one direction that matters.
    """
    shipped = {parser.name for parser in PARSERS}
    assert shipped >= GENERIC_READERS, sorted(GENERIC_READERS - shipped)


def test_every_entry_handed_to_another_tool_is_real_and_still_unread() -> None:
    """The table that says "somebody else's reader is better", held to both halves.

    An id that left the catalogue would leave an excuse standing for nothing, and an entry
    that gained a reader here would be described to a reader of the support page as handed
    over when it is not. Both are the same defect as a stale comment, and this project has
    paid for enough of those.
    """
    from agentforensics.catalog import load_catalogue

    catalogue = load_catalogue(Path(__file__).resolve().parents[2] / "catalog")
    known = {artifact.id for artifact in catalogue.artifacts}
    for artifact_id, reason in HANDED_OVER.items():
        assert artifact_id in known, f"{artifact_id} is not in the catalogue"
        assert for_artifact(artifact_id) is None, (
            f"{artifact_id} is described as handed to another tool and a reader in this "
            "suite now claims it"
        )
        assert reason.strip(), artifact_id


def test_a_readable_artifact_is_read_or_says_why_not() -> None:
    """The quiet way this project's coverage would stop growing.

    A catalogue entry in a format the suite already reads, claimed by no parser, produces
    one inventory row in a case and nothing else. That is indistinguishable from an agent
    that wrote nothing, and it is the state a hundred and ninety artifacts were in when the
    parsers were started. What stops it coming back is not remembering: it is that adding
    such an entry fails here until somebody either reads it or writes down why not.

    Both directions, so a reason that stops being needed has to be removed rather than
    sitting here making the check look narrower than it is.
    """
    from agentforensics.catalog import load_catalogue

    catalogue = load_catalogue(Path(__file__).resolve().parents[2] / "catalog")
    unread = {
        artifact.id
        for artifact in catalogue.artifacts
        if artifact.format in READABLE_FORMATS
        and artifact.sensitivity != "secret"
        and for_artifact(artifact.id) is None
    }
    assert unread == set(READABLE_AND_UNREAD), {
        "readable, read by nothing, and no reason given": sorted(unread - set(READABLE_AND_UNREAD)),
        "now read, or gone from the catalogue": sorted(set(READABLE_AND_UNREAD) - unread),
    }
    known = {artifact.id for artifact in catalogue.artifacts}
    for artifact_id, excused in READABLE_AND_UNREAD.items():
        assert excused.reason.strip(), artifact_id
        for other in excused.covered_by:
            assert other in known, (
                f"{artifact_id} is excused because {other} carries its evidence, and the "
                "catalogue has no such entry"
            )
            assert for_artifact(other) is not None, (
                f"{artifact_id} is excused because {other} carries its evidence, and "
                "nothing reads that either, so the evidence is in no case at all"
            )


def test_the_unfinished_readings_still_describe_something_that_exists() -> None:
    """The one list on the support page that is a promise rather than a decision.

    Everything else in coverage.py says why an entry is not read, and a stale line there
    makes the tool look less capable than it is. This one says an entry is read and not
    read completely, which makes it look more capable than it is if the sentence outlives
    the file it is about. So both halves are held: the entry is still in the catalogue, and
    the sentence is not empty.

    Not asserted: that the work is still unfinished. Nothing in the code can know that, and
    a check that pretended to would be the kind of comment this project keeps paying for.
    Finishing one of these means deleting its line here, and the page is generated from
    this table, so the deletion is what removes the claim.
    """
    from agentforensics.catalog import load_catalogue

    catalogue = load_catalogue(Path(__file__).resolve().parents[2] / "catalog")
    known = {artifact.id for artifact in catalogue.artifacts}
    for artifact_id, reason in UNFINISHED.items():
        assert artifact_id in known, (
            f"{artifact_id} is named on the support page as a reading somebody started, "
            "and the catalogue has no such entry any more"
        )
        assert reason.strip(), artifact_id


def test_a_withheld_artifact_is_the_only_thing_excused_without_a_reason() -> None:
    """The one class that needs no individual justification, held to its own rule.

    An entry marked secret has its content withheld by the collector, so a parser would be
    handed a file that is not there. That is a good reason and it applies to every one of
    them equally, which is why they are excused as a class. This asserts the class is what
    it says it is: every excused entry is a credential store, so the exemption cannot
    quietly widen to cover a transcript somebody marked secret by mistake.
    """
    from agentforensics.catalog import load_catalogue

    catalogue = load_catalogue(Path(__file__).resolve().parents[2] / "catalog")
    wrong = [
        artifact.id
        for artifact in catalogue.artifacts
        if artifact.sensitivity == "secret" and artifact.category != "credentials"
    ]
    assert not wrong, (
        "these entries withhold their content and are not credential stores, so they are "
        f"excused from being read for a reason that does not apply to them: {wrong}"
    )


def test_the_documented_coverage_is_the_one_the_code_has() -> None:
    """The count in the architecture document, held against what is actually in the box.

    Three numbers stand in one sentence of `docs/ARCHITECTURE.md` and in its German
    sibling: how many reader modules there are, how many catalogue entries they read, and
    how many entries the catalogue has. All three were true the day somebody typed them,
    and the English sentence had been wrong for two commits when this test was written
    while the German one beside it was right, which is the shape of defect this project
    keeps finding: a claim in one place about another place, written once and never
    checked again.

    Counting them here rather than generating the sentence keeps the paragraph prose, which
    is what the rest of the document is, and still makes the numbers fail rather than age.
    """
    import re

    from agentforensics.catalog import load_catalogue

    root = Path(__file__).resolve().parents[2]
    catalogue = load_catalogue(root / "catalog")
    counted = (
        len(PARSERS),
        sum(1 for artifact in catalogue.artifacts if for_artifact(artifact.id) is not None),
        len(catalogue.artifacts),
    )

    # The two sentences, in the two languages the docs are written in. Both are matched
    # against one set of numbers, so the pair cannot drift apart either.
    written = {
        "docs/ARCHITECTURE.md": r"(\d+) modules read (\d+) of the catalogue's (\d+) artifacts",
        "docs/ARCHITECTURE.de.md": r"(\d+) Module lesen (\d+) der (\d+) Katalogartefakte",
    }
    for name, pattern in written.items():
        # The documents wrap their paragraphs, so a sentence can hold a newline anywhere.
        text = " ".join((root / name).read_text(encoding="utf-8").split())
        found = re.search(pattern, text)
        assert found is not None, (
            f"{name} no longer states its coverage in the shape a test can read"
        )
        assert tuple(int(number) for number in found.groups()) == counted, (
            f"{name} says {found.group(0)!r} and the code has "
            f"{counted[0]} modules reading {counted[1]} of {counted[2]} artifacts"
        )
