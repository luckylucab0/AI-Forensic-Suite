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
    """Which is recorded as unsupported rather than hidden."""
    assert for_artifact("windsurf.cascade_trajectories") is None
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


def test_codex_event_msg_is_counted_not_mapped(tmp_path: Path) -> None:
    """It mirrors response_item, so mapping both would double every turn.

    Counted and reported once per file instead, which keeps the records accounted for
    without inflating the conversation.
    """
    events = parse_codex(
        codex(
            tmp_path,
            [
                SESSION_META,
                {**CODEX_BASE, "type": "event_msg", "payload": {"type": "agent_message"}},
                {**CODEX_BASE, "type": "event_msg", "payload": {"type": "agent_message"}},
            ],
        )
    )
    kinds = [e.kind for e in events]
    assert kinds.count("assistant.text") == 0, "the mirror must not become a turn"
    summary = [e for e in events if e.payload.get("event_msg_counts")]
    assert len(summary) == 1
    assert summary[0].payload["event_msg_counts"] == {"agent_message": 2}
    assert "not doubled" in summary[0].payload["text"]


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
