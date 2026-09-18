"""Tests for the Hermes parser, against a store built from the vendor's own CREATE TABLE.

The schema here is copied out of the vendor's session-storage document rather than reduced
to the columns the parser reads, because the columns it does not read are where the traps
are: `active` decides whether a turn is pre-compaction history or live, `reasoning` holds a
reply that `content` does not, and `codex_message_items` holds one that neither does.

What is asserted is mostly what the parser must refuse to do: collapse the two compaction
generations, show an assistant turn as silence because the reply was in another column,
present the system prompt at a scope wider than the session it applied to, claim a tool did
something the vendor documents nothing about, or lose a row whose role it does not know.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from agentforensics.parsers import for_artifact
from agentforensics.parsers.base import ParseContext

# Straight from the vendor's document, abridged there and abridged identically here. The
# columns the parser reads are all present; so are the ones it must not misread.
SESSIONS_SCHEMA = """CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    user_id TEXT,
    model TEXT,
    model_config TEXT,
    system_prompt TEXT,
    parent_session_id TEXT,
    started_at REAL NOT NULL,
    ended_at REAL,
    end_reason TEXT,
    message_count INTEGER DEFAULT 0,
    tool_call_count INTEGER DEFAULT 0,
    input_tokens INTEGER DEFAULT 0,
    output_tokens INTEGER DEFAULT 0,
    title TEXT,
    cwd TEXT,
    git_branch TEXT,
    git_repo_root TEXT
)"""

MESSAGES_SCHEMA = """CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    role TEXT NOT NULL,
    content TEXT,
    tool_call_id TEXT,
    tool_calls TEXT,
    tool_name TEXT,
    timestamp REAL NOT NULL,
    token_count INTEGER,
    finish_reason TEXT,
    reasoning TEXT,
    reasoning_content TEXT,
    codex_message_items TEXT,
    active INTEGER DEFAULT 1,
    compacted INTEGER DEFAULT 0
)"""

SESSION = "01J0SESSION0000000000"
# 2026-09-06T09:00:00Z, as the Unix epoch float the vendor documents.
STARTED = 1788685200.0
PROMPT = "# House rules\nNever push to main."


def session_row(**overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": SESSION,
        "source": "cli",
        "user_id": "",
        "model": "example-model-1",
        "model_config": None,
        "system_prompt": PROMPT,
        "parent_session_id": None,
        "started_at": STARTED,
        "ended_at": None,
        "end_reason": None,
        "message_count": 4,
        "tool_call_count": 1,
        "input_tokens": 120,
        "output_tokens": 80,
        "title": "fix the build",
        "cwd": "/home/alice/src/app",
        "git_branch": "main",
        "git_repo_root": "/home/alice/src/app",
    }
    row.update(overrides)
    return row


def message_row(**overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "session_id": SESSION,
        "role": "user",
        "content": "check the lockfile",
        "tool_call_id": None,
        "tool_calls": None,
        "tool_name": None,
        "timestamp": STARTED + 1,
        "token_count": 6,
        "finish_reason": None,
        "reasoning": None,
        "reasoning_content": None,
        "codex_message_items": None,
        "active": 1,
        "compacted": 0,
    }
    row.update(overrides)
    return row


def store(
    path: Path,
    sessions: list[dict[str, Any]] | None = None,
    messages: list[dict[str, Any]] | None = None,
    *,
    extra_table: str | None = None,
) -> Path:
    connection = sqlite3.connect(path)
    try:
        connection.execute(SESSIONS_SCHEMA)
        connection.execute(MESSAGES_SCHEMA)
        for row in sessions if sessions is not None else [session_row()]:
            keys = ", ".join(row)
            marks = ", ".join("?" for _ in row)
            connection.execute(
                f"INSERT INTO sessions ({keys}) VALUES ({marks})",  # noqa: S608
                tuple(row.values()),
            )
        for row in messages or []:
            keys = ", ".join(row)
            marks = ", ".join("?" for _ in row)
            connection.execute(
                f"INSERT INTO messages ({keys}) VALUES ({marks})",  # noqa: S608
                tuple(row.values()),
            )
        if extra_table:
            connection.executescript(extra_table)
        connection.commit()
    finally:
        connection.close()
    return path


def parse(path: Path) -> list:
    parser = for_artifact("hermes.state_db")
    assert parser is not None
    assert parser.name == "hermes", "the store has a verified schema, so it is not generic"
    return list(
        parser.parse(
            ParseContext(
                bundle_uuid="b1",
                original_path="~/.hermes/state.db",
                local_path=path,
                sha256="aa",
                artifact_id="hermes.state_db",
                agent="hermes",
                user="alice",
            )
        )
    )


def kinds(events: list) -> list[str]:
    return [event.kind for event in events]


# ------------------------------------------------------------------------- the header


def test_the_session_row_carries_the_context_every_turn_inherits(tmp_path: Path) -> None:
    """A message row has no working directory, no model and no platform of its own."""
    events = parse(store(tmp_path / "state.db", messages=[message_row()]))
    start = next(event for event in events if event.kind == "session.start")

    assert start.ts_utc == "2026-09-06T09:00:00.000000Z"
    assert start.ts_source == "started_at, documented as a Unix epoch float"
    assert start.parse_problem is None, (
        "the vendor states the unit, so reading it is not an assumption worth a note"
    )
    assert start.session_id == SESSION
    assert start.project_path == "/home/alice/src/app"
    assert start.git_branch == "main"
    assert start.payload["source"] == "cli"
    assert start.payload["models"] == [{"model": "example-model-1"}]

    prompt = next(event for event in events if event.kind == "user.prompt")
    assert prompt.project_path == "/home/alice/src/app", "inherited from the session row"
    assert prompt.git_branch == "main"
    assert prompt.payload["models"] == [{"model": "example-model-1"}]


def test_a_session_driven_from_a_chat_platform_says_so(tmp_path: Path) -> None:
    """The evidence no other agent's store carries.

    The vendor documents `source` as the platform tag and `user_id` as the principal on the
    other end. A session somebody drove from a messaging platform is a different finding
    from one driven at the console, and it travels on every event of that session so a
    filtered timeline cannot lose it.
    """
    events = parse(
        store(
            tmp_path / "state.db",
            sessions=[session_row(source="telegram", user_id="123456789")],
            messages=[message_row()],
        )
    )
    for event in events:
        if event.kind in ("session.start", "user.prompt"):
            assert event.payload["source"] == "telegram"
            assert event.payload["user_id"] == "123456789"


def test_a_compression_split_names_the_session_that_holds_the_earlier_turns(
    tmp_path: Path,
) -> None:
    """A parent session means the history before the split is in other rows, and an analyst
    reading one session would otherwise conclude the conversation began there."""
    events = parse(
        store(tmp_path / "state.db", sessions=[session_row(parent_session_id="01J0PARENT")])
    )
    start = next(event for event in events if event.kind == "session.start")
    assert start.payload["parent_session_id"] == "01J0PARENT"
    assert "01J0PARENT" in start.payload["text"]


def test_an_ended_session_gets_its_own_event_with_its_own_time(tmp_path: Path) -> None:
    events = parse(
        store(
            tmp_path / "state.db",
            sessions=[session_row(ended_at=STARTED + 3600, end_reason="user_exit")],
        )
    )
    end = next(event for event in events if event.kind == "session.end")
    assert end.ts_utc == "2026-09-06T10:00:00.000000Z"
    assert end.ts_source == "ended_at, documented as a Unix epoch float"
    assert end.payload["end_reason"] == "user_exit"


# ------------------------------------------------------------------ the system prompt


def test_the_system_prompt_is_an_instruction_at_session_scope(tmp_path: Path) -> None:
    """What the agent was told to obey, and how widely.

    This prompt is a database row rather than a file, and it applied to one session. The
    managed, user and project scopes all describe files that apply more widely, so
    presenting it at any of them would say the agent was told this everywhere. The scope
    `session` is in the instruction surface's own vocabulary for exactly this.
    """
    events = parse(store(tmp_path / "state.db"))
    instruction = next(event for event in events if event.kind == "instruction.source")

    assert instruction.payload["text"] == PROMPT
    assert instruction.payload["scope"] == "session"
    assert instruction.payload["instructions"] == [
        {"path": "~/.hermes/state.db#sessions.system_prompt", "scope": "session"}
    ]
    assert instruction.payload["in_database"] is True
    assert instruction.session_id == SESSION
    # No time of its own: the session.start event carries the session's clock, and a second
    # copy here would present it as the instruction's own.
    assert instruction.ts_utc is None
    assert instruction.ts_precision == "absent"


def test_a_session_without_a_system_prompt_produces_no_instruction(tmp_path: Path) -> None:
    """An absent prompt is absent. An empty instruction row would be an invention."""
    events = parse(store(tmp_path / "state.db", sessions=[session_row(system_prompt=None)]))
    assert "instruction.source" not in kinds(events)


def test_a_system_role_message_is_an_instruction_too(tmp_path: Path) -> None:
    events = parse(
        store(
            tmp_path / "state.db",
            messages=[message_row(role="system", content="Obey the deployment checklist.")],
        )
    )
    rows = [
        event
        for event in events
        if event.kind == "instruction.source" and event.payload.get("file") == "messages.content"
    ]
    assert len(rows) == 1
    assert rows[0].payload["scope"] == "session"
    assert rows[0].payload["text"] == "Obey the deployment checklist."


# --------------------------------------------------------------------- the turn stream


def test_a_reasoning_only_reply_is_not_an_empty_turn(tmp_path: Path) -> None:
    """The vendor documents this case and it is the one that reads as silence.

    A clean stop with reasoning and no content leaves `content` empty, and the answer the
    user saw is the reasoning text. A parser that only read `content` would show a turn
    where the agent said nothing, which is the same wrong answer as showing no turn at all.
    """
    events = parse(
        store(
            tmp_path / "state.db",
            messages=[
                message_row(
                    role="assistant",
                    content="",
                    finish_reason="stop",
                    reasoning="the lockfile is out of date, so the install fails",
                )
            ],
        )
    )
    thinking = next(event for event in events if event.kind == "assistant.thinking")
    assert "lockfile is out of date" in thinking.payload["text"]
    assert thinking.payload["reasoning_only_reply"] is True
    assert thinking.payload["reasoning_column"] == "reasoning"
    assert "assistant.text" not in kinds(events), (
        "an empty content column must not become an empty assistant turn"
    )


def test_a_reply_that_lives_only_in_the_items_column_is_still_a_reply(tmp_path: Path) -> None:
    """The vendor states a final reply can live only in codex_message_items."""
    events = parse(
        store(
            tmp_path / "state.db",
            messages=[
                message_row(
                    role="assistant",
                    content="",
                    codex_message_items=json.dumps([{"text": "lockfile regenerated"}]),
                )
            ],
        )
    )
    reply = next(event for event in events if event.kind == "assistant.text")
    assert reply.payload["text"] == "lockfile regenerated"
    assert reply.payload["text_source"] == "codex_message_items"
    assert "codex_message_items" in (reply.parse_problem or ""), (
        "where the text came from has to travel with it"
    )


def test_a_reply_and_its_reasoning_are_two_events(tmp_path: Path) -> None:
    events = parse(
        store(
            tmp_path / "state.db",
            messages=[
                message_row(
                    role="assistant",
                    content="regenerating the lockfile",
                    reasoning_content="npm ci failed, so the lockfile is stale",
                )
            ],
        )
    )
    assert kinds(events).count("assistant.text") == 1
    thinking = next(event for event in events if event.kind == "assistant.thinking")
    assert thinking.payload["reasoning_column"] == "reasoning_content"
    assert "reasoning_only_reply" not in thinking.payload, "there is a reply as well"
    locators = {event.provenance.locator for event in events if event.kind.startswith("assistant")}
    assert len(locators) == 2, "two events from one row need two locators, or their ids collide"


def test_a_tool_call_is_carried_whole_and_nothing_is_claimed_about_it(tmp_path: Path) -> None:
    """The vendor documents the column as a list of tool call objects and names no tools.

    So the arguments are in the event and no command, file or network facet is derived: a
    path guessed out of an unread tool shape would put files in the facet that the agent may
    never have touched.
    """
    events = parse(
        store(
            tmp_path / "state.db",
            messages=[
                message_row(
                    role="assistant",
                    content="",
                    tool_calls=json.dumps(
                        [
                            {
                                "id": "call_1",
                                "type": "function",
                                "function": {
                                    "name": "shell",
                                    "arguments": '{"command": "npm ci"}',
                                },
                            }
                        ]
                    ),
                )
            ],
        )
    )
    call = next(event for event in events if event.kind == "tool.call")
    assert call.payload["tool"] == "shell"
    assert call.payload["tool_use_id"] == "call_1"
    assert call.payload["input"] == {"command": "npm ci"}
    assert "commands" not in call.payload, "no command facet from an unread tool shape"
    assert "files" not in call.payload
    assert "command.exec" not in kinds(events)


def test_two_tool_calls_in_one_row_are_two_events(tmp_path: Path) -> None:
    events = parse(
        store(
            tmp_path / "state.db",
            messages=[
                message_row(
                    role="assistant",
                    content="",
                    tool_calls=json.dumps(
                        [
                            {"function": {"name": "read", "arguments": "{}"}},
                            {"function": {"name": "write", "arguments": "{}"}},
                        ]
                    ),
                )
            ],
        )
    )
    calls = [event for event in events if event.kind == "tool.call"]
    assert [event.payload["tool"] for event in calls] == ["read", "write"]
    assert len({event.provenance.locator for event in calls}) == 2


def test_a_truncated_tool_call_column_is_kept_as_evidence(tmp_path: Path) -> None:
    """A killed process leaves half a JSON string, and half an argument list is still
    evidence of what the agent was about to do."""
    events = parse(
        store(
            tmp_path / "state.db",
            messages=[
                message_row(role="assistant", content="", tool_calls='[{"function": {"name'),
            ],
        )
    )
    call = next(event for event in events if event.kind == "tool.call")
    assert call.payload["input"]["tool_calls"] == '[{"function": {"name'
    assert "did not parse" in (call.parse_problem or "")


def test_a_tool_result_names_the_call_it_answers(tmp_path: Path) -> None:
    events = parse(
        store(
            tmp_path / "state.db",
            messages=[
                message_row(
                    role="tool",
                    content="lockfile out of date",
                    tool_call_id="call_1",
                    tool_name="shell",
                )
            ],
        )
    )
    result = next(event for event in events if event.kind == "tool.result")
    assert result.payload["tool_use_id"] == "call_1"
    assert result.payload["tool"] == "shell"
    assert result.payload["text"] == "lockfile out of date"
    assert "is_error" not in result.payload, (
        "the documented columns carry no error signal, so none is claimed"
    )


def test_a_role_this_parser_does_not_know_keeps_its_row(tmp_path: Path) -> None:
    events = parse(
        store(tmp_path / "state.db", messages=[message_row(role="developer", content="hello")])
    )
    unknown = next(event for event in events if event.kind == "unparsed.record")
    assert unknown.raw["role"] == "developer"
    assert unknown.raw["content"] == "hello"
    assert "developer" in (unknown.parse_problem or "")
    assert unknown.ts_utc is not None, "an unmapped row still belongs on the timeline"


# ---------------------------------------------------------------------- compaction


def test_the_two_compaction_generations_are_both_kept_and_told_apart(tmp_path: Path) -> None:
    """The vendor's own instruction: do not delete the archive rows as duplicates.

    In-place compaction archives the old rows with active=0 and re-inserts the retained
    context with active=1, so a protected message legitimately appears twice with identical
    content and timestamp. Collapsing them would delete the pre-compaction history from the
    case, which is usually the history somebody is looking for.
    """
    same = {"role": "user", "content": "check the lockfile", "timestamp": STARTED + 1}
    events = parse(
        store(
            tmp_path / "state.db",
            messages=[
                message_row(**same, active=0, compacted=1),
                message_row(**same, active=1),
            ],
        )
    )
    prompts = [event for event in events if event.kind == "user.prompt"]
    assert len(prompts) == 2, "identical rows in two generations are two records"
    assert [event.payload["compaction_generation"] for event in prompts] == ["archived", "live"]
    assert len({event.event_id for event in prompts}) == 2, "two records need two ids"
    archived = prompts[0]
    assert "compaction archive" in (archived.parse_problem or "")
    assert archived.payload["compacted"] == 1


def test_a_store_without_the_active_column_does_not_claim_a_generation(tmp_path: Path) -> None:
    """An older database has no such column, and absent has to read as absent.

    Calling a row live when the store never said so would be an invention, and it is the
    kind that matters: it would say a turn survived a compaction that may have archived it.
    """
    path = tmp_path / "state.db"
    connection = sqlite3.connect(path)
    try:
        connection.execute(SESSIONS_SCHEMA)
        connection.execute(
            "CREATE TABLE messages (id INTEGER PRIMARY KEY, session_id TEXT, role TEXT, "
            "content TEXT, timestamp REAL NOT NULL)"
        )
        row = session_row()
        connection.execute(
            f"INSERT INTO sessions ({', '.join(row)}) VALUES "  # noqa: S608
            f"({', '.join('?' for _ in row)})",
            tuple(row.values()),
        )
        connection.execute(
            "INSERT INTO messages (session_id, role, content, timestamp) VALUES (?,?,?,?)",
            (SESSION, "user", "check the lockfile", STARTED + 1),
        )
        connection.commit()
    finally:
        connection.close()

    prompt = next(event for event in parse(path) if event.kind == "user.prompt")
    assert "compaction_generation" not in prompt.payload


# ------------------------------------------------------------------ the rest of the store


def test_a_table_this_parser_does_not_map_is_still_read(tmp_path: Path) -> None:
    """Including the FTS5 shadows, which the catalogue notes can retain message text after
    the messages row was altered. A store half read with the other half absent is the
    failure ADR 0022 exists to prevent."""
    events = parse(
        store(
            tmp_path / "state.db",
            extra_table=(
                "CREATE TABLE state_meta (key TEXT PRIMARY KEY, value TEXT); "
                "INSERT INTO state_meta VALUES ('schema_version', '23')"
            ),
        )
    )
    rows = [
        event
        for event in events
        if event.kind == "unparsed.record" and "state_meta" in str(event.provenance.locator)
    ]
    assert rows, "an unmapped table's rows are evidence, not noise"


def test_a_store_that_will_not_open_becomes_a_record_rather_than_silence(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.db"
    path.write_bytes(b"this is not a database")
    events = parse(path)
    assert len(events) == 1
    assert events[0].kind == "unparsed.record"
    assert events[0].parse_problem
