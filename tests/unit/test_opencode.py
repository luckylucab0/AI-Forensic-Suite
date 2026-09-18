"""Tests for the opencode parser, against a store built like the agent builds one.

The fixture creates the tables with the column names from the vendor's generated migration
and fills the data columns with the record shapes from the vendor's session-message schema.
Both were fetched and read; the parser's module docstring cites them. A fixture invented to
match the parser would test that the parser agrees with itself, which is the failure mode a
schema parser has: it looks right and reads nothing.

What is asserted here is mostly what the parser must refuse to do. It must not drop a table
it has no schema for, because a store half read with the other half absent is the defect
ADR 0022 exists to prevent. It must not collapse the two records a prompt produces. It must
not lose a tool call because two of them sit in one row. And it must not invent a time: the
store writes epoch milliseconds, and the vendor's own schema is what says so.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from agentforensics.parsers import for_artifact
from agentforensics.parsers.base import ParseContext

# The columns the vendor's migration creates, for the three tables this parser maps plus one
# it does not. Written out rather than imported: if the agent changes its schema, this
# fixture stops matching reality and somebody has to come back and look.
SCHEMA = [
    """CREATE TABLE session (
        id TEXT PRIMARY KEY, project_id TEXT NOT NULL, workspace_id TEXT, parent_id TEXT,
        slug TEXT NOT NULL, directory TEXT NOT NULL, path TEXT, title TEXT NOT NULL,
        version TEXT NOT NULL, share_url TEXT, summary_additions INTEGER,
        summary_deletions INTEGER, summary_files INTEGER, summary_diffs TEXT, metadata TEXT,
        cost REAL DEFAULT 0 NOT NULL, tokens_input INTEGER DEFAULT 0 NOT NULL,
        tokens_output INTEGER DEFAULT 0 NOT NULL, tokens_reasoning INTEGER DEFAULT 0 NOT NULL,
        tokens_cache_read INTEGER DEFAULT 0 NOT NULL,
        tokens_cache_write INTEGER DEFAULT 0 NOT NULL, revert TEXT, permission TEXT,
        agent TEXT, model TEXT, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL,
        time_compacting INTEGER, time_archived INTEGER)""",
    """CREATE TABLE session_input (
        id TEXT PRIMARY KEY, session_id TEXT NOT NULL, prompt TEXT NOT NULL,
        delivery TEXT NOT NULL, admitted_seq INTEGER NOT NULL, promoted_seq INTEGER,
        time_created INTEGER NOT NULL)""",
    """CREATE TABLE session_message (
        id TEXT PRIMARY KEY, session_id TEXT NOT NULL, type TEXT NOT NULL,
        seq INTEGER NOT NULL, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL,
        data TEXT NOT NULL)""",
    # The older pair, which the migration still creates and whose data column this parser
    # has not verified.
    """CREATE TABLE message (
        id TEXT PRIMARY KEY, session_id TEXT NOT NULL, time_created INTEGER NOT NULL,
        time_updated INTEGER NOT NULL, data TEXT NOT NULL)""",
]

CREATED = 1788000000000  # epoch milliseconds, which is what the vendor's schema stores
SESSION = "ses_0000000000000001"


def store(path: Path, messages: list[tuple[str, dict]] | None = None) -> Path:
    connection = sqlite3.connect(path)
    try:
        for statement in SCHEMA:
            connection.execute(statement)
        connection.execute(
            "INSERT INTO session (id, project_id, slug, directory, title, version, agent, "
            "model, cost, tokens_input, tokens_output, tokens_reasoning, tokens_cache_read, "
            "tokens_cache_write, time_created, time_updated, share_url, parent_id, "
            "time_archived) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                SESSION,
                "prj_1",
                "fix-the-build",
                "/home/alice/src/app",
                "fix the build",
                "1.2.3",
                "build",
                "example/model-1",
                0.42,
                120,
                80,
                10,
                5,
                2,
                CREATED,
                CREATED + 60000,
                "https://example.org/s/abc",
                "ses_0000000000000000",
                CREATED + 120000,
            ),
        )
        connection.execute(
            "INSERT INTO session_input (id, session_id, prompt, delivery, admitted_seq, "
            "promoted_seq, time_created) VALUES (?,?,?,?,?,?,?)",
            ("inp_1", SESSION, "please fix the build", "cli", 1, 2, CREATED + 1000),
        )
        for index, (kind, data) in enumerate(messages or [], start=1):
            connection.execute(
                "INSERT INTO session_message (id, session_id, type, seq, time_created, "
                "time_updated, data) VALUES (?,?,?,?,?,?,?)",
                (
                    f"msg_{index:016d}",
                    SESSION,
                    kind,
                    index,
                    CREATED + 1000 * index,
                    CREATED + 1000 * index,
                    json.dumps({"id": f"msg_{index:016d}", **data}),
                ),
            )
        connection.execute(
            "INSERT INTO message (id, session_id, time_created, time_updated, data) "
            "VALUES (?,?,?,?,?)",
            ("old_1", SESSION, CREATED, CREATED, json.dumps({"role": "user"})),
        )
        connection.commit()
    finally:
        connection.close()
    return path


def parse(path: Path) -> list:
    parser = for_artifact("opencode.db")
    assert parser is not None
    assert parser.name == "opencode", "a verified parser has to take the store over"
    return list(
        parser.parse(
            ParseContext(
                bundle_uuid="b1",
                original_path="/home/alice/.local/share/opencode/opencode.db",
                local_path=path,
                sha256="aa",
                artifact_id="opencode.db",
                agent="opencode",
                user="alice",
            )
        )
    )


def kinds(events: list) -> list[str]:
    return [event.kind for event in events]


# ------------------------------------------------------------------- the session


def test_the_session_row_carries_what_a_timeline_needs(tmp_path: Path) -> None:
    events = parse(store(tmp_path / "opencode.db"))

    start = next(e for e in events if e.kind == "session.start")
    assert start.session_id == SESSION
    assert start.project_path == "/home/alice/src/app"
    assert start.ts_utc is not None and start.ts_utc.startswith("2026-")
    assert start.ts_source == "time_created"
    assert start.payload["agent_name"] == "build"
    assert start.payload["models"] == [{"model": "example/model-1"}]
    # A fork: the turns it continues from are in another row, so a conversation starting
    # mid-thought is a fork rather than a gap in the collection.
    assert start.payload["parent_session"] == "ses_0000000000000000"
    # A shared conversation left the device.
    assert start.payload["share_url"] == "https://example.org/s/abc"


def test_an_archived_session_ends(tmp_path: Path) -> None:
    events = parse(store(tmp_path / "opencode.db"))

    end = next(e for e in events if e.kind == "session.end")
    assert end.ts_source == "time_archived"
    assert end.session_id == SESSION


def test_the_time_is_read_as_the_vendor_stores_it(tmp_path: Path) -> None:
    """Epoch milliseconds, which opencode's schema says in as many words by naming the type
    DateTimeUtcFromMillis. Read as seconds it would put the session in 1970."""
    events = parse(store(tmp_path / "opencode.db"))

    start = next(e for e in events if e.kind == "session.start")
    # Read as seconds the same number would land in 1970, and a timeline is the one place a
    # wrong reading of a clock survives into a report.
    assert start.ts_utc == "2026-08-29T10:40:00.000000Z"


# -------------------------------------------------------------------- the prompt


def test_a_prompt_is_kept_as_both_records_it_is(tmp_path: Path) -> None:
    """One is a prompt being admitted, with its delivery and sequence; the other is the turn
    as the model saw it. Collapsing them would decide for the analyst which is the evidence.
    """
    events = parse(
        store(
            tmp_path / "opencode.db", [("user", {"type": "user", "text": "please fix the build"})]
        )
    )

    prompts = [e for e in events if e.kind == "user.prompt"]
    assert len(prompts) == 2
    tables = {e.payload["source_table"] for e in prompts}
    assert tables == {"session_input", "session_message"}
    admitted = next(e for e in prompts if e.payload["source_table"] == "session_input")
    assert admitted.payload["delivery"] == "cli"
    assert admitted.payload["promoted_seq"] == 2
    assert {e.event_id for e in prompts}.__len__() == 2


def test_a_prompt_that_was_never_promoted_says_so(tmp_path: Path) -> None:
    """A prompt the agent took and never answered, which no message row would show."""
    path = store(tmp_path / "opencode.db")
    connection = sqlite3.connect(path)
    connection.execute("UPDATE session_input SET promoted_seq = NULL")
    connection.commit()
    connection.close()

    admitted = next(
        e
        for e in parse(path)
        if e.kind == "user.prompt" and e.payload["source_table"] == "session_input"
    )

    assert admitted.payload["promoted_seq"] is None


# --------------------------------------------------------------------- the turns


def test_an_assistant_turn_becomes_one_event_per_content_block(tmp_path: Path) -> None:
    """Two tool calls in one row must not collapse into one event: the id is derived from
    provenance, so the block's index has to be in the locator or the turn loses a call."""
    data = {
        "type": "assistant",
        "agent": "build",
        "model": {"providerID": "example", "modelID": "model-1"},
        "content": [
            {"type": "text", "id": "t1", "text": "running the build"},
            {"type": "reasoning", "id": "r1", "text": "the lockfile looks stale"},
            {
                "type": "tool",
                "id": "call_1",
                "name": "bash",
                "state": {
                    "status": "completed",
                    "input": {"command": "npm run build"},
                    "content": [{"type": "text", "text": "ok"}],
                    "structured": {},
                },
            },
            {
                "type": "tool",
                "id": "call_2",
                "name": "bash",
                "state": {
                    "status": "error",
                    "input": {"command": "npm test"},
                    "content": [{"type": "text", "text": "1 failing"}],
                    "structured": {},
                    "error": {"type": "unknown", "message": "exit 1"},
                },
            },
        ],
        "time": {"created": CREATED},
    }
    events = parse(store(tmp_path / "opencode.db", [("assistant", data)]))

    assert kinds(events).count("assistant.text") == 1
    assert kinds(events).count("assistant.thinking") == 1
    assert kinds(events).count("tool.call") == 2
    assert kinds(events).count("tool.result") == 2
    assert kinds(events).count("command.exec") == 2
    assert len({e.event_id for e in events}) == len(events), "every event id is distinct"
    failed = next(e for e in events if e.kind == "tool.result" and e.payload["is_error"])
    assert "exit 1" in (failed.payload["error"] or "")
    commands = [e.payload["commands"][0]["command"] for e in events if e.kind == "command.exec"]
    assert commands == ["npm run build", "npm test"]


def test_a_shell_message_is_a_command(tmp_path: Path) -> None:
    data = {
        "type": "shell",
        "callID": "call_9",
        "command": "git status",
        "output": "clean",
        "time": {"created": CREATED},
    }
    events = parse(store(tmp_path / "opencode.db", [("shell", data)]))

    command = next(e for e in events if e.kind == "command.exec")
    assert command.payload["commands"][0]["executable"] == "git"
    assert command.payload["commands"][0]["cwd"] == "/home/alice/src/app"
    assert command.payload["output"] == "clean"


def test_a_system_message_is_part_of_the_instruction_surface(tmp_path: Path) -> None:
    """It is the part of a system prompt that is on the endpoint, recorded verbatim by the
    agent rather than reconstructed, so it belongs in the view that answers what the agent
    was told to obey."""
    events = parse(
        store(
            tmp_path / "opencode.db",
            [("system", {"type": "system", "text": "You are a build assistant."})],
        )
    )

    instruction = next(e for e in events if e.kind == "instruction.source")
    assert instruction.payload["text"] == "You are a build assistant."
    assert instruction.payload["scope"] == "session"
    assert instruction.payload["instructions"][0]["scope"] == "session"


def test_a_synthetic_message_is_carried_without_claiming_what_it_means(tmp_path: Path) -> None:
    events = parse(
        store(
            tmp_path / "opencode.db",
            [("synthetic", {"type": "synthetic", "sessionID": SESSION, "text": "interrupted"})],
        )
    )

    synthetic = next(e for e in events if e.payload.get("origin") == "synthetic")
    assert synthetic.payload["text"] == "interrupted"
    assert "not claimed here" in (synthetic.parse_problem or "")


def test_a_model_switch_is_configuration(tmp_path: Path) -> None:
    events = parse(
        store(
            tmp_path / "opencode.db",
            [("model-switched", {"type": "model-switched", "model": "example/model-2"})],
        )
    )

    change = next(e for e in events if e.kind == "config.snapshot")
    assert change.payload["models"] == [{"model": "example/model-2"}]


def test_a_compaction_ends_the_session(tmp_path: Path) -> None:
    events = parse(
        store(
            tmp_path / "opencode.db",
            [
                (
                    "compaction",
                    {"type": "compaction", "reason": "auto", "summary": "so far", "recent": ""},
                )
            ],
        )
    )

    compaction = next(e for e in events if e.kind == "session.end" and e.payload.get("compaction"))
    assert compaction.payload["text"] == "so far"
    assert compaction.payload["reason"] == "auto"


# ------------------------------------------------------- what it refuses to hide


def test_a_table_with_no_verified_schema_is_still_read(tmp_path: Path) -> None:
    """The older message table. A store half read with the other half silently absent is the
    defect the generic reader exists to prevent, and a schema parser must not reintroduce it.
    """
    events = parse(store(tmp_path / "opencode.db"))

    from_old = [e for e in events if (e.provenance.locator or "").startswith("table:message ")]
    assert from_old, "the tables this parser does not map still produce events"
    assert all(e.kind == "unparsed.record" for e in from_old)


def test_a_message_type_the_vendor_added_later_is_kept(tmp_path: Path) -> None:
    events = parse(
        store(tmp_path / "opencode.db", [("time-travel", {"type": "time-travel", "text": "?"})])
    )

    unknown = next(e for e in events if "time-travel" in (e.parse_problem or ""))
    assert unknown.kind == "unparsed.record"
    assert unknown.session_id == SESSION
    # With its time, so it sorts into the timeline where it belongs.
    assert unknown.ts_utc is not None


def test_a_data_column_that_will_not_parse_costs_the_mapping_and_not_the_row(
    tmp_path: Path,
) -> None:
    path = store(tmp_path / "opencode.db", [("user", {"type": "user", "text": "hi"})])
    connection = sqlite3.connect(path)
    connection.execute("UPDATE session_message SET data = '{not json'")
    connection.commit()
    connection.close()

    events = parse(path)

    broken = next(e for e in events if "not valid JSON" in (e.parse_problem or ""))
    assert broken.kind == "unparsed.record"
    assert broken.session_id == SESSION


def test_a_file_that_is_not_a_database_is_an_event(tmp_path: Path) -> None:
    path = tmp_path / "opencode.db"
    path.write_bytes(b"not a database")

    events = parse(path)

    assert len(events) == 1
    assert events[0].kind == "unparsed.record"


def test_reading_the_same_store_twice_gives_the_same_events(tmp_path: Path) -> None:
    path = store(
        tmp_path / "opencode.db",
        [
            ("user", {"type": "user", "text": "hi"}),
            ("shell", {"type": "shell", "command": "ls", "output": ""}),
        ],
    )

    first = [(e.event_id, e.raw_json(), e.payload_json()) for e in parse(path)]
    second = [(e.event_id, e.raw_json(), e.payload_json()) for e in parse(path)]

    assert first == second
