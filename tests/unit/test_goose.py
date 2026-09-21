"""Tests for the Goose parser, against a store and a file built the way the agent builds them.

The fixtures use the column names from the CREATE TABLE statements the product executes and
the record shapes from the serde tags on its own message model. Both were fetched and read;
the parser's module docstring cites them. A fixture invented to match the parser would test
that the parser agrees with itself, which is the failure mode a schema parser has: it looks
right and reads nothing.

What is asserted here is mostly what the parser must refuse to do. It must not drop a table
it has no schema for. It must not lose a tool call because two of them sit in one message. It
must not claim an MCP server from a tool's name alone. It must not read epoch seconds as
milliseconds. And it must not lose the two records the product itself hides: a message marked
not user-visible, and a row whose role the product's own reader skips.

Everything in here is synthetic.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from agentforensics.parsers import for_artifact
from agentforensics.parsers.base import ParseContext

# The tables the product creates, written out rather than imported: if the agent changes its
# schema, this fixture stops matching reality and somebody has to come back and look. The
# four mapped ones plus the usage ledger, which the parser deliberately does not map.
SCHEMA = [
    """CREATE TABLE schema_version (
        version INTEGER PRIMARY KEY, applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""",
    """CREATE TABLE sessions (
        id TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '',
        user_set_name BOOLEAN DEFAULT FALSE, session_type TEXT NOT NULL DEFAULT 'user',
        working_dir TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, extension_data TEXT DEFAULT '{}',
        total_tokens INTEGER, input_tokens INTEGER, output_tokens INTEGER,
        cache_read_tokens INTEGER, cache_write_tokens INTEGER, accumulated_total_tokens INTEGER,
        accumulated_input_tokens INTEGER, accumulated_output_tokens INTEGER,
        accumulated_cache_read_tokens INTEGER, accumulated_cache_write_tokens INTEGER,
        accumulated_cost REAL, schedule_id TEXT, recipe_json TEXT, user_recipe_values_json TEXT,
        provider_name TEXT, model_config_json TEXT, goose_mode TEXT NOT NULL DEFAULT 'auto',
        archived_at TIMESTAMP, project_id TEXT, parent_session_id TEXT)""",
    """CREATE TABLE messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT, message_id TEXT,
        session_id TEXT NOT NULL REFERENCES sessions(id), role TEXT NOT NULL,
        content_json TEXT NOT NULL, created_timestamp INTEGER NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, tokens INTEGER, metadata_json TEXT)""",
    """CREATE TABLE threads (
        id TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT 'New Chat',
        user_set_name BOOLEAN DEFAULT FALSE, working_dir TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, archived_at TIMESTAMP,
        metadata_json TEXT DEFAULT '{}')""",
    """CREATE TABLE thread_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        thread_id TEXT NOT NULL REFERENCES threads(id), session_id TEXT, message_id TEXT,
        role TEXT NOT NULL, content_json TEXT NOT NULL, created_timestamp INTEGER NOT NULL,
        metadata_json TEXT DEFAULT '{}')""",
    # The ledger the parser does not map: the columns are known and the event model has no
    # kind for a per-request token and cost row.
    """CREATE TABLE usage_ledger (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT NOT NULL REFERENCES sessions(id), created_timestamp INTEGER NOT NULL,
        model TEXT, input_tokens INTEGER, output_tokens INTEGER, total_tokens INTEGER,
        cache_read_tokens INTEGER, cache_write_tokens INTEGER, cost REAL, cost_source TEXT,
        is_compaction INTEGER DEFAULT 0)""",
]

SESSION = "01JEXAMPLE0000000000000001"
WORKING_DIR = "/home/alice/src/app"
# Epoch seconds, which is what the vendor's own comment beside the ordering query says the
# message column holds.
CREATED = 1788000000
CREATED_AT = "2026-08-29T10:40:00+00:00"

# The enabled-extension state a session carries, under the versioned key the product builds.
# One server and one built-in, so the MCP reading has both cases to tell apart.
EXTENSION_DATA: dict[str, Any] = {
    "enabled_extensions.v0": {
        "extensions": [
            {
                "type": "stdio",
                "name": "ticketing",
                "description": "",
                "cmd": "ticketing-mcp",
                "args": [],
            },
            {"type": "builtin", "name": "developer", "description": ""},
        ]
    }
}


def store(
    path: Path,
    messages: list[tuple[str, list[dict[str, Any]], dict[str, Any]]] | None = None,
    *,
    recipe: dict[str, Any] | None = None,
    archived: str | None = None,
) -> Path:
    connection = sqlite3.connect(path)
    try:
        for statement in SCHEMA:
            connection.execute(statement)
        connection.execute(
            "INSERT INTO sessions (id, name, description, session_type, working_dir, "
            "created_at, updated_at, extension_data, input_tokens, output_tokens, "
            "total_tokens, accumulated_cost, provider_name, model_config_json, goose_mode, "
            "archived_at, parent_session_id, recipe_json) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                SESSION,
                "fix the build",
                "fix the build",
                "user",
                WORKING_DIR,
                CREATED_AT,
                CREATED_AT,
                json.dumps(EXTENSION_DATA),
                120,
                80,
                200,
                0.42,
                "example_provider",
                json.dumps({"model_name": "model-1", "toolshim": False}),
                "approve",
                archived,
                "01JEXAMPLE0000000000000000",
                json.dumps(recipe) if recipe else None,
            ),
        )
        for index, (role, content, metadata) in enumerate(messages or [], start=1):
            connection.execute(
                "INSERT INTO messages (message_id, session_id, role, content_json, "
                "created_timestamp, metadata_json) VALUES (?,?,?,?,?,?)",
                (
                    f"msg_{index:04d}",
                    SESSION,
                    role,
                    json.dumps(content),
                    CREATED + index,
                    json.dumps(metadata),
                ),
            )
        connection.execute(
            "INSERT INTO usage_ledger (session_id, created_timestamp, model, input_tokens, "
            "output_tokens, total_tokens, cost) VALUES (?,?,?,?,?,?,?)",
            (SESSION, CREATED, "model-1", 120, 80, 200, 0.42),
        )
        connection.commit()
    finally:
        connection.close()
    return path


def legacy(path: Path, lines: list[Any]) -> Path:
    path.write_text(
        "".join((line if isinstance(line, str) else json.dumps(line)) + "\n" for line in lines),
        encoding="utf-8",
    )
    return path


def header_line(**extra: Any) -> dict[str, Any]:
    """The metadata line the product reads first, in the shape its session struct has."""
    return {
        "id": "ignored-the-product-uses-the-file-stem",
        "description": "fix the build",
        "working_dir": WORKING_DIR,
        "created_at": CREATED_AT,
        "updated_at": CREATED_AT,
        "extension_data": EXTENSION_DATA,
        "message_count": 2,
        "total_tokens": 200,
        "input_tokens": 120,
        "output_tokens": 80,
        "provider_name": "example_provider",
        "goose_mode": "approve",
        **extra,
    }


def message_line(role: str, content: list[dict[str, Any]], **metadata: Any) -> dict[str, Any]:
    return {"id": None, "role": role, "created": CREATED, "content": content, "metadata": metadata}


def parse(path: Path, artifact_id: str = "goose.sessions_db") -> list:
    parser = for_artifact(artifact_id)
    assert parser is not None
    assert parser.name == "goose", "a verified parser has to take the store over"
    return list(
        parser.parse(
            ParseContext(
                bundle_uuid="b1",
                original_path=f"/home/alice/.local/share/goose/sessions/{path.name}",
                local_path=path,
                sha256="aa",
                artifact_id=artifact_id,
                agent="goose",
                user="alice",
            )
        )
    )


def kinds(events: list) -> list[str]:
    return [event.kind for event in events]


# ------------------------------------------------------------------- the session


def test_the_session_row_carries_what_a_timeline_needs(tmp_path: Path) -> None:
    events = parse(store(tmp_path / "sessions.db"))

    start = next(e for e in events if e.kind == "session.start" and e.session_id == SESSION)
    assert start.project_path == WORKING_DIR
    assert start.ts_source == "created_at"
    assert start.payload["models"] == [{"model": "example_provider/model-1"}]
    assert start.payload["session_kind"] == "user"
    assert start.payload["goose_mode"] == "approve"
    # A fork: the turns it continues from are in another row.
    assert start.payload["parent_session"] == "01JEXAMPLE0000000000000000"
    assert {entry["name"] for entry in start.payload["extensions"]} == {"ticketing", "developer"}


def test_the_session_mode_is_not_filed_as_a_change(tmp_path: Path) -> None:
    """The column is the mode in force and the product's default is auto, so a
    permission.change would make every default session read as a mid-session bypass."""
    events = parse(store(tmp_path / "sessions.db"))

    assert "permission.change" not in kinds(events)
    start = next(e for e in events if e.kind == "session.start")
    assert start.payload["permissions"][0] == {
        "decision": "in_force",
        "mode": "approve",
        "subject": "every tool call in this session",
    }


def test_a_recipe_is_part_of_the_instruction_surface(tmp_path: Path) -> None:
    """A recipe carries the instructions and the opening prompt the model was given, which
    is the part of a system prompt that is on the endpoint."""
    events = parse(
        store(
            tmp_path / "sessions.db",
            recipe={
                "version": "1.0.0",
                "title": "build fixer",
                "description": "fixes builds",
                "instructions": "Only touch files under src.",
                "prompt": "Start by reading the lockfile.",
            },
        )
    )

    instruction = next(e for e in events if e.kind == "instruction.source")
    assert "Only touch files under src." in instruction.payload["text"]
    assert instruction.payload["scope"] == "session"
    assert instruction.payload["instructions"][0]["scope"] == "session"
    assert instruction.payload["origin"] == "recipe"


def test_an_archived_session_ends(tmp_path: Path) -> None:
    events = parse(store(tmp_path / "sessions.db", archived="2026-08-29T12:00:00+00:00"))

    end = next(e for e in events if e.kind == "session.end")
    assert end.ts_source == "archived_at"
    assert end.session_id == SESSION


def test_a_message_time_is_read_as_the_seconds_the_vendor_stores(tmp_path: Path) -> None:
    """The vendor states it in a comment beside the query that orders by the column. Read as
    milliseconds the same number would put the turn in 1970, and a timeline is the one place
    a wrong reading of a clock survives into a report."""
    events = parse(
        store(tmp_path / "sessions.db", [("user", [{"type": "text", "text": "hi"}], {})])
    )

    prompt = next(e for e in events if e.kind == "user.prompt")
    assert prompt.ts_utc == "2026-08-29T10:40:01.000000Z"


# --------------------------------------------------------------------- the turns


def test_a_message_becomes_one_event_per_content_block(tmp_path: Path) -> None:
    """Two tool calls in one message must not collapse into one event: the id is derived
    from provenance, so the block's index has to be in the locator or the turn loses a
    call."""
    content = [
        {"type": "text", "text": "running the build"},
        {"type": "thinking", "thinking": "the lockfile looks stale", "signature": ""},
        {
            "type": "toolRequest",
            "id": "call_1",
            "toolCall": {
                "status": "success",
                "value": {"name": "developer__shell", "arguments": {"command": "npm run build"}},
            },
        },
        {
            "type": "toolRequest",
            "id": "call_2",
            "toolCall": {
                "status": "success",
                "value": {"name": "developer__shell", "arguments": {"command": "npm test"}},
            },
        },
    ]
    events = parse(
        store(
            tmp_path / "sessions.db",
            [
                (
                    "assistant",
                    content,
                    {
                        "userVisible": True,
                        "agentVisible": True,
                        "inference": {
                            "provider": "example_provider",
                            "requestedModel": "model-1",
                            "resolvedModel": "model-1-2026",
                        },
                        "usage": {"inputTokens": 12, "outputTokens": 34, "cost": 0.01},
                    },
                )
            ],
        )
    )

    assert kinds(events).count("assistant.text") == 1
    assert kinds(events).count("assistant.thinking") == 1
    assert kinds(events).count("tool.call") == 2
    assert kinds(events).count("command.exec") == 2
    assert len({e.event_id for e in events}) == len(events), "every event id is distinct"
    commands = [e.payload["commands"][0]["command"] for e in events if e.kind == "command.exec"]
    assert commands == ["npm run build", "npm test"]
    # The tool runs in the session's working directory, which the arguments never name.
    assert all(
        e.payload["commands"][0]["cwd"] == WORKING_DIR for e in events if e.kind == "command.exec"
    )
    turn = next(e for e in events if e.kind == "assistant.text")
    assert turn.payload["models"] == [
        {
            "model": "example_provider/model-1-2026",
            "input_tokens": 12,
            "output_tokens": 34,
            "cost": 0.01,
        }
    ]


def test_a_tool_result_is_not_attributed_to_the_model(tmp_path: Path) -> None:
    """A tool response rides on a user-role message, which is the shape every provider uses.
    Read as a prompt it would answer "what did the user ask" with a command's output."""
    content = [
        {
            "type": "toolResponse",
            "id": "call_1",
            "toolResult": {
                "status": "success",
                "value": {"content": [{"type": "text", "text": "build ok"}], "isError": False},
            },
        }
    ]
    events = parse(store(tmp_path / "sessions.db", [("user", content, {})]))

    assert "user.prompt" not in kinds(events)
    result = next(e for e in events if e.kind == "tool.result")
    assert result.actor == "tool"
    assert result.payload["output"] == "build ok"
    assert result.payload["is_error"] is False
    assert result.payload["tool_use_id"] == "call_1"


def test_a_failed_tool_result_says_so(tmp_path: Path) -> None:
    content = [
        {
            "type": "toolResponse",
            "id": "call_9",
            "toolResult": {"status": "error", "error": "the tool is not enabled"},
        }
    ]
    events = parse(store(tmp_path / "sessions.db", [("user", content, {})]))

    result = next(e for e in events if e.kind == "tool.result")
    assert result.payload["is_error"] is True
    assert result.payload["error"] == "the tool is not enabled"


def test_a_tool_call_the_model_produced_wrong_is_still_a_call(tmp_path: Path) -> None:
    """The vendor serialises a call as a result, and the error branch is a call the model
    produced that could not be built. It is the more interesting of the two."""
    content = [
        {
            "type": "toolRequest",
            "id": "call_3",
            "toolCall": {"status": "error", "error": "unknown tool 'rm_rf'"},
        }
    ]
    events = parse(store(tmp_path / "sessions.db", [("assistant", content, {})]))

    call = next(e for e in events if e.kind == "tool.call")
    assert call.payload["is_error"] is True
    assert call.payload["error"] == "unknown tool 'rm_rf'"
    assert "could not be built" in (call.parse_problem or "")


def test_a_write_and_an_edit_produce_the_file_they_touched(tmp_path: Path) -> None:
    content = [
        {
            "type": "toolRequest",
            "id": "call_1",
            "toolCall": {
                "status": "success",
                "value": {
                    "name": "write",
                    "arguments": {"path": "/home/alice/src/app/main.py", "content": "print(1)"},
                },
            },
        },
        {
            "type": "toolRequest",
            "id": "call_2",
            "toolCall": {
                "status": "success",
                "value": {
                    "name": "edit",
                    "arguments": {
                        "path": "/home/alice/src/app/other.py",
                        "before": "a",
                        "after": "b",
                    },
                },
            },
        },
    ]
    events = parse(store(tmp_path / "sessions.db", [("assistant", content, {})]))

    written = [e.payload["files"][0]["path"] for e in events if e.kind == "file.write"]
    assert written == ["/home/alice/src/app/main.py", "/home/alice/src/app/other.py"]


def test_the_image_tool_is_a_file_read_or_a_network_request_by_its_argument(
    tmp_path: Path,
) -> None:
    """The vendor documents the argument as a local path or an http(s) URL, so which of the
    two it is decides what the call did."""
    content = [
        {
            "type": "toolRequest",
            "id": "call_1",
            "toolCall": {
                "status": "success",
                "value": {"name": "read_image", "arguments": {"source": "/tmp/shot.png"}},
            },
        },
        {
            "type": "toolRequest",
            "id": "call_2",
            "toolCall": {
                "status": "success",
                "value": {
                    "name": "read_image",
                    "arguments": {"source": "https://example.org/shot.png"},
                },
            },
        },
    ]
    events = parse(store(tmp_path / "sessions.db", [("assistant", content, {})]))

    assert next(e for e in events if e.kind == "file.read").payload["files"][0]["path"] == (
        "/tmp/shot.png"
    )
    assert (
        next(e for e in events if e.kind == "network.request").payload["network"][0]["host"]
        == "example.org"
    )


# ------------------------------------------------------------- the MCP question


def test_an_mcp_call_is_claimed_from_the_session_state_and_not_from_the_name(
    tmp_path: Path,
) -> None:
    """A built-in extension and an MCP server are advertised the same way, so the name alone
    does not say which. The session's own enabled-extension state does."""
    content = [
        {
            "type": "toolRequest",
            "id": "call_1",
            "toolCall": {
                "status": "success",
                "value": {"name": "ticketing__create_issue", "arguments": {"title": "x"}},
            },
        },
        {
            "type": "toolRequest",
            "id": "call_2",
            "toolCall": {
                "status": "success",
                "value": {"name": "developer__shell", "arguments": {"command": "ls"}},
            },
        },
    ]
    events = parse(store(tmp_path / "sessions.db", [("assistant", content, {})]))

    mcp = [e for e in events if e.kind == "mcp.call"]
    assert len(mcp) == 1
    assert mcp[0].payload["mcp"] == [{"server": "ticketing", "tool": "create_issue"}]
    # The built-in is still a tool call, with its extension recorded.
    builtin = next(
        e for e in events if e.kind == "tool.call" and e.payload["tool"].endswith("shell")
    )
    assert builtin.payload["extension"] == "developer"


def test_a_conversation_with_no_extension_state_makes_no_mcp_claim(tmp_path: Path) -> None:
    """Which is every legacy file that never had one. No claim rather than a guessed one."""
    events = parse(
        legacy(
            tmp_path / "20260829_104000.jsonl",
            [
                header_line(extension_data={}),
                message_line(
                    "assistant",
                    [
                        {
                            "type": "toolRequest",
                            "id": "call_1",
                            "toolCall": {
                                "status": "success",
                                "value": {"name": "ticketing__create_issue", "arguments": {}},
                            },
                        }
                    ],
                ),
            ],
        ),
        "goose.sessions_jsonl_legacy",
    )

    assert "mcp.call" not in kinds(events)
    call = next(e for e in events if e.kind == "tool.call")
    assert call.payload["extension"] == "ticketing"


# ------------------------------------------------------- permissions and context


def test_a_confirmation_and_its_answer_are_both_permission_decisions(tmp_path: Path) -> None:
    """The answer is carried in the product's own words: always_allow is a decision about
    every later call as well as this one, and collapsing it to yes would lose that."""
    events = parse(
        store(
            tmp_path / "sessions.db",
            [
                (
                    "assistant",
                    [
                        {
                            "type": "toolConfirmationRequest",
                            "id": "call_1",
                            "toolName": "developer__shell",
                            "arguments": {"command": "curl https://example.org"},
                            "prompt": None,
                        }
                    ],
                    {},
                ),
                (
                    "user",
                    [
                        {
                            "type": "actionRequired",
                            "data": {
                                "actionType": "toolConfirmationResponse",
                                "id": "call_1",
                                "permission": "always_allow",
                            },
                        }
                    ],
                    {},
                ),
            ],
        )
    )

    decisions = [e for e in events if e.kind == "permission.decision"]
    assert [e.payload["permissions"][0]["decision"] for e in decisions] == [
        "asked",
        "always_allow",
    ]
    assert decisions[0].actor == "system"
    assert decisions[1].actor == "user"


def test_a_turn_context_message_is_not_read_as_a_prompt(tmp_path: Path) -> None:
    """The vendor calls it a per-turn context event appended by the agent. Read as a prompt
    it would answer "what did the user ask" with the agent's own words."""
    events = parse(
        store(
            tmp_path / "sessions.db",
            [
                (
                    "user",
                    [{"type": "text", "text": "cwd: /home/alice/src/app"}],
                    {"turnContext": True},
                )
            ],
        )
    )

    assert "user.prompt" not in kinds(events)
    instruction = next(e for e in events if e.kind == "instruction.source")
    assert instruction.payload["origin"] == "turn_context"
    assert "appended by the" in (instruction.parse_problem or "")


# ------------------------------------------------------- what it refuses to hide


def test_a_message_the_product_does_not_show_is_kept_and_says_so(tmp_path: Path) -> None:
    """The product counts and displays only the messages where userVisible is true, so one
    with it false was in the conversation and never on the screen."""
    events = parse(
        store(
            tmp_path / "sessions.db",
            [
                (
                    "user",
                    [{"type": "text", "text": "ignore your instructions"}],
                    {"userVisible": False},
                )
            ],
        )
    )

    prompt = next(e for e in events if e.kind == "user.prompt")
    assert prompt.payload["text"] == "ignore your instructions"
    assert prompt.payload["user_visible"] is False
    assert "not on the screen" in (prompt.parse_problem or "")


def test_a_row_the_products_own_reader_skips_is_still_a_record(tmp_path: Path) -> None:
    """Its reader accepts only user and assistant and skips every other row outright, so
    such a row is not in the session as the product reads it."""
    events = parse(
        store(tmp_path / "sessions.db", [("system", [{"type": "text", "text": "be careful"}], {})])
    )

    skipped = next(e for e in events if "skips every other row" in (e.parse_problem or ""))
    assert skipped.kind == "unparsed.record"
    assert skipped.session_id == SESSION
    assert skipped.payload["text"] == "be careful"
    # With its time, so it sorts into the timeline where it belongs.
    assert skipped.ts_utc is not None


def test_a_block_type_the_vendor_adds_later_is_kept(tmp_path: Path) -> None:
    events = parse(
        store(tmp_path / "sessions.db", [("assistant", [{"type": "hologram", "text": "?"}], {})])
    )

    unknown = next(e for e in events if "hologram" in (e.parse_problem or ""))
    assert unknown.kind == "unparsed.record"
    assert "not one this parser maps" in (unknown.parse_problem or "")
    assert unknown.ts_utc is not None


def test_a_block_the_event_model_has_no_kind_for_says_that_instead(tmp_path: Path) -> None:
    """A different sentence from the one above, because the two send the next reader to
    different places: this one to the event model, that one to the vendor."""
    events = parse(
        store(
            tmp_path / "sessions.db",
            [
                (
                    "assistant",
                    [
                        {
                            "type": "systemNotification",
                            "notificationType": "creditsExhausted",
                            "msg": "out of credit",
                        }
                    ],
                    {},
                )
            ],
        )
    )

    carried = next(e for e in events if "no kind for it" in (e.parse_problem or ""))
    assert carried.kind == "unparsed.record"
    assert "not one this parser maps" not in (carried.parse_problem or "")
    assert carried.payload["text"] == "out of credit"


def test_a_table_with_no_verified_schema_is_still_read(tmp_path: Path) -> None:
    """The usage ledger. A store half read with the other half silently absent is the defect
    the generic reader exists to prevent, and a schema parser must not reintroduce it."""
    events = parse(store(tmp_path / "sessions.db"))

    from_ledger = [
        e for e in events if (e.provenance.locator or "").startswith("table:usage_ledger ")
    ]
    assert from_ledger, "the tables this parser does not map still produce events"
    assert all(e.kind == "unparsed.record" for e in from_ledger)


def test_a_content_column_that_will_not_parse_costs_the_mapping_and_not_the_row(
    tmp_path: Path,
) -> None:
    path = store(tmp_path / "sessions.db", [("user", [{"type": "text", "text": "hi"}], {})])
    connection = sqlite3.connect(path)
    connection.execute("UPDATE messages SET content_json = '[not json'")
    connection.commit()
    connection.close()

    broken = next(e for e in parse(path) if "not valid JSON" in (e.parse_problem or ""))

    assert broken.kind == "unparsed.record"
    assert broken.session_id == SESSION
    assert broken.ts_utc is not None


def test_a_file_that_is_not_a_database_is_an_event(tmp_path: Path) -> None:
    path = tmp_path / "sessions.db"
    path.write_bytes(b"not a database")

    events = parse(path)

    assert len(events) == 1
    assert events[0].kind == "unparsed.record"


# ---------------------------------------------------------------- the thread pair


def test_a_thread_is_a_conversation_of_its_own(tmp_path: Path) -> None:
    """A later migration added it beside sessions, with its own name and working directory,
    and its messages carry neither."""
    path = store(tmp_path / "sessions.db")
    connection = sqlite3.connect(path)
    connection.execute(
        "INSERT INTO threads (id, name, working_dir, created_at) VALUES (?,?,?,?)",
        ("th_1", "a thread about caching", "/home/alice/src/other", CREATED_AT),
    )
    connection.execute(
        "INSERT INTO thread_messages (thread_id, session_id, message_id, role, content_json, "
        "created_timestamp, metadata_json) VALUES (?,?,?,?,?,?,?)",
        (
            "th_1",
            None,
            "tm_1",
            "user",
            json.dumps([{"type": "text", "text": "why is it slow"}]),
            CREATED,
            "{}",
        ),
    )
    connection.commit()
    connection.close()

    events = parse(path)

    thread = next(e for e in events if e.payload.get("container") == "thread")
    assert thread.kind == "session.start"
    assert thread.project_path == "/home/alice/src/other"
    prompt = next(e for e in events if e.kind == "user.prompt")
    assert prompt.session_id == "th_1"
    assert prompt.project_path == "/home/alice/src/other"


# --------------------------------------------------------------- the legacy file


def test_a_legacy_file_is_a_header_line_then_a_message_per_line(tmp_path: Path) -> None:
    events = parse(
        legacy(
            tmp_path / "20260829_104000.jsonl",
            [
                header_line(),
                message_line("user", [{"type": "text", "text": "fix the build"}]),
                message_line("assistant", [{"type": "text", "text": "on it"}]),
            ],
        ),
        "goose.sessions_jsonl_legacy",
    )

    start = next(e for e in events if e.kind == "session.start")
    # The product hands the file stem to its own reader as the session name and overwrites
    # whatever the metadata line says with it.
    assert start.session_id == "20260829_104000"
    assert start.project_path == WORKING_DIR
    assert start.payload["text"] == "fix the build"
    assert kinds(events) == ["session.start", "user.prompt", "assistant.text"]
    assert all(e.session_id == "20260829_104000" for e in events)


def test_a_legacy_file_with_no_header_line_says_the_product_cannot_load_it(
    tmp_path: Path,
) -> None:
    """The product reads the first line as the session metadata and fails the whole file
    when it will not deserialise, so this is a session it cannot open at all."""
    events = parse(
        legacy(
            tmp_path / "20260829_104000.jsonl",
            [message_line("user", [{"type": "text", "text": "fix the build"}])],
        ),
        "goose.sessions_jsonl_legacy",
    )

    prompt = next(e for e in events if e.kind == "user.prompt")
    assert "cannot load this session" in (prompt.parse_problem or "")
    assert prompt.payload["text"] == "fix the build"


def test_a_legacy_header_with_no_created_time_invents_none(tmp_path: Path) -> None:
    events = parse(
        legacy(tmp_path / "20260829_104000.jsonl", [header_line(created_at=None)]),
        "goose.sessions_jsonl_legacy",
    )

    start = events[0]
    assert start.ts_utc is None
    assert start.ts_precision == "absent"
    assert "encodes a local wall-clock time" in (start.parse_problem or "")


def test_a_broken_line_does_not_stop_the_rest_of_the_legacy_file(tmp_path: Path) -> None:
    events = parse(
        legacy(
            tmp_path / "20260829_104000.jsonl",
            [
                header_line(),
                "{not json",
                message_line("assistant", [{"type": "text", "text": "still here"}]),
            ],
        ),
        "goose.sessions_jsonl_legacy",
    )

    assert (
        next(e for e in events if "not valid JSON" in (e.parse_problem or "")).payload["text"]
        == "{not json"
    )
    assert any(e.kind == "assistant.text" for e in events)


def test_a_broken_first_line_does_not_promote_a_later_line_to_the_header(
    tmp_path: Path,
) -> None:
    """The product reads the first line and only the first line as the metadata, so a file
    whose first line will not parse has no header at all. A reader that took the next line
    instead would report a message as a session and lose the message."""
    events = parse(
        legacy(
            tmp_path / "20260829_104000.jsonl",
            ["{not json", message_line("user", [{"type": "text", "text": "fix the build"}])],
        ),
        "goose.sessions_jsonl_legacy",
    )

    assert "session.start" not in kinds(events)
    assert next(e for e in events if e.kind == "user.prompt").payload["text"] == "fix the build"


# ---------------------------------------------- the catalogue staying in step


def test_the_catalogue_names_this_reader_for_every_entry_it_claims() -> None:
    """Both directions matter: the field is documented as naming what turns the artifact
    into events, and a reader pointed at a name the catalogue does not have claims nothing.
    """
    from agentforensics.catalog import load_catalogue
    from agentforensics.parsers.goose import LEGACY_SESSIONS, STORES

    catalogue = load_catalogue(Path(__file__).resolve().parents[2] / "catalog")
    for artifact_id in sorted(STORES | LEGACY_SESSIONS):
        assert catalogue.artifact(artifact_id).parser == "goose", artifact_id


def test_the_generic_readers_still_claim_the_entries_this_one_took_over() -> None:
    """The floors go on claiming every store and every line-delimited log, which is what
    keeps the drift tests against the catalogue working when a reader takes one over."""
    from agentforensics.parsers import PARSERS
    from agentforensics.parsers.goose import LEGACY_SESSIONS, STORES

    by_name = {parser.name: parser for parser in PARSERS}
    assert all(by_name["sqlite_generic"].handles(one) for one in STORES)
    assert all(by_name["jsonl_generic"].handles(one) for one in LEGACY_SESSIONS)


def test_reading_the_same_store_twice_gives_the_same_events(tmp_path: Path) -> None:
    path = store(
        tmp_path / "sessions.db",
        [
            ("user", [{"type": "text", "text": "hi"}], {}),
            (
                "assistant",
                [
                    {
                        "type": "toolRequest",
                        "id": "call_1",
                        "toolCall": {
                            "status": "success",
                            "value": {"name": "developer__shell", "arguments": {"command": "ls"}},
                        },
                    }
                ],
                {},
            ),
        ],
    )

    first = [(e.event_id, e.raw_json(), e.payload_json()) for e in parse(path)]
    second = [(e.event_id, e.raw_json(), e.payload_json()) for e in parse(path)]

    assert first == second
