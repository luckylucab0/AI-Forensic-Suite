"""Tests for the Amazon Q parser, against a store built like the agent builds one.

The fixture creates the tables with the column names from the vendor's SQL migrations and
fills the conversations value with the JSON that the vendor's Rust types serialise to,
including serde's external tagging for the two message enums. Both were fetched and read;
the parser's module docstring cites them.

Getting the tagging wrong is the interesting failure here, and it is silent: a parser that
expected `{"type": "prompt"}` instead of `{"Prompt": {...}}` would read every turn as
unmapped, report a conversation as unreadable, and look like it was working.

What else is asserted is mostly what the parser must refuse to do: invent a time for a
record that has none, drop a turn the agent has stopped sending to the model, render a
credential as an event's text, or build a hostname out of a service name.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from agentforensics.parsers import for_artifact
from agentforensics.parsers.base import ParseContext

# The vendor's migrations, in the order they run, with 003 and 006 applied.
SCHEMA = [
    """CREATE TABLE history (
        id INTEGER PRIMARY KEY, command TEXT, shell TEXT, pid INTEGER, session_id TEXT,
        cwd TEXT, start_time INTEGER, in_ssh INTEGER, in_docker INTEGER, hostname TEXT,
        exit_code INTEGER, end_time INTEGER, duration INTEGER)""",
    "CREATE TABLE state (key TEXT PRIMARY KEY, value BLOB)",
    "CREATE TABLE auth_kv (key TEXT PRIMARY KEY, value TEXT)",
    "CREATE TABLE conversations (key TEXT PRIMARY KEY, value TEXT)",
    "CREATE TABLE migrations (id INTEGER PRIMARY KEY, version INTEGER, migration_time INTEGER)",
]

CWD = "/home/alice/src/app"
CONVERSATION = "11111111-2222-3333-4444-555555555555"
WHEN = "2026-09-06T09:00:00+00:00"


def prompt(text: str, when: str | None = WHEN) -> dict:
    """A user message as serde writes one: the content enum is externally tagged."""
    return {
        "additional_context": "",
        "env_context": {"env_state": {"operating_system": "linux"}},
        "content": {"Prompt": {"prompt": text}},
        "timestamp": when,
        "images": None,
    }


def tool_results(results: list[dict], when: str | None = WHEN) -> dict:
    return {
        "additional_context": "",
        "env_context": {"env_state": None},
        "content": {"ToolUseResults": {"tool_use_results": results}},
        "timestamp": when,
        "images": None,
    }


def answer(text: str) -> dict:
    return {"Response": {"message_id": "m1", "content": text}}


def tool_use(name: str, args: dict, call_id: str = "call_1", text: str = "") -> dict:
    return {
        "ToolUse": {
            "message_id": "m2",
            "content": text,
            "tool_uses": [
                {"id": call_id, "name": name, "orig_name": name, "args": args, "orig_args": args}
            ],
        }
    }


def state(**overrides) -> dict:
    base = {
        "conversation_id": CONVERSATION,
        "next_message": None,
        "history": [],
        "valid_history_range": [0, 0],
        "transcript": ["> please fix the build", "I will run make."],
        "tools": {},
        "context_manager": None,
        "context_message_length": None,
        "latest_summary": None,
        "model": "example-model-1",
        "file_line_tracker": {},
        "mcp_enabled": True,
    }
    base.update(overrides)
    return base


def store(path: Path, conversation: dict | None = None, commands: list[tuple] = ()) -> Path:
    connection = sqlite3.connect(path)
    try:
        for statement in SCHEMA:
            connection.execute(statement)
        if conversation is not None:
            connection.execute(
                "INSERT INTO conversations (key, value) VALUES (?,?)",
                (CWD, json.dumps(conversation)),
            )
        for row in commands:
            connection.execute(
                "INSERT INTO history (command, shell, pid, session_id, cwd, start_time, "
                "hostname, exit_code, end_time, duration) VALUES (?,?,?,?,?,?,?,?,?,?)",
                row,
            )
        connection.execute(
            "INSERT INTO state (key, value) VALUES (?,?)", ("api.selectedCustomization", b"none")
        )
        connection.execute(
            "INSERT INTO auth_kv (key, value) VALUES (?,?)",
            # The vendor spells it odic, not oidc. A grep for oidc finds nothing.
            ("codewhisperer:odic:token", '{"accessToken":"example-not-a-real-token"}'),
        )
        connection.commit()
    finally:
        connection.close()
    return path


def parse(path: Path) -> list:
    parser = for_artifact("amazonq.cli_state_database")
    assert parser is not None
    assert parser.name == "amazonq"
    return list(
        parser.parse(
            ParseContext(
                bundle_uuid="b1",
                original_path="/home/alice/.local/share/amazon-q/data.sqlite3",
                local_path=path,
                sha256="aa",
                artifact_id="amazonq.cli_state_database",
                agent="amazonq",
                user="alice",
                host="workstation",
            )
        )
    )


def kinds(events: list) -> list[str]:
    return [event.kind for event in events]


# ----------------------------------------------------------- the conversation key


def test_the_conversation_is_attributed_to_its_working_directory(tmp_path: Path) -> None:
    """The key is the path, which the vendor's own accessor states by taking one and using
    it as the key. It maps activity to a project without the project having to still exist.
    """
    events = parse(store(tmp_path / "data.sqlite3", state()))

    start = next(e for e in events if e.kind == "session.start")
    assert start.project_path == CWD
    assert start.session_id == CONVERSATION
    assert start.payload["models"] == [{"model": "example-model-1"}]
    assert start.payload["mcp_enabled"] is True
    # The agent's own rendering, which holds errors posted in the chat and survives the
    # trimming of the structured history.
    assert start.payload["transcript"][0].startswith("> ")


# -------------------------------------------------------- the externally tagged enums


def test_a_prompt_is_read_through_serde_external_tagging(tmp_path: Path) -> None:
    """The silent failure this guards: a parser expecting a "type" field would read every
    turn as unmapped and report a working conversation as unreadable."""
    conversation = state(
        history=[{"user": prompt("please fix the build"), "assistant": answer("I will run make.")}],
        valid_history_range=[0, 1],
    )
    events = parse(store(tmp_path / "data.sqlite3", conversation))

    asked = next(e for e in events if e.kind == "user.prompt")
    assert asked.payload["text"] == "please fix the build"
    assert asked.ts_utc == "2026-09-06T09:00:00.000000Z"
    assert asked.payload["sent"] is True
    said = next(e for e in events if e.kind == "assistant.text")
    assert said.payload["text"] == "I will run make."
    assert said.payload["message_id"] == "m1"


def test_a_tool_call_and_its_result_are_paired_by_their_id(tmp_path: Path) -> None:
    conversation = state(
        history=[
            {
                "user": prompt("build it"),
                "assistant": tool_use("execute_bash", {"command": "make -j4"}, "call_7"),
            },
            {
                "user": tool_results(
                    [
                        {
                            "tool_use_id": "call_7",
                            "content": [{"Text": "build failed"}],
                            "status": "Error",
                        }
                    ]
                ),
                "assistant": answer("the lockfile is stale"),
            },
        ],
        valid_history_range=[0, 2],
    )
    events = parse(store(tmp_path / "data.sqlite3", conversation))

    call = next(e for e in events if e.kind == "tool.call")
    assert call.payload["tool_use_id"] == "call_7"
    command = next(e for e in events if e.kind == "command.exec" and e.payload.get("commands"))
    assert command.payload["commands"][0]["command"] == "make -j4"
    assert command.payload["commands"][0]["cwd"] == CWD
    result = next(e for e in events if e.kind == "tool.result")
    assert result.payload["tool_use_id"] == "call_7"
    assert result.payload["output"] == "build failed"
    assert result.payload["is_error"] is True


def test_an_enum_shape_the_vendor_changes_is_reported_rather_than_guessed(
    tmp_path: Path,
) -> None:
    conversation = state(
        history=[{"user": {"content": {"Something": {}, "Else": {}}}, "assistant": answer("hm")}],
        valid_history_range=[0, 1],
    )
    events = parse(store(tmp_path / "data.sqlite3", conversation))

    unmapped = next(e for e in events if "not one of the three shapes" in (e.parse_problem or ""))
    assert unmapped.kind == "unparsed.record"


# ------------------------------------------------------------ the trimmed history


def test_a_turn_outside_the_valid_range_is_kept_and_says_so(tmp_path: Path) -> None:
    """The agent stopped sending it to the model. It is still on disk and it still
    happened, and "the agent forgot this" and "this did not happen" are different findings.
    """
    conversation = state(
        history=[
            {"user": prompt("the old question"), "assistant": answer("the old answer")},
            {"user": prompt("the current question"), "assistant": answer("the current answer")},
        ],
        # Only the second entry is still sent.
        valid_history_range=[1, 2],
    )
    events = parse(store(tmp_path / "data.sqlite3", conversation))

    old = next(e for e in events if e.payload.get("text") == "the old question")
    assert "outside the conversation's valid history range" in (old.parse_problem or "")
    current = next(e for e in events if e.payload.get("text") == "the current question")
    assert current.parse_problem is None


def test_a_range_that_does_not_fit_the_history_is_clamped(tmp_path: Path) -> None:
    conversation = state(
        history=[{"user": prompt("only one"), "assistant": answer("ok")}],
        valid_history_range=[0, 99],
    )
    events = parse(store(tmp_path / "data.sqlite3", conversation))

    start = next(e for e in events if e.kind == "session.start")
    assert start.payload["valid_history_range"] == [0, 1]


# --------------------------------------------------------- what only this store has


def test_a_queued_prompt_that_was_never_sent_is_evidence(tmp_path: Path) -> None:
    """What somebody was about to ask. No turn records it."""
    events = parse(
        store(tmp_path / "data.sqlite3", state(next_message=prompt("delete the audit logs")))
    )

    queued = next(e for e in events if e.payload.get("text") == "delete the audit logs")
    assert queued.kind == "user.prompt"
    assert queued.payload["sent"] is False


def test_the_line_tracker_says_what_the_agent_wrote_and_carries_no_time(
    tmp_path: Path,
) -> None:
    conversation = state(
        file_line_tracker={
            "/home/alice/src/app/main.py": {
                "prev_fswrite_lines": 10,
                "before_fswrite_lines": 10,
                "after_fswrite_lines": 42,
                "lines_added_by_agent": 32,
                "lines_removed_by_agent": 0,
                "is_first_write": True,
            }
        }
    )
    events = parse(store(tmp_path / "data.sqlite3", conversation))

    written = next(e for e in events if e.kind == "file.write")
    assert written.payload["files"][0]["path"] == "/home/alice/src/app/main.py"
    assert written.payload["lines_added_by_agent"] == 32
    # No time of its own, and none invented. The turn that did the writing is the dated
    # record; a fabricated moment here would sit on the timeline looking like evidence.
    assert written.ts_utc is None
    assert "no time of its own" in (written.parse_problem or "")


def test_a_stashed_tangent_conversation_is_surfaced_rather_than_expanded(
    tmp_path: Path,
) -> None:
    conversation = state(
        tangent_state={
            "main_history": [{"user": prompt("the stashed question"), "assistant": answer("x")}],
            "main_next_message": None,
            "main_transcript": ["> the stashed question"],
            "main_latest_summary": None,
            "tangent_start_time": "2026-09-06T10:00:00+00:00",
        }
    )
    events = parse(store(tmp_path / "data.sqlite3", conversation))

    tangent = next(e for e in events if "stashed main conversation" in (e.parse_problem or ""))
    assert tangent.kind == "unparsed.record"
    assert tangent.ts_utc == "2026-09-06T10:00:00.000000Z"
    # Not expanded, but not lost either: the whole structure is in raw.
    assert tangent.raw["main_transcript"] == ["> the stashed question"]


def test_a_summary_ends_the_conversation(tmp_path: Path) -> None:
    conversation = state(latest_summary=["what happened so far", {"request_id": "r1"}])
    events = parse(store(tmp_path / "data.sqlite3", conversation))

    summary = next(e for e in events if e.kind == "session.end")
    assert summary.payload["text"] == "what happened so far"
    assert summary.payload["compaction"] is True


# ---------------------------------------------------------------------- the facets


def test_a_read_of_several_files_produces_one_event_naming_all_of_them(
    tmp_path: Path,
) -> None:
    """fs_read takes a list of operations, each with its own path, so one call can read
    several files and a parser reading a single path key would miss most of them."""
    conversation = state(
        history=[
            {
                "user": prompt("read these"),
                "assistant": tool_use(
                    "fs_read",
                    {
                        "operations": [
                            {"mode": "Line", "path": "/home/alice/src/app/a.py"},
                            {"mode": "Line", "path": "/home/alice/src/app/b.py"},
                        ]
                    },
                ),
            }
        ],
        valid_history_range=[0, 1],
    )
    events = parse(store(tmp_path / "data.sqlite3", conversation))

    read = next(e for e in events if e.kind == "file.read")
    assert [entry["path"] for entry in read.payload["files"]] == [
        "/home/alice/src/app/a.py",
        "/home/alice/src/app/b.py",
    ]


def test_an_aws_call_names_the_service_and_no_hostname(tmp_path: Path) -> None:
    """The record names a service, a region and an operation, and not an endpoint.
    Building one out of them would put a hostname in the case that the evidence never
    contained, and an analyst would quote it."""
    conversation = state(
        history=[
            {
                "user": prompt("list the buckets"),
                "assistant": tool_use(
                    "use_aws",
                    {
                        "service_name": "s3",
                        "operation_name": "ListBuckets",
                        "region": "eu-central-1",
                        "profile_name": "default",
                    },
                ),
            }
        ],
        valid_history_range=[0, 1],
    )
    events = parse(store(tmp_path / "data.sqlite3", conversation))

    call = next(e for e in events if e.kind == "network.request")
    assert call.payload["aws_service"] == "s3"
    assert call.payload["aws_operation"] == "ListBuckets"
    assert call.payload["aws_region"] == "eu-central-1"
    assert "network" not in call.payload


def test_a_delegated_subagent_is_named(tmp_path: Path) -> None:
    conversation = state(
        history=[
            {
                "user": prompt("delegate it"),
                "assistant": tool_use(
                    "delegate", {"agent": "reviewer", "operation": "start", "task": "review"}
                ),
            }
        ],
        valid_history_range=[0, 1],
    )
    events = parse(store(tmp_path / "data.sqlite3", conversation))

    call = next(e for e in events if e.kind == "tool.call")
    assert call.payload["subagent"] == "reviewer"


# ------------------------------------------------------------- the other tables


def test_the_shell_history_is_a_record_of_execution(tmp_path: Path) -> None:
    """Independent of the shell's own history file and of the agent's transcript."""
    events = parse(
        store(
            tmp_path / "data.sqlite3",
            None,
            [("rm -rf build", "zsh", 4242, "s-1", CWD, 1788000000, "buildhost", 0, None, 120)],
        )
    )

    command = next(e for e in events if e.kind == "command.exec")
    assert command.payload["commands"][0]["command"] == "rm -rf build"
    assert command.payload["commands"][0]["exit_code"] == 0
    assert command.payload["commands"][0]["shell"] == "zsh"
    assert command.payload["commands"][0]["pid"] == 4242
    # The row's own hostname, which can differ from the host the collection came from.
    assert command.host == "buildhost"
    assert command.project_path == CWD
    assert command.ts_utc is not None
    # normalise_ts says which reading it used, because the unit is stated nowhere.
    assert "epoch" in (command.parse_problem or "")


def test_a_credential_is_recorded_without_being_rendered_as_text(tmp_path: Path) -> None:
    """The vendor split auth_kv out of state on purpose. Its presence and its key are the
    finding; the value stays in raw, and the catalogue names the key so an export redacts
    it."""
    events = parse(store(tmp_path / "data.sqlite3", state()))

    secret = next(e for e in events if e.payload.get("table") == "auth_kv")
    assert secret.payload["credential"] is True
    assert secret.payload["key"] == "codewhisperer:odic:token"
    assert "example-not-a-real-token" not in secret.payload["text"]
    # Not hidden: the value is in raw, where the evidence belongs.
    assert "example-not-a-real-token" in str(secret.raw)


def test_a_setting_is_a_configuration_snapshot(tmp_path: Path) -> None:
    events = parse(store(tmp_path / "data.sqlite3", state()))

    setting = next(e for e in events if e.payload.get("table") == "state")
    assert setting.payload["key"] == "api.selectedCustomization"
    assert setting.payload["credential"] is False


def test_a_table_with_no_verified_schema_is_still_read(tmp_path: Path) -> None:
    """A store half read with the other half silently absent is the defect the generic
    reader exists to prevent, and a schema parser must not reintroduce it."""
    path = store(tmp_path / "data.sqlite3", state())
    connection = sqlite3.connect(path)
    connection.execute(
        "INSERT INTO migrations (version, migration_time) VALUES (?,?)", (7, 1788000000)
    )
    connection.commit()
    connection.close()

    from_migrations = [
        e for e in parse(path) if (e.provenance.locator or "").startswith("table:migrations ")
    ]

    assert len(from_migrations) == 1
    assert from_migrations[0].kind == "unparsed.record"
    assert from_migrations[0].raw["version"] == 7


# ------------------------------------------------------------------- the awkward


def test_a_conversation_value_that_will_not_parse_is_an_event(tmp_path: Path) -> None:
    path = store(tmp_path / "data.sqlite3", state())
    connection = sqlite3.connect(path)
    connection.execute("UPDATE conversations SET value = '{not json'")
    connection.commit()
    connection.close()

    broken = next(e for e in parse(path) if "not valid JSON" in (e.parse_problem or ""))

    assert broken.kind == "unparsed.record"
    # Attributed to its directory even though nothing inside could be read.
    assert broken.project_path == CWD


def test_a_file_that_is_not_a_database_is_an_event(tmp_path: Path) -> None:
    path = tmp_path / "data.sqlite3"
    path.write_bytes(b"not a database")

    events = parse(path)

    assert len(events) == 1
    assert events[0].kind == "unparsed.record"


def test_every_event_id_is_distinct(tmp_path: Path) -> None:
    conversation = state(
        history=[
            {
                "user": prompt("do two things"),
                "assistant": {
                    "ToolUse": {
                        "message_id": "m2",
                        "content": "",
                        "tool_uses": [
                            {
                                "id": "c1",
                                "name": "execute_bash",
                                "orig_name": "execute_bash",
                                "args": {"command": "ls"},
                                "orig_args": {"command": "ls"},
                            },
                            {
                                "id": "c2",
                                "name": "execute_bash",
                                "orig_name": "execute_bash",
                                "args": {"command": "pwd"},
                                "orig_args": {"command": "pwd"},
                            },
                        ],
                    }
                },
            }
        ],
        valid_history_range=[0, 1],
    )
    events = parse(store(tmp_path / "data.sqlite3", conversation))

    assert kinds(events).count("tool.call") == 2
    assert kinds(events).count("command.exec") == 2
    assert len({e.event_id for e in events}) == len(events)


def test_reading_the_same_store_twice_gives_the_same_events(tmp_path: Path) -> None:
    path = store(
        tmp_path / "data.sqlite3",
        state(
            history=[{"user": prompt("hi"), "assistant": answer("hello")}],
            valid_history_range=[0, 1],
        ),
        [("ls", "bash", 1, "s-1", CWD, 1788000000, "h", 0, None, 1)],
    )

    first = [(e.event_id, e.raw_json(), e.payload_json()) for e in parse(path)]
    second = [(e.event_id, e.raw_json(), e.payload_json()) for e in parse(path)]

    assert first == second
