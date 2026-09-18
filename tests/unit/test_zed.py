"""Tests for the Zed parser, against a store whose content is really compressed.

The fixture writes the nine columns the vendor's migration creates and puts a genuine zstd
frame in the data column, because the compression is the whole point of this store: it is
the one shape where every other method an examiner has returns nothing, so a test that put
plain JSON there would pass while the real thing stayed unreadable.

The record shapes are serde's, with its default external tagging, which is what the vendor's
derives select. Getting that wrong is silent: a parser expecting `{"role": "user"}` would
read a full thread as a thread of unmapped records.

Beyond the mapping, what is asserted is what the parser must refuse to do: invent a per-turn
timestamp the store does not have, present the last-changed time as the beginning, claim a
file or a command out of a tool record whose shape it has not read, or lose a thread whose
frame will not decompress.
"""

from __future__ import annotations

import compression.zstd as zstd
import json
import sqlite3
from pathlib import Path

from agentforensics.parsers import for_artifact
from agentforensics.parsers.base import ParseContext

# The table as the vendor's migration leaves it: the original five columns plus the four
# added by later ALTERs, in that order.
SCHEMA = """CREATE TABLE threads (
    id TEXT PRIMARY KEY,
    summary TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    data_type TEXT NOT NULL,
    data BLOB NOT NULL,
    parent_id TEXT,
    folder_paths TEXT,
    folder_paths_order TEXT,
    created_at TEXT
)"""

THREAD = "01H0000000000000000000"
CREATED = "2026-09-06T09:00:00Z"
UPDATED = "2026-09-06T09:30:00Z"
FOLDER = "/home/alice/src/app"


def thread(messages: list | None = None, **overrides) -> dict:
    document = {
        "title": "fix the build",
        "messages": messages or [],
        "updated_at": UPDATED,
        "detailed_summary": None,
        "cumulative_token_usage": {"input_tokens": 120, "output_tokens": 80},
        "model": {"provider": "example", "model": "model-1"},
        "profile": "write",
        "thinking_enabled": True,
        "thinking_effort": "high",
    }
    document.update(overrides)
    return document


def store(
    path: Path,
    document: dict | None = None,
    *,
    created: str | None = CREATED,
    data: bytes | None = None,
    data_type: str = "zstd",
) -> Path:
    connection = sqlite3.connect(path)
    try:
        connection.execute(SCHEMA)
        if data is None:
            body = json.dumps(document if document is not None else thread())
            # A real frame. The reader has to decompress it before the parser sees JSON.
            data = zstd.compress(body.encode("utf-8"))
        connection.execute(
            "INSERT INTO threads (id, summary, updated_at, data_type, data, parent_id, "
            "folder_paths, folder_paths_order, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                THREAD,
                "fix the build",
                UPDATED,
                data_type,
                data,
                None,
                json.dumps([FOLDER]),
                "0",
                created,
            ),
        )
        connection.commit()
    finally:
        connection.close()
    return path


def parse(path: Path) -> list:
    parser = for_artifact("zed.threads_db")
    assert parser is not None
    assert parser.name == "zed"
    return list(
        parser.parse(
            ParseContext(
                bundle_uuid="b1",
                original_path="/home/alice/.local/share/zed/threads/threads.db",
                local_path=path,
                sha256="aa",
                artifact_id="zed.threads_db",
                agent="zed",
                user="alice",
            )
        )
    )


def kinds(events: list) -> list[str]:
    return [event.kind for event in events]


# ------------------------------------------------------------- the compression


def test_a_compressed_thread_is_read(tmp_path: Path) -> None:
    """The reason this store needed the Python floor raised. Compressed content is
    invisible to strings and to a keyword search, so a reader that stopped at the BLOB
    would leave a case saying Zed held some opaque bytes, and an analyst reading that
    concludes the agent was not used."""
    document = thread([{"User": {"id": "u1", "content": [{"Text": "please fix the build"}]}}])
    events = parse(store(tmp_path / "threads.db", document))

    asked = next(e for e in events if e.kind == "user.prompt")
    assert asked.payload["text"] == "please fix the build"
    assert asked.session_id == THREAD


def test_a_frame_that_will_not_decompress_costs_the_turns_and_not_the_thread(
    tmp_path: Path,
) -> None:
    """The header is in the row's own columns, so a thread whose content is damaged is
    still a thread that existed, with its title, its folder and its times."""
    path = store(tmp_path / "threads.db", data=b"\x28\xb5\x2f\xfd" + b"\x00" * 16)

    events = parse(path)

    assert len(events) == 1
    start = events[0]
    assert start.kind == "session.start"
    assert start.payload["text"] == "fix the build"
    assert start.project_path == FOLDER
    assert "could not be read" in (start.parse_problem or "")


def test_an_uncompressed_thread_is_read_too(tmp_path: Path) -> None:
    """The vendor's data_type column has a json value as well as a zstd one."""
    document = thread([{"User": {"id": "u1", "content": [{"Text": "plain"}]}}])
    path = store(
        tmp_path / "threads.db",
        data=json.dumps(document).encode("utf-8"),
        data_type="json",
    )

    asked = next(e for e in parse(path) if e.kind == "user.prompt")

    assert asked.payload["text"] == "plain"


# ------------------------------------------------------------------ the header


def test_the_header_carries_what_the_turns_do_not(tmp_path: Path) -> None:
    events = parse(store(tmp_path / "threads.db"))

    start = next(e for e in events if e.kind == "session.start")
    assert start.ts_utc == "2026-09-06T09:00:00.000000Z"
    assert start.ts_source == "created_at"
    assert start.payload["folder_paths"] == [FOLDER]
    assert start.payload["models"] == [{"model": "example/model-1"}]
    assert start.payload["profile"] == "write"
    assert start.payload["thinking_enabled"] is True
    assert start.payload["updated_at"] == "2026-09-06T09:30:00.000000Z"


def test_a_row_from_before_the_created_at_migration_says_which_time_it_used(
    tmp_path: Path,
) -> None:
    """Zed added created_at later, so an older row has none. Presenting the last change as
    the beginning would be a wrong answer to when the conversation started."""
    events = parse(store(tmp_path / "threads.db", created=None))

    start = next(e for e in events if e.kind == "session.start")
    assert start.ts_source == "updated_at"
    assert "no created_at" in (start.parse_problem or "")
    assert "not when it started" in (start.parse_problem or "")


def test_the_folder_paths_column_is_read_both_ways(tmp_path: Path) -> None:
    """The vendor writes it from a path list whose serialisation this parser has not read,
    so JSON and a separated list are both tried and neither is claimed."""
    from agentforensics.parsers.zed import _folders

    assert _folders(json.dumps(["/a", "/b"])) == ["/a", "/b"]
    assert _folders("/a\n/b") == ["/a", "/b"]
    assert _folders("/a,/b") == ["/a", "/b"]
    assert _folders("") == []
    assert _folders(None) == []


# ------------------------------------------------------------------- the turns


def test_no_turn_is_given_a_timestamp_the_store_does_not_have(tmp_path: Path) -> None:
    """Zed keeps one time for the thread and none for the messages. A time per turn
    invented from the thread's would put fabricated moments on a timeline, which is worse
    than a gap: a gap is visible and a fabrication is not."""
    document = thread(
        [
            {"User": {"id": "u1", "content": [{"Text": "hi"}]}},
            {"Agent": {"content": [{"Text": "hello"}], "tool_results": {}}},
        ]
    )
    events = parse(store(tmp_path / "threads.db", document))

    turns = [e for e in events if e.kind != "session.start"]
    assert turns
    assert all(event.ts_utc is None for event in turns)
    assert all(event.ts_precision == "absent" for event in turns)


def test_an_agent_turn_becomes_one_event_per_content_item(tmp_path: Path) -> None:
    document = thread(
        [
            {
                "Agent": {
                    "content": [
                        {"Text": "running the build"},
                        {"Thinking": {"text": "the lockfile looks stale", "signature": "sig"}},
                        {"RedactedThinking": "opaque"},
                        {
                            "ToolUse": {
                                "id": "call_1",
                                "name": "terminal",
                                "input": {"command": "make"},
                            }
                        },
                    ],
                    "tool_results": {"call_1": {"content": "build failed"}},
                }
            }
        ]
    )
    events = parse(store(tmp_path / "threads.db", document))

    assert kinds(events).count("assistant.text") == 1
    assert kinds(events).count("assistant.thinking") == 2
    assert kinds(events).count("tool.call") == 1
    assert kinds(events).count("tool.result") == 1
    assert len({event.event_id for event in events}) == len(events)


def test_withheld_reasoning_is_told_apart_from_no_reasoning(tmp_path: Path) -> None:
    """Redacted means the provider withheld it, which is a different thing from the model
    not having reasoned, and the difference belongs in the case."""
    document = thread(
        [{"Agent": {"content": [{"RedactedThinking": "opaque"}], "tool_results": {}}}]
    )
    events = parse(store(tmp_path / "threads.db", document))

    thinking = next(e for e in events if e.kind == "assistant.thinking")
    assert thinking.payload["redacted"] is True
    assert "withheld this reasoning" in (thinking.parse_problem or "")


def test_a_tool_record_is_carried_whole_without_claiming_what_it_touched(
    tmp_path: Path,
) -> None:
    """Its inner shape lives in a crate this parser has not read. The call is on the
    timeline and searchable; what is not claimed is the file or the command, because a
    guessed facet is one an analyst would query and trust."""
    document = thread(
        [
            {
                "Agent": {
                    "content": [
                        {"ToolUse": {"id": "c1", "name": "edit_file", "input": {"path": "/x"}}}
                    ],
                    "tool_results": {},
                }
            }
        ]
    )
    events = parse(store(tmp_path / "threads.db", document))

    call = next(e for e in events if e.kind == "tool.call")
    assert call.payload["tool"] == "edit_file"
    assert call.payload["input"] == {"path": "/x"}
    assert "no file, command or destination is claimed" in (call.parse_problem or "")
    # And no facet was produced from it.
    assert "files" not in call.payload
    assert not any(event.kind == "file.write" for event in events)


def test_a_mention_is_carried_as_the_uri_it_is(tmp_path: Path) -> None:
    """Zed's mentions address a file, a symbol, a rule or another thread, and which of
    those comes from a type in another crate. Read as a file path it would put things in
    the files facet that are not files."""
    document = thread(
        [
            {
                "User": {
                    "id": "u1",
                    "content": [
                        {"Text": "look at this"},
                        {
                            "Mention": {
                                "uri": "file:///home/alice/src/app/main.py",
                                "content": "...",
                            }
                        },
                    ],
                }
            }
        ]
    )
    events = parse(store(tmp_path / "threads.db", document))

    asked = next(e for e in events if e.kind == "user.prompt")
    assert asked.payload["text"] == "look at this"
    assert asked.payload["mentions"][0]["uri"] == "file:///home/alice/src/app/main.py"
    assert not any(event.kind == "file.read" for event in events)


def test_a_resumed_thread_is_marked(tmp_path: Path) -> None:
    """The one shape here that is not an object: serde writes a unit variant as a string."""
    document = thread(["Resume", {"User": {"id": "u1", "content": [{"Text": "carry on"}]}}])
    events = parse(store(tmp_path / "threads.db", document))

    resumed = next(e for e in events if e.payload.get("text") == "the thread was resumed here")
    assert resumed.kind == "config.snapshot"


def test_a_compaction_ends_the_thread(tmp_path: Path) -> None:
    document = thread([{"Compaction": {"Summary": "what happened so far"}}])
    events = parse(store(tmp_path / "threads.db", document))

    compaction = next(e for e in events if e.kind == "session.end")
    assert compaction.payload["text"] == "what happened so far"
    assert compaction.payload["compaction_kind"] == "Summary"


def test_a_providers_own_compaction_is_rendered_rather_than_interpreted(
    tmp_path: Path,
) -> None:
    document = thread(
        [{"Compaction": {"ProviderNative": {"provider": "example", "items": [{"a": 1}]}}}]
    )
    events = parse(store(tmp_path / "threads.db", document))

    compaction = next(e for e in events if e.kind == "session.end")
    assert compaction.payload["compaction_kind"] == "ProviderNative"
    assert "example" in compaction.payload["text"]


def test_a_message_shape_the_vendor_adds_later_is_kept(tmp_path: Path) -> None:
    document = thread([{"TimeTravel": {"to": "yesterday"}}])
    events = parse(store(tmp_path / "threads.db", document))

    unknown = next(e for e in events if "TimeTravel" in (e.parse_problem or ""))
    assert unknown.kind == "unparsed.record"
    assert unknown.session_id == THREAD


# ----------------------------------------------------------------- the awkward


def test_a_table_with_no_verified_schema_is_still_read(tmp_path: Path) -> None:
    path = store(tmp_path / "threads.db")
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE kv (key TEXT PRIMARY KEY, value TEXT)")
    connection.execute("INSERT INTO kv VALUES ('a', 'b')")
    connection.commit()
    connection.close()

    from_kv = [e for e in parse(path) if (e.provenance.locator or "").startswith("table:kv ")]

    assert len(from_kv) == 1
    assert from_kv[0].kind == "unparsed.record"


def test_a_file_that_is_not_a_database_is_an_event(tmp_path: Path) -> None:
    path = tmp_path / "threads.db"
    path.write_bytes(b"not a database")

    events = parse(path)

    assert len(events) == 1
    assert events[0].kind == "unparsed.record"


def test_reading_the_same_store_twice_gives_the_same_events(tmp_path: Path) -> None:
    document = thread(
        [
            {"User": {"id": "u1", "content": [{"Text": "hi"}]}},
            {"Agent": {"content": [{"Text": "hello"}], "tool_results": {}}},
        ]
    )
    path = store(tmp_path / "threads.db", document)

    first = [(e.event_id, e.raw_json(), e.payload_json()) for e in parse(path)]
    second = [(e.event_id, e.raw_json(), e.payload_json()) for e in parse(path)]

    assert first == second
