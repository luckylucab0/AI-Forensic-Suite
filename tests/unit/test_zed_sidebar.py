"""Tests for Zed's sidebar store, the half of Zed on disk that is not the conversations.

The questions this store answers are the ones an examination is opened for: which agent ran
a thread, whether the thread was archived out of the interface while staying on disk, and
whether it ran against a remote host. Each of those is a column whose empty value means
something, which is why most of what follows is about reading an absence correctly rather
than about reading a value.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from pathlib import Path
from typing import Any

from agentforensics.parsers import for_artifact
from agentforensics.parsers.base import ParseContext

ARTIFACT = "zed.sidebar_threads"

# The table as the vendor's migrations leave it, from the source the parser cites:
# https://raw.githubusercontent.com/zed-industries/zed/main/crates/agent_ui/src/thread_metadata_store.rs
SCHEMA = """CREATE TABLE sidebar_threads(
    thread_id BLOB PRIMARY KEY,
    session_id TEXT,
    agent_id TEXT,
    title TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    created_at TEXT,
    folder_paths TEXT,
    folder_paths_order TEXT,
    archived INTEGER DEFAULT 0,
    main_worktree_paths TEXT,
    main_worktree_paths_order TEXT,
    remote_connection TEXT,
    interacted_at TEXT,
    title_override TEXT
) STRICT"""

COLUMNS = (
    "thread_id, session_id, agent_id, title, updated_at, created_at, folder_paths, "
    "folder_paths_order, archived, main_worktree_paths, main_worktree_paths_order, "
    "remote_connection, interacted_at, title_override"
)

THREAD_UUID = uuid.UUID("4f8c1e2a-0000-4000-8000-000000000001")
SESSION = "01H0000000000000000000"
FOLDER = "/home/alice/src/app"


def row(**overrides: Any) -> tuple:
    values: dict[str, Any] = {
        "thread_id": THREAD_UUID.bytes,
        "session_id": SESSION,
        "agent_id": None,
        "title": "fix the build",
        "updated_at": "2026-09-06T09:30:00+00:00",
        "created_at": "2026-09-06T09:00:00+00:00",
        "folder_paths": FOLDER,
        "folder_paths_order": "0",
        "archived": 0,
        "main_worktree_paths": None,
        "main_worktree_paths_order": None,
        "remote_connection": None,
        "interacted_at": None,
        "title_override": None,
    }
    values.update(overrides)
    return tuple(values[name.strip()] for name in COLUMNS.split(","))


def store(path: Path, rows: list[tuple], *, extra: str = "") -> Path:
    connection = sqlite3.connect(path)
    try:
        connection.execute(SCHEMA)
        # The column list is a constant in this file and the values are bound, so the
        # interpolation ruff sees here is the schema and not input.
        connection.executemany(
            f"INSERT INTO sidebar_threads ({COLUMNS}) VALUES ({','.join('?' * 14)})",  # noqa: S608
            rows,
        )
        if extra:
            connection.executescript(extra)
        connection.commit()
    finally:
        connection.close()
    return path


def parse(path: Path) -> list:
    parser = for_artifact(ARTIFACT)
    assert parser is not None
    return list(
        parser.parse(
            ParseContext(
                bundle_uuid="b",
                original_path="/home/alice/.local/share/zed/db/0-stable/db.sqlite",
                local_path=path,
                sha256="f" * 64,
                artifact_id=ARTIFACT,
                agent="zed",
                user="alice",
            )
        )
    )


# ------------------------------------------------------------------- who ran it


def test_an_empty_agent_column_is_the_editors_own_agent(tmp_path: Path) -> None:
    """The blank is the record, not a gap in it.

    The editor writes an external agent's id here and leaves the column empty when the
    agent is its own. A reader that passed the blank through would put a thread with no
    known agent in the case, and an analyst would go looking for the agent that ran it.
    """
    event = parse(store(tmp_path / "db.sqlite", [row()]))[0]

    assert event.payload["agent_id"] == "the editor's own agent"
    assert event.payload["external_agent"] is False
    assert event.parse_problem is None, "an ordinary row is not a problem"


def test_an_external_agent_is_named(tmp_path: Path) -> None:
    """The case an examination is opened for: a different piece of software ran the thread.

    An external agent speaking the agent client protocol has its own permissions, its own
    network destinations and its own installation, none of which the editor's own agent
    shares.
    """
    event = parse(store(tmp_path / "db.sqlite", [row(agent_id="example-external-agent")]))[0]

    assert event.payload["agent_id"] == "example-external-agent"
    assert event.payload["external_agent"] is True


# --------------------------------------------------------------- what was hidden


def test_an_archived_thread_is_reported_as_archived(tmp_path: Path) -> None:
    """Hidden from the sidebar and fully present on disk.

    The difference between a conversation nobody mentioned and one somebody put away is
    this column, and it is the sort of thing an interview turns on.
    """
    events = parse(store(tmp_path / "db.sqlite", [row(), row(thread_id=b"\x01" * 16, archived=1)]))

    assert [event.payload["archived"] for event in events] == [False, True]


def test_the_archived_worktrees_are_carried_even_though_they_are_not_mapped(
    tmp_path: Path,
) -> None:
    """Zed stashes a git worktree when a thread is archived, with three commit hashes.

    That is the state an agent's run left a working copy in. This parser has read the
    CREATE statement and not the code that writes it, so the rows are carried uninterpreted
    rather than turned into claims about what the agent did to the repository. What must
    not happen is that they are left out.
    """
    path = store(
        tmp_path / "db.sqlite",
        [row()],
        extra=(
            "CREATE TABLE archived_git_worktrees(id INTEGER PRIMARY KEY, "
            "worktree_path TEXT NOT NULL, main_repo_path TEXT NOT NULL, branch_name TEXT, "
            "staged_commit_hash TEXT, unstaged_commit_hash TEXT, "
            "original_commit_hash TEXT) STRICT;"
            "INSERT INTO archived_git_worktrees VALUES (1, '/tmp/wt', '/home/alice/src/app', "
            "'feature', 'aaa', 'bbb', 'ccc');"
        ),
    )
    events = parse(path)

    carried = [event for event in events if event.kind == "unparsed.record"]
    assert len(carried) == 1
    assert "archived_git_worktrees" in (carried[0].provenance.locator or "")
    assert carried[0].raw["branch_name"] == "feature"
    assert "no verified schema" in (carried[0].parse_problem or "")


# ------------------------------------------------------------------- the thread id


def test_the_thread_id_comes_back_readable(tmp_path: Path) -> None:
    """Sixteen raw bytes of a UUID, which is the only link to the other store.

    Left as the store reader hands it over, this is either a description of some bytes or a
    string of control characters, and either way a thread nobody can look up in threads.db.
    """
    event = parse(store(tmp_path / "db.sqlite", [row()]))[0]

    assert event.payload["thread_id"] == str(THREAD_UUID)


def test_a_thread_id_that_decodes_as_text_comes_back_the_same_way(tmp_path: Path) -> None:
    """Some UUIDs are valid UTF-8, and those arrive as text rather than as bytes.

    The two paths through the store reader are not an edge case to shrug at: which one a
    row takes depends on the random bytes in it, so a parser that handled one of them would
    read most ids and silently lose the rest.
    """
    readable = uuid.UUID(bytes=bytes(range(16)))
    event = parse(store(tmp_path / "db.sqlite", [row(thread_id=readable.bytes)]))[0]

    assert event.payload["thread_id"] == str(readable)


def test_a_thread_id_that_is_not_sixteen_bytes_is_not_forced_into_one(tmp_path: Path) -> None:
    """A column this parser cannot read an id out of still has its bytes in raw."""
    event = parse(store(tmp_path / "db.sqlite", [row(thread_id=b"short")]))[0]

    assert event.payload["thread_id"] is None
    assert event.raw["thread_id"]


# ---------------------------------------------------------------------- the times


def test_the_thread_is_dated_from_created_at_where_it_has_one(tmp_path: Path) -> None:
    event = parse(store(tmp_path / "db.sqlite", [row()]))[0]

    assert event.ts_utc == "2026-09-06T09:00:00.000000Z"
    assert event.ts_source == "created_at"
    assert event.parse_problem is None


def test_a_row_from_before_the_migration_says_which_time_it_used(tmp_path: Path) -> None:
    """created_at and interacted_at both arrived later, so an older row has neither.

    Presenting a last change as a beginning would put a thread hours or days away from when
    it started, and nothing in the case would say so.
    """
    event = parse(store(tmp_path / "db.sqlite", [row(created_at=None)]))[0]

    assert event.ts_source == "updated_at"
    assert "no created_at" in (event.parse_problem or "")
    assert "not when the thread started" in (event.parse_problem or "")


def test_a_row_with_interacted_at_and_no_created_at_uses_it(tmp_path: Path) -> None:
    """Between the two, the interaction is the earlier evidence of the thread existing."""
    event = parse(
        store(
            tmp_path / "db.sqlite",
            [row(created_at=None, interacted_at="2026-09-06T09:15:00+00:00")],
        )
    )[0]

    assert event.ts_source == "interacted_at"
    assert event.payload["interacted_at"] == "2026-09-06T09:15:00+00:00"


# ------------------------------------------------------------- where it ran and on what


def test_a_remote_connection_is_carried_parsed_and_flagged(tmp_path: Path) -> None:
    """A thread that ran over a remote connection did its file reads somewhere else.

    The structure is carried as the editor wrote it and no host or user is read out of it:
    this module has read the column's type and not the shape of what goes in it, and naming
    a host an agent connected to is exactly the claim that has to rest on something.
    """
    connection = json.dumps({"SshConnection": {"host": "example.org", "port": 22}})
    event = parse(store(tmp_path / "db.sqlite", [row(remote_connection=connection)]))[0]

    assert event.payload["ran_remotely"] is True
    assert event.payload["remote_connection"] == {
        "SshConnection": {"host": "example.org", "port": 22}
    }


def test_a_thread_with_no_remote_connection_says_so(tmp_path: Path) -> None:
    event = parse(store(tmp_path / "db.sqlite", [row()]))[0]

    assert event.payload["ran_remotely"] is False
    assert event.payload["remote_connection"] is None


def test_the_worktrees_are_read_in_the_order_the_person_opened_them(tmp_path: Path) -> None:
    """Both path columns are the vendor's path list, the same as in threads.db."""
    event = parse(
        store(
            tmp_path / "db.sqlite",
            [
                row(
                    folder_paths="/home/alice/a\n/home/alice/b",
                    folder_paths_order="1,0",
                    main_worktree_paths="/home/alice/b",
                    main_worktree_paths_order="0",
                )
            ],
        )
    )[0]

    assert event.payload["folder_paths"] == ["/home/alice/b", "/home/alice/a"]
    assert event.project_path == "/home/alice/b"
    assert event.payload["main_worktree_paths"] == ["/home/alice/b"]


def test_a_renamed_thread_keeps_both_titles(tmp_path: Path) -> None:
    """A thread somebody renamed is a thread somebody looked at."""
    event = parse(store(tmp_path / "db.sqlite", [row(title_override="the incident")]))[0]

    assert event.payload["text"] == "the incident"
    assert event.payload["title_override"] == "the incident"
    assert event.raw["title"] == "fix the build"


# --------------------------------------------------------------- the store as a whole


def test_a_table_that_only_shares_the_name_is_not_read_as_the_vendors(tmp_path: Path) -> None:
    """The store is shared with the rest of the editor, and names get reused.

    Reading a table this parser does not recognise as though it were the vendor's would put
    a session id and an agent in a case out of columns that hold neither.
    """
    path = tmp_path / "db.sqlite"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE sidebar_threads (a TEXT, b TEXT)")
    connection.execute("INSERT INTO sidebar_threads VALUES ('x', 'y')")
    connection.commit()
    connection.close()

    events = parse(path)

    assert [event.kind for event in events] == ["unparsed.record"]
    assert "no verified schema" in (events[0].parse_problem or "")


def test_a_file_that_is_not_a_database_is_reported(tmp_path: Path) -> None:
    path = tmp_path / "db.sqlite"
    path.write_bytes(b"not a database")

    events = parse(path)

    assert len(events) == 1
    assert events[0].parse_problem
