"""Read Zed's sidebar store, which is where it records who ran a thread and what it hid.

`threads.db` holds the conversations. This store, the one the editor's shared database
keeps under `db/0-<release channel>/db.sqlite`, holds what the conversations do not say
about themselves, and three of those things are the kind an examination is opened for:

- **Which agent ran it.** `agent_id` names the agent behind a thread. Zed's own agent is
  written as NULL, because the editor leaves the column empty when the agent is its native
  one, so an empty column is an answer and not a gap. A value is an external agent speaking
  the agent client protocol, which is a different piece of software with its own
  permissions and its own network destinations.
- **Whether it was hidden.** `archived` is what the sidebar hides. An archived thread is
  absent from the interface the person used and completely present on disk, which is the
  difference between a conversation nobody mentioned and a conversation somebody put away.
- **Whether it ran somewhere else.** `remote_connection` carries the connection the thread
  ran over, as the editor's own JSON. A thread that ran against a remote host did its file
  reads and its commands there.

And the store answers a question the transcript store cannot: a thread listed here whose
id is in no `threads.db` row, or the other way round, is a gap. The vendor's own migration
history shows both directions happening, so the two stores are reported and not reconciled
into one story here: the reconciliation belongs to a rule that can see both.

Sources, fetched and read. The schema and its migrations:
https://raw.githubusercontent.com/zed-industries/zed/main/crates/agent_ui/src/thread_metadata_store.rs
The path list the folder columns are written from:
https://raw.githubusercontent.com/zed-industries/zed/main/crates/util/src/path_list.rs
The binding that puts a UUID in a BLOB column:
https://raw.githubusercontent.com/zed-industries/zed/main/crates/sqlez/src/bindable.rs

Two shapes in there are worth stating because getting them wrong is silent. `thread_id` is
a BLOB holding the sixteen raw bytes of a UUID, not its text, and rows migrated from before
that column existed were given `randomblob(16)`, so an id here need not match anything.
And the times are RFC 3339 strings written by the editor, with `created_at` and
`interacted_at` added in later migrations: a row written before them has neither, and the
event says which of the three times it used rather than presenting the last change as the
beginning.

The two other tables in this store are read as well, because of what they are. Zed archives
a git worktree when a thread is put away, and `archived_git_worktrees` records the path, the
repository, the branch and three commit hashes: the state a working copy was left in by an
agent's run. `thread_archived_worktrees` joins that to the thread. They are carried
uninterpreted, as rows, rather than mapped: this module has read their CREATE statements and
not the code that writes them, and a commit hash presented as a claim about what an agent
did to a repository needs more than a column name.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Iterator
from typing import Any

from agentforensics.model import Event, TsPrecision, unparsed
from agentforensics.parsers.base import ParseContext, normalise_ts, text_of
from agentforensics.parsers.sqlite_generic import rows_as_events
from agentforensics.parsers.sqlite_store import (
    BLOB_NOTE,
    StoreError,
    describe,
    open_store,
    rows_of,
    sidecar,
    tables,
)
from agentforensics.parsers.zed import folders

# The one table this module maps. The other two are read as rows, for the reason in the
# module docstring.
MAPPED = ("sidebar_threads",)

# The columns the current schema has, after every migration in the vendor's list. Used to
# tell the vendor's table from one that merely shares its name, and to say which of them a
# row was missing rather than silently reading a None.
_REQUIRED = ("session_id", "title", "updated_at")

# What an empty agent_id means, written into the field itself. A blank there would be read
# as a store that did not record which agent ran the thread, and the blank is the record:
# the editor names an external agent and leaves the column empty for its own. It is not a
# parse problem, because nothing went wrong with the reading and most rows are this one.
NATIVE_AGENT = "the editor's own agent"


class ZedSidebarParser:
    """Zed's thread metadata store, read against the vendor's migrations."""

    name = "zed_sidebar"

    _STORES = frozenset({"zed.sidebar_threads"})

    def handles(self, artifact_id: str | None) -> bool:
        return artifact_id in self._STORES

    def parse(self, context: ParseContext) -> Iterator[Event]:
        beside = sidecar(context)
        if beside is not None:
            # A database's own log or shared-memory file, which this entry claims along
            # with the database. It is not a store and must not be reported as one that
            # could not be read.
            yield beside
            return
        try:
            with open_store(context.local_path) as connection:
                listed = {table.name: table for table in tables(connection)}
                threads = listed.get("sidebar_threads")
                if threads is not None and _is_the_vendors_table(threads.sql):
                    yield from _threads(context, connection, threads)
                for name, table in sorted(listed.items()):
                    if name in MAPPED and _is_the_vendors_table(table.sql):
                        continue
                    # The worktree tables, and a sidebar_threads this parser does not
                    # recognise. Read as rows rather than left out: this store is shared,
                    # and a table nobody has mapped is still evidence that it was there.
                    yield from rows_as_events(context, connection, table)
        except StoreError as exc:
            yield describe(context, str(exc))


def _is_the_vendors_table(sql: str | None) -> bool:
    lowered = (sql or "").lower()
    return all(column in lowered for column in _REQUIRED)


def _threads(context: ParseContext, connection: sqlite3.Connection, table: Any) -> Iterator[Event]:
    for locator, values, problem in rows_of(connection, table):
        if problem:
            yield unparsed(
                context.provenance(locator),
                context.agent,
                values or None,
                problem,
                user=context.user,
                host=context.host,
            )
            continue
        yield _thread(context, locator, values)


def _thread(context: ParseContext, locator: str, values: dict[str, Any]) -> Event:
    """One row of sidebar_threads, as the start of the thread it describes."""
    session_id = text_of(values.get("session_id")) or None
    opened = folders(values.get("folder_paths"), values.get("folder_paths_order"))
    main_worktrees = folders(
        values.get("main_worktree_paths"), values.get("main_worktree_paths_order")
    )
    ts, precision, source, note = _when(values)
    agent_id = text_of(values.get("agent_id")) or None
    archived = _flag(values.get("archived"))
    remote = _remote(values.get("remote_connection"))

    problems = [part for part in (note,) if part]
    return Event(
        kind="session.start",
        provenance=context.provenance(locator),
        agent=context.agent,
        raw=values,
        ts_utc=ts,
        ts_precision=precision,
        ts_source=source if ts else None,
        actor="system",
        user=context.user,
        host=context.host,
        session_id=session_id,
        # The first worktree in the order the person opened them, which the order column
        # restores. All of them stay in the payload.
        project_path=opened[0] if opened else None,
        payload={
            # title_override is what the person renamed the thread to, and it is worth
            # having beside the generated title rather than instead of it: a renamed thread
            # is a thread somebody looked at.
            "text": text_of(values.get("title_override")) or text_of(values.get("title")),
            "title_override": text_of(values.get("title_override")) or None,
            "thread_id": _uuid(values.get("thread_id")),
            # Named rather than left to the empty string, so a case can be searched for the
            # threads an external agent ran.
            "agent_id": agent_id or NATIVE_AGENT,
            "external_agent": bool(agent_id),
            # Hidden from the sidebar and present on disk. False is recorded as well as
            # True: the absence of a hidden thread is an answer somebody asked for.
            "archived": archived,
            "folder_paths": opened or None,
            "main_worktree_paths": main_worktrees or None,
            "remote_connection": remote,
            "ran_remotely": remote is not None,
            "updated_at": text_of(values.get("updated_at")) or None,
            "interacted_at": text_of(values.get("interacted_at")) or None,
        },
        parse_problem=" ".join(problems) or None,
    )


def _when(values: dict[str, Any]) -> tuple[str | None, TsPrecision, str, str | None]:
    """The thread's time, from the earliest of the three the row may carry.

    `created_at` and `interacted_at` both arrived in later migrations, so a row written
    before them has neither and the last change is all there is. Which one was used is on
    the event: presenting a last change as a beginning would put a thread hours or days
    away from when it started.
    """
    for column in ("created_at", "interacted_at", "updated_at"):
        when, precision, note = normalise_ts(values.get(column))
        if when:
            if column == "created_at":
                return when, precision, column, note
            return (
                when,
                precision,
                column,
                " ".join(
                    part
                    for part in (
                        note,
                        f"this row has no created_at, which Zed added in a later migration, "
                        f"so the time on this event is the {column} column and not when the "
                        f"thread started",
                    )
                    if part
                ),
            )
    return None, "absent", "", "this row carries no time at all"


def _uuid(value: Any) -> str | None:
    """The thread id, which the editor stores as the sixteen raw bytes of a UUID.

    Both shapes the store reader can hand over are accepted. Bytes that happen to decode as
    UTF-8 arrive as text, and encoding that text again is the exact inverse of the decode;
    bytes that do not arrive described, with their hex. Either way the id comes back
    readable, and an id nobody can read is a thread nobody can find in the other store.
    """
    if isinstance(value, dict) and value.get(BLOB_NOTE):
        raw = bytes.fromhex(value["hex"]) if isinstance(value.get("hex"), str) else b""
    elif isinstance(value, str):
        raw = value.encode("utf-8")
    elif isinstance(value, bytes):
        raw = value
    else:
        return None
    if len(raw) != 16:
        # Not a UUID. Said rather than forced into one: the column is a BLOB and a row this
        # parser cannot read an id out of still has its bytes in raw.
        return None
    return str(uuid.UUID(bytes=raw))


def _flag(value: Any) -> bool:
    """The archived column, which is an INTEGER defaulting to 0."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        return value.strip() not in ("", "0", "false", "False")
    return False


def _remote(value: Any) -> Any:
    """The remote connection, which the editor writes as its own JSON.

    Returned parsed where it parses and as the text otherwise. What is not done is to read
    a host or a user out of it: this module has read the column's type and not the shape of
    the structure the editor serialises into it, and naming a host an agent connected to is
    exactly the claim that has to rest on something.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return json.loads(value)
    except ValueError:
        return value
