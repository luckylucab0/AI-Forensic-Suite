"""Read a SQLite store the suite has no verified schema for, without inventing one.

Twenty-eight of the catalogue's artifacts are SQLite databases, and before this module not
one of them produced a single event. A collected `opencode.db` became one `artifact.fs`
record: the case stated that the file existed and said nothing at all about the
conversations inside it. An analyst reading that case would conclude there was nothing to
read, which is the one failure this project must not have (non-negotiable 6).

This parser is the honest floor under all of them. It claims every SQLite artifact in the
catalogue and returns, for each one, the tables with their real row counts and then every
row as its own event with the whole row in `raw`. What it does not do is decide what a row
means. Nothing is read out of a row except what the row literally says: a column *named*
as a time is a time, a column *named* as text is text, and everything else stays in `raw`
for a person. Every event it produces carries a `parse_problem` saying that this is an
uninterpreted reading, so the store shows up as evidence somebody still has to look at
rather than as an answer.

That rule is the same one the generated Velociraptor artifact applies to a line-delimited
log it has no mapping for, deliberately, so a fleet hunt and a local case agree on what
"uninterpreted" means and an analyst comparing the two is not told two different stories.

It is a floor, not a ceiling. An agent-specific parser can be written on top of
`sqlite_store` one verified schema at a time, and when one exists it is placed ahead of
this parser in `PARSERS` and takes the artifact over. Until then the rows are visible.
Doing it the other way round, guessing a schema now and correcting it later, would produce
a case that reads as answered while being wrong, and a wrong timeline is worse for an
investigation than an unread one.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from typing import Any

from agentforensics.model import UNINTERPRETED_MARK, Event, unparsed
from agentforensics.parsers.base import ParseContext
from agentforensics.parsers.sqlite_store import (
    StoreError,
    Table,
    describe,
    literal_text,
    literal_time,
    open_store,
    rows_of,
    sidecar,
    tables,
)

# Every SQLite artifact in the catalogue, written out rather than derived from the format
# field at runtime. Two reasons: a parser is handed an artifact id and not the catalogue
# entry, and, more to the point, a new SQLite store should be read because somebody decided
# it should be. tests/unit/test_parsers.py asserts that this set is exactly the catalogue's
# SQLite artifacts, so adding one there fails CI until it is listed here.
STORES = frozenset(
    {
        "aider.tags_cache",
        "amazonq.cli_state_database",
        "cline.sqlite_dbs",
        "codex.sqlite_glob",
        "codex.state_databases",
        "continue.dev_data_db",
        "continue.index",
        "copilot.session_store",
        "crosscutting.macos_download_provenance",
        "cursor.acp_session_store",
        "cursor.agent_store_sync",
        "cursor.ai_code_tracking_db",
        "cursor.macos_bundle_storage",
        "cursor.chat_store_db",
        "cursor.conversation_search_db",
        "cursor.global_state_vscdb",
        "cursor.workspace_state_vscdb",
        "devin.sessions_db",
        "goose.sessions_db",
        "goose.sessions_db_windows",
        "hermes.cron_executions",
        "hermes.memory_store",
        "hermes.projects_db",
        "hermes.response_store",
        "hermes.retired_wal_transcripts",
        "hermes.state_db",
        "hermes.state_snapshot_transcripts",
        "hermes.verification_evidence",
        "kilo_code.cli_db",
        "kiro.cli_session_database",
        "ollama.app_chat_database",
        "opencode.db",
        "vscode.state_vscdb",
        "vscode.workspace_storage",
        "warp.sqlite",
        "windsurf.acp_message_stores",
        "windsurf.cli_sessions_db",
        "windsurf.embedding_database",
        "windsurf.ide_global_state_vscdb",
        "windsurf.ide_workspace_state_vscdb",
        "windsurf.macos_bundle_storage",
        "windsurf.shared_storage",
        "zed.sidebar_threads",
        "zed.threads_db",
    }
)


# The two catalogue entries that are a database's sidecars and nothing else. Every other
# entry claims a store's log in the same entry as the store, so that log reaches the store's
# own parser; these two arrive on their own, and until they were claimed here they became an
# inventory row that said a file was there and nothing about what it was. A write-ahead log
# that nothing explains is the one file in a collection most likely to be read as evidence
# that was lost, when in both of these cases the records in it are already in the case.
SIDECAR_STORES = frozenset(
    {
        "codex.sqlite_write_ahead_logs",
        "copilot.session_store_sidecars",
    }
)

# Stores whose tables are inventoried and whose rows are not ingested, with the reason
# carried onto the event so an analyst reads why rather than guessing.
#
# These are machine-generated derived data: a symbol cache, a repository index, a vector
# store. One of them can hold several hundred thousand rows of chunked file content, and a
# row per chunk would bury a case's real evidence under its own index. They are not skipped
# either, because how much of a working copy an agent had indexed is itself evidence: the
# table list and the row counts are returned, and the rows stay one `sqlite3` away through
# the provenance on the event.
INVENTORY_ONLY = {
    "aider.tags_cache": "a symbol cache the agent builds from the working copy",
    "continue.index": "a repository index the agent builds from the working copy",
    "windsurf.embedding_database": "a vector store the agent builds from the working copy",
}

# The columns a row is read for, by exact name. Kept short and literal: every name added
# here on a hunch is a chance to attach the wrong time to an event, and a wrong time on a
# timeline is the kind of mistake that survives into a report.
_SESSION_COLUMNS = (
    "session_id",
    "sessionId",
    "conversation_id",
    "conversationId",
    "thread_id",
    "threadId",
)
_PROJECT_COLUMNS = ("cwd", "workspace", "project_path", "projectPath", "workspace_path")

# What every event out of this parser says about itself. Second person to the analyst
# rather than to the developer, because this is the text that appears in the case.
_UNINTERPRETED = (
    f"this collection has no verified schema for this store, so the row {UNINTERPRETED_MARK}. "
    "Everything it contained is in raw. Re-read this store once a parser for it exists."
)


class SqliteGenericParser:
    """The reading of last resort for a SQLite store, and the first one for most of them."""

    name = "sqlite_generic"

    def handles(self, artifact_id: str | None) -> bool:
        return artifact_id in STORES or artifact_id in SIDECAR_STORES

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
                listed = tables(connection)
                yield self._inventory(context, listed)
                if context.artifact_id in INVENTORY_ONLY:
                    return
                for table in listed:
                    yield from self._rows(context, connection, table)
        except StoreError as exc:
            # The file is not a database, or is encrypted, or was copied mid-write. An event
            # of its own, because "we collected this and could not open it" is a finding an
            # analyst has to see, not a blank.
            yield describe(context, str(exc))

    def _inventory(self, context: ParseContext, listed: list[Table]) -> Event:
        """The map of the store: every table, its row count, its CREATE statement.

        Emitted even when the store has no tables at all, since an empty chat database is a
        different answer from an uncollected one and a case has to be able to tell them
        apart.
        """
        summary = ", ".join(f"{table.name} ({table.rows} rows)" for table in listed)
        reason = INVENTORY_ONLY.get(context.artifact_id or "")
        text = f"{len(listed)} table(s) in this store" + (f": {summary}" if summary else "")
        if reason:
            text += (
                f". The rows are not ingested: this store is {reason}, and one event per "
                "row would bury the case's evidence under the agent's own index."
            )
        return unparsed(
            context.provenance("schema"),
            context.agent,
            {
                "tables": [
                    {
                        "name": table.name,
                        "rows": table.rows,
                        "sql": table.sql,
                        "has_rowid": table.has_rowid,
                        "problem": table.problem,
                    }
                    for table in listed
                ]
            },
            _UNINTERPRETED
            if not reason
            # Still carries the mark, because this event is the store's table list and
            # nobody has read the store: counted as a record that could not be read, it
            # would show up in a case as a defect in the evidence rather than as a reading
            # nobody has made yet.
            else f"the rows of this store are not ingested: {reason}. The table list "
            f"{UNINTERPRETED_MARK}.",
            user=context.user,
            host=context.host,
            payload={"text": text},
        )

    def _rows(
        self, context: ParseContext, connection: sqlite3.Connection, table: Table
    ) -> Iterator[Event]:
        yield from rows_as_events(context, connection, table)


def rows_as_events(
    context: ParseContext,
    connection: sqlite3.Connection,
    table: Table,
    note: str | None = None,
    *,
    project_path: str | None = None,
) -> Iterator[Event]:
    """One table, uninterpreted, as events.

    Module level rather than a method because an agent-specific parser needs it too: it maps
    the tables whose schema somebody verified and hands every other table here, so a store
    is never half read with the other half silently absent.

    `note` replaces the reason on the events. Without it the reason is that nobody has read
    a schema for this store, which is the usual case and is what an analyst needs to know.
    A parser that has read the schema and is carrying the rows for a different reason, such
    as a table whose rows the event model has no kind for, says that instead: leaving the
    default there would tell a case that a store nobody had read was the problem, and the
    next person would go and read it again.

    `project_path` is the folder the whole store belongs to, for a store that is per
    workspace and whose rows do not name one. A column that names a path wins over it,
    because a row about one project inside a store about another is the row's own answer.
    """
    for locator, values, problem in rows_of(connection, table):
        ts, precision, source, timing_note = literal_time(values)
        problems = [problem or note or _UNINTERPRETED]
        if timing_note:
            problems.append(timing_note)
        yield unparsed(
            context.provenance(locator),
            context.agent,
            values or None,
            " ".join(problems),
            ts_utc=ts,
            ts_precision=precision,
            # Named so the difference between the agent's own clock and a column that
            # merely looks like a time stays visible in the case.
            ts_source=f"the column named {source}" if ts and source else None,
            user=context.user,
            host=context.host,
            session_id=_literal(values, _SESSION_COLUMNS),
            project_path=_literal(values, _PROJECT_COLUMNS) or project_path,
            payload={"table": table.name, "text": literal_text(values)},
        )


def _literal(values: dict[str, Any], columns: tuple[str, ...]) -> str | None:
    """A field, only where a column carries exactly one of these names."""
    for column in columns:
        value = values.get(column)
        if isinstance(value, str) and value.strip():
            return value
        if isinstance(value, int) and not isinstance(value, bool):
            return str(value)
    return None


__all__ = [
    "INVENTORY_ONLY",
    "SIDECAR_STORES",
    "STORES",
    "SqliteGenericParser",
    "rows_as_events",
]
