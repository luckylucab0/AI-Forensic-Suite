"""Read the key/value store VS Code and the editors built on it keep their state in.

Five catalogue artifacts are this one file under three product names: the editor's own
`state.vscdb`, Cursor's global and per-workspace copies, and the two Windsurf keeps. It is
where an extension puts everything it wants to survive a restart, so it is where an
examination finds which agent extensions were installed, what they were configured with,
and, on older builds, the chat text itself.

Before this module they were read by the generic SQLite reader, which returned every row
with the value in `text` and the key only inside `raw`. In a store whose whole structure is
that the key names the thing, that is the wrong way round: an analyst looking for what an
agent extension left behind searches for the key, and the key was not a field. Every one of
those events also said that no verified schema existed for the store, which stopped being
true once somebody read the vendor's.

The schema, from the editor's own source:

    CREATE TABLE IF NOT EXISTS ItemTable (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB)

Source, fetched and read:
https://raw.githubusercontent.com/microsoft/vscode/main/src/vs/base/parts/storage/node/storage.ts

Two things in that file decide how this parser reads a row. The table is created with
`PRAGMA user_version = 1` and, when the editor asks for it, `PRAGMA journal_mode=WAL`,
which is why a collection of one of these is worth nothing without its `-wal` sibling. And
the editor reads the table back with `SELECT * FROM ItemTable` into a `Map<string, string>`:
the column is declared BLOB and holds a string. JSON is the convention every extension
follows and not a contract the storage layer states, so a value that parses as JSON is
carried parsed as well as whole, and a value that does not is still a value rather than a
defect.

**What this parser does not claim.** It says nothing about what any individual key means.
The keys are namespaced by whoever wrote them, the products fork and rename, and the one
thing worse than an unread store is a case that states an extension did something because a
key looked like it said so. So every row becomes a configuration snapshot naming its key,
and the reading of a particular key is left to an analyst who can see it. The tables this
module has not read, among them the ones Cursor keeps its conversations in, go through the
uninterpreted reader unchanged rather than being left out.

**Credential material.** The catalogue records that this file also holds the editor's
SecretStorage rows. They are ciphertext, the collector treats the file as ordinary evidence
because the rest of it is, and this parser carries the values exactly as the generic reader
did before it. Telling a secret row from an ordinary one would need a source for how those
keys are spelled, and this module does not have one, so it does not guess at it.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from typing import Any

from agentforensics.model import Event
from agentforensics.parsers.base import ParseContext
from agentforensics.parsers.sqlite_generic import rows_as_events
from agentforensics.parsers.sqlite_store import (
    BLOB_NOTE,
    StoreError,
    Table,
    describe,
    open_store,
    rows_of,
    sidecar,
    tables,
)

# The one table this module has read against the vendor's source.
MAPPED = "ItemTable"

# The two columns that table is declared with. Checked rather than assumed: a store whose
# ItemTable has different columns is not the table this parser was written for, and reading
# it as though it were would put invented fields in a case.
_COLUMNS = ("key", "value")

# Said on the store's own event rather than only here, because an analyst reading the case
# has the case and not this file. On the store and not on every row: the rows carry it in
# ts_precision, which is the field made for it, and a parse problem on all three thousand of
# them would say that something went wrong with the reading when nothing did.
_NO_TIME = (
    "This store keeps no time of its own: a row says what a value was when the file was last "
    "written and nothing about when it was set, so no event from it carries a timestamp."
)


class VscodeStateParser:
    """VS Code's ItemTable, and the same table under the names the forks give the file."""

    name = "vscode_state"

    _STORES = frozenset(
        {
            "vscode.state_vscdb",
            "cursor.global_state_vscdb",
            "cursor.workspace_state_vscdb",
            "windsurf.ide_global_state_vscdb",
            "windsurf.ide_workspace_state_vscdb",
            "windsurf.shared_storage",
        }
    )

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
                listed = tables(connection)
                yield _inventory(context, listed)
                for table in listed:
                    if table.name == MAPPED and _is_the_vendors_table(table):
                        yield from _items(context, connection, table)
                    else:
                        # Everything else, including an ItemTable whose columns are not the
                        # ones the vendor declares. A store half read with the other half
                        # silently absent is the failure this project does not accept.
                        yield from rows_as_events(context, connection, table)
        except StoreError as exc:
            # Collected and not openable is a finding in its own right. These files are
            # written continuously while the editor runs, so a copy taken from a live host
            # is the usual way to get one.
            yield describe(context, str(exc))


def _is_the_vendors_table(table: Table) -> bool:
    """Whether the table declares the two columns the vendor's CREATE statement does.

    Read off the CREATE statement rather than from a query, because a table this parser
    cannot recognise has to fall through to the uninterpreted reader, and finding that out
    by having a SELECT fail would lose the rows.
    """
    sql = (table.sql or "").lower()
    return all(column in sql for column in _COLUMNS)


def _inventory(context: ParseContext, listed: list[Table]) -> Event:
    """The shape of the store, as one event.

    Worth an event of its own here rather than only in the generic reader: which tables a
    state store has is itself a dating signal for the product that wrote it, and an empty
    store and an uncollected one have to be distinguishable in a case.
    """
    summary = ", ".join(f"{table.name} ({table.rows} rows)" for table in listed)
    return Event(
        kind="config.snapshot",
        provenance=context.provenance("schema"),
        agent=context.agent,
        actor="system",
        ts_utc=None,
        ts_precision="absent",
        ts_source=None,
        user=context.user,
        host=context.host,
        raw={
            "tables": [
                {"name": table.name, "rows": table.rows, "sql": table.sql} for table in listed
            ]
        },
        payload={
            "text": f"{len(listed)} table(s) in this state store"
            + (f": {summary}. " if summary else ". ")
            + _NO_TIME,
            "tables": [table.name for table in listed],
        },
    )


def _items(context: ParseContext, connection: sqlite3.Connection, table: Table) -> Iterator[Event]:
    """Every row of ItemTable, as a configuration snapshot naming its key."""
    for locator, values, problem in rows_of(connection, table):
        key = values.get("key") if values else None
        value = values.get("value") if values else None
        text, parsed, note = _read(value)
        problems = [p for p in (problem, note) if p]
        yield Event(
            kind="config.snapshot",
            provenance=context.provenance(locator),
            agent=context.agent,
            actor="system",
            ts_utc=None,
            ts_precision="absent",
            ts_source=None,
            user=context.user,
            host=context.host,
            raw=values or None,
            parse_problem=" ".join(problems) or None,
            payload={
                # The key first, because in this store the key is the evidence: it names
                # the extension that wrote the row and what the row is for.
                "key": key if isinstance(key, str) else None,
                "text": text,
                **({"value": parsed} if parsed is not None else {}),
            },
        )


def _read(value: Any) -> tuple[str, Any, str | None]:
    """One stored value, as text, as structure where it has any, and what was odd about it.

    The storage layer hands the editor a string. JSON is what every extension puts in it,
    which is a convention rather than a contract, so a value that does not parse is returned
    as the text it is and not as a problem.
    """
    if isinstance(value, dict) and value.get(BLOB_NOTE):
        # The store reader could not make text of the column. It has already described it by
        # hash and length, and that description is the honest reading of it: it goes in the
        # text so a person sees it, and not in `value`, which is for a value that parsed.
        # The description itself stays in raw with the rest of the row.
        return (
            str(value.get("note") or ""),
            None,
            (
                "the value column is not text the reader could decode, so the case holds a "
                "description of the bytes rather than their content"
            ),
        )
    if value is None:
        return "", None, "the value column is null, which the vendor's own reader cannot produce"
    if not isinstance(value, str):
        # A number or a blob that decoded to something else. Carried as written.
        return str(value), None, None
    try:
        return value, json.loads(value), None
    except ValueError:
        # Not JSON, which is ordinary: the column holds whatever string an extension put in
        # it, and several put a bare number or a plain string there.
        return value, None, None
