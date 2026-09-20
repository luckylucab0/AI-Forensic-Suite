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

**The workspace directory name, and the one file that undoes it.** A per-workspace store
lives in a directory whose name says nothing: measurement showed it is not a digest of the
folder path, because fifty combinations of normalisation and digest algorithm failed to
reproduce one, and the same folder produces the same name in two different products. Beside
each store the editor writes a `workspace.json` holding the folder's URI in plain text, and
that file is the only way from the name back to the folder.

It used to reach a case as a complaint. The catalogue claims it under the same entry as the
store, so it arrived here, was opened as a database, failed, and produced one event saying
the file is not a database, with the URI in no field of it. That is the failure this project
is built around: the content was in the bundle and in no event.

So two things happen now. The file is read as the small document it is, and every event out
of the store beside it carries `project_path`, resolved from it. The second half is what
makes a per-workspace store answerable at all: without it no rule and no view can say which
project a row belongs to, and `project_path` is a field of the event model that every one of
these stores left empty.

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
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

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


# The file the editor writes beside a per-workspace store, holding the folder that store
# belongs to. Its name is fixed by the editor rather than by any of the forks, so one name
# covers every product in _STORES.
WORKSPACE_FILE = "workspace.json"

# The keys that file uses for the thing that was open. `folder` is a single directory and
# `workspace` is a multi-root workspace file; the editor writes one or the other and never
# both. `configuration` is the older spelling of the second, kept because a store written by
# an older build is exactly the kind of evidence this suite is collected for.
_WORKSPACE_KEYS = ("folder", "workspace", "configuration")

# Said on the resolved event rather than only here. A remote URI is a path on another
# machine, and a report that showed it as a local path would send somebody to a directory
# that was never on this endpoint.
REMOTE_URI = (
    "This workspace was not local: the URI names another machine, so the path is a path "
    "there and the agent's own files for it are on that machine rather than this one."
)

# What a store says when the file that names its folder was not collected beside it.
NO_WORKSPACE_FILE = (
    "No workspace.json was collected beside this store, so the directory name it sits in "
    "cannot be resolved to a folder. The name is not a digest of the path and cannot be "
    "computed back into one."
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
        if Path(context.original_path).name == WORKSPACE_FILE:
            # Claimed by the same catalogue entry as the store it sits beside, and not a
            # database. Opening it as one produced an event that said so and carried none
            # of its content, which is the one failure this project does not accept.
            yield _workspace_document(context)
            return
        beside = sidecar(context)
        if beside is not None:
            # A database's own log or shared-memory file, which this entry claims along
            # with the database. It is not a store and must not be reported as one that
            # could not be read.
            yield beside
            return
        project, unresolved = _folder_beside(context)
        try:
            with open_store(context.local_path) as connection:
                listed = tables(connection)
                yield _inventory(context, listed, project, unresolved)
                for table in listed:
                    if table.name == MAPPED and _is_the_vendors_table(table):
                        yield from _items(context, connection, table, project)
                    else:
                        # Everything else, including an ItemTable whose columns are not the
                        # ones the vendor declares. A store half read with the other half
                        # silently absent is the failure this project does not accept.
                        yield from rows_as_events(context, connection, table, project_path=project)
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


def _inventory(
    context: ParseContext,
    listed: list[Table],
    project: str | None = None,
    unresolved: str | None = None,
) -> Event:
    """The shape of the store, as one event.

    Worth an event of its own here rather than only in the generic reader: which tables a
    state store has is itself a dating signal for the product that wrote it, and an empty
    store and an uncollected one have to be distinguishable in a case.

    It is also where a per-workspace store says which folder it belongs to, or says that
    nothing beside it could answer that. Once per store rather than once per row, because
    it is a fact about the file.
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
        project_path=project,
        parse_problem=unresolved,
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


def _items(
    context: ParseContext,
    connection: sqlite3.Connection,
    table: Table,
    project: str | None = None,
) -> Iterator[Event]:
    """Every row of ItemTable, as a configuration snapshot naming its key.

    `project` is the folder a per-workspace store belongs to, read from the file beside it.
    It is on every row rather than only on the store, because a rule and a timeline both
    group by the field on the event and neither of them reads back to the store's own.
    """
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
            project_path=project,
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


def _workspace_document(context: ParseContext) -> Event:
    """The file that names the folder a per-workspace store belongs to, as an event.

    Small and worth all of it: the URI is the only thing that undoes the store's directory
    name, and a case that held a complaint about the file instead of its content would leave
    an analyst with a directory name nobody can reverse.
    """
    try:
        text = context.local_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return Event(
            kind="config.snapshot",
            provenance=context.provenance("file"),
            agent=context.agent,
            actor="system",
            ts_utc=None,
            ts_precision="absent",
            ts_source=None,
            user=context.user,
            host=context.host,
            raw={"file": WORKSPACE_FILE},
            parse_problem=f"this file could not be read: {exc}",
            payload={"text": ""},
        )
    try:
        document = json.loads(text)
    except ValueError as exc:
        document = None
        problem: str | None = (
            f"this file is not valid JSON ({exc}), so its text is carried as it stands"
        )
    else:
        problem = None
    uri = _uri(document)
    project, remote = _folder(uri)
    return Event(
        kind="config.snapshot",
        provenance=context.provenance("file"),
        agent=context.agent,
        actor="system",
        ts_utc=None,
        ts_precision="absent",
        ts_source=None,
        user=context.user,
        host=context.host,
        project_path=project,
        raw=document if isinstance(document, dict) else {"text": text},
        parse_problem=" ".join(part for part in (problem, REMOTE_URI if remote else None) if part)
        or None,
        payload={
            "text": text,
            "key": WORKSPACE_FILE,
            **({"uri": uri} if uri else {}),
            **({"value": document} if isinstance(document, dict) else {}),
        },
    )


def _folder_beside(context: ParseContext) -> tuple[str | None, str | None]:
    """The folder a per-workspace store belongs to, and why it is unknown where it is.

    The bundle mirrors original paths, so the file the editor writes beside the store is
    beside it here too. Read per store rather than held across the run: a parser that
    remembered one workspace while reading another would attribute rows to the wrong
    project, which is worse than not attributing them at all.

    Only for a store that sits in a per-workspace directory. A global store belongs to no
    single folder and a neighbour file would be somebody else's.
    """
    if "workspaceStorage" not in context.original_path.replace("\\", "/"):
        return None, None
    beside = context.local_path.parent / WORKSPACE_FILE
    try:
        document = json.loads(beside.read_text(encoding="utf-8", errors="replace"))
    except OSError, ValueError:
        return None, NO_WORKSPACE_FILE
    project, remote = _folder(_uri(document))
    if project is None:
        return None, NO_WORKSPACE_FILE
    return project, REMOTE_URI if remote else None


def _uri(document: Any) -> str | None:
    """The URI of the thing that was open, under whichever of the three keys carries it."""
    if not isinstance(document, dict):
        return None
    for key in _WORKSPACE_KEYS:
        value = document.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


def _folder(uri: str | None) -> tuple[str | None, bool]:
    """A URI as a path, and whether it names another machine.

    A `file:` URI is percent-encoded, and on Windows the drive letter is encoded too, so
    `file:///c%3A/Users/alice` is `c:/Users/alice` and a reader that skipped the decoding
    would produce a path no filesystem has. Anything else is returned whole: a remote URI is
    a path on another host and shortening it to its path component would claim a local
    directory that was never here.
    """
    if not uri:
        return None, False
    parts = urlsplit(uri)
    if parts.scheme in ("", "file"):
        path = unquote(parts.path)
        # file:///c%3A/... decodes to /c:/..., and the leading separator is the URI's, not
        # the path's.
        if len(path) > 2 and path[0] == "/" and path[2] == ":":
            path = path[1:]
        return (path or None), False
    return uri, True


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
