"""Reading a collected SQLite store, and saying what is in one without guessing.

Twenty-one of the catalogue's transcript artifacts are SQLite databases, across fifteen
agents, and until this module none of them produced anything. A collected `opencode.db`
became a single `artifact.fs` event: the case recorded that the file existed and said
nothing about the four hundred messages in it. That is the failure this project exists to
prevent, in the place it was easiest to overlook.

This module does two separable things, and the split is the point.

**It opens a store safely.** Evidence is read-only (non-negotiable 3), so the file is never
opened in place: it is copied to a temporary directory first, together with its `-wal` and
`-shm` siblings, and the copy is opened through a `mode=ro` URI. Copying is not caution for
its own sake. A read-only WAL connection still wants to create a shared-memory file beside
the database, and a bundle directory an examiner has made read-only would refuse it; worse,
opening the original at all takes a lock on evidence. The siblings travel because that is
where uncommitted transactions live: a chat store collected from a running agent can have
its newest messages only in the write-ahead log, and opening the database without it
silently returns a conversation that stops early.

**It describes a store it has no schema for.** Every table with its row count, then every
row, as its own event with the whole row in `raw`. Nothing is inferred beyond what a row
literally says: a column named `timestamp`, `ts`, `created_at` or `createdAt` is read as a
time, and a column named `text`, `content`, `message` or `body` is read as text. That is
the same rule the Velociraptor artifact's generic normalizer uses for a line-delimited log
it has no mapping for, deliberately, so the two producers stay consistent about what
"uninterpreted" means. Everything else is left in `raw` for a human, and every such event
carries a `parse_problem` saying so.

An agent-specific parser can then be written on top of the reader, one verified schema at a
time, and until it exists the store is visible rather than absent. That ordering matters:
guessing a schema would produce a case that looks answered.
"""

from __future__ import annotations

import compression.zstd as zstd
import hashlib
import shutil
import sqlite3
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agentforensics.model import Event, TsPrecision, unparsed
from agentforensics.parsers.base import ParseContext, normalise_ts, text_of

# The siblings a write-ahead-log database keeps beside itself. Copied with the database
# because the newest transactions can be in the log and nowhere else.
SIBLINGS = ("-wal", "-shm", "-journal")

# How many rows of one table are read before the reader stops and says so. A chat store can
# hold hundreds of thousands of rows, and one event per row is the right shape for evidence
# right up to the point where it stops fitting in a case. The limit is visible in the output
# rather than silent, which is the same choice the line reader makes for a very long file.
MAX_ROWS = 50_000

# A value that is bytes and does not decode as text. Recorded by hash and length instead of
# being carried into the case. Not hiding it: the row's provenance names the bundle, the
# table and the rowid, so the bytes are one `sqlite3` away, and a fifty megabyte blob copied
# into a case database would cost more than it tells anybody.
BLOB_NOTE = "__blob__"

# The first four bytes of a zstd frame, from RFC 8878 section 3.1.1. An agent that
# compresses its transcripts this way, and at least one does, leaves a BLOB that `strings`
# finds nothing in and a keyword search never matches. Recognising the frame is not a guess
# about the column: the magic number says what the bytes are.
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"

# How much one compressed column is allowed to expand to. A zstd frame can be a few hundred
# bytes and expand without limit, so a cap is not caution for its own sake: a case database
# should not be fillable by one row of a collected file. Reaching it is reported on the
# value rather than silently truncating what an analyst then reads as the whole thing.
MAX_DECOMPRESSED = 64 * 1024 * 1024

# The column names a row is allowed to be read for. Literal, short, and not extended by
# guesswork: a mapping invented for a schema nobody verified produces output that looks
# like an answer.
_TIME_COLUMNS = ("timestamp", "ts", "created_at", "createdAt", "time", "date", "updated_at")
_TEXT_COLUMNS = ("text", "content", "message", "body", "prompt", "value", "data")


@dataclass(frozen=True, slots=True)
class Table:
    """One table of a store, with what the reader could learn about it cheaply."""

    name: str
    sql: str | None
    rows: int
    has_rowid: bool
    problem: str | None = None


class StoreError(Exception):
    """The file could not be opened as a database at all."""


@contextmanager
def open_store(path: Path) -> Iterator[sqlite3.Connection]:
    """A read-only connection to a copy of one store.

    A copy, always, even when the original is writable. The alternative is a lock and a
    shared-memory file beside evidence, and an analyst who later hashes the bundle would
    find it changed by the act of reading it.
    """
    workspace = Path(tempfile.mkdtemp(prefix="afx-sqlite-"))
    try:
        local = workspace / path.name
        try:
            shutil.copy2(path, local)
            for suffix in SIBLINGS:
                sibling = path.with_name(path.name + suffix)
                if sibling.is_file():
                    shutil.copy2(sibling, local.with_name(local.name + suffix))
        except OSError as exc:
            raise StoreError(f"could not be copied for reading: {exc}") from exc

        try:
            connection = sqlite3.connect(f"{local.resolve().as_uri()}?mode=ro", uri=True)
        except sqlite3.Error as exc:
            raise StoreError(f"could not be opened as a database: {exc}") from exc
        connection.row_factory = sqlite3.Row
        # Text that is not valid UTF-8 comes back with replacement characters rather than
        # raising. A column holding one bad byte would otherwise take the whole table with
        # it, and the rest of that table is evidence.
        connection.text_factory = lambda raw: raw.decode("utf-8", "replace")
        try:
            yield connection
        finally:
            connection.close()
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def tables(connection: sqlite3.Connection) -> list[Table]:
    """Every table in the store, with its row count.

    The count is a real count rather than a statistic, because the number an analyst is
    about to quote should not come from whatever the last ANALYZE happened to record.
    """
    try:
        listed = connection.execute(
            "SELECT name, sql FROM sqlite_master WHERE type = 'table' ORDER BY name"
        ).fetchall()
    except sqlite3.DatabaseError as exc:
        raise StoreError(f"the table list could not be read: {exc}") from exc

    out = []
    for row in listed:
        name = str(row["name"])
        # A quoted identifier, because a table can be called anything at all, including
        # something that would otherwise parse as SQL.
        quoted = '"' + name.replace('"', '""') + '"'
        problem = None
        count = 0
        has_rowid = True
        try:
            count = int(connection.execute(f"SELECT count(*) AS n FROM {quoted}").fetchone()["n"])  # noqa: S608
        except sqlite3.DatabaseError as exc:
            problem = f"the row count could not be read: {exc}"
        try:
            connection.execute(f"SELECT rowid FROM {quoted} LIMIT 1").fetchone()  # noqa: S608
        except sqlite3.DatabaseError:
            # A WITHOUT ROWID table has no rowid to select, which is not an error and does
            # change how a row is located. Recorded so the locator can say so.
            has_rowid = False
        out.append(
            Table(name=name, sql=row["sql"], rows=count, has_rowid=has_rowid, problem=problem)
        )
    return out


def rows_of(
    connection: sqlite3.Connection, table: Table, limit: int = MAX_ROWS
) -> Iterator[tuple[str, dict[str, Any], str | None]]:
    """Every row of one table, as (locator, values, problem).

    Ordered by rowid where there is one, so two reads of the same store produce the same
    sequence and a case can be rebuilt byte for byte. A WITHOUT ROWID table is read in
    whatever order it comes back in, and its locator says so rather than implying a
    position the table does not have.
    """
    quoted = '"' + table.name.replace('"', '""') + '"'
    if table.has_rowid:
        sql = f"SELECT rowid AS __rowid, * FROM {quoted} ORDER BY rowid LIMIT ?"  # noqa: S608
    else:
        sql = f"SELECT * FROM {quoted} LIMIT ?"  # noqa: S608

    try:
        cursor = connection.execute(sql, (limit + 1,))
    except sqlite3.DatabaseError as exc:
        yield f"table:{table.name}", {}, f"the table could not be read: {exc}"
        return

    seen = 0
    while True:
        try:
            row = cursor.fetchone()
        except sqlite3.DatabaseError as exc:
            # A corrupt page stops this table and not the store. The rows already read are
            # still evidence, and the failure is a record of its own.
            # Located as an offset into the read rather than as a rowid: rowids are not
            # consecutive, so `rowid:seen + 1` would be a number some other row in this
            # table may really have, and two events with one locator collide on their id.
            yield (
                f"table:{table.name} after-row:{seen}",
                {},
                f"reading stopped after {seen} row(s): {exc}",
            )
            return
        if row is None:
            return
        seen += 1
        if seen > limit:
            yield (
                f"table:{table.name}",
                {},
                f"stopped after {limit} rows: the table is longer than the ingest limit, "
                "so the rest of it has not been read",
            )
            return
        # `.keys()` is not redundant here and ruff's SIM118 is wrong about this type: a
        # sqlite3.Row iterates its values, not its column names, so `for key in row` would
        # silently use each value as a key and produce a dictionary of nonsense.
        values = {key: _value(row[key]) for key in row.keys() if key != "__rowid"}  # noqa: SIM118
        if table.has_rowid:
            locator = f"table:{table.name} rowid:{row['__rowid']}"
        else:
            locator = f"table:{table.name} row:{seen} (the table has no rowid)"
        yield locator, values, None


def _value(value: Any) -> Any:
    """One column value, as something a case can hold.

    Bytes that decode as UTF-8 become text, because a great many of these stores keep JSON
    in a BLOB column and an analyst wants to read it. A zstd frame is decompressed first,
    for the same reason and a stronger one: compressed content is invisible to every other
    method an examiner has, so a store that keeps its transcripts this way reads as a store
    with nothing in it. Bytes that are neither are described by hash and length.
    """
    if not isinstance(value, bytes):
        return value
    if value.startswith(ZSTD_MAGIC):
        return _unzstd(value)
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        return _opaque(value, "binary column, not carried into the case")


def _unzstd(value: bytes) -> Any:
    """A zstd frame, decompressed, or an honest description of why it is not."""
    try:
        decompressor = zstd.ZstdDecompressor()
        out = decompressor.decompress(value, max_length=MAX_DECOMPRESSED)
    except zstd.ZstdError as exc:
        # A frame that will not decompress is evidence of its own: a truncated file, or a
        # column that only begins like one.
        return _opaque(value, f"a zstd frame that could not be decompressed: {exc}")
    if not decompressor.eof and len(out) < MAX_DECOMPRESSED:
        # The frame ended before the frame did. A column cut short, or four bytes that only
        # look like a frame. Told apart from hitting the cap below, because one is damaged
        # evidence and the other is this reader's own limit, and reporting either as the
        # other would send an analyst after the wrong thing.
        return _opaque(
            value,
            "an incomplete zstd frame: it decompressed without error and stopped before "
            "the end of the frame, so the column is truncated or is not a frame at all",
        )
    try:
        text = out.decode("utf-8")
    except UnicodeDecodeError:
        return _opaque(
            value,
            "a zstd frame whose contents are not UTF-8, so the compressed bytes are "
            "recorded rather than their expansion",
        )
    if not decompressor.eof:
        return {
            BLOB_NOTE: True,
            "bytes": len(value),
            "sha256": hashlib.sha256(value).hexdigest(),
            "note": f"a zstd frame that expands past the ingest limit of "
            f"{MAX_DECOMPRESSED} bytes. The first part of it is in text; the rest has not "
            "been read",
            "text": text,
        }
    return text


def _opaque(value: bytes, why: str) -> dict[str, Any]:
    return {
        BLOB_NOTE: True,
        "bytes": len(value),
        "sha256": hashlib.sha256(value).hexdigest(),
        "note": f"{why}. The row's provenance names the file, the table and the rowid.",
    }


def literal_time(
    values: dict[str, Any],
) -> tuple[str | None, TsPrecision, str | None, str | None]:
    """A time, only where a column is named as one. Returns (ts, precision, source, note)."""
    for column in _TIME_COLUMNS:
        if column in values and values[column] not in (None, ""):
            ts, precision, note = normalise_ts(values[column])
            if ts:
                return ts, precision, column, note
    return None, "absent", None, None


def literal_text(values: dict[str, Any]) -> str:
    """Text, only where a column is named as text."""
    for column in _TEXT_COLUMNS:
        value = values.get(column)
        if isinstance(value, str) and value.strip():
            return value
        if isinstance(value, (list, dict)):
            return text_of(value)
    return ""


def describe(context: ParseContext, store_problem: str) -> Event:
    """The event a store that could not be opened at all becomes."""
    return unparsed(
        context.provenance("file"),
        context.agent,
        {"file": context.local_path.name, "problem": store_problem},
        f"this store {store_problem}",
        user=context.user,
        host=context.host,
    )


__all__ = [
    "BLOB_NOTE",
    "MAX_DECOMPRESSED",
    "MAX_ROWS",
    "SIBLINGS",
    "ZSTD_MAGIC",
    "StoreError",
    "Table",
    "describe",
    "literal_text",
    "literal_time",
    "open_store",
    "rows_of",
    "tables",
]
