"""Tests for the SQLite reader and the uninterpreted reading built on it.

Two things are being defended here, and only one of them is the code.

The first is that a collected database produces evidence at all. Twenty-eight catalogue
artifacts are SQLite stores, and a case that recorded their existence and none of their
contents would tell an analyst there was nothing to find. So the tests below care most
about the awkward stores: the one that is not a database, the one with a table name that
would parse as SQL, the one whose newest rows are only in the write-ahead log, the one with
a column of bytes that are not text, the WITHOUT ROWID table, the empty one.

The second is the catalogue staying in step. The test at the bottom compares the parser's
committed set of artifact ids against every SQLite artifact in the real catalogue, so
adding a store to the catalogue fails until somebody decides how it is read. That is the
only part of this pipeline where a silent omission would be invisible in every other test:
the artifact would be collected, then pass through ingest as unsupported, and nothing would
look wrong.

Every database here is built in a temporary directory by the test that needs it. Nothing is
copied from a real agent.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from agentforensics.catalog import load_catalogue
from agentforensics.parsers import PARSERS, for_artifact
from agentforensics.parsers.base import ParseContext
from agentforensics.parsers.sqlite_generic import INVENTORY_ONLY, STORES
from agentforensics.parsers.sqlite_store import (
    BLOB_NOTE,
    open_store,
    rows_of,
    tables,
)

CATALOG_DIR = Path(__file__).resolve().parents[2] / "catalog"


def store(path: Path, statements: list[str]) -> Path:
    """A database built from SQL, closed before anybody reads it."""
    connection = sqlite3.connect(path)
    try:
        for statement in statements:
            connection.execute(statement)
        connection.commit()
    finally:
        connection.close()
    return path


def context(path: Path, artifact_id: str = "goose.sessions_db") -> ParseContext:
    return ParseContext(
        bundle_uuid="b1",
        original_path="/home/alice/.local/share/goose/sessions.db",
        local_path=path,
        sha256="aa",
        artifact_id=artifact_id,
        agent="goose",
        user="alice",
    )


def parse(path: Path, artifact_id: str = "goose.sessions_db") -> list:
    parser = for_artifact(artifact_id)
    assert parser is not None, artifact_id
    return list(parser.parse(context(path, artifact_id)))


# ------------------------------------------------------------------- the reader


def test_the_original_file_is_never_touched(tmp_path: Path) -> None:
    """Non-negotiable 3, at the one place in the analyzer that could break it.

    Opening a SQLite database takes a lock, and a read-only connection to a WAL database
    still wants to create a shared-memory file beside it. Both would change evidence, and
    an analyst who hashed the bundle afterwards would find it altered by the act of reading.
    """
    path = store(
        tmp_path / "chat.db",
        ["CREATE TABLE messages (id INTEGER PRIMARY KEY, text TEXT)"],
    )
    before = {item.name: item.stat().st_mtime_ns for item in tmp_path.iterdir()}
    digest_before = path.read_bytes()

    with open_store(path) as connection:
        tables(connection)

    assert {item.name: item.stat().st_mtime_ns for item in tmp_path.iterdir()} == before
    assert path.read_bytes() == digest_before


def test_a_file_that_is_not_a_database_is_an_event_and_not_a_crash(tmp_path: Path) -> None:
    """A collected file can be anything. Truncated, encrypted, or the wrong file entirely.

    The answer has to be a record saying so, because "we collected this and could not read
    it" is a finding an analyst must see. A blank would read as an empty database.
    """
    path = tmp_path / "chat.db"
    path.write_bytes(b"this is not a database at all")

    events = parse(path)

    assert len(events) == 1
    assert events[0].kind == "unparsed.record"
    assert events[0].parse_problem is not None


def test_the_rows_in_the_write_ahead_log_are_read(tmp_path: Path) -> None:
    """The defect this reader exists to avoid, and the one nobody would notice.

    A chat store collected from a running agent can have its newest messages only in the
    -wal file. Opening the database without it returns a conversation that stops early, and
    a conversation that stops early looks like a conversation that ended.
    """
    path = tmp_path / "chat.db"
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, text TEXT)")
    connection.execute("INSERT INTO messages VALUES (1, 'committed before collection')")
    connection.commit()
    # Left open on purpose: the WAL file is still beside the database, which is the state a
    # live collection captures.
    assert (tmp_path / "chat.db-wal").is_file()

    try:
        with open_store(path) as reader:
            listed = tables(reader)
            assert [table.rows for table in listed] == [1]
            texts = [values["text"] for _, values, _ in rows_of(reader, listed[0])]
    finally:
        connection.close()

    assert texts == ["committed before collection"]


def test_a_table_name_that_would_parse_as_sql_is_read(tmp_path: Path) -> None:
    """A table can be called anything, including something that looks like a statement."""
    path = store(
        tmp_path / "chat.db",
        [
            'CREATE TABLE "select from where" (a TEXT)',
            "INSERT INTO \"select from where\" VALUES ('x')",
        ],
    )

    with open_store(path) as connection:
        listed = tables(connection)
        assert [table.name for table in listed] == ["select from where"]
        assert [table.rows for table in listed] == [1]
        assert [values for _, values, _ in rows_of(connection, listed[0])] == [{"a": "x"}]


def test_a_without_rowid_table_says_so_in_its_locator(tmp_path: Path) -> None:
    """It has no rowid to point at, so the locator must not imply one.

    A fabricated rowid in a provenance record is worse than an honest position: an analyst
    going back to the evidence with it would find a different row or none at all.
    """
    path = store(
        tmp_path / "chat.db",
        [
            "CREATE TABLE kv (k TEXT PRIMARY KEY, v TEXT) WITHOUT ROWID",
            "INSERT INTO kv VALUES ('a', '1')",
        ],
    )

    with open_store(path) as connection:
        listed = tables(connection)
        assert listed[0].has_rowid is False
        locators = [locator for locator, _, _ in rows_of(connection, listed[0])]

    assert locators == ["table:kv row:1 (the table has no rowid)"]


def test_a_rowid_table_is_located_by_its_real_rowid(tmp_path: Path) -> None:
    """Not by position, because a deleted row leaves a gap and the two then disagree."""
    path = store(
        tmp_path / "chat.db",
        [
            "CREATE TABLE messages (id INTEGER PRIMARY KEY, text TEXT)",
            "INSERT INTO messages VALUES (1, 'a'), (2, 'b'), (3, 'c')",
            "DELETE FROM messages WHERE id = 2",
        ],
    )

    with open_store(path) as connection:
        listed = tables(connection)
        locators = [locator for locator, _, _ in rows_of(connection, listed[0])]

    assert locators == ["table:messages rowid:1", "table:messages rowid:3"]


def test_bytes_that_are_text_are_read_and_bytes_that_are_not_are_described(
    tmp_path: Path,
) -> None:
    """Several of these stores keep JSON in a BLOB column, and it is the evidence.

    Bytes that are not text are recorded by hash and length instead. Not hidden: the row's
    provenance names the file, the table and the rowid, so the bytes are one query away,
    and carrying a large binary column into a case would cost more than it tells anybody.
    """
    path = tmp_path / "chat.db"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE blobs (id INTEGER PRIMARY KEY, data BLOB)")
    connection.execute("INSERT INTO blobs VALUES (1, ?)", (b'{"role": "user"}',))
    connection.execute("INSERT INTO blobs VALUES (2, ?)", (b"\x00\xff\xfe binary",))
    connection.commit()
    connection.close()

    with open_store(path) as reader:
        listed = tables(reader)
        values = [row for _, row, _ in rows_of(reader, listed[0])]

    assert values[0]["data"] == '{"role": "user"}'
    assert values[1]["data"][BLOB_NOTE] is True
    assert values[1]["data"]["bytes"] == 10
    assert len(values[1]["data"]["sha256"]) == 64


def test_text_that_is_not_valid_utf8_costs_the_column_and_not_the_table(
    tmp_path: Path,
) -> None:
    """One bad byte in one column must not take the rest of a transcript with it."""
    path = tmp_path / "chat.db"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, text TEXT)")
    # Written as bytes into a TEXT column, which SQLite allows and agents do produce.
    connection.execute("INSERT INTO messages VALUES (1, CAST(x'61ff62' AS TEXT))")
    connection.execute("INSERT INTO messages VALUES (2, 'readable')")
    connection.commit()
    connection.close()

    with open_store(path) as reader:
        listed = tables(reader)
        values = [row for _, row, _ in rows_of(reader, listed[0])]

    assert "�" in values[0]["text"]
    assert values[1]["text"] == "readable"


def test_the_row_limit_is_reported_rather_than_silent(tmp_path: Path) -> None:
    """A truncated read that says nothing is the same defect as a dropped record."""
    path = store(
        tmp_path / "chat.db",
        [
            "CREATE TABLE messages (id INTEGER PRIMARY KEY)",
            "INSERT INTO messages VALUES (1), (2), (3)",
        ],
    )

    with open_store(path) as connection:
        listed = tables(connection)
        read = list(rows_of(connection, listed[0], limit=2))

    assert len(read) == 3
    assert read[-1][1] == {}
    assert "stopped after 2 rows" in (read[-1][2] or "")


def test_an_empty_store_is_not_the_same_answer_as_an_uncollected_one(tmp_path: Path) -> None:
    """So a store with no tables still produces its inventory event."""
    path = store(tmp_path / "chat.db", ["CREATE TABLE t (a TEXT)", "DROP TABLE t"])

    events = parse(path)

    assert len(events) == 1
    assert events[0].provenance.locator == "schema"
    assert "0 table(s)" in events[0].payload["text"]


# ---------------------------------------------------- the uninterpreted reading


def test_every_row_becomes_an_event_carrying_the_whole_row(tmp_path: Path) -> None:
    path = store(
        tmp_path / "chat.db",
        [
            "CREATE TABLE messages (id INTEGER PRIMARY KEY, session_id TEXT, "
            "created_at TEXT, cwd TEXT, text TEXT, extra TEXT)",
            "INSERT INTO messages VALUES (1, 's1', '2026-09-06T09:00:00Z', "
            "'/home/alice/work', 'please refactor this', 'nobody mapped this column')",
        ],
    )

    events = parse(path)
    rows = [event for event in events if event.provenance.locator != "schema"]

    assert len(rows) == 1
    row = rows[0]
    assert row.kind == "unparsed.record"
    assert row.ts_utc == "2026-09-06T09:00:00.000000Z"
    assert row.ts_source == "the column named created_at"
    assert row.session_id == "s1"
    assert row.project_path == "/home/alice/work"
    assert row.payload["text"] == "please refactor this"
    assert row.payload["table"] == "messages"
    # The point of the whole exercise: the column nobody mapped is still in the case.
    assert row.raw["extra"] == "nobody mapped this column"
    assert row.parse_problem is not None


def test_a_column_that_is_not_named_as_a_time_is_not_read_as_one(tmp_path: Path) -> None:
    """Guessing here would attach a wrong time to an event, which survives into a report."""
    path = store(
        tmp_path / "chat.db",
        [
            "CREATE TABLE messages (id INTEGER PRIMARY KEY, sent TEXT)",
            "INSERT INTO messages VALUES (1, '2026-09-06T09:00:00Z')",
        ],
    )

    rows = [event for event in parse(path) if event.provenance.locator != "schema"]

    assert rows[0].ts_utc is None
    assert rows[0].ts_precision == "absent"
    # And the value is still there to be read by a person.
    assert rows[0].raw["sent"] == "2026-09-06T09:00:00Z"


def test_the_inventory_lists_every_table_with_a_real_count(tmp_path: Path) -> None:
    """A real count, not a statistic: the number an analyst quotes should not come from
    whatever the last ANALYZE happened to record."""
    path = store(
        tmp_path / "chat.db",
        [
            "CREATE TABLE messages (id INTEGER PRIMARY KEY)",
            "CREATE TABLE sessions (id TEXT)",
            "INSERT INTO messages VALUES (1), (2)",
        ],
    )

    schema = next(event for event in parse(path) if event.provenance.locator == "schema")

    assert "messages (2 rows)" in schema.payload["text"]
    assert "sessions (0 rows)" in schema.payload["text"]
    assert [table["name"] for table in schema.raw["tables"]] == ["messages", "sessions"]


def test_every_event_id_is_distinct(tmp_path: Path) -> None:
    """Ingest is idempotent through the event id, so two rows sharing one would collapse
    into a single event and a conversation would lose a turn."""
    path = store(
        tmp_path / "chat.db",
        [
            "CREATE TABLE messages (id INTEGER PRIMARY KEY, text TEXT)",
            "CREATE TABLE notes (id INTEGER PRIMARY KEY, text TEXT)",
            "INSERT INTO messages VALUES (1, 'a'), (2, 'b')",
            "INSERT INTO notes VALUES (1, 'a'), (2, 'b')",
        ],
    )

    events = parse(path)

    assert len(events) == 5
    assert len({event.event_id for event in events}) == 5


def test_reading_the_same_store_twice_gives_the_same_events(tmp_path: Path) -> None:
    """Non-negotiable 5. Ordered by rowid so a case can be rebuilt byte for byte."""
    path = store(
        tmp_path / "chat.db",
        [
            "CREATE TABLE messages (id INTEGER PRIMARY KEY, text TEXT)",
            "INSERT INTO messages VALUES (1, 'a'), (2, 'b'), (3, 'c')",
        ],
    )

    first = [(event.event_id, event.raw_json()) for event in parse(path)]
    second = [(event.event_id, event.raw_json()) for event in parse(path)]

    assert first == second


def test_an_index_store_is_inventoried_and_its_rows_are_not_ingested(tmp_path: Path) -> None:
    """A vector store can hold several hundred thousand chunks of a working copy.

    A row per chunk would bury the case's real evidence, so the tables and their counts are
    returned and the rows are not, with the reason on the event. How much of a working copy
    the agent had indexed is still visible, which is what an analyst asks of one of these.
    """
    path = store(
        tmp_path / "index.db",
        [
            "CREATE TABLE chunks (id INTEGER PRIMARY KEY, text TEXT)",
            "INSERT INTO chunks VALUES (1, 'a chunk of a source file'), (2, 'another')",
        ],
    )

    events = parse(path, "windsurf.embedding_database")

    assert len(events) == 1
    assert events[0].provenance.locator == "schema"
    assert "chunks (2 rows)" in events[0].payload["text"]
    assert "not ingested" in events[0].payload["text"]
    assert "not ingested" in (events[0].parse_problem or "")


# --------------------------------------------- the catalogue staying in step


def test_the_parser_claims_every_sqlite_artifact_in_the_catalogue() -> None:
    """The one omission no other test would catch.

    An unclaimed SQLite store is collected, passes ingest as unsupported, and produces a
    case where nothing looks wrong. So the committed set is compared against the catalogue
    itself: adding a store there fails here until somebody decides how it is read.
    """
    catalogue = load_catalogue(CATALOG_DIR)
    in_catalogue = {
        artifact.id
        for agent in catalogue.agents
        for artifact in agent.artifacts
        if artifact.format == "sqlite"
    }

    assert in_catalogue == STORES


def test_every_inventory_only_store_is_one_of_the_claimed_ones() -> None:
    """Otherwise the reason would sit on an id nothing reads, and the store it was written
    for would be dumped row by row after all."""
    assert set(INVENTORY_ONLY) <= STORES


@pytest.mark.parametrize("artifact_id", sorted(STORES))
def test_every_claimed_store_is_read_by_something(artifact_id: str) -> None:
    """Either by the generic reader or by a parser with a verified schema placed ahead of it.

    The set does not shrink when one is taken over, and that is the point: the generic
    reader goes on claiming every SQLite artifact, so the drift test above keeps working,
    while a verified parser decides what a store's rows mean. What must never happen is a
    store that neither reads.
    """
    parser = for_artifact(artifact_id)
    assert parser is not None
    if parser.name != "sqlite_generic":
        generic = next(p for p in PARSERS if p.name == "sqlite_generic")
        assert generic.handles(artifact_id), (
            f"{artifact_id} was taken over by {parser.name} and dropped out of the generic "
            "reader's set, so adding a SQLite store to the catalogue would stop failing here"
        )


# ------------------------------------------------------- compressed content


def test_a_zstd_column_is_decompressed(tmp_path: Path) -> None:
    """The worst shape a store can have for this tool, and one agent uses it.

    Compressed content is invisible to every other method an examiner has: strings finds
    nothing, a keyword search matches nothing, and a generic reader that recorded a hash
    would leave the case saying the store held one opaque blob. Recognising the frame is
    not a guess about the column, the magic number says what the bytes are.
    """
    import compression.zstd as zstd

    body = '{"title": "fix the build", "messages": [{"User": {"content": [{"Text": "hi"}]}}]}'
    path = tmp_path / "threads.db"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE threads (id TEXT PRIMARY KEY, data BLOB)")
    connection.execute("INSERT INTO threads VALUES (?, ?)", ("t1", zstd.compress(body.encode())))
    connection.commit()
    connection.close()

    with open_store(path) as reader:
        listed = tables(reader)
        values = [row for _, row, _ in rows_of(reader, listed[0])]

    assert values[0]["data"] == body


def test_something_that_only_begins_like_a_frame_is_described_and_not_dropped(
    tmp_path: Path,
) -> None:
    """A truncated file, or a column that happens to start with those four bytes. Either
    way the bytes are evidence and the failure is a record of its own."""
    path = tmp_path / "threads.db"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE threads (id TEXT PRIMARY KEY, data BLOB)")
    connection.execute(
        "INSERT INTO threads VALUES (?, ?)", ("t1", b"\x28\xb5\x2f\xfd" + b"\x00" * 16)
    )
    connection.commit()
    connection.close()

    with open_store(path) as reader:
        listed = tables(reader)
        values = [row for _, row, _ in rows_of(reader, listed[0])]

    blob = values[0]["data"]
    assert blob[BLOB_NOTE] is True
    assert "incomplete zstd frame" in blob["note"]
    assert len(blob["sha256"]) == 64


def test_a_frame_that_expands_past_the_limit_says_so(tmp_path: Path) -> None:
    """Truncation that says nothing is the same defect as a dropped record, and a
    compressed column is where it would be cheapest to hit: a few hundred bytes on disk
    can expand without limit."""
    import compression.zstd as zstd

    from agentforensics.parsers import sqlite_store

    path = tmp_path / "threads.db"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE threads (id TEXT PRIMARY KEY, data BLOB)")
    connection.execute("INSERT INTO threads VALUES (?, ?)", ("t1", zstd.compress(b"x" * 4096)))
    connection.commit()
    connection.close()

    original = sqlite_store.MAX_DECOMPRESSED
    sqlite_store.MAX_DECOMPRESSED = 100
    try:
        with open_store(path) as reader:
            listed = tables(reader)
            values = [row for _, row, _ in rows_of(reader, listed[0])]
    finally:
        sqlite_store.MAX_DECOMPRESSED = original

    blob = values[0]["data"]
    assert blob[BLOB_NOTE] is True
    assert "expands past the ingest limit" in blob["note"]
    # The part that was read is still there, rather than the whole thing being withheld.
    assert blob["text"] == "x" * 100
