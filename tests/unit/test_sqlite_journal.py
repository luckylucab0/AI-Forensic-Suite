"""Tests for the one failure in this pipeline that SQLite itself reports as success.

A database in write-ahead-log mode keeps its newest transactions in a file beside itself.
Collect the database alone and it opens, every table is there, every row reads, and the
conversation simply stops early. No error, no warning, nothing in the case saying the
reading might be short. An analyst would quote a last message that is not the last message.

So the first test here is the defect itself, written down: the same store read with and
without its log returns different rows. The rest is what the suite now says about it.
"""

from __future__ import annotations

import shutil
import sqlite3
from collections.abc import Iterator
from pathlib import Path

import pytest

from agentforensics.parsers.sqlite_store import journal, open_store

# The connections the fixtures leave open, closed once the module is done. They have to stay
# open while the files are copied: closing one checkpoints the log into the database and
# destroys the very state these tests are about.
_HELD: list[sqlite3.Connection] = []


@pytest.fixture(scope="module", autouse=True)
def _close_what_was_held() -> Iterator[None]:
    yield
    for connection in _HELD:
        connection.close()
    _HELD.clear()


def wal_store(directory: Path) -> Path:
    """A database whose newest row is in the log and nowhere else.

    Built the way a collection finds one: the application is still holding the database
    open, so the log has not been checkpointed away. Closing the connection first would
    fold the row into the database and destroy the very case this is about.
    """
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "sessions.db"
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("CREATE TABLE messages (id INTEGER, text TEXT)")
    connection.execute("INSERT INTO messages VALUES (1, 'the first message')")
    connection.commit()
    connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    connection.execute("INSERT INTO messages VALUES (2, 'the message that is only in the log')")
    connection.commit()
    # Left open on purpose. The caller copies the files out from under it, which is what a
    # live collection does.
    _HELD.append(connection)
    return path


def collect(source: Path, into: Path, *, with_the_log: bool) -> Path:
    into.mkdir(parents=True, exist_ok=True)
    for candidate in sorted(source.parent.iterdir()):
        if not with_the_log and candidate.name != source.name:
            continue
        shutil.copy2(candidate, into / candidate.name)
    return into / source.name


def test_a_database_collected_without_its_log_reads_short(tmp_path: Path) -> None:
    """The defect, stated as a test so it cannot come back unnoticed."""
    source = wal_store(tmp_path / "endpoint")
    whole = collect(source, tmp_path / "with-log", with_the_log=True)
    partial = collect(source, tmp_path / "without-log", with_the_log=False)

    with open_store(whole) as connection:
        complete = [row["text"] for row in connection.execute("SELECT text FROM messages")]
    with open_store(partial) as connection:
        short = [row["text"] for row in connection.execute("SELECT text FROM messages")]

    assert "the message that is only in the log" in complete
    assert "the message that is only in the log" not in short
    # And the second reading raised nothing at all, which is the whole problem.
    assert short == ["the first message"]


def test_the_reader_says_which_of_the_two_readings_it_made(tmp_path: Path) -> None:
    source = wal_store(tmp_path / "endpoint")
    whole = journal(collect(source, tmp_path / "with-log", with_the_log=True))
    partial = journal(collect(source, tmp_path / "without-log", with_the_log=False))

    assert whole is not None and whole.wal_mode and whole.log_bytes is not None
    assert partial is not None and partial.wal_mode
    # None rather than zero. A log that was collected and is empty means nothing is
    # missing; a log that was not collected means nobody can say.
    assert partial.log_bytes is None


def test_a_database_that_does_not_journal_ahead_is_not_flagged(tmp_path: Path) -> None:
    """The default journal mode keeps everything in the database, so there is nothing to
    warn about and a warning on every store would be noise nobody reads."""
    path = tmp_path / "rollback.db"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE t (a)")
    connection.commit()
    connection.close()
    state = journal(path)
    assert state is not None and not state.wal_mode


def test_a_file_that_is_not_a_database_is_not_answered_about(tmp_path: Path) -> None:
    """Every collected file passes this check, so a file that is not a database has to come
    back as no answer rather than as a store with no log."""
    path = tmp_path / "notes.md"
    path.write_text("# not a database\n", newline="")
    assert journal(path) is None


def test_a_file_shorter_than_a_header_is_not_answered_about(tmp_path: Path) -> None:
    """A partially written or truncated store, which is a shape a live collection produces."""
    path = tmp_path / "truncated.db"
    path.write_bytes(b"SQLite format 3\x00")
    assert journal(path) is None
