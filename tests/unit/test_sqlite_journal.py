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

from agentforensics.parsers import ParseContext, for_artifact
from agentforensics.parsers.sqlite_store import SIDECAR_SUFFIXES, journal, open_store

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


# ------------------------------------ the sidecar as a file of its own in a collection


def test_a_log_collected_as_its_own_file_is_named_for_what_it_is(tmp_path: Path) -> None:
    """The other half of the same problem, and the one that cried loss where there was none.

    A collection carries a log as a file of its own, because the catalogue claims it in the
    same entry as the database. So it arrives at the parser that opens databases, is not
    one, and became "this store the table list could not be read: file is not a database".
    Two defects in one sentence: it does not parse as English, and it reports a store that
    could not be read when the records in that file are in the case already, read through
    the database beside it. An analyst counting unreadable stores would have counted up to
    twenty-four that were never unreadable.
    """
    source = wal_store(tmp_path / "endpoint")
    into = collect(source, tmp_path / "bundle", with_the_log=True)
    parser = for_artifact("opencode.db")
    assert parser is not None

    def read(name: str) -> list:
        return list(
            parser.parse(
                ParseContext(
                    bundle_uuid="b1",
                    original_path=f"/home/alice/.local/share/opencode/{name}",
                    local_path=into.with_name(name),
                    sha256="aa",
                    artifact_id="opencode.db",
                    agent="opencode",
                    user="alice",
                )
            )
        )

    log = read("sessions.db-wal")
    assert len(log) == 1
    assert "write-ahead log of sessions.db" in (log[0].parse_problem or "")
    assert "already" in (log[0].parse_problem or "")
    assert log[0].raw["database_collected"] is True
    assert "could not be read" not in (log[0].parse_problem or "")

    shared = read("sessions.db-shm")
    assert "shared-memory index" in (shared[0].parse_problem or "")
    assert "the store was open" in (shared[0].parse_problem or "")

    # And the answer that is a finding rather than a reassurance: the log is here and the
    # database it belongs to is not, so its records are in no case at all.
    alone = tmp_path / "alone"
    alone.mkdir()
    shutil.copy2(into.with_name("sessions.db-wal"), alone / "sessions.db-wal")
    orphan = list(
        parser.parse(
            ParseContext(
                bundle_uuid="b1",
                original_path="/home/alice/.local/share/opencode/sessions.db-wal",
                local_path=alone / "sessions.db-wal",
                sha256="aa",
                artifact_id="opencode.db",
                agent="opencode",
                user="alice",
            )
        )
    )
    assert "is not in this collection" in (orphan[0].parse_problem or "")
    assert orphan[0].raw["database_collected"] is False


def test_every_entry_that_claims_a_log_has_a_parser_that_names_it(tmp_path: Path) -> None:
    """The guard, held against the catalogue rather than against a list.

    Every parser that opens a store has to answer for the sidecars its own entries claim,
    and there are eight of them. A ninth written without that branch would report a log as
    a store that could not be read, on exactly the entries whose newest records are in the
    log, and nothing else in this suite would notice. So this asks the catalogue which
    entries claim a sidecar, and asks each one's parser what it makes of one.
    """
    from agentforensics.catalog import load_catalogue

    catalogue = load_catalogue(Path(__file__).resolve().parents[2] / "catalog")
    claiming = [
        artifact
        for artifact in catalogue.artifacts
        if any(path.endswith(SIDECAR_SUFFIXES) for path in artifact.paths)
    ]
    assert len(claiming) >= 20, "the catalogue should claim the logs of the stores it takes"

    (tmp_path / "store.db").write_bytes(b"")
    (tmp_path / "store.db-wal").write_bytes(b"")
    wrong = []
    for artifact in claiming:
        parser = for_artifact(artifact.id)
        if parser is None:
            wrong.append(f"{artifact.id}: nothing claims this entry at all")
            continue
        events = list(
            parser.parse(
                ParseContext(
                    bundle_uuid="b1",
                    original_path=f"/home/alice/store.db-wal ({artifact.id})",
                    local_path=tmp_path / "store.db-wal",
                    sha256="aa",
                    artifact_id=artifact.id,
                    agent=artifact.id.split(".")[0],
                    user="alice",
                )
            )
        )
        said = " ".join(event.parse_problem or "" for event in events)
        if "write-ahead log" not in said:
            wrong.append(f"{artifact.id} ({parser.name}): {said[:120]}")
    assert not wrong, (
        "these entries claim a database's log and their parser does not say what one is, "
        f"so a log in a collection reads as a store that could not be read: {wrong}"
    )


@pytest.mark.slow
def test_a_row_that_exists_only_in_a_log_reaches_a_case(tmp_path: Path) -> None:
    """The whole path, from a profile on disk to a row in a case.

    Everything above this tests a piece: the reader over two files in one directory, the
    gap report when a log was not collected, the sentence a log gets when it arrives as a
    file of its own. None of them tests the thing that has to work, which is that a
    database and its log are claimed by two different catalogue entries, travel as two
    files, and are put back together by the reader. If the mapping from an original path to
    a place in a bundle ever stopped putting them side by side, every one of those tests
    would still pass and every live-collected chat store would quietly stop one message
    early.

    So the profile carries a store in that state, and this asks the case for the message
    that is in the log and in nothing else.
    """
    import sys

    from agentforensics.catalog import load_catalogue
    from agentforensics.ingest import ingest
    from agentforensics.model import Case

    root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(root / "tests" / "fixtures"))
    from generate import build_home

    home = tmp_path / "profile"
    summary = build_home(home, with_edge_cases=False)
    wanted = summary["only_in_the_write_ahead_log"]
    assert isinstance(wanted, str) and wanted

    with Case.open(tmp_path / "case.db") as case:
        ingest(case, home, load_catalogue(root / "catalog"))
        found = case.query("SELECT count(*) AS n FROM events WHERE raw LIKE ?", (f"%{wanted}%",))
    assert found[0]["n"] >= 1, (
        "the row that exists only in the write-ahead log is in no event, so a store "
        "collected from a running agent reads one message short"
    )
