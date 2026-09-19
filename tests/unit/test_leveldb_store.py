"""Tests for the parser over the two Electron key-value stores.

The reader underneath is tested against the format's own specification in test_leveldb.py.
This file asks the other question: given one of those files under the catalogue entry that
claims a whole directory, does a case end up with records in it, and does every record say
how much of itself was actually understood. That second half is the point of the module.
A store whose records came out looking read would be worse than one that came out unread.
"""

from __future__ import annotations

from pathlib import Path

from test_leveldb import batch, log, table

from agentforensics.model import is_uninterpreted
from agentforensics.parsers import ParseContext, for_artifact
from agentforensics.parsers.leveldb_store import STORES

ARTIFACT = "claude_desktop.renderer_state"


def parse(path: Path, artifact_id: str = ARTIFACT) -> list:
    parser = for_artifact(artifact_id)
    assert parser is not None, artifact_id
    return list(
        parser.parse(
            ParseContext(
                bundle_uuid="b1",
                original_path="/Users/alice/Library/Application Support/Claude/"
                f"Local Storage/leveldb/{path.name}",
                local_path=path,
                sha256="aa",
                artifact_id=artifact_id,
                agent="claude_desktop",
                user="alice",
            )
        )
    )


def test_both_stores_reach_this_parser() -> None:
    """Two products, one browser engine, one module. A store that stopped arriving here
    would go back to being a list of file names in a case."""
    for artifact_id in STORES:
        parser = for_artifact(artifact_id)
        assert parser is not None and parser.name == "leveldb_store", artifact_id


def test_a_table_becomes_one_record_per_entry(tmp_path: Path) -> None:
    path = tmp_path / "000005.ldb"
    path.write_bytes(table([(b"_https://example.org\x00recent", b"a folder the user opened")]))
    events = parse(path)
    assert len(events) == 1
    assert events[0].raw["key"].startswith("_https://example.org")
    assert "a folder the user opened" in events[0].payload["text"]


def test_every_record_says_that_nobody_has_read_its_shape(tmp_path: Path) -> None:
    """The floor this module stands on. The bytes inside a value are the browser engine's
    own serialisation, and a record that did not say so would read as an answer."""
    path = tmp_path / "000005.ldb"
    path.write_bytes(table([(b"key", b"value")]))
    events = parse(path)
    assert all(is_uninterpreted(event) for event in events)


def test_the_write_ahead_log_is_read_as_well(tmp_path: Path) -> None:
    """The writeup behind one of these entries puts the prompts in the log before
    compaction, so a parser that took only the tables would miss what happened last."""
    path = tmp_path / "000008.log"
    path.write_bytes(log([batch([(b"prompt", b"deploy it without asking")], 42)]))
    events = parse(path)
    assert [event.raw["sequence"] for event in events] == [42]
    assert "deploy it without asking" in events[0].payload["text"]


def test_a_deletion_is_kept_and_named_as_one(tmp_path: Path) -> None:
    """A removed key is the difference between a deleted conversation and none."""
    path = tmp_path / "000009.log"
    path.write_bytes(log([batch([(b"conversation-7", None)], 7)]))
    events = parse(path)
    assert events[0].raw["deleted"] is True
    assert "removed the key" in (events[0].parse_problem or "")


def test_a_value_stored_as_utf_16_is_still_searchable(tmp_path: Path) -> None:
    """Local Storage writes a string in either encoding behind a tag byte. A rule cannot
    match bytes, so a value only one of the two readings recovers still has to yield text."""
    path = tmp_path / "000005.ldb"
    wide = b"\x00" + "a key that went to a gateway".encode("utf-16-le")
    path.write_bytes(table([(b"key", wide)]))
    events = parse(path)
    assert "a key that went to a gateway" in events[0].payload["text"]


def test_the_misaligned_reading_of_a_wide_string_does_not_win(tmp_path: Path) -> None:
    """The tie the encoding tag creates, which length alone cannot break.

    Read from the wrong byte, a sixteen bit string yields exactly as many characters as it
    should, and every one of them is printable, so the two readings are the same length and
    whichever was tried first would be kept. Here that would put a line of ideographs in a
    case as the folder the user pointed the agent at.
    """
    path = tmp_path / "000005.ldb"
    path.write_bytes(table([(b"k", b"\x00" + "C:/Users/alice/src/app".encode("utf-16-le"))]))
    assert "C:/Users/alice/src/app" in parse(path)[0].payload["text"]


def test_current_names_the_live_manifest(tmp_path: Path) -> None:
    """It is the store's entry point, and which manifest is live says which tables belong
    to the store as it last stood."""
    path = tmp_path / "CURRENT"
    path.write_bytes(b"MANIFEST-000012\n")
    events = parse(path)
    assert "MANIFEST-000012" in (events[0].parse_problem or "")


def test_the_manifest_is_counted_rather_than_guessed_at(tmp_path: Path) -> None:
    """Its records are version edits and this collection has no reading for them, so the
    file is reported as what it is instead of being walked as conversation records."""
    path = tmp_path / "MANIFEST-000012"
    path.write_bytes(log([b"\x00" * 12, b"\x00" * 12]))
    events = parse(path)
    assert "2 record(s)" in (events[0].parse_problem or "")


def test_the_engines_own_log_comes_through_line_by_line(tmp_path: Path) -> None:
    """A compaction line dates the moment the records this parser reads out of the
    write-ahead log stopped being separately visible."""
    path = tmp_path / "LOG"
    path.write_text("recovering log #3\ncompacted to: files[ 1 0 ]\n", newline="")
    events = parse(path)
    assert [event.raw["line"] for event in events] == [
        "recovering log #3",
        "compacted to: files[ 1 0 ]",
    ]


def test_a_file_that_is_not_part_of_the_store_is_reported_not_guessed(tmp_path: Path) -> None:
    """One catalogue entry claims a whole application-data tree, so files that are not the
    store's own arrive here too. Saying so is the difference between a case that shows a
    gap and a case that shows nothing."""
    path = tmp_path / "Preferences"
    path.write_text('{"a": 1}', newline="")
    events = parse(path, "chatgpt_desktop.windows_msix_localcache")
    assert "is not a file this parser maps" in (events[0].parse_problem or "")


def test_a_table_that_breaks_halfway_keeps_what_came_out_before_it(tmp_path: Path) -> None:
    """A store whose reading broke has to be visible as a store whose reading broke, with
    the records it did give up, rather than as a store that read as empty."""
    good = table([(b"key", b"value")])
    path = tmp_path / "000005.ldb"
    # The footer's index handle is left alone and the block it points at is cut, which is
    # the shape a partially written or carved table has on disk.
    path.write_bytes(good[:4] + good[8:])
    events = parse(path)
    assert events
    assert any("stopped reading" in (event.parse_problem or "") for event in events)
