"""Tests for the Chromium key-value store reader and the Snappy block it needs.

Two desktop agents keep their conversations in this store, and until it could be read a
collection of one reached a case as a list of file names. There is no library here to test
against, so the fixtures are built to the format's own specification: a table file with a
footer, an index block and a data block, and a write-ahead log with its fragments. A reader
that agrees with a file assembled from the specification is a reader that agrees with the
specification.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from agentforensics.parsers.leveldb import (
    TABLE_MAGIC,
    LevelDbError,
    looks_like_table,
    read_log,
    read_table,
)
from agentforensics.parsers.snappy import SnappyError
from agentforensics.parsers.snappy import decompress as unsnappy


def varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def block(entries: list[tuple[bytes, bytes]]) -> bytes:
    """One block, with every entry at a restart point so the keys are whole."""
    out = bytearray()
    restarts = []
    for key, value in entries:
        restarts.append(len(out))
        out += varint(0) + varint(len(key)) + varint(len(value)) + key + value
    for offset in restarts:
        out += struct.pack("<I", offset)
    out += struct.pack("<I", len(restarts))
    return bytes(out)


def snappy_literal(data: bytes) -> bytes:
    """The simplest valid Snappy block: a preamble and one literal run."""
    return varint(len(data)) + bytes([((len(data) - 1) << 2)]) + data


def table(entries: list[tuple[bytes, bytes]], compress: bool = False) -> bytes:
    """A table file built the way the format describes one."""
    data_block = block(entries)
    stored = snappy_literal(data_block) if compress else data_block
    out = bytearray()
    data_offset = 0
    out += stored
    out += bytes([1 if compress else 0]) + struct.pack("<I", 0)

    index_offset = len(out)
    index = block([(entries[-1][0], varint(data_offset) + varint(len(stored)))])
    out += index + bytes([0]) + struct.pack("<I", 0)

    footer = bytearray()
    footer += varint(0) + varint(0)
    footer += varint(index_offset) + varint(len(index))
    footer += bytes(40 - len(footer))
    footer += struct.pack("<Q", TABLE_MAGIC)
    return bytes(out + footer)


def log(batches: list[bytes]) -> bytes:
    out = bytearray()
    for batch in batches:
        out += struct.pack("<I", 0) + struct.pack("<H", len(batch)) + bytes([1]) + batch
    return bytes(out)


def batch(records: list[tuple[bytes, bytes | None]], sequence: int = 1) -> bytes:
    out = bytearray(struct.pack("<Q", sequence) + struct.pack("<I", len(records)))
    for key, value in records:
        if value is None:
            out += bytes([0]) + varint(len(key)) + key
        else:
            out += bytes([1]) + varint(len(key)) + key + varint(len(value)) + value
    return bytes(out)


# ------------------------------------------------------------------------- snappy


def test_a_literal_run_comes_back_as_itself() -> None:
    assert unsnappy(snappy_literal(b"a conversation")) == b"a conversation"


def test_a_copy_repeats_what_was_already_produced() -> None:
    """The overlapping case, which is how the format expresses a repeated run and the one
    a slice-based implementation gets wrong."""
    data = varint(8) + bytes([(3 << 2)]) + b"abcd" + bytes([(0 << 2) | 1, 4])
    assert unsnappy(data) == b"abcdabcd"


def test_a_block_that_stops_early_raises_rather_than_returning_half() -> None:
    """A truncated block that came back as a short result would put half a record in a case
    with nothing saying so."""
    with pytest.raises(SnappyError):
        unsnappy(varint(32) + bytes([(3 << 2)]) + b"abcd")


def test_a_copy_pointing_before_the_start_is_refused() -> None:
    with pytest.raises(SnappyError):
        unsnappy(varint(4) + bytes([(0 << 2) | 1, 9]))


# -------------------------------------------------------------------------- tables


def test_a_table_gives_up_its_keys_and_values(tmp_path: Path) -> None:
    path = tmp_path / "000005.ldb"
    path.write_bytes(
        table(
            [
                (b"_https://example.org\x00key-one", b"first"),
                (b"_https://example.org\x00key-two", b"second"),
            ]
        )
    )
    records = list(read_table(path))
    assert [record.key for record in records] == [
        b"_https://example.org\x00key-one",
        b"_https://example.org\x00key-two",
    ]
    assert [record.value for record in records] == [b"first", b"second"]


def test_a_snappy_compressed_block_is_expanded(tmp_path: Path) -> None:
    """Most blocks in a real store are compressed, so a reader that only handled the plain
    ones would report a store with almost nothing in it."""
    path = tmp_path / "000006.ldb"
    path.write_bytes(table([(b"key", b"a value worth compressing")], compress=True))
    assert [record.value for record in read_table(path)] == [b"a value worth compressing"]


def test_a_file_that_is_not_a_table_says_so(tmp_path: Path) -> None:
    path = tmp_path / "CURRENT"
    path.write_bytes(b"MANIFEST-000001\n")
    assert not looks_like_table(path)
    with pytest.raises(LevelDbError):
        list(read_table(path))


def test_the_magic_is_what_identifies_a_table(tmp_path: Path) -> None:
    path = tmp_path / "000007.ldb"
    path.write_bytes(table([(b"key", b"value")]))
    assert looks_like_table(path)


# ----------------------------------------------------------------------------- log


def test_the_write_ahead_log_carries_the_newest_records(tmp_path: Path) -> None:
    """They are the ones not yet folded into a table, so a reader that took only the tables
    would return everything except what happened last."""
    path = tmp_path / "000008.log"
    path.write_bytes(log([batch([(b"key-one", b"first"), (b"key-two", b"second")], 42)]))
    records = list(read_log(path))
    assert [record.key for record in records] == [b"key-one", b"key-two"]
    assert [record.sequence for record in records] == [42, 43]


def test_a_deletion_is_a_record_of_its_own(tmp_path: Path) -> None:
    """For a conversation store the difference between a key that never existed and one
    that was removed is the whole question."""
    path = tmp_path / "000009.log"
    path.write_bytes(log([batch([(b"gone", None)], 7)]))
    records = list(read_log(path))
    assert records[0].deleted is True
    assert records[0].value is None


def test_a_record_limit_stops_the_reading(tmp_path: Path) -> None:
    path = tmp_path / "000010.log"
    path.write_bytes(log([batch([(f"k{n}".encode(), b"v") for n in range(10)])]))
    assert len(list(read_log(path, limit=3))) == 3
