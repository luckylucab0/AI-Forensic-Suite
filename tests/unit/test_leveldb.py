"""Tests for the Chromium key-value store reader and the Snappy block it needs.

Two desktop agents keep their conversations in this store, and until it could be read a
collection of one reached a case as a list of file names. There is no library here to test
against, so the fixtures are built to the format's own specification: a table file with a
footer, an index block and a data block, and a write-ahead log with its fragments. A reader
that agrees with a file assembled from the specification is a reader that agrees with the
specification.
"""

from __future__ import annotations

import compression.zstd as zstd
import struct
from pathlib import Path

import pytest
from test_snappy import literal as snappy_literal_run

from agentforensics.parsers.leveldb import (
    FOOTER_LENGTH,
    LOG_BLOCK,
    TABLE_MAGIC,
    LevelDbError,
    log_records,
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
    """The simplest valid Snappy block: a preamble and one literal run.

    The run's own encoding comes from the Snappy tests beside this file rather than being
    written twice, because a length over sixty bytes moves out of the tag and into the
    bytes after it, and a helper that only knew the short form built a block no data block
    of a realistic size could use.
    """
    return varint(len(data)) + snappy_literal_run(data)


# The trailer byte on a block says how it was stored. Bool works as an argument because
# True is 1, which is what it meant before this took the other kinds.
NONE, SNAPPY, ZSTD = 0, 1, 4


def table(entries: list[tuple[bytes, bytes]], compress: int = NONE) -> bytes:
    """A table file built the way the format describes one."""
    data_block = block(entries)
    if compress == SNAPPY:
        stored = snappy_literal(data_block)
    elif compress == ZSTD:
        stored = zstd.compress(data_block)
    else:
        stored = data_block
    out = bytearray()
    data_offset = 0
    out += stored
    out += bytes([compress]) + struct.pack("<I", 0)

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


# ------------------------------------------------------ the log's fragment framing

# A record too large for what is left of a 32 kilobyte block is split across blocks, and
# until these tests nothing had ever produced one. That path is not an edge case here: a
# write batch in a conversation store carries whole messages, and a message with a pasted
# file in it passes 32 kilobytes easily, so the newest and most valuable records in a
# store are exactly the ones that arrive in pieces.

LOG_HEADER = 7
FULL, FIRST, MIDDLE, LAST = 1, 2, 3, 4


def framed(payloads: list[bytes]) -> bytes:
    """Payloads in the log framing, fragmented across blocks the way the format says.

    Written from the specification rather than from the reader: a header holds a checksum
    this reader does not verify, a two byte length and a type, a record never crosses a
    block boundary without being split, and fewer than seven bytes left in a block is
    padding rather than a header.
    """
    out = bytearray()
    for payload in payloads:
        at = 0
        first = True
        while True:
            room = LOG_BLOCK - (len(out) % LOG_BLOCK)
            if room < LOG_HEADER:
                out += bytes(room)
                room = LOG_BLOCK
            room -= LOG_HEADER
            take = min(room, len(payload) - at)
            last = at + take == len(payload)
            kind = (FULL if last else FIRST) if first else (LAST if last else MIDDLE)
            out += struct.pack("<I", 0) + struct.pack("<H", take) + bytes([kind])
            out += payload[at : at + take]
            at += take
            first = False
            if last:
                break
    return bytes(out)


def test_a_record_larger_than_a_block_is_reassembled(tmp_path: Path) -> None:
    """Three fragments at least, and the value has to come back byte for byte."""
    pasted = bytes((index * 31 + 7) & 0xFF for index in range(90_000))
    path = tmp_path / "000011.log"
    path.write_bytes(framed([batch([(b"chat/1", pasted), (b"chat/2", b"after it")], 5)]))

    records = list(read_log(path))
    assert [record.key for record in records] == [b"chat/1", b"chat/2"]
    assert records[0].value == pasted


def test_the_locator_names_the_offset_the_record_starts_at(tmp_path: Path) -> None:
    """A byte offset is provenance, so it has to be somewhere the record actually is.

    It pointed past the record before: the offset was taken after the first fragment had
    been consumed, so an analyst following it landed in the middle of a large record or
    just after a small one.
    """
    path = tmp_path / "000012.log"
    payload = batch([(b"chat/1", b"x" * 50_000)], 9)
    path.write_bytes(framed([batch([(b"first", b"small")], 1), payload]))

    data = path.read_bytes()
    for record in read_log(path):
        offset = int(record.locator.split()[0].removeprefix("log:"))
        assert data[offset + 6] in (FULL, FIRST), (
            f"the locator {record.locator!r} does not point at a fragment header, so it "
            "does not point at the record it claims to name"
        )


def test_a_log_that_ends_mid_record_gives_up_what_it_held_and_says_so(
    tmp_path: Path,
) -> None:
    """The failure this reader had: a truncated tail vanished without a trace.

    A log copied off a running endpoint, or left by a crash, routinely ends in the middle
    of a record. The reader returned the records before it and nothing at all about the
    one that was cut, so the newest part of a conversation was absent from the case and
    indistinguishable from never having existed.
    """
    entries = [(f"chat/{index}".encode(), b"a message " * 200) for index in range(30)]
    whole = framed([batch(entries, 100)])
    path = tmp_path / "000013.log"
    # Cut inside the second fragment, so the first block's worth of entries is complete.
    path.write_bytes(whole[: LOG_BLOCK + 400])

    recovered = []
    with pytest.raises(LevelDbError, match="ends inside the record that starts at offset"):
        for record in read_log(path):
            recovered.append(record.key)

    assert recovered, "the entries that were whole before the cut have to stay in the case"
    assert recovered == [key for key, _ in entries][: len(recovered)]
    assert len(recovered) < len(entries), "the fixture has to actually be cut short"


def test_a_log_that_ends_after_a_first_fragment_is_reported(tmp_path: Path) -> None:
    """The other shape of the same cut: the opening fragment arrived and nothing after it."""
    path = tmp_path / "000014.log"
    path.write_bytes(framed([batch([(b"chat/1", b"m" * 60_000)], 3)])[:LOG_BLOCK])
    with pytest.raises(LevelDbError, match="ends inside the record that starts at offset"):
        list(read_log(path))


def test_the_framing_reader_reports_the_same_cut(tmp_path: Path) -> None:
    """The manifest path reads the same framing, so it has to say the same thing.

    Two readers over one format that disagree about whether a file is whole would make a
    manifest look complete beside a log that did not.
    """
    path = tmp_path / "MANIFEST-000015"
    path.write_bytes(framed([b"edit one", b"e" * 70_000])[: LOG_BLOCK + 200])
    seen = []
    with pytest.raises(LevelDbError, match="ends inside the record that starts at offset"):
        for record in log_records(path):
            seen.append(record)
    assert seen[0] == b"edit one"


def test_a_fragment_with_no_start_is_skipped(tmp_path: Path) -> None:
    """What a log truncated at the front leaves, which is what a carver hands over.

    Joining it to whatever came before would invent a record, so it is passed over, and
    the whole records after it still read.
    """
    whole = framed([batch([(b"chat/1", b"m" * 60_000)], 3), batch([(b"after", b"here")], 9)])
    path = tmp_path / "000016.log"
    # Drop the first block, so the file opens on a LAST fragment with no FIRST.
    path.write_bytes(whole[LOG_BLOCK:])
    assert [record.key for record in read_log(path)] == [b"after"]


def test_the_zero_padding_of_a_preallocated_file_is_not_a_record(tmp_path: Path) -> None:
    path = tmp_path / "000017.log"
    path.write_bytes(framed([batch([(b"chat/1", b"one")], 4)]) + bytes(200))
    assert [record.key for record in read_log(path)] == [b"chat/1"]


def test_a_fragment_type_this_reader_does_not_know_is_refused(tmp_path: Path) -> None:
    """Guessed at, it would join two unrelated records into one message."""
    path = tmp_path / "000018.log"
    path.write_bytes(struct.pack("<I", 0) + struct.pack("<H", 3) + bytes([9]) + b"abc")
    with pytest.raises(LevelDbError, match="type this reader does not know"):
        list(read_log(path))


# ------------------------------------------------ how a block says it was compressed

# The trailer byte on each block picks the expansion, and a block this reader cannot
# expand is a block whose records are not in the case. Only the uncompressed and the
# Snappy paths had ever run, and the module's own docstring says why the other one
# matters: a store whose blocks this suite could not expand would read as a store with
# nothing in it.


def test_a_zstd_compressed_block_is_expanded(tmp_path: Path) -> None:
    path = tmp_path / "000021.ldb"
    path.write_bytes(table([(b"chat/1", b"the newest message")], compress=ZSTD))
    assert [record.value for record in read_table(path)] == [b"the newest message"]


def test_a_zstd_block_that_will_not_expand_is_reported_not_skipped(tmp_path: Path) -> None:
    path = tmp_path / "000022.ldb"
    whole = table([(b"chat/1", b"m" * 400)], compress=ZSTD)
    # Corrupt the frame rather than the handle, so the reader gets as far as expanding it.
    path.write_bytes(bytes([whole[0] ^ 0xFF]) + whole[1:])
    with pytest.raises(LevelDbError, match="zstd block would not expand"):
        list(read_table(path))


def test_a_snappy_block_that_will_not_expand_is_reported_not_skipped(tmp_path: Path) -> None:
    path = tmp_path / "000023.ldb"
    whole = table([(b"chat/1", b"m" * 400)], compress=SNAPPY)
    path.write_bytes(bytes([whole[0] ^ 0xFF]) + whole[1:])
    with pytest.raises(LevelDbError, match="Snappy block would not expand"):
        list(read_table(path))


def test_a_compression_kind_this_reader_does_not_know_is_refused(tmp_path: Path) -> None:
    """Returned raw it would be a block of noise read as keys and values."""
    path = tmp_path / "000024.ldb"
    path.write_bytes(table([(b"chat/1", b"one")], compress=7))
    with pytest.raises(LevelDbError, match="compressed in a way this reader does not know"):
        list(read_table(path))


# ------------------------------------------------------- what is not a table at all


def test_a_file_shorter_than_a_footer_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "000025.ldb"
    path.write_bytes(b"too short to hold a footer")
    with pytest.raises(LevelDbError, match="shorter than a table footer"):
        list(read_table(path))


def test_a_file_without_the_magic_number_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "000026.ldb"
    path.write_bytes(bytes(200))
    with pytest.raises(LevelDbError, match="does not end with the table magic"):
        list(read_table(path))
    assert not looks_like_table(path)


def test_a_block_handle_pointing_outside_the_file_is_refused(tmp_path: Path) -> None:
    """What a carved or partially written table has, and reading past it would hand back
    whatever else the file happened to contain as records."""
    whole = table([(b"chat/1", b"one")])
    path = tmp_path / "000027.ldb"
    # Enlarge the index block's length in the footer past the end of the file.
    footer = bytearray(whole[-FOOTER_LENGTH:])
    footer[3] = 0x7F
    path.write_bytes(whole[:-FOOTER_LENGTH] + bytes(footer))
    with pytest.raises(LevelDbError):
        list(read_table(path))


def test_a_directory_is_not_mistaken_for_a_table(tmp_path: Path) -> None:
    """looks_like_table seeks in whatever it is handed, and what it is handed comes from a
    directory listing, so it has to answer rather than raise."""
    assert not looks_like_table(tmp_path)
