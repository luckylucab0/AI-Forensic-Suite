"""Read a Chromium key-value store, table by table and record by record.

Two of the desktop agents keep their conversations in the store a browser engine uses for
IndexedDB and for local storage. It is a LevelDB: a set of immutable table files, a
write-ahead log holding whatever has not been folded into one yet, and a manifest naming
which of them are live. Until this module a collection of one of those directories reached
a case as a list of file names.

What is implemented here is the reading, not the meaning. A table gives up keys and values
as bytes, and what those bytes mean is a second question this module does not answer: the
browser engine wraps a value in its own serialisation, and a parser claiming to know that
shape without a source would be inventing one. So the records come out whole and the reader
above this one says so.

**The table format.** A file ends with a footer that names two blocks, and the one that
matters is the index: entries whose value is the offset and length of a data block. A data
block is a run of entries with the key stored as a shared prefix length, the rest of the
key, and the value, followed by an array of restart points this reader does not need
because it walks every entry from the first restart anyway. Each block carries one trailing
byte saying how it was compressed and four bytes of checksum.

**The compression.** None, Snappy, or zstd, and the last two are why this file exists: a
store whose blocks this suite could not expand would read as a store with nothing in it.
Snappy is implemented beside this module and zstd is in the standard library, which is one
of the reasons the Python floor is where it is.

**The checksum is not verified.** It is a CRC32C with a mask, a polynomial the standard
library does not carry, and a reader that refused a block over it would refuse evidence
that decompresses perfectly well. A block that fails to expand fails loudly instead.

**The write-ahead log.** The records a store has not folded into a table are in a log of
32 kilobyte blocks, each holding fragments with a length and a type saying whether a record
starts, continues or ends there. A reassembled record is a write batch: a sequence number,
a count, and then the puts and deletes themselves. Those are often the newest conversation
in the store, so a reader that took only the tables would return everything except what
happened last.

**A log that stops in the middle of a record.** Common rather than exotic: the file is
preallocated and written into, so a copy taken while the agent is running, and anything
left by a crash, ends inside a record. What the file did hold of that record is handed over
and then the truncation is raised, so the entries that were whole stay in the case and the
cut is a line an analyst reads rather than an absence. This reader used to drop the
unterminated record, which meant the newest part of a conversation left no trace at all.

Format references, read while writing this:
https://raw.githubusercontent.com/google/leveldb/main/doc/table_format.md
https://raw.githubusercontent.com/google/leveldb/main/doc/log_format.md
"""

from __future__ import annotations

import compression.zstd as zstd
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from agentforensics.parsers.snappy import SnappyError
from agentforensics.parsers.snappy import decompress as unsnappy

# The last eight bytes of a table file, which is how a reader knows it is one.
TABLE_MAGIC = 0xDB4775248B80FB57

# The footer is two block handles and then the magic, padded to a fixed size.
FOOTER_LENGTH = 48

# One block of the write-ahead log, and the header on each fragment inside it.
LOG_BLOCK = 32768
LOG_HEADER = 7

# The fragment types, from the log format: a whole record, or the first, a middle or the
# last piece of one that did not fit in a block.
FULL, FIRST, MIDDLE, LAST = 1, 2, 3, 4

# How many records one file may produce. A store can hold millions, and a case that
# swallowed a whole browser profile would be unusable for the conversation it was opened
# for. Reaching it is reported by the caller rather than passed over.
MAX_RECORDS = 200_000


class LevelDbError(ValueError):
    """The file is not the shape this reader expects."""


# Said by both log readers, so the two cannot drift into describing the same file
# differently. It is a report rather than a refusal: the bytes that did arrive have already
# been handed over by the time it is raised.
_TRUNCATED = (
    "the file ends inside the record that starts at offset {}: {} byte(s) of that record "
    "were in the file and the rest was never written or was not collected. What was "
    "readable in it is in the case, and the bytes themselves are in the collection at that "
    "offset"
)


@dataclass(frozen=True, slots=True)
class Record:
    """One key and value, with where it came from."""

    key: bytes
    value: bytes | None
    locator: str
    # A deletion carries no value. It is a record all the same: it says a key was removed,
    # which for a conversation store is the difference between never existing and being
    # deleted.
    deleted: bool = False
    sequence: int | None = None


def looks_like_table(path: Path) -> bool:
    """Whether the file ends with a table footer."""
    try:
        with path.open("rb") as handle:
            handle.seek(-8, 2)
            return int.from_bytes(handle.read(8), "little") == TABLE_MAGIC
    except OSError:
        return False


def read_table(path: Path, limit: int = MAX_RECORDS) -> Iterator[Record]:
    """Every entry of every data block the index names."""
    data = path.read_bytes()
    if len(data) < FOOTER_LENGTH:
        raise LevelDbError("the file is shorter than a table footer")
    footer = data[-FOOTER_LENGTH:]
    if int.from_bytes(footer[-8:], "little") != TABLE_MAGIC:
        raise LevelDbError("the file does not end with the table magic number")
    at = 0
    _, at = _varint(footer, at)  # the metaindex handle, which holds filters and statistics
    _, at = _varint(footer, at)
    index_offset, at = _varint(footer, at)
    index_size, at = _varint(footer, at)

    seen = 0
    for entry in _entries(_block(data, index_offset, index_size)):
        handle_at = 0
        offset, handle_at = _varint(entry.value, handle_at)
        size, handle_at = _varint(entry.value, handle_at)
        for record in _entries(_block(data, offset, size)):
            if seen >= limit:
                return
            seen += 1
            yield Record(
                key=record.key,
                value=record.value,
                locator=f"table:{offset} key:{seen}",
            )


def log_records(path: Path) -> Iterator[bytes]:
    """The reassembled records of a file in the log framing, without reading inside them.

    The framing carries two different things. In a write-ahead log a record is a write
    batch, which `read_log` below takes apart. In a manifest a record is a version edit
    saying which table files are live, and this collection has no verified reading for one,
    so a caller that only needs to know how many there are gets them whole.

    A record the file ends in the middle of is yielded as well, because the bytes that did
    arrive are still evidence, and then the truncation is raised so the caller can say so.
    """
    truncated = None
    for framed in _log_records(path.read_bytes()):
        yield framed.record
        if not framed.complete:
            truncated = framed
    if truncated is not None:
        raise LevelDbError(_TRUNCATED.format(truncated.at, len(truncated.record)))


def read_log(path: Path, limit: int = MAX_RECORDS) -> Iterator[Record]:
    """Every put and delete in the write-ahead log, in the order it was written."""
    data = path.read_bytes()
    seen = 0
    truncated = None
    for framed in _log_records(data):
        if not framed.complete:
            truncated = framed
        batch = framed.record
        if len(batch) < 12:
            continue
        sequence = int.from_bytes(batch[0:8], "little")
        count = int.from_bytes(batch[8:12], "little")
        cursor = 12
        for index in range(count):
            if cursor >= len(batch):
                break
            kind = batch[cursor]
            cursor += 1
            try:
                key, cursor = _length_prefixed(batch, cursor)
                if kind == 1:
                    value, cursor = _length_prefixed(batch, cursor)
                    deleted = False
                elif kind == 0:
                    value, deleted = None, True
                else:
                    # A record type this reader does not know. The batch is abandoned
                    # rather than guessed at, because the next field's position depends on
                    # this one.
                    break
            except LevelDbError:
                # In a whole batch this is a malformed file and the caller has to hear it.
                # In a batch the log ends in the middle of it is the expected shape of the
                # last entry, so the entries before it stay in the case and the truncation
                # is reported once, below, instead of as a failure to read the file.
                if framed.complete:
                    raise
                break
            if seen >= limit:
                return
            seen += 1
            yield Record(
                key=key,
                value=value,
                locator=f"log:{framed.at} record:{index}",
                deleted=deleted,
                sequence=sequence + index,
            )
    if truncated is not None:
        raise LevelDbError(_TRUNCATED.format(truncated.at, len(truncated.record)))


@dataclass(frozen=True, slots=True)
class _Entry:
    key: bytes
    value: bytes


@dataclass(frozen=True, slots=True)
class _Framed:
    """One record out of the log framing, and whether the file held all of it."""

    record: bytes
    # The offset of the header of the fragment this record starts in.
    at: int
    complete: bool


def _block(data: bytes, offset: int, size: int) -> bytes:
    """One block, expanded according to the byte that says how it was compressed."""
    end = offset + size
    if offset < 0 or end + 5 > len(data):
        raise LevelDbError("a block handle points outside the file")
    raw = data[offset:end]
    kind = data[end]
    if kind == 0:
        return raw
    if kind == 1:
        try:
            return unsnappy(raw)
        except SnappyError as error:
            raise LevelDbError(f"a Snappy block would not expand: {error}") from error
    if kind == 4:
        try:
            return zstd.decompress(raw)
        except zstd.ZstdError as error:
            raise LevelDbError(f"a zstd block would not expand: {error}") from error
    raise LevelDbError(f"a block is compressed in a way this reader does not know: {kind}")


def _entries(block: bytes) -> Iterator[_Entry]:
    """The entries of one block, with the shared key prefixes restored.

    The restart array at the end is where a reader would binary search. This one walks the
    whole block, so it only has to know where the entries stop, which the array's own
    length says.
    """
    if len(block) < 4:
        return
    restarts = int.from_bytes(block[-4:], "little")
    end = len(block) - 4 - restarts * 4
    if end < 0:
        raise LevelDbError("a block's restart array is longer than the block")
    at = 0
    key = b""
    while at < end:
        shared, at = _varint(block, at)
        non_shared, at = _varint(block, at)
        value_length, at = _varint(block, at)
        if shared > len(key) or at + non_shared + value_length > len(block):
            raise LevelDbError("an entry runs off the end of its block")
        key = key[:shared] + block[at : at + non_shared]
        at += non_shared
        value = block[at : at + value_length]
        at += value_length
        yield _Entry(key=key, value=value)


def _log_records(data: bytes) -> Iterator[_Framed]:
    """Reassembled records out of the log's fragments, with the offset each started at.

    A record that the file ends in the middle of is yielded too, marked incomplete. It is
    the case worth getting right rather than the exotic one: this log holds whatever the
    store has not folded into a table, so its tail is the newest conversation in the
    store, and a log copied off a running endpoint or left behind by a crash routinely
    ends mid record. Dropping those bytes would take the most recent part of the evidence
    out of the case with nothing saying it had been there.
    """
    at = 0
    pending = bytearray()
    started = 0
    while at + LOG_HEADER <= len(data):
        if at % LOG_BLOCK > LOG_BLOCK - LOG_HEADER:
            # The tail of a block is padding: a header does not fit, so the next record
            # starts at the beginning of the next block.
            at += LOG_BLOCK - (at % LOG_BLOCK)
            continue
        # Where this fragment's header sits, which is where the record it starts begins.
        # The offset travels into an event's locator, so it has to be somewhere an analyst
        # can seek to and find the record, not the position after it.
        header_at = at
        length = int.from_bytes(data[at + 4 : at + 6], "little")
        kind = data[at + 6]
        body = data[at + LOG_HEADER : at + LOG_HEADER + length]
        if len(body) < length:
            # The file ends inside this fragment's payload.
            if kind in (FULL, FIRST):
                yield _Framed(bytes(body), header_at, False)
            elif pending:
                yield _Framed(bytes(pending + body), started, False)
            return
        at += LOG_HEADER + length
        if kind == FULL:
            yield _Framed(bytes(body), header_at, True)
        elif kind == FIRST:
            pending = bytearray(body)
            started = header_at
        elif kind in (MIDDLE, LAST):
            if not pending:
                # A fragment with no start, which is what a log truncated at the front
                # leaves. Skipped rather than joined to whatever came before it.
                continue
            pending += body
            if kind == LAST:
                yield _Framed(bytes(pending), started, True)
                pending = bytearray()
        elif kind == 0 and length == 0:
            # Zero padding at the end of a preallocated file.
            continue
        else:
            raise LevelDbError(f"a log fragment has a type this reader does not know: {kind}")

    if pending:
        # The last record began and the file ran out before the fragment that would end it.
        yield _Framed(bytes(pending), started, False)


def _length_prefixed(data: bytes, at: int) -> tuple[bytes, int]:
    length, at = _varint(data, at)
    if at + length > len(data):
        raise LevelDbError("a length prefixed value runs off the end of the record")
    return data[at : at + length], at + length


def _varint(data: bytes, at: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        if at >= len(data):
            raise LevelDbError("a varint ran off the end")
        byte = data[at]
        at += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, at
        shift += 7
        if shift > 63:
            raise LevelDbError("a varint longer than 64 bits")


__all__ = [
    "FOOTER_LENGTH",
    "LOG_BLOCK",
    "MAX_RECORDS",
    "TABLE_MAGIC",
    "LevelDbError",
    "Record",
    "log_records",
    "looks_like_table",
    "read_log",
    "read_table",
]
