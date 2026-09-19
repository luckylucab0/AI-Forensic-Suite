"""Decompress a raw Snappy block, because the desktop agents' stores are full of them.

Two agents keep their conversations in a Chromium key-value store, and that store writes
most of its blocks through Snappy. Nothing in the standard library reads it, and the wheel
that does is neither pure Python nor dependency free, which is the reason ADR 0012 keeps
the runtime to two dependencies an air-gapped workstation can vendor. So the format is
implemented here, and it is short enough to be worth it: a preamble giving the uncompressed
length, then a stream of tags that are either a literal run or a copy from what has already
been produced.

This is the raw block format, not the framed one. The framed format adds a stream header
and checksums and is what a `.sz` file uses; a block inside a table file is the raw form.

Nothing here is a general purpose Snappy implementation and it does not need to be: it
decompresses, it never compresses, and every malformed input raises rather than returning a
short result, because a truncated block that came back as half a record would put half a
conversation in a case with nothing saying so.

Format reference, read while writing this:
https://raw.githubusercontent.com/google/snappy/main/format_description.txt
"""

from __future__ import annotations

# The four tag types, in the two bits the spec gives them.
_LITERAL = 0
_COPY_1 = 1
_COPY_2 = 2
_COPY_4 = 3

# How large a block is allowed to claim to be. A corrupt preamble can claim gigabytes, and
# allocating that before reading a byte of it is how a reader turns a damaged file into a
# dead process.
MAX_UNCOMPRESSED = 256 * 1024 * 1024


class SnappyError(ValueError):
    """The bytes are not a Snappy block, or not all of one."""


def decompress(data: bytes) -> bytes:
    """One raw Snappy block, expanded."""
    length, at = _varint(data, 0)
    if length > MAX_UNCOMPRESSED:
        raise SnappyError(f"the block claims {length} bytes, more than this reader expands")
    out = bytearray()
    end = len(data)
    while at < end:
        tag = data[at]
        at += 1
        kind = tag & 0x03
        if kind == _LITERAL:
            run = tag >> 2
            if run < 60:
                size = run + 1
            else:
                # 60, 61, 62 and 63 mean the length is in the next one, two, three or four
                # bytes rather than in the tag.
                extra = run - 59
                if at + extra > end:
                    raise SnappyError("a literal length ran off the end of the block")
                size = int.from_bytes(data[at : at + extra], "little") + 1
                at += extra
            if at + size > end:
                raise SnappyError("a literal ran off the end of the block")
            out += data[at : at + size]
            at += size
            continue

        if kind == _COPY_1:
            if at >= end:
                raise SnappyError("a copy ran off the end of the block")
            size = 4 + ((tag >> 2) & 0x07)
            offset = ((tag >> 5) << 8) | data[at]
            at += 1
        elif kind == _COPY_2:
            if at + 2 > end:
                raise SnappyError("a copy ran off the end of the block")
            size = (tag >> 2) + 1
            offset = int.from_bytes(data[at : at + 2], "little")
            at += 2
        else:
            if at + 4 > end:
                raise SnappyError("a copy ran off the end of the block")
            size = (tag >> 2) + 1
            offset = int.from_bytes(data[at : at + 4], "little")
            at += 4

        if offset == 0 or offset > len(out):
            raise SnappyError("a copy points before the start of the block")
        # Copied byte by byte on purpose: a copy may overlap the end of what has been
        # produced, which is how the format expresses a repeated run, and a slice would
        # read the old bytes rather than the ones being written.
        start = len(out) - offset
        for index in range(size):
            out.append(out[start + index])

    if len(out) != length:
        raise SnappyError(f"the block expanded to {len(out)} bytes and its preamble said {length}")
    return bytes(out)


def _varint(data: bytes, at: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        if at >= len(data):
            raise SnappyError("the length preamble ran off the end of the block")
        byte = data[at]
        at += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, at
        shift += 7
        if shift > 35:
            raise SnappyError("the length preamble is longer than a 32 bit value")


__all__ = ["MAX_UNCOMPRESSED", "SnappyError", "decompress"]
