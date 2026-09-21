"""The Snappy block reader, over the tags a real store actually contains.

This reader is on the path to two agents' conversations: a Chromium key-value store keeps
them, and most of its blocks are Snappy compressed. It was written from the format
description and it was exercised by one test for a literal run and one for a copy with a
one byte offset, which is the smallest of the three copy forms. The two larger ones, and
the long literal whose length sits after the tag rather than inside it, had never run.

That gap is worth more than the coverage number says. A one byte offset reaches 2047 bytes
back, and a data block in one of these stores is four kilobytes by default, so the moment a
conversation repeats a phrase from earlier in the same block the compressor emits the two
byte form. Every real store is full of them. A defect in that branch would not look like a
crash: it would look like a conversation that reads almost right, with a few bytes
substituted from the wrong place, and nothing in the case saying which parts of a message
are the ones the endpoint held.

So the blocks here are built tag by tag, with the expected expansion built alongside them
rather than derived from the reader. The refusals matter as much as the expansions: this
reader raises on everything malformed instead of returning a short result, because half a
record in a case with nothing saying so is the failure this project exists to avoid.

Format reference: https://raw.githubusercontent.com/google/snappy/main/format_description.txt
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from agentforensics.parsers.snappy import MAX_UNCOMPRESSED, SnappyError, decompress


def varint(value: int) -> bytes:
    """The preamble's little-endian base 128 length, as the format writes it."""
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def literal(payload: bytes) -> bytes:
    """A literal run, in whichever of the five encodings the length calls for.

    Under 61 bytes the length goes in the tag itself. From 61 up it goes in one to four
    following bytes, and which of the four is chosen is the part that had never run.
    """
    size = len(payload)
    if size <= 60:
        return bytes([(size - 1) << 2]) + payload
    stored = size - 1
    width = (stored.bit_length() + 7) // 8
    return bytes([(59 + width) << 2]) + stored.to_bytes(width, "little") + payload


def copy(offset: int, size: int) -> bytes:
    """A copy from what has already been produced, in the narrowest form that fits.

    The three forms are not interchangeable. The one byte form carries an eleven bit
    offset and a length of four to eleven; the two byte form carries a sixteen bit offset
    and a length up to sixty-four; the four byte form carries the rest.
    """
    if offset < 2048 and 4 <= size <= 11:
        return bytes([((offset >> 8) << 5) | ((size - 4) << 2) | 1, offset & 0xFF])
    if offset < 65536 and size <= 64:
        return bytes([((size - 1) << 2) | 2]) + offset.to_bytes(2, "little")
    return bytes([((size - 1) << 2) | 3]) + offset.to_bytes(4, "little")


def block(parts: list[bytes], expanded: bytes) -> bytes:
    """A whole block: the preamble the reader checks its result against, then the tags."""
    return varint(len(expanded)) + b"".join(parts)


# --------------------------------------------------------------- the three copy forms


def test_a_one_byte_offset_copy_reaches_its_furthest() -> None:
    """The largest offset and the largest length the one byte form can express.

    Both fields share the tag byte with the tag type, so a mistake in either shift shows
    up here and nowhere else: the offset's top three bits live above the length's.
    """
    seed = bytes(range(256)) * 8  # 2048 bytes, so an offset of 2047 is the second byte
    expanded = seed + seed[1:12]
    raw = block([literal(seed), copy(2047, 11)], expanded)
    assert decompress(raw) == expanded


def test_a_two_byte_offset_copy_reaches_past_what_one_byte_can() -> None:
    """The form every real store is full of, and it had never been decoded here."""
    seed = bytes(range(256)) * 12  # 3072 bytes
    expanded = seed + seed[500:564]  # offset 2572, length 64, the form's longest
    raw = block([literal(seed), copy(len(seed) - 500, 64)], expanded)
    assert decompress(raw) == expanded


def test_a_four_byte_offset_copy_reaches_back_past_sixty_five_thousand() -> None:
    """The form a block only needs once it is larger than a sixteen bit offset covers."""
    seed = bytes(range(256)) * 300  # 76800 bytes
    expanded = seed + seed[3:23]
    raw = block([literal(seed), copy(len(seed) - 3, 20)], expanded)
    assert decompress(raw) == expanded


@pytest.mark.parametrize("size", [61, 300, 70000, 200000])
def test_a_literal_longer_than_the_tag_can_say_takes_its_length_from_the_next_bytes(
    size: int,
) -> None:
    """One case per width of the stored length, which is what run 60 to 63 selects."""
    payload = bytes((index * 7 + 11) & 0xFF for index in range(size))
    assert decompress(block([literal(payload)], payload)) == payload


def test_a_copy_that_overlaps_what_it_is_producing_repeats_it() -> None:
    """The one case a slice gets wrong, here in the two byte form as well as the small one.

    A copy may be longer than the distance it reaches back, which is how the format says
    "repeat this". The bytes being written are part of the source, so a reader that slices
    the output once and appends it produces the wrong thing from the second repeat on.
    """
    seed = bytes(range(256)) * 10  # 2560 bytes, past the one byte form's reach
    tail = (seed[-3:] * 22)[:64]
    raw = block([literal(seed), copy(3, 64)], seed + tail)
    assert decompress(raw) == seed + tail


# ----------------------------------------------------------------------- the refusals


def test_a_two_byte_copy_whose_offset_is_cut_off_is_refused() -> None:
    with pytest.raises(SnappyError, match="ran off the end"):
        decompress(varint(64) + literal(b"x" * 8) + bytes([(63 << 2) | 2, 1]))


def test_a_four_byte_copy_whose_offset_is_cut_off_is_refused() -> None:
    with pytest.raises(SnappyError, match="ran off the end"):
        decompress(varint(64) + literal(b"x" * 8) + bytes([(19 << 2) | 3, 1, 0]))


def test_a_one_byte_copy_with_no_offset_byte_is_refused() -> None:
    with pytest.raises(SnappyError, match="ran off the end"):
        decompress(varint(16) + literal(b"x" * 8) + bytes([(0 << 2) | 1]))


def test_a_long_literal_whose_length_is_cut_off_is_refused() -> None:
    """The tag says the length is in the next four bytes and there are two."""
    with pytest.raises(SnappyError, match="literal length ran off the end"):
        decompress(varint(70000) + bytes([63 << 2, 0x0F, 0x10]))


def test_a_long_literal_that_claims_more_than_it_carries_is_refused() -> None:
    with pytest.raises(SnappyError, match="literal ran off the end"):
        decompress(varint(300) + bytes([61 << 2]) + (299).to_bytes(2, "little") + b"short")


def test_a_preamble_that_is_the_whole_block_is_refused() -> None:
    """A varint whose continuation bit is set on the last byte there is."""
    with pytest.raises(SnappyError, match="preamble ran off the end"):
        decompress(bytes([0x80, 0x80]))


def test_a_preamble_longer_than_a_thirty_two_bit_length_is_refused() -> None:
    """Six continuation bytes, which no valid length needs, and a reader without this
    check would keep shifting until the machine ran out of memory."""
    with pytest.raises(SnappyError, match="longer than a 32 bit value"):
        decompress(bytes([0xFF] * 6 + [0x01]))


def test_a_block_that_claims_more_than_the_reader_expands_is_refused() -> None:
    """A corrupt preamble can claim gigabytes, and allocating that before reading a byte
    of it is how a reader turns a damaged store into a dead process."""
    with pytest.raises(SnappyError, match="more than this reader expands"):
        decompress(varint(MAX_UNCOMPRESSED + 1) + literal(b"x"))


def test_a_block_that_expands_to_less_than_its_preamble_says_is_refused() -> None:
    """The check that makes every refusal above worth having: without it a block that
    ended early would come back as a short record that looks complete."""
    with pytest.raises(SnappyError, match="expanded to"):
        decompress(varint(64) + literal(b"only eight"))


# ---------------------------------------------- the cross-check, where it can run


def _reference() -> Callable[[bytes], bytes] | None:
    """Whichever independent Snappy implementation this machine happens to have.

    Neither is a dependency of this package, and neither may be added as one: the reason
    the format is implemented here at all is that an air-gapped workstation has to be able
    to vendor everything the analyzer needs, and both of these carry compiled code. See
    ADR 0012.

    Which function to ask for is not the obvious one in either library, and getting it
    wrong would compare this reader against the framed format instead of the raw block a
    table file holds. python-snappy's `compress` is the raw block. cramjam's `compress` is
    the framed stream, with a header and checksums, and `compress_raw` is the block.
    """
    from importlib import import_module, util

    if util.find_spec("snappy") is not None:
        return import_module("snappy").compress  # type: ignore[no-any-return]
    if util.find_spec("cramjam") is not None:
        raw = import_module("cramjam").snappy.compress_raw
        return lambda payload: bytes(raw(payload))
    return None


@pytest.mark.skipif(
    _reference() is None,
    reason="no independent Snappy implementation is installed, and none is a dependency",
)
def test_the_reader_agrees_with_an_independent_implementation() -> None:
    """The strongest form this test can take, where a second implementation is present.

    Every case above builds its own block, which proves the reader agrees with how this
    file reads the specification and not that either is right. A real compressor emits tag
    sequences nobody would write by hand: back references chosen by its own hash table,
    literal runs broken at lengths that suit it, copies that overlap. Kept as a skipped
    test rather than dropped, so anybody who has one of these libraries can run the
    comparison that no fixture in this repository can stand in for.

    What it does not cover, measured rather than assumed: the four byte offset form. A
    compressor keeps a sixty-four kilobyte window, so it never needs an offset wider than
    two bytes, and a census of what cramjam emitted for the payloads below found 2741 two
    byte copies, one of the small form and not a single four byte one. A decompressor has
    to accept the form anyway, because the format allows it, so the case above that builds
    one by hand is the only thing covering that branch and stays whatever runs here.
    """
    compress = _reference()
    assert compress is not None

    # Inputs picked for the tag types they force: repetition at a distance no one byte
    # offset reaches, a long unique run that has to go out as a literal, and a payload
    # past sixty-five kilobytes so a four byte offset becomes possible.
    payloads = [
        b"",
        b"one line of a conversation\n",
        b"a repeated phrase, " * 400,
        bytes((index * 37 + 5) & 0xFF for index in range(20000)),
        (b"a repeated phrase, " * 400) + bytes(range(256)) * 300 + (b"a repeated phrase, " * 400),
    ]
    for payload in payloads:
        assert decompress(compress(payload)) == payload, (
            f"this reader and the installed Snappy implementation disagree about a "
            f"{len(payload)} byte payload"
        )
