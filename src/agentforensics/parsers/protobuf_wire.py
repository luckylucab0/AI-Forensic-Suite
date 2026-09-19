"""Read a protocol buffer without its schema, by the wire format alone.

An agent that stores its conversations as protocol buffers and ships no schema leaves an
analyst with bytes. The wire format is self-describing enough to walk anyway: every field
carries its number and one of four wire types, and that is enough to produce a structure
with the values in it. What it cannot produce is names, because names live in the schema,
so every field here is `f<number>` and the reading says on itself that it is unnamed.

That limit is the honest one and it is worth stating plainly rather than papering over:
this module does not know that field 3 is the prompt. It knows that field 3 of this message
is a string and what the string says, which is what an analyst needs in order to read the
conversation and to quote it with a locator that somebody else can check.

Two ambiguities are inherent to the format and are resolved the same way every time, so
that a case is deterministic:

- A length-delimited field is a nested message, a string or raw bytes, and the wire format
  does not say which. It is tried as a message first, accepted only when the whole of it
  parses, then as UTF-8 text, and kept as bytes otherwise. A wrong guess here is visible:
  a message that was really a string comes out as a structure of nonsense field numbers,
  which is why the whole-length check matters.
- A varint is a signed or an unsigned integer or a boolean, again undeclared. It is kept as
  the unsigned value it literally is, and no zigzag decoding is applied, because applying
  it to a field that was not zigzag encoded changes the number rather than failing.
"""

from __future__ import annotations

from typing import Any

# How deep a nested message is followed. A protocol buffer can nest without limit and a
# hostile or corrupt file can claim to; the depth is finite so that reading one cannot run
# out of stack, and reaching it is reported on the value rather than silently flattened.
MAX_DEPTH = 24

# How long a bytes value may be before it is kept as a description rather than as content.
# A trajectory can embed a screenshot, and a megabyte of base64 in an event payload buys
# nobody anything: the file itself is in the bundle.
MAX_BYTES = 1 * 1024 * 1024

TOO_DEEP = "__too_deep__"
OPAQUE = "__bytes__"


class WireError(ValueError):
    """The bytes are not a protocol buffer, or not all of one."""


def parse_message(data: bytes, *, depth: int = 0) -> dict[str, Any]:
    """One message as a mapping of `f<number>` to value, or a list where it repeats.

    Raises WireError unless the whole of `data` parses, which is what makes trying a
    length-delimited field as a nested message safe: a field that is really a string
    almost never consumes exactly to its own end as a message.
    """
    if depth > MAX_DEPTH:
        return {TOO_DEEP: True}
    out: dict[str, Any] = {}
    at = 0
    end = len(data)
    while at < end:
        tag, at = _varint(data, at)
        number, wire = tag >> 3, tag & 0x07
        if number == 0:
            raise WireError("field number 0 is not valid")
        if wire == 0:
            value, at = _varint(data, at)
        elif wire == 1:
            value, at = int.from_bytes(_take(data, at, 8), "little"), at + 8
        elif wire == 2:
            length, at = _varint(data, at)
            raw = _take(data, at, length)
            at += length
            value = _length_delimited(raw, depth)
        elif wire == 5:
            value, at = int.from_bytes(_take(data, at, 4), "little"), at + 4
        else:
            # Wire types 3 and 4 are the deprecated group encoding, and 6 and 7 never
            # existed. Either way this is not a message this reader can walk.
            raise WireError(f"wire type {wire} is not one this reader walks")
        key = f"f{number}"
        if key in out:
            # A repeated field, which the wire format expresses by repeating the tag. The
            # first repeat turns the value into a list, so a conversation's turns come out
            # in the order they were written rather than with all but the last thrown away.
            existing = out[key]
            if isinstance(existing, list):
                existing.append(value)
            else:
                out[key] = [existing, value]
        else:
            out[key] = value
    return out


def _length_delimited(raw: bytes, depth: int) -> Any:
    """A nested message, a string, or bytes, decided in that order."""
    if raw:
        try:
            return parse_message(raw, depth=depth + 1)
        except WireError, IndexError:
            pass
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        if len(raw) > MAX_BYTES:
            return {OPAQUE: True, "bytes": len(raw)}
        return {OPAQUE: True, "bytes": len(raw), "hex": raw[:64].hex()}
    return text


def _varint(data: bytes, at: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        if at >= len(data):
            raise WireError("a varint ran off the end of the message")
        byte = data[at]
        at += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, at
        shift += 7
        if shift > 63:
            raise WireError("a varint longer than 64 bits")


def _take(data: bytes, at: int, length: int) -> bytes:
    if length < 0 or at + length > len(data):
        raise WireError("a field ran off the end of the message")
    return data[at : at + length]


__all__ = ["MAX_BYTES", "MAX_DEPTH", "OPAQUE", "TOO_DEEP", "WireError", "parse_message"]
