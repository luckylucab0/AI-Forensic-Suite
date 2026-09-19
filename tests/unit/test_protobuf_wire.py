"""Tests for the schema-free protocol buffer reader.

The wire format carries field numbers and four wire types and nothing else, so this reader
can say what a message contains and never what it means. What has to be right is the part
that is decidable from the bytes: a repeated field has to come back as a list in order, a
nested message has to be told from a string, and a file that is not a protocol buffer has
to fail rather than produce a structure of nonsense.
"""

from __future__ import annotations

import pytest

from agentforensics.parsers.protobuf_wire import TOO_DEEP, WireError, parse_message


def varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def field(number: int, wire: int, body: bytes) -> bytes:
    return varint(number << 3 | wire) + body


def string(number: int, text: str) -> bytes:
    raw = text.encode("utf-8")
    return field(number, 2, varint(len(raw)) + raw)


def nested(number: int, body: bytes) -> bytes:
    return field(number, 2, varint(len(body)) + body)


def test_the_four_wire_types_come_back_as_what_they_are() -> None:
    data = (
        field(1, 0, varint(150))
        + string(2, "hello")
        + field(3, 5, (7).to_bytes(4, "little"))
        + field(4, 1, (9).to_bytes(8, "little"))
    )
    assert parse_message(data) == {"f1": 150, "f2": "hello", "f3": 7, "f4": 9}


def test_a_repeated_field_keeps_its_order() -> None:
    """A conversation's turns are a repeated field, and keeping only the last one would
    show an analyst the end of a conversation as the whole of it."""
    data = string(1, "first") + string(1, "second") + string(1, "third")
    assert parse_message(data) == {"f1": ["first", "second", "third"]}


def test_a_nested_message_is_told_from_a_string() -> None:
    data = nested(1, field(1, 0, varint(5)) + string(2, "inner"))
    assert parse_message(data) == {"f1": {"f1": 5, "f2": "inner"}}


def test_bytes_that_are_not_a_message_are_kept_as_what_they_are() -> None:
    data = field(1, 2, varint(4) + b"\xff\xfe\xfd\xfc")
    value = parse_message(data)["f1"]
    assert value["__bytes__"] is True
    assert value["bytes"] == 4


def test_a_file_that_is_not_a_protocol_buffer_fails(tmp_path: object) -> None:
    """The check that makes trying a length-delimited field as a nested message safe: a
    reader that accepted a partial parse would turn a string into a structure of invented
    field numbers."""
    with pytest.raises(WireError):
        parse_message(b"this is prose, not a message")


def test_a_message_nested_past_the_limit_says_so_rather_than_recursing() -> None:
    body = string(1, "bottom")
    for _ in range(40):
        body = nested(1, body)
    value = parse_message(body)
    depth = 0
    while isinstance(value, dict) and "f1" in value:
        value = value["f1"]
        depth += 1
    assert value is True or TOO_DEEP in str(value), "the limit has to be visible in the record"
