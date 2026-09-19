"""Tests for the encrypted trajectory reader.

These files are the whole conversation record of one product, and the vendor's own
troubleshooting advice destroys them, so what is on the disk at collection time is often
all there will be. The questions here are the ones an analyst would ask of any reading of
an encrypted store: does it say what it could not do and why, does it refuse a wrong key
rather than producing plausible nonsense, and does the reading it produces say what it
does not know.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from agentforensics.model import UNINTERPRETED_MARK
from agentforensics.parsers import encrypted, for_artifact
from agentforensics.parsers.base import ParseContext

STORE = "windsurf.cascade_trajectories"
KEY = bytes(range(32))

pytestmark = pytest.mark.skipif(
    not encrypted.available(),
    reason="the optional cipher is not installed, which is itself a supported state",
)


def message() -> bytes:
    """A protocol buffer in the shape a trajectory has: a header and repeated turns."""

    def field(number: int, wire: int, body: bytes) -> bytes:
        return bytes([number << 3 | wire]) + body

    def string(number: int, text: str) -> bytes:
        raw = text.encode("utf-8")
        return field(number, 2, bytes([len(raw)]) + raw)

    turn_one = string(1, "user") + string(2, "delete the old logs")
    turn_two = string(1, "assistant") + string(2, "running rm -rf /var/log/old")
    return (
        string(1, "cascade-0001")
        + field(2, 2, bytes([len(turn_one)]) + turn_one)
        + field(2, 2, bytes([len(turn_two)]) + turn_two)
    )


def container(plaintext: bytes, key: bytes = KEY) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def parse(path: Path, key: str | None = None) -> list:
    parser = for_artifact(STORE)
    assert parser is not None
    return list(
        parser.parse(
            ParseContext(
                bundle_uuid="b",
                original_path=f"/home/alice/.codeium/windsurf/cascade/{path.name}",
                local_path=path,
                sha256="f" * 64,
                artifact_id=STORE,
                agent="windsurf",
                user="alice",
                keys={"windsurf": key} if key else {},
            )
        )
    )


def test_a_conversation_comes_back_when_the_key_is_given(tmp_path: Path) -> None:
    """The point of the whole module: this is the only record of what was said."""
    path = tmp_path / "cascade-0001.pb"
    path.write_bytes(container(message()))

    events = parse(path, KEY.hex())
    text = "\n".join(event.payload.get("text", "") for event in events)
    assert "delete the old logs" in text
    assert "rm -rf /var/log/old" in text


def test_every_record_says_its_fields_have_no_names(tmp_path: Path) -> None:
    """The limit that has to travel with the reading. Without the schema this reader knows
    that a field is a string and what it says, not that it is the prompt, and a case that
    implied otherwise would be quoting a claim nobody can check."""
    path = tmp_path / "cascade-0001.pb"
    path.write_bytes(container(message()))

    events = parse(path, KEY.hex())
    assert all(UNINTERPRETED_MARK in (event.parse_problem or "") for event in events)
    assert all("f1" in str(event.raw) or "f2" in str(event.raw) for event in events)


def test_the_conversation_is_split_into_records(tmp_path: Path) -> None:
    """One event with a whole conversation in raw is a wall. The locator is the path
    through the structure, so a finding points at the message it came from."""
    path = tmp_path / "cascade-0001.pb"
    path.write_bytes(container(message()))

    events = parse(path, KEY.hex())
    assert [event.provenance.locator for event in events] == ["$", "$f2[0]", "$f2[1]"]


def test_without_a_key_the_file_is_reported_as_an_encrypted_store(tmp_path: Path) -> None:
    """Not as a file nobody read: the difference is that this one tells the analyst what
    to do about it."""
    path = tmp_path / "cascade-0001.pb"
    path.write_bytes(container(message()))

    events = parse(path)
    assert [event.kind for event in events] == ["unparsed.record"]
    assert "no key for this agent was given" in (events[0].parse_problem or "")
    assert events[0].raw["sha256"], "the file is still identifiable in the case"


def test_a_wrong_key_is_refused_rather_than_guessed_at(tmp_path: Path) -> None:
    """The tag check is what makes trying several framings honest. A wrong key fails all
    of them, and the event says so instead of showing an analyst bytes that decrypted to
    nothing."""
    path = tmp_path / "cascade-0001.pb"
    path.write_bytes(container(message()))

    events = parse(path, (b"\x11" * 32).hex())
    assert "did not open it" in (events[0].parse_problem or "")


def test_a_key_that_is_not_a_key_says_nothing_was_attempted(tmp_path: Path) -> None:
    path = tmp_path / "cascade-0001.pb"
    path.write_bytes(container(message()))

    events = parse(path, "not-a-key")
    assert "hexadecimal or base64" in (events[0].parse_problem or "")


def test_an_archived_conversation_is_named_as_a_destroyed_one(tmp_path: Path) -> None:
    """This product replaces an archived conversation with a zero-byte file, so an empty
    file here is the destruction of a conversation rather than an empty conversation."""
    path = tmp_path / "cascade-0002.pb.archived"
    path.write_bytes(b"")

    events = parse(path, KEY.hex())
    assert "archived" in (events[0].parse_problem or "")
    assert "destroyed" in (events[0].parse_problem or "")


def test_a_framing_with_a_header_and_a_leading_tag_is_found(tmp_path: Path) -> None:
    """Nothing published states this product's container layout, so the reader tries a few
    and lets the tag decide. The event records which one authenticated, so somebody else
    can repeat the reading."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = os.urandom(12)
    sealed = AESGCM(KEY).encrypt(nonce, message(), None)
    path = tmp_path / "cascade-0003.pb"
    path.write_bytes(b"\x01" + nonce + sealed[-16:] + sealed[:-16])

    events = parse(path, KEY.hex())
    assert "1 byte header" in (events[0].parse_problem or "")
    assert "tag before the ciphertext" in (events[0].parse_problem or "")
