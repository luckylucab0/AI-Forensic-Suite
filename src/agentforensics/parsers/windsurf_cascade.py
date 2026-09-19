"""Read the conversations one agent keeps in an encrypted container, given the key.

These files are the whole conversation record of this product. The vendor's own
troubleshooting page tells a stuck user to delete the directory they are in, and its
archiving replaces a conversation with a zero-byte placeholder, so what is on the disk at
the moment of collection is often all there will ever be. Until now the collection
gathered them and the case said a file existed.

They are an AES-GCM container around a protocol buffer, and reading one needs two things
this project does not ship: a cipher that is not in the standard library, which is an
optional extra, and the product's key, which the analyst supplies at run time. See ADR
0029 for why the key is not in this repository. Without either, the event says which of
the two is missing and what to do about it, because "we collected this and could not read
it, and here is why" is a fact an analyst can act on.

With both, the container is opened under whichever framing authenticates, and the
plaintext is walked as a protocol buffer with no schema. That produces a structure whose
fields are numbers rather than names, and every event says so: this reader knows that
field 3 of a message is a string and what the string says, and it does not know that field
3 is the prompt. An analyst reading the structure can tell a conversation from a
screenshot; a parser claiming to know the field names could not be checked by anybody.

One event per message, not one per file, because a trajectory holds a conversation and a
single event with all of it in raw would be a wall. The locator is the path through the
structure, so a finding points at the message it came from.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from typing import Any

from agentforensics.model import UNINTERPRETED_MARK, Event, unparsed
from agentforensics.parsers import encrypted
from agentforensics.parsers.base import ParseContext
from agentforensics.parsers.protobuf_wire import WireError, parse_message
from agentforensics.parsers.structured_generic import SPLIT_LIMIT

# The trajectories of this product, in both the directory the interface writes and the one
# its background work writes. The memories beside them are the same container and are left
# to the reader for memories until somebody has a sample to check this one against.
STORES = frozenset(
    {
        "windsurf.cascade_trajectories",
        "windsurf.implicit_trajectories",
    }
)

UNINTERPRETED = (
    "this record came out of a protocol buffer with no schema, so its fields are numbers "
    f"rather than names and the record {UNINTERPRETED_MARK}. Everything the message held "
    "is in raw."
)

NOT_A_MESSAGE = (
    "this file decrypted and the plaintext is not a protocol buffer this reader can walk: "
    "{reason}. The plaintext is not put in the case, because bytes nobody can read are "
    "already in the bundle under this event's hash"
)


class WindsurfCascadeParser:
    """The encrypted trajectory store, read when the analyst supplies the key."""

    name = "windsurf_cascade"

    def handles(self, artifact_id: str | None) -> bool:
        return artifact_id in STORES

    def parse(self, context: ParseContext) -> Iterator[Event]:
        try:
            raw = context.local_path.read_bytes()
        except OSError as error:
            yield unparsed(
                context.provenance("file"),
                context.agent,
                None,
                f"this file could not be read: {error}",
                user=context.user,
                host=context.host,
            )
            return

        if not raw:
            # An archived conversation, which this product replaces with a zero-byte file.
            # Said plainly, because an empty file here is the destruction of a conversation
            # rather than a conversation that was empty.
            yield self._closed(
                context,
                raw,
                "this file is empty, which is what this "
                "product leaves behind when a conversation is archived: the "
                "content was destroyed rather than moved",
            )
            return

        given = context.key_for()
        if given is None:
            yield self._closed(context, raw, encrypted.NO_KEY)
            return
        if not encrypted.available():
            yield self._closed(context, raw, encrypted.MISSING_LIBRARY)
            return
        key = encrypted.parse_key(given)
        if key is None:
            yield self._closed(
                context,
                raw,
                "the key given for this agent is not 16, 24 or 32 bytes of hexadecimal or "
                "base64, so nothing was attempted with it",
            )
            return

        opened = encrypted.open_container(raw, key)
        if opened is None:
            yield self._closed(
                context, raw, encrypted.NOT_OPENED.format(tried=encrypted.framings_tried())
            )
            return

        try:
            message = parse_message(opened.plaintext)
        except (WireError, IndexError) as error:
            yield self._closed(context, raw, NOT_A_MESSAGE.format(reason=error))
            return

        yield from self._records(context, message, opened.framing)

    def _closed(self, context: ParseContext, raw: bytes, reason: str) -> Event:
        """A container that was not opened, recorded by what it is rather than by nothing."""
        return unparsed(
            context.provenance("file"),
            context.agent,
            {
                "file": context.local_path.name,
                "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            },
            reason,
            user=context.user,
            host=context.host,
        )

    def _records(
        self, context: ParseContext, message: dict[str, Any], framing: str
    ) -> Iterator[Event]:
        """One event for the message, then one per element of each repeated field of it.

        The same split the whole-document readers use and for the same reason: the records
        of a conversation are one level in, and going deeper to find them means deciding
        which branch holds them, which is a claim about a schema nobody has.
        """
        opened = f"opened as {framing}."
        yield self._record(context, "$", message, opened)
        for key, value in message.items():
            if isinstance(value, list) and value and all(isinstance(e, dict) for e in value):
                if len(value) > SPLIT_LIMIT:
                    continue
                for index, element in enumerate(value):
                    yield self._record(context, f"${key}[{index}]", element, opened)

    def _record(self, context: ParseContext, at: str, value: Any, opened: str) -> Event:
        return unparsed(
            context.provenance(at),
            context.agent,
            value,
            f"{opened} {UNINTERPRETED}",
            user=context.user,
            host=context.host,
            payload={"text": _text_of(value)} if _text_of(value) else {},
        )


def _text_of(value: Any) -> str | None:
    """Every string in the message, in the order the wire put them, as one block.

    Not a reading of which field is the prompt, which nobody can do without the schema. It
    is what makes the record searchable: a rule looking for a credential or an injected
    instruction matches the text a message contains whatever its field numbers are.
    """
    if not isinstance(value, dict):
        return str(value) if isinstance(value, str) else None
    found: list[str] = []
    _collect(value, found)
    return "\n".join(found) if found else None


def _collect(value: Any, found: list[str]) -> None:
    if isinstance(value, str):
        if value.strip():
            found.append(value)
        return
    if isinstance(value, dict):
        for nested in value.values():
            _collect(nested, found)
        return
    if isinstance(value, list):
        for element in value:
            _collect(element, found)


__all__ = ["STORES", "UNINTERPRETED", "WindsurfCascadeParser"]
