"""Read a memory-mapped B-tree store the suite has no schema for, without inventing one.

The floor under the format the module beside this one reads. One catalogue entry is such a
store and nobody has a source for what is in it: an editor's Flatpak build is reported to
have kept its conversations in one, the entry says so and says it is a recollection, and
the reason given for reading nothing was that it would need a reader this project did not
have. It has one now, so the entry can be read for what it literally holds rather than left
as a directory a case mentions and says nothing about.

What it returns is every record of every database in the store, with the key and the value
as they came out and nothing decided about either. A value that decodes as UTF-8 is offered
as text beside the record, because a person reading a case can then see a conversation in
it; that is an offer and not a claim, and every event says the reading is uninterpreted. The
rule is the same one the SQLite floor and the generated fleet artifact apply, deliberately,
so a case and a hunt do not tell an analyst two different stories about what uninterpreted
means.

The pages a store no longer points at are read here too, and marked. For a store nobody has
a schema for that matters more rather than less: if the entry is what its notes say it is,
those pages hold conversations somebody deleted, and this reader has no way to tell which
records those are beyond saying which pages they came from.

A store this project has a verified schema for is claimed by a parser of its own placed
ahead of this one, the way the prompt library is. Until such a schema exists, the records
are visible rather than absent, because guessing one would produce a case that reads as
answered and is wrong.
"""

from __future__ import annotations

from collections.abc import Iterator

from agentforensics.model import UNINTERPRETED_MARK, Event, unparsed
from agentforensics.parsers import lmdb
from agentforensics.parsers.base import ParseContext, looks_binary

# The artifacts this reader claims: every catalogue entry whose format is this one and
# which no parser with a verified schema has taken over.
STORES = frozenset({"zed.flatpak_legacy_threads"})

# How many records of one store reach a case, live and recovered together. A store of
# conversations can be large and an uninterpreted reading of it is the coarsest evidence
# there is, so the limit is lower than the format reader's own and is reported where it
# bites.
MAX_RECORDS = 20_000

# Said on every record, because this reading decides nothing. The wording is the shared one
# so that a case, a fleet hunt and the two other floors all count the same thing.
UNINTERPRETED = (
    f"this collection has no verified schema for this store, so the record "
    f"{UNINTERPRETED_MARK}. Its key and its value are on this event as they came out of the "
    "database. Read this store again once somebody has a source for what is in it"
)

LOCK = (
    "this is the lock file of the database beside it, which holds the table of readers "
    "rather than any records. What it says is that the store was opened at some point"
)

NOT_A_STORE = (
    "this file sits in a directory the catalogue records as a memory-mapped database and "
    "is not one: {reason}. It is in the bundle, whole, at the path in this event's "
    "provenance"
)

STORE = (
    "a memory-mapped database with {records} record(s) in {databases}. Nothing in this "
    "suite has a schema for it, so what follows is the records as they are"
)


class LmdbGenericParser:
    """The reading of last resort for a memory-mapped B-tree store."""

    name = "lmdb_generic"

    def handles(self, artifact_id: str | None) -> bool:
        return artifact_id in STORES

    def parse(self, context: ParseContext) -> Iterator[Event]:
        name = context.local_path.name
        if name == "lock.mdb":
            yield self._note(context, {"file": name}, LOCK)
            return
        try:
            raw = context.local_path.read_bytes()
        except OSError as error:
            yield self._note(context, {"file": name}, f"this file could not be read: {error}")
            return
        if not lmdb.looks_like_lmdb(raw):
            yield self._note(
                context,
                {"file": name, "bytes": len(raw)},
                NOT_A_STORE.format(reason="it does not begin with a meta page"),
            )
            return
        try:
            store = lmdb.read(raw, limit=MAX_RECORDS)
        except lmdb.LmdbError as error:
            yield self._note(
                context,
                {"file": name, "bytes": len(raw)},
                NOT_A_STORE.format(reason=str(error)),
            )
            return

        named = ", ".join(sorted(one.name for one in store.databases if one.name))
        yield self._note(
            context,
            {
                "file": name,
                "records": len(store.records),
                "databases": [
                    {"name": one.name, "entries": one.entries} for one in store.databases
                ],
                "transaction": store.current.transaction,
            },
            STORE.format(records=len(store.records), databases=named or "one unnamed database")
            + (f". {store.stopped}" if store.stopped else ""),
        )
        for record in store.records:
            yield self._record(context, record)
        for record in lmdb.stale(raw, store, limit=max(MAX_RECORDS - len(store.records), 0)):
            yield self._record(context, record)

    def _record(self, context: ParseContext, record: lmdb.Record) -> Event:
        """One record, with a locator that identifies it rather than merely naming it.

        The page is in the locator because an event is identified by its provenance and its
        kind: two records with one locator are one row in a case and the second is dropped
        without a word. A key is unique within a database and not within a store, and the
        same key can also be in a page the store no longer points at.
        """
        locator = f"page:{record.page}#{_readable(record.key)[:120]}"
        if record.duplicate:
            locator = f"{locator}#{record.duplicate}"
        problems = [UNINTERPRETED]
        if record.problem:
            problems.insert(0, record.problem)
        return unparsed(
            context.provenance(locator),
            context.agent,
            {
                "database": record.database or None,
                "key": _readable(record.key),
                "value": _readable(record.value),
                "bytes": len(record.value),
            },
            " ".join(problems),
            user=context.user,
            host=context.host,
            # Offered as text where it is text, so a person reading the case sees a
            # conversation rather than a length. The problem above says what that is worth.
            payload={"text": _text(record.value)},
        )

    def _note(self, context: ParseContext, record: dict[str, object], problem: str) -> Event:
        return unparsed(
            context.provenance("file"),
            context.agent,
            record,
            problem,
            user=context.user,
            host=context.host,
        )


def _readable(raw: bytes) -> str:
    """Bytes an analyst can read, without pretending they are text.

    Whether they are text is the same question the rest of this package asks, and asked the
    same way: bytes that decode are not thereby text, because a packed structure decodes as
    control characters and would go into a case looking like an empty value.
    """
    if looks_binary(raw):
        return raw.hex()
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.hex()


def _text(raw: bytes) -> str | None:
    """The value offered as text, where it is text. An offer, not a claim."""
    if looks_binary(raw):
        return None
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return decoded if decoded.strip() else None


__all__ = [
    "LOCK",
    "MAX_RECORDS",
    "NOT_A_STORE",
    "STORE",
    "STORES",
    "UNINTERPRETED",
    "LmdbGenericParser",
]
