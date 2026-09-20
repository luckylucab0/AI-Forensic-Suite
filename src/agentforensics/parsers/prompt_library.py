"""Read one editor's prompt library, which is the instruction surface kept in a database.

Every other instruction artifact in this catalogue is a file: a CLAUDE.md, a rules
directory, a hook script. This one is an LMDB store, and until it was read the case said a
directory existed and nothing about the text in it. What is in it is the text a user wrote
for the agent to obey, with a title and the time it was last saved, which is evidence of
what the agent was told and when somebody changed it.

Two named sub-databases hold it, and the join between them is the whole reading: one maps a
prompt id to its metadata and the other maps the same id to the text. So a prompt is a pair,
and a half of a pair is a finding rather than something to drop: a body with no metadata is
a prompt whose title and save time are gone, and metadata with no body is a prompt whose
text is gone, and both of those are states this file can really be in.

**A prompt somebody deleted is usually still in the file.** The store never overwrites a
page in place, so the pages it no longer points at hold earlier versions of live records and
the records of deleted ones. Those are read too and every one of them says so. They are
still filed as instruction sources, because the question this suite exists to answer is what
the agent was told to obey and a prompt that was removed last week is part of that answer.
What they are not is presented as live: the event carries `recovered` and the reason, so a
report can say "this was in the library and is not any more" rather than quietly listing it
beside the current prompts.

**The vendor's own base prompt is not in here.** This store holds the user's prompts. The
same limit applies as to every instruction artifact: what a case can show is the part of the
instruction surface that was on the machine.

Source for the layout, the two database names and the shape of each record:
https://raw.githubusercontent.com/zed-industries/zed/main/crates/prompt_store/src/prompt_store.rs
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

from agentforensics.model import Event, unparsed
from agentforensics.parsers import lmdb
from agentforensics.parsers.base import ParseContext, normalise_ts
from agentforensics.parsers.instructions import MAX_TEXT

# The artifacts this reader claims.
SOURCES = frozenset({"zed.prompt_library"})

# The two databases the store keeps, and the older pair the vendor's own code says can still
# be in the file. Read from the names rather than guessed at from the contents, because
# which database a record came from is what says whether it is a title or a prompt.
METADATA = ("metadata.v2", "metadata.v1")
BODIES = ("bodies.v2", "bodies.v1")

# How many recovered records reach a case. A store that has been edited for a year can hold
# a copy of every version of every prompt, and one deleted prompt is worth more to an
# analyst than four hundred earlier drafts of a live one. Reported where it bites.
MAX_RECOVERED = 500

# The file the store keeps beside the database. It holds no records: it is the reader and
# writer table, and what its presence says is that something opened the store.
LOCK = (
    "this is the lock file of the database beside it, which holds the table of readers "
    "rather than any records. What it says is that the store was opened at some point; a "
    "store that has never been opened has no lock file"
)

NOT_A_STORE = (
    "this file sits in the prompt library directory and is not the database: {reason}. It "
    "is in the bundle, whole, at the path in this event's provenance"
)

# A record in a database this reader does not know. The store is opened with room for four
# databases and two of them are the pair below, so a third is either a version this reader
# was written before or something the editor added.
UNKNOWN_DATABASE = (
    "this record is in a database called {name}, which is not one of the two this reader "
    "knows. Its key and value are on this event as they came out of the store, because a "
    "record nobody has mapped is still a record"
)

NO_BODY = (
    "this prompt's metadata is in the store and no text is: there is no record under its "
    "key in the bodies database. So the title and the save time are evidence and the "
    "prompt itself is not in this case. Look at the recovered records from this store: a "
    "body that was replaced is often still in a page the store no longer points at"
)
NO_METADATA = (
    "this prompt's text is in the store and its metadata is not: there is no record under "
    "its key in the metadata database, so this prompt has no title and no save time here"
)

# What one recovered record is. A record out of a page nobody points at is half of a prompt,
# because the two halves live in different databases and a transaction that changed both
# left two old pages. Pairing two recovered halves would be inventing a relationship the
# file does not record, so each one is its own event and says which half it is. The prompt
# id is on both, which is what an analyst joins them by.
RECOVERED_METADATA = (
    "this is the metadata half of a prompt: a title, a save time and a prompt id, with no "
    "text beside it. The text of this version is either on another recovered event from "
    "this file or is gone"
)
RECOVERED_BODY = (
    "this is the text half of a prompt: the prompt itself, with no title and no save time "
    "beside it. The prompt id on this event is what ties it to the rest"
)
EARLIER_VERSION = (
    "a record under this same key is live in the store, so this is an earlier version of a "
    "prompt that is still in the library rather than one that was removed"
)
REMOVED = (
    "no record under this key is live in the store, so as far as this file says, this "
    "prompt is not in the library any more"
)

# Said on the store itself, once, so a case can show what the file is and what state it was
# in without an analyst opening it.
STORE = (
    "the prompt library database: {prompts} prompt(s) live, in {databases}. Its current "
    "transaction is {current} and the one before it is {previous}, and the pages of that "
    "earlier state are still in the file, which is where the recovered records on the "
    "other events from this file come from"
)


class PromptLibraryParser:
    """The prompt library, read as the instruction surface it is."""

    name = "prompt_library"

    def handles(self, artifact_id: str | None) -> bool:
        return artifact_id in SOURCES

    def parse(self, context: ParseContext) -> Iterator[Event]:
        """Dispatch on the file, because the artifact is a directory of three shapes."""
        name = context.local_path.name
        if name == "lock.mdb":
            yield unparsed(
                context.provenance("file"),
                context.agent,
                {"file": name},
                LOCK,
                user=context.user,
                host=context.host,
            )
            return
        try:
            raw = context.local_path.read_bytes()
        except OSError as error:
            yield unparsed(
                context.provenance("file"),
                context.agent,
                {"file": name},
                f"this file could not be read: {error}",
                user=context.user,
                host=context.host,
            )
            return
        if not lmdb.looks_like_lmdb(raw):
            yield unparsed(
                context.provenance("file"),
                context.agent,
                {"file": name, "bytes": len(raw)},
                NOT_A_STORE.format(reason="it does not begin with a meta page"),
                user=context.user,
                host=context.host,
            )
            return
        try:
            store = lmdb.read(raw)
        except lmdb.LmdbError as error:
            yield unparsed(
                context.provenance("file"),
                context.agent,
                {"file": name, "bytes": len(raw)},
                NOT_A_STORE.format(reason=str(error)),
                user=context.user,
                host=context.host,
            )
            return
        yield from self._live(context, store)
        yield from self._recovered(context, raw, store)

    def _live(self, context: ParseContext, store: lmdb.Store) -> Iterator[Event]:
        """The prompts the store still points at, as the pairs they are."""
        metadata: dict[bytes, lmdb.Record] = {}
        bodies: dict[bytes, lmdb.Record] = {}
        for record in store.records:
            if record.database in METADATA:
                metadata[record.key] = record
            elif record.database in BODIES:
                bodies[record.key] = record
            else:
                yield unparsed(
                    context.provenance(f"page:{record.page}"),
                    context.agent,
                    {
                        "database": record.database,
                        "key": _text(record.key),
                        "value": _text(record.value),
                    },
                    UNKNOWN_DATABASE.format(name=record.database or "the main database"),
                    user=context.user,
                    host=context.host,
                )

        named = ", ".join(sorted(database.name for database in store.databases if database.name))
        yield unparsed(
            context.provenance("file"),
            context.agent,
            {
                "file": context.local_path.name,
                "prompts": len(metadata) or len(bodies),
                "databases": [
                    {"name": database.name, "entries": database.entries}
                    for database in store.databases
                ],
                "transaction": store.current.transaction,
            },
            STORE.format(
                prompts=len(metadata) or len(bodies),
                databases=named or "no named database",
                current=store.current.transaction,
                previous=store.previous.transaction if store.previous else "not readable",
            )
            + (f". {store.stopped}" if store.stopped else ""),
            user=context.user,
            host=context.host,
        )

        for key in sorted(set(metadata) | set(bodies)):
            yield self._prompt(context, key, metadata.get(key), bodies.get(key))

    def _recovered(self, context: ParseContext, raw: bytes, store: lmdb.Store) -> Iterator[Event]:
        """The records in pages the store no longer points at, each one saying so."""
        live = {record.key for record in store.records}
        count = 0
        for record in lmdb.stale(raw, store, limit=MAX_RECOVERED * 4):
            if count >= MAX_RECOVERED:
                yield unparsed(
                    context.provenance("file"),
                    context.agent,
                    {"file": context.local_path.name, "recovered": count},
                    f"this store holds more recoverable records than the {MAX_RECOVERED} "
                    "on the events before this one, and the reading stopped there. They "
                    "are earlier versions of records and deleted ones, in the pages the "
                    "store no longer points at, and the file is in the bundle whole",
                    user=context.user,
                    host=context.host,
                )
                return
            identity = _prompt_id(record.key)
            if identity is None:
                # A record out of a page nobody points at whose key is not one of this
                # store's keys. It is kept and it is not called a prompt: the pages of a
                # database also hold the store's own bookkeeping, and calling one of those
                # an instruction would put a page number in a case as somebody's text.
                yield unparsed(
                    context.provenance(f"page:{record.page}"),
                    context.agent,
                    {"key": _text(record.key), "value": _text(record.value)},
                    record.problem,
                    user=context.user,
                    host=context.host,
                )
                count += 1
                continue
            document = _json(record.value)
            is_metadata = isinstance(document, dict) and "saved_at" in document
            count += 1
            yield self._prompt(
                context,
                record.key,
                record if is_metadata else None,
                None if is_metadata else record,
                problems=[
                    RECOVERED_METADATA if is_metadata else RECOVERED_BODY,
                    lmdb.STALE,
                    EARLIER_VERSION if record.key in live else REMOVED,
                ],
            )

    def _prompt(
        self,
        context: ParseContext,
        key: bytes,
        metadata: lmdb.Record | None,
        body: lmdb.Record | None,
        *,
        problems: list[str] | None = None,
    ) -> Event:
        """One prompt, out of whichever half of the pair is here.

        The caller passes the sentences that are about where the record came from, because
        the two callers have different ones to say: for a live prompt a missing half is a
        gap in the store, and for a recovered one it is simply what a page holds.
        """
        recovered = bool(problems)  # set by the caller that read the freed pages
        document = _json(metadata.value) if metadata else None
        fields = document if isinstance(document, dict) else {}
        text, text_problem = _prompt_text(body.value) if body else (None, None)
        identity = _prompt_id(key)

        when = precision = source = None
        timing = None
        saved = fields.get("saved_at")
        if isinstance(saved, str) and saved:
            when, precision, timing = normalise_ts(saved)
            source = "the prompt's own saved_at"

        # Where a record came from is not a problem with reading it, and the difference
        # decides what a case counts as unreadable. A prompt out of a page the store no
        # longer points at was read completely; what the sentences say is that it is not in
        # the library any more, which is evidence rather than a defect. They travel in the
        # payload, beside the same view's scope caveat and for the same reason: counting
        # them as unread would tell an analyst the collection had failed when it had not.
        recovery = list(problems or [])
        problems = []
        if text_problem:
            problems.append(text_problem)
        if not recovered and metadata is not None and body is None:
            problems.append(NO_BODY)
        if not recovered and body is not None and metadata is None:
            problems.append(NO_METADATA)
        if metadata is not None and document is None:
            problems.append(
                "this prompt's metadata record is not the JSON document this store keeps, "
                "so its title and save time could not be read. The bytes are in raw"
            )

        record: dict[str, Any] = {
            "prompt_id": identity,
            "title": fields.get("title"),
            "default": fields.get("default"),
            "saved_at": saved,
            "text": text,
            "recovered": recovered,
        }
        if metadata is not None and document is None:
            record["metadata_bytes"] = _text(metadata.value)
        found = metadata or body
        page = found.page if found is not None else 0
        # An event's identity is its provenance and its kind, so two events out of one file
        # that share a locator are one event in a case and the second is dropped without a
        # word. A prompt id does not identify a record here: the live prompt, an earlier
        # version of it and the two halves of a recovered one all carry the same id. The
        # page does identify it, because a key appears at most once in a page.
        locator = f"prompt:{identity or _text(key)}"
        if recovered:
            locator = f"page:{page}#{locator}"
        return Event(
            kind="instruction.source",
            provenance=context.provenance(locator),
            agent=context.agent,
            raw={key_: value for key_, value in record.items() if value is not None},
            ts_utc=when,
            ts_precision=precision or "absent",
            ts_source=source if when else None,
            # The environment the agent ran in rather than a turn somebody took. Who wrote
            # the prompt is not in the store: it records when it was last saved, and by
            # whom is a question only the account and the filesystem can answer.
            actor="system",
            user=context.user,
            host=context.host,
            payload={
                "text": text,
                "title": fields.get("title"),
                # The user's own, stated rather than worked out. The catalogue roots this
                # entry at the user profile and the editor builds the path from its own
                # configuration or data directory, so there is no reading of it that is a
                # project's file or an administrator's. Asking the shared helper would
                # answer unknown on any collection that recorded no working copies, which
                # is a caveat about a question this path does not raise.
                "scope": "user",
                # Empty for a prompt in the library. For one out of a freed page: which
                # half of a prompt it is, that its page is one the store no longer points
                # at, and whether a record under the same key is still live.
                "recovery_note": " ".join(recovery) or None,
                # The facet the instruction surface view joins on. The path is the store
                # plus the prompt, because a store holds many and a path alone would make
                # them one instruction.
                "instructions": [
                    {
                        "path": f"{context.original_path}#{identity or _text(key)}",
                        "scope": "user",
                    }
                ],
                "page": page,
            },
            parse_problem=" ".join(part for part in [*problems, timing or ""] if part) or None,
        )


def _prompt_id(key: bytes) -> str | None:
    """The prompt id a key spells, or nothing when the key is not one of this store's.

    The key is the JSON of the vendor's own id type, which is an internally tagged enum: a
    user's prompt carries a kind and a uuid. Anything else is not a key from this store,
    and saying so is what keeps a page of bookkeeping from being read as a prompt.
    """
    document = _json(key)
    if not isinstance(document, dict):
        return None
    kind = document.get("kind")
    if not isinstance(kind, str):
        return None
    uuid = document.get("uuid")
    if isinstance(uuid, str) and uuid:
        return uuid
    return kind


def _json(raw: bytes) -> Any:
    try:
        return json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError, ValueError:
        return None


def _prompt_text(raw: bytes) -> tuple[str, str | None]:
    """A prompt body as text, with the reason when it is not exactly what was stored."""
    text = raw.decode("utf-8", "replace")
    problems = []
    if "�" in text:
        problems.append(
            "this prompt did not decode as UTF-8 and was read with replacement "
            "characters, so its text is not exact"
        )
    if len(text) > MAX_TEXT:
        text = text[:MAX_TEXT]
        problems.append(
            f"this prompt is longer than the ingest limit of {MAX_TEXT} characters and is "
            "carried truncated. The whole of it is in the store, in the bundle"
        )
    return text, " ".join(problems) or None


def _text(raw: bytes) -> str:
    """Bytes as something an analyst can read, without pretending they are text."""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.hex()


__all__ = [
    "BODIES",
    "EARLIER_VERSION",
    "LOCK",
    "MAX_RECOVERED",
    "METADATA",
    "NOT_A_STORE",
    "NO_BODY",
    "NO_METADATA",
    "RECOVERED_BODY",
    "RECOVERED_METADATA",
    "REMOVED",
    "SOURCES",
    "STORE",
    "UNKNOWN_DATABASE",
    "PromptLibraryParser",
]
