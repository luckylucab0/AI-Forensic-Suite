"""Read the conversation stores two desktop agents keep in a browser engine's key-value set.

Both products are Electron applications, which means their window is a browser and their
state is where a browser puts it: IndexedDB, Local Storage and Session Storage, each of
them a LevelDB directory. For one of them a vendor page calls that directory "renderer-side
UI state", and for the other a published writeup puts the prompts and the responses in it.
Until this module a collection of either directory reached a case as a list of file names,
which is exactly the reading non-negotiable 6 exists to prevent: an analyst looking at a
case that says nothing was read concludes there was nothing there.

What it does. One catalogue entry claims a whole directory, so the file's own name decides
how it is read, the same dispatch the task directories of another agent need:

  *.ldb, *.sst    a sorted table, read entry by entry
  *.log           the write-ahead log, which holds what has not been folded into a table
                  yet and is therefore usually the newest conversation in the store
  MANIFEST-*      the list of version edits saying which tables are live
  CURRENT         one line naming the live manifest
  LOCK, LOG       the store's own bookkeeping
  anything else   reported as a file in the store's tree that this parser does not map

The log matters more than it looks. The writeup behind one of these entries says the
prompts sit in the log file before compaction, and a reader that took only the tables would
return a store's whole history except the part of it that happened last.

What it does not do. It does not say what a record means. A key and a value come out of the
store as bytes, and the shape inside those bytes is a second question: Local Storage puts a
one-byte encoding tag in front of a string, IndexedDB wraps a value in the browser engine's
own object serialisation, and a parser claiming to read either without a source would be
inventing a format. So every record carries the uninterpreted mark, its bytes are in raw,
and the text this module offers beside them says how it was obtained. That is the same
floor the generic SQLite and JSON readers stand on, and it is a floor rather than a
ceiling: a reader for the engine's serialisation can be placed in front of this one when
somebody has a sample to check it against.

Deleted records are kept and said to be deleted. A write batch in the log records a removal
as a record of its own, and for a conversation store the difference between a key that was
removed and a key that never existed is the difference between a deleted chat and no chat.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Iterator
from pathlib import Path

from agentforensics.model import UNINTERPRETED_MARK, Event, unparsed
from agentforensics.parsers import leveldb
from agentforensics.parsers.base import ParseContext, text_lines

# The catalogue entries this parser claims. Written out rather than derived from the
# format field, for the reason the SQLite reader gives: a parser is handed an artifact id
# and not a catalogue entry, and a new store should be read because somebody decided it
# should be. tests/unit/test_leveldb_store.py holds this set against the catalogue.
STORES = frozenset(
    {
        "chatgpt_desktop.windows_msix_localcache",
        "claude_desktop.renderer_state",
    }
)

# A table file under either of the two names the engine writes. The older one is still on
# disk in stores that have been upgraded rather than recreated.
_TABLE_SUFFIXES = (".ldb", ".sst")

# The manifest, which is written in the log's framing and holds version edits rather than
# write batches. Its records are not walked: an edit says which table files are live at a
# sequence number, and mapping that without a source would be a guess about a format whose
# records this module has no sample of.
_MANIFEST = re.compile(r"^MANIFEST-\d+$")

# What every record out of a store says about itself.
UNINTERPRETED = (
    "this collection has no verified reading for the shape inside a record of this store, "
    f"so the record {UNINTERPRETED_MARK}. The key and the value are in raw as bytes, and "
    "any text beside them was extracted rather than decoded."
)

DELETED = (
    "this record is a deletion: the write batch removed the key and carried no value. The "
    "key is evidence that something was there and was taken away."
)

# Text is offered for a value only when enough of it is text. A blob of engine
# serialisation contains a few readable runs between its type tags, and presenting those as
# the content of a record would read in a report as what somebody wrote.
_MIN_RUN = 4

# How much of one file this parser will turn into events, and the note when it stops. A
# browser profile can hold millions of records and a case that swallowed one whole would be
# unusable for the conversation it was opened for. Reaching the limit is said out loud
# rather than passed over, because a silent cut is a case that looks complete.
MAX_RECORDS = leveldb.MAX_RECORDS

TRUNCATED = (
    f"this file holds more than {MAX_RECORDS} records and this reading stopped there. What "
    "is missing is the rest of this file, not the rest of the store: the bytes are in the "
    "bundle under this event's hash and can be read again with a higher limit."
)


# The shape of the two readers, so the dispatch below can be handed either one.
_Reader = Callable[[Path, int], Iterator[leveldb.Record]]


class LevelDbStoreParser:
    """The Electron key-value stores, read record by record and interpreted by nobody."""

    name = "leveldb_store"

    def handles(self, artifact_id: str | None) -> bool:
        return artifact_id in STORES

    def parse(self, context: ParseContext) -> Iterator[Event]:
        """Dispatch on the file's own name, because one catalogue entry claims a directory."""
        name = context.local_path.name
        if name.endswith(_TABLE_SUFFIXES):
            yield from self._records(context, leveldb.read_table, "table")
        elif name.endswith(".log"):
            yield from self._records(context, leveldb.read_log, "log")
        elif _MANIFEST.match(name):
            yield from self._manifest(context)
        elif name == "CURRENT":
            yield from self._current(context)
        elif name in ("LOG", "LOG.old"):
            yield from self._own_log(context)
        elif name == "LOCK":
            yield self._file(
                context,
                "this is the store's lock file, which is empty by design and says only that "
                "the store was opened by a process",
            )
        elif leveldb.looks_like_table(context.local_path):
            # A table that was not named like one. Read rather than refused, because the
            # footer is the engine's own test for what a table is and a name is not.
            yield from self._records(context, leveldb.read_table, "table")
        else:
            yield self._file(
                context,
                f"{name!r} is in the tree of a key-value store and is not a file this "
                "parser maps. It is not part of the store's own set, so nothing here reads "
                "it; the collection carries its bytes",
            )

    # ------------------------------------------------------------------ records

    def _records(
        self,
        context: ParseContext,
        read: _Reader,
        what: str,
    ) -> Iterator[Event]:
        """Every key and value one file gives up, with the failure reported as an event.

        A table whose blocks will not expand is not a table that reads as empty. The
        exception is caught here and becomes a record of its own, so a store whose reading
        broke halfway is visible as a store whose reading broke halfway, together with
        every record that came out before it did.
        """
        seen = 0
        try:
            for record in read(context.local_path, MAX_RECORDS):
                seen += 1
                yield self._record(context, record)
        except (leveldb.LevelDbError, OSError) as error:
            yield self._file(
                context,
                f"this {what} stopped reading after {seen} record(s): {error}. What came "
                "out before it is in the case",
            )
            return
        if seen >= MAX_RECORDS:
            yield self._file(context, TRUNCATED)

    def _record(self, context: ParseContext, record: leveldb.Record) -> Event:
        raw: dict[str, object] = {
            "key": _readable(record.key),
            "key_bytes": len(record.key),
        }
        if record.sequence is not None:
            raw["sequence"] = record.sequence
        if record.deleted:
            raw["deleted"] = True
        else:
            value = record.value or b""
            raw["value_bytes"] = len(value)
            raw["value"] = _readable(value)
        text = _text_of(record)
        return unparsed(
            context.provenance(record.locator),
            context.agent,
            raw,
            DELETED if record.deleted else UNINTERPRETED,
            user=context.user,
            host=context.host,
            payload={"text": text} if text else {},
        )

    # ------------------------------------------------- the store's own bookkeeping

    def _manifest(self, context: ParseContext) -> Iterator[Event]:
        """How many version edits the manifest holds, and that they are not read here."""
        # Counted as they arrive rather than with a sum over the whole iterator, because
        # a manifest that ends mid record hands over what it had and then says so, and a
        # sum would discard that count along with the exception.
        edits = 0
        try:
            for _ in leveldb.log_records(context.local_path):
                edits += 1
        except (leveldb.LevelDbError, OSError) as error:
            yield self._file(
                context,
                f"this manifest gave up {edits} record(s), the last of them cut short, "
                f"and then stopped: {error}",
            )
            return
        yield self._file(
            context,
            f"this is the store's manifest and it holds {edits} record(s) in the log's "
            "framing. Those records are version edits naming which table files are live, "
            "not conversation records, and this collection has no verified reading for "
            f"them, so the manifest {UNINTERPRETED_MARK}",
        )

    def _current(self, context: ParseContext) -> Iterator[Event]:
        """The one line that names the live manifest, which is the store's entry point."""
        lines = [line.text.strip() for line in text_lines(context.local_path) if line.text.strip()]
        named = lines[0] if lines else None
        yield self._file(
            context,
            (
                f"this file names {named!r} as the store's live manifest, which is the file "
                "that says which tables belong to the store as it last stood"
                if named
                else "this file names the store's live manifest and is empty, which is the "
                "state a store is left in when it was interrupted while being opened"
            ),
        )

    def _own_log(self, context: ParseContext) -> Iterator[Event]:
        """The store's own text log, line by line.

        Kept because it dates compactions and recoveries, and a compaction is when the
        records this parser would otherwise have found in the write-ahead log stopped being
        separately visible.
        """
        for line in text_lines(context.local_path):
            if not line.text.strip():
                continue
            yield unparsed(
                context.provenance(f"line:{line.number}"),
                context.agent,
                {"line": line.text},
                line.problem
                or "this is a line of the store engine's own log, which records openings, "
                f"compactions and recoveries. It {UNINTERPRETED_MARK}: no field of it is "
                "mapped to an event",
                user=context.user,
                host=context.host,
                payload={"text": line.text},
            )

    def _file(self, context: ParseContext, reason: str) -> Event:
        """One record about the file itself, for what is not a key and a value."""
        try:
            raw_bytes = context.local_path.read_bytes()
        except OSError as error:
            raw_bytes = b""
            reason = f"{reason} (and the file could not be read again: {error})"
        return unparsed(
            context.provenance("file"),
            context.agent,
            {
                "file": context.local_path.name,
                "bytes": len(raw_bytes),
                "sha256": hashlib.sha256(raw_bytes).hexdigest(),
            },
            reason,
            user=context.user,
            host=context.host,
        )


def _readable(raw: bytes) -> str:
    """The bytes as something a person and a rule can both look at.

    A store's keys are usually text with a separator byte or two in them, and its values
    usually are not. Both are rendered the same way, with every byte that is not printable
    shown as an escape, so that what is in `raw` is reversible and nothing silently
    disappears from a record. Not base64, which would make a key nobody can read out of a
    key that reads perfectly well.
    """
    return raw.decode("utf-8", "backslashreplace").encode("unicode_escape").decode("ascii")


def _text_of(record: leveldb.Record) -> str | None:
    """The readable runs in a record, kept apart from raw so nobody mistakes one for the other.

    Local Storage stores a string behind a one-byte encoding tag, either UTF-8 or UTF-16,
    and IndexedDB stores the browser engine's own serialisation of an object, which has its
    strings in both encodings between its type tags. Nothing here decides which one a value
    is. Every reading is taken and the one that yields the most text wins.

    The tag byte is why both starting offsets are tried. A UTF-16 string that begins one
    byte into the value decodes, read from byte zero, into characters that are printable
    and are not the string: pairing every byte with its neighbour on the wrong side turns
    plain Latin text into a run of ideographs. That reading has to lose, and it does,
    because the aligned one recovers twice as many characters.

    It exists so a record is searchable. A rule looking for a credential or an injected
    instruction has to match the text a record contains, and a rule cannot match bytes.
    """
    parts = [_best(record.key)]
    if record.value:
        parts.append(_best(record.value))
    text = "\n".join(part for part in parts if part)
    return text or None


def _best(raw: bytes) -> str:
    """The reading that found real text, out of the four a value could be.

    Scored by how much of the result is plain ASCII before how long it is, and the order
    matters. A sixteen bit string read from the wrong byte pairs every character's low half
    with its neighbour's high half, which turns Latin text into exactly as many characters
    of ideographs: length alone cannot tell the two apart and would keep whichever came
    first. Counting the ASCII separates them, because the misaligned reading has none.

    A string that is genuinely not Latin has no ASCII in either alignment, and then length
    decides, which is a guess. It is a guess about a search aid and not about evidence: the
    bytes are in raw either way, and this text says of itself that it was extracted.
    """
    return max(
        (_runs(raw[skip:], encoding) for encoding in ("utf-8", "utf-16-le") for skip in (0, 1)),
        key=lambda text: (sum(1 for c in text if " " <= c <= "~"), len(text)),
    )


def _runs(raw: bytes, encoding: str) -> str:
    """Every run of at least `_MIN_RUN` printable characters, in the order they appear."""
    if encoding == "utf-16-le" and len(raw) % 2:
        raw = raw[:-1]
    text = raw.decode(encoding, "replace")
    found: list[str] = []
    run: list[str] = []
    for character in text:
        # A replacement character means this reading is the wrong one for that byte, which
        # ends the run as surely as a type tag does.
        if character == "\ufffd" or not (character == " " or character.isprintable()):
            if len(run) >= _MIN_RUN:
                found.append("".join(run))
            run = []
        else:
            run.append(character)
    if len(run) >= _MIN_RUN:
        found.append("".join(run))
    return "\n".join(found)


__all__ = [
    "DELETED",
    "MAX_RECORDS",
    "STORES",
    "TRUNCATED",
    "UNINTERPRETED",
    "LevelDbStoreParser",
]
