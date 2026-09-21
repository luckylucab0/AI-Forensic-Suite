"""Read the copy an agent kept of a file before it changed it.

Three products keep the previous contents of every file they edit, so that an undo or a
rewind can put it back. For an investigation that makes these the only place the original
text of an overwritten file exists when the change was never committed, and the catalogue
says so in its own words: the entry for one of them calls it the highest-value artifact for
what did this agent overwrite, and the entry for another calls it one of the most valuable
artifacts in the whole family. Sixteen artifacts are file snapshots and until this module
none of them produced anything but a file name.

**The content is the point, and it goes where a rule can reach it.** A snapshot is not a
format to parse: it is somebody's file. So the reading is the file, put in the event's text
view, and that is what makes the difference. A credential that was in a configuration file
until the agent rewrote it, an injected instruction in a source file the agent was told to
clean up: neither is in the transcript, neither is in git, and before this neither was
searchable. A file that is not text is recorded by size and hash instead, because a page of
replacement characters reads as content.

**What the snapshot is a copy of is usually not in the snapshot.** This is the part that
has to be said rather than guessed, and it differs per product:

  - One names its backups by the first sixteen hex characters of the SHA-256 of the
    original absolute path, followed by @v and a version. The digest is one way, so the
    backup genuinely does not name the file it came from; the mapping is in the session's
    own file-history records. Both parts are read out of the name and reported, because a
    digest an analyst can match against a candidate path is still an answer.
  - One files its snapshots under a directory named for the session and documents nothing
    about the names inside it. The session is therefore reported and the original path is
    not: the vendor's own documentation does not state the layout, and a reader that
    invented a mapping would put a filename in a report that nobody could check. The
    transcript's file-history-snapshot records are the route, and they are a different
    artifact.
  - One keeps a scratch directory for its apply flow holding the text before the edit and
    the text proposed, with nothing in the path to say which is which.
  - And one keeps the answer beside the copies. The editor family writes a directory per
    file, named by a hash of the file's URI, holding an index that names the original
    resource and lists every copy in it with the time it was taken and what caused it. So
    for those three products a snapshot is fully attributable, which none of the others
    are, and the reader goes and gets the index rather than reporting the copy as unnamed.

So every event carries what the path really states and says plainly what it does not. An
analyst reading one knows the content is real and the attribution needs the session records
beside it, which is a different thing from a case that quietly attributes it wrongly.

**The timestamp is the one place these two halves differ.** For the three products whose
copies name nothing, the event carries no time: the copy holds none inside it and the
filesystem's mtime already reaches the case attributed to the filesystem, so repeating it
here would present it as the moment of the edit. The editor family's index does hold that
moment, per copy, written by the editor when it took the copy, so those events carry it.
That is a timestamp out of a record rather than off a file, which is the difference between
evidence and a guess.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterator

from agentforensics.model import Event, unparsed
from agentforensics.parsers.base import (
    ParseContext,
    looks_binary,
    normalise_ts,
    read_json,
    uri_as_path,
)
from agentforensics.parsers.instructions import BINARY_FILE, MAX_TEXT

# The artifacts whose files are a copy of somebody's file. Written out rather than derived
# from the category at runtime, for the reason the other readers' sets are: a parser is
# handed an artifact id and not a catalogue entry, and a snapshot store should be read
# because somebody decided it should be. tests/unit/test_file_snapshot.py holds this set
# against the catalogue's file_snapshot entries, with the ones left out named there.
SOURCES = frozenset(
    {
        "claude_code.file_history_snapshots",
        "continue.diffs",
        "cursor.local_file_history",
        "qwen_code.file_history_backups",
        "vscode.local_history",
        "windsurf.local_file_history",
    }
)

# The three that share the editor family's layout, which is the only one with an index.
# Kept as a set rather than a branch on one id because there are three of them and the
# next fork of that editor is one line.
LOCAL_HISTORY = frozenset(
    {"cursor.local_file_history", "vscode.local_history", "windsurf.local_file_history"}
)

# The name the editor gives the index inside each per-file directory. Constant in its own
# source, where the model class declares it, which is also where the rest of this layout
# comes from: the directory is named by a hash of the file's URI, and each copy is named by
# four random alphanumeric characters plus the original file's extension.
# https://raw.githubusercontent.com/microsoft/vscode/main/src/vs/workbench/services/workingCopy/common/workingCopyHistoryService.ts
INDEX_FILE = "entries.json"

# The name one product gives a backup: the first sixteen hex characters of the SHA-256 of
# the original absolute path, then @v and the version. Sourced, unlike the other two
# products' layouts, which is why this is the only one anything is read out of.
_DIGEST_NAME = re.compile(r"^(?P<digest>[0-9a-f]{16})@v(?P<version>\d+)$")

# The session a snapshot belongs to, where the catalogue's own path pattern puts it in a
# directory of its own. Read from the original endpoint path rather than from the local
# one, because a bundle's layout is this suite's and the endpoint's is the evidence.
_SESSION_DIRS = ("/file-history/",)

NOT_NAMED = (
    "this file is a copy of a file on the endpoint and does not say which one. The name is "
    "a digest of the original path, which cannot be reversed, so the file it came from is "
    "named only in the session's own file-history records. Those are a separate artifact, "
    "and the digest is here to match against a candidate path"
)

NOT_DOCUMENTED = (
    "this file is a copy of a file on the endpoint and does not say which one. The vendor "
    "documents the directory and not the naming inside it, so nothing here reads an "
    "original path out of the name: the transcript's file-history-snapshot records are "
    "what maps a snapshot to a file, to a checkpoint and to a time"
)

SCRATCH = (
    "this file is the apply flow's working copy of an edit, which is either the text "
    "before the change or the text proposed, with nothing in the path to say which. Both "
    "are evidence and neither is in the transcript or in git if the change was never "
    "accepted"
)

TRUNCATED = (
    "the content is longer than the ingest limit of {limit} characters and is carried "
    "truncated. The whole file is in the bundle, at the path in this event's provenance"
)

INDEX = (
    "this is the index of one file's local history and not a copy of anything: it names "
    "the file the copies in this directory were taken from, and lists each copy with the "
    "time the editor took it and the save source that caused it. It is here as an event of "
    "its own because it is the only thing that maps the directory's name, a hash of the "
    "file's URI, back to a path, and because the copies it lists can have been pruned "
    "before the collection while the index still names them"
)

NO_INDEX = (
    "this is a copy of a file and the index that would name it is not in this collection, "
    "so neither the original path nor the time the copy was taken is known here. The "
    "directory this sits in is named by a hash of the file's URI and cannot be reversed. "
    "The index is entries.json beside it, and it is worth going back for"
)

NOT_LISTED = (
    "this is a copy of a file and the index beside it does not list it, so its original "
    "path and its time are unknown. The editor prunes the index and the copies separately, "
    "and a copy the index has forgotten is exactly what is left behind by that, so this is "
    "content nothing else on the endpoint accounts for"
)

BROKEN_INDEX = "the index beside this copy could not be read as JSON: {error}"

# What each artifact's events say about their own attribution. The editor family is not
# here: what its events say depends on what the index beside the copy turned out to hold,
# which is decided per file rather than per artifact.
_REASONS = {
    "claude_code.file_history_snapshots": NOT_DOCUMENTED,
    "continue.diffs": SCRATCH,
    "qwen_code.file_history_backups": NOT_NAMED,
}


REMOTE = (
    "the file this is a copy of is on another machine: the index names it with a remote "
    "URI rather than a path, so the copy is local and the original never was"
)

NO_RESOURCE = (
    "the index does not name the file its copies were taken from, so the directory's hash "
    "is all there is and it cannot be reversed"
)


class FileSnapshotParser:
    """The pre-edit copies, read for their content and honest about whose file it was."""

    name = "file_snapshot"

    def handles(self, artifact_id: str | None) -> bool:
        return artifact_id in SOURCES

    def parse(self, context: ParseContext) -> Iterator[Event]:
        if context.artifact_id in LOCAL_HISTORY:
            yield from _local_history(context)
            return
        try:
            raw_bytes = context.local_path.read_bytes()
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

        record: dict[str, object] = {
            "file": context.local_path.name,
            "bytes": len(raw_bytes),
            "sha256": hashlib.sha256(raw_bytes).hexdigest(),
        }
        session = _session_of(context.original_path)
        if session:
            record["session_id"] = session
        found = _DIGEST_NAME.match(context.local_path.name)
        if found:
            # Named rather than left in the file name, so an analyst can match a candidate
            # path against it without having to know this product's naming rule.
            record["original_path_sha256_prefix"] = found.group("digest")
            record["version"] = int(found.group("version"))

        problems = [_REASONS[str(context.artifact_id)]]
        text: str | None = None
        if looks_binary(raw_bytes):
            # Not text, so there is nothing to put in the text view. The bytes are in the
            # bundle under the hash above, which is the honest reading of a copy of a
            # compiled file or an image.
            problems.append(BINARY_FILE)
        else:
            text = raw_bytes.decode("utf-8", "replace")
            if "�" in text:
                problems.append(
                    "the file did not decode as UTF-8 and was read with replacement "
                    "characters, so its content is not exact"
                )
            if len(text) > MAX_TEXT:
                problems.append(TRUNCATED.format(limit=MAX_TEXT))
                text = text[:MAX_TEXT]
            record["content"] = text

        yield Event(
            kind="file.snapshot",
            provenance=context.provenance("file"),
            agent=context.agent,
            raw=record,
            # No timestamp. The copy carries none inside it, and the artifact event for the
            # same path already carries the filesystem's, attributed to the filesystem.
            # Repeating an mtime here would present it as the moment of the edit, which is
            # what the session's own records are for.
            ts_utc=None,
            ts_precision="absent",
            # The agent took the copy, not the person.
            actor="assistant",
            user=context.user,
            host=context.host,
            session_id=session,
            payload={
                "text": text,
                "file": context.local_path.name,
                "bytes": len(raw_bytes),
            }
            if text
            else {"file": context.local_path.name, "bytes": len(raw_bytes)},
            parse_problem=" ".join(problems),
        )


def _local_history(context: ParseContext) -> Iterator[Event]:
    """The editor family's layout: a directory per file, an index and the copies beside it.

    Split from the rest of this reader because the question is different. For the other
    three products a copy is read and reported as unattributable; here the attribution
    exists and is one file away, so the reading is worth the extra read and an event that
    left the path out would be throwing away an answer the collection already has.
    """
    if context.local_path.name == INDEX_FILE:
        yield from _history_index(context)
        return
    yield from _history_copy(context)


def _history_index(context: ParseContext) -> Iterator[Event]:
    """The index, as an event of its own, because it is the only mapping there is."""
    document, error, relaxation = read_json(context.local_path)
    if error is not None:
        # Surfaced rather than skipped: without this file nothing in the directory can be
        # attributed, so an unreadable one is a finding and not a quiet miss.
        yield unparsed(
            context.provenance("$"),
            context.agent,
            {"file": context.local_path.name},
            BROKEN_INDEX.format(error=error),
            user=context.user,
            host=context.host,
        )
        return

    resource = document.get("resource") if isinstance(document, dict) else None
    original, remote = uri_as_path(resource if isinstance(resource, str) else None)
    versions = [
        {
            "id": entry.get("id"),
            "timestamp": entry.get("timestamp"),
            "source": entry.get("source"),
            "source_description": entry.get("sourceDescription"),
        }
        for entry in _entries(document)
    ]
    problems = [INDEX]
    if relaxation:
        problems.append(relaxation)
    if original is None:
        problems.append(NO_RESOURCE)
    if remote:
        problems.append(REMOTE)
    yield Event(
        kind="file.snapshot",
        provenance=context.provenance("$"),
        agent=context.agent,
        raw={
            "file": context.local_path.name,
            "index": True,
            "original_path": original,
            "versions": versions,
        },
        # No time of its own. The index is rewritten whenever a copy is added, so its own
        # mtime is the last copy's and the per-copy times are in the rows above.
        ts_utc=None,
        ts_precision="absent",
        actor="assistant",
        user=context.user,
        host=context.host,
        payload={"file": context.local_path.name, "original_path": original},
        parse_problem=" ".join(problems),
    )


def _history_copy(context: ParseContext) -> Iterator[Event]:
    """One copy of somebody's file, attributed from the index beside it where there is one."""
    try:
        raw_bytes = context.local_path.read_bytes()
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

    record: dict[str, object] = {
        "file": context.local_path.name,
        "bytes": len(raw_bytes),
        "sha256": hashlib.sha256(raw_bytes).hexdigest(),
    }
    entry, original, remote, problem = _from_index(context)
    problems = []
    ts_utc: str | None = None
    precision = "absent"
    ts_source: str | None = None
    if problem:
        problems.append(problem)
    if entry is not None:
        record["original_path"] = original
        record["version_source"] = entry.get("source")
        if entry.get("sourceDescription"):
            record["version_source_description"] = entry.get("sourceDescription")
        ts_utc, precision, note = normalise_ts(entry.get("timestamp"))
        if ts_utc:
            # The editor wrote this when it took the copy, so it is the moment of the edit
            # rather than a filesystem time. Named as its own field for that reason.
            ts_source = "the local history index's timestamp for this copy"
        if note:
            problems.append(note)
        if original is None:
            problems.append(NO_RESOURCE)
        if remote:
            problems.append(REMOTE)

    text: str | None = None
    if looks_binary(raw_bytes):
        problems.append(BINARY_FILE)
    else:
        text = raw_bytes.decode("utf-8", "replace")
        if "\ufffd" in text:
            problems.append(
                "the file did not decode as UTF-8 and was read with replacement "
                "characters, so its content is not exact"
            )
        if len(text) > MAX_TEXT:
            problems.append(TRUNCATED.format(limit=MAX_TEXT))
            text = text[:MAX_TEXT]
        record["content"] = text

    yield Event(
        kind="file.snapshot",
        provenance=context.provenance("file"),
        agent=context.agent,
        raw=record,
        ts_utc=ts_utc,
        ts_precision=precision,  # type: ignore[arg-type]
        ts_source=ts_source,
        actor="assistant",
        user=context.user,
        host=context.host,
        payload={"text": text, "file": context.local_path.name, "bytes": len(raw_bytes)}
        if text
        else {"file": context.local_path.name, "bytes": len(raw_bytes)},
        parse_problem=" ".join(problems) if problems else None,
    )


def _from_index(
    context: ParseContext,
) -> tuple[dict[str, object] | None, str | None, bool, str | None]:
    """This copy's row in the index beside it, and why there is none when there is none.

    The bundle mirrors original paths, so the index the editor wrote beside the copies is
    beside them here too. Read per copy rather than held across the run: one directory's
    index describes one file, and a reader that remembered the last one would attribute a
    copy to whichever file it happened to read before.
    """
    document, error, _ = read_json(context.local_path.parent / INDEX_FILE)
    if error is not None:
        return None, None, False, NO_INDEX
    for entry in _entries(document):
        if entry.get("id") == context.local_path.name:
            resource = document.get("resource") if isinstance(document, dict) else None
            original, remote = uri_as_path(resource if isinstance(resource, str) else None)
            return entry, original, remote, None
    return None, None, False, NOT_LISTED


def _entries(document: object) -> list[dict[str, object]]:
    """The index's rows, and nothing else. A malformed row is skipped rather than guessed at.

    Kept permissive on purpose: this is a vendor's file and a version of it with a row shape
    nobody here has seen must not take the rest of the directory down with it.
    """
    if not isinstance(document, dict):
        return []
    rows = document.get("entries")
    if not isinstance(rows, list):
        return []
    return [row for row in rows if isinstance(row, dict)]


def _session_of(original_path: str) -> str | None:
    """The session directory a snapshot sits in, where the layout has one.

    Read from the endpoint path in the manifest rather than from the local copy: the
    bundle's own layout is this suite's and the endpoint's is the evidence. Returns nothing
    where the path has no such directory, which is a different answer from an unknown
    session and is left as an absent field rather than filled in.
    """
    normalised = original_path.replace("\\", "/")
    for marker in _SESSION_DIRS:
        at = normalised.find(marker)
        if at == -1:
            continue
        rest = normalised[at + len(marker) :].split("/")
        if len(rest) >= 2 and rest[0]:
            return rest[0]
    return None


__all__ = [
    "BROKEN_INDEX",
    "INDEX",
    "INDEX_FILE",
    "LOCAL_HISTORY",
    "NOT_DOCUMENTED",
    "NOT_LISTED",
    "NOT_NAMED",
    "NO_INDEX",
    "NO_RESOURCE",
    "REMOTE",
    "SCRATCH",
    "SOURCES",
    "TRUNCATED",
    "FileSnapshotParser",
]
