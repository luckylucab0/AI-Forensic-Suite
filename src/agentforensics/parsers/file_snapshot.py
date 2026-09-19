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

So every event carries what the path really states and says plainly what it does not. An
analyst reading one knows the content is real and the attribution needs the session records
beside it, which is a different thing from a case that quietly attributes it wrongly.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterator

from agentforensics.model import Event, unparsed
from agentforensics.parsers.base import ParseContext, looks_binary
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
        "qwen_code.file_history_backups",
    }
)

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

# What each artifact's events say about their own attribution.
_REASONS = {
    "claude_code.file_history_snapshots": NOT_DOCUMENTED,
    "continue.diffs": SCRATCH,
    "qwen_code.file_history_backups": NOT_NAMED,
}


class FileSnapshotParser:
    """The pre-edit copies, read for their content and honest about whose file it was."""

    name = "file_snapshot"

    def handles(self, artifact_id: str | None) -> bool:
        return artifact_id in SOURCES

    def parse(self, context: ParseContext) -> Iterator[Event]:
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
    "NOT_DOCUMENTED",
    "NOT_NAMED",
    "SCRATCH",
    "SOURCES",
    "TRUNCATED",
    "FileSnapshotParser",
]
