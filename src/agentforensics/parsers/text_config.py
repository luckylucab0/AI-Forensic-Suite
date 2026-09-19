"""Read the small text files that say how an agent was set up, and two that say more.

Eight catalogue entries are plain text configuration and nothing read any of them, so a
collected file reached a case as a file name. Most of them are one line or a handful: which
identity was in use, where a product put its data directory, which per-install identifier a
vendor's server can join this host to. They are read whole and filed as configuration, and
that is the end of it.

Two of the eight are not that, and they are the reason this module exists rather than
another line in a generic reader.

**An ignore file is the inverse of every other artifact in this suite.** It does not record
what the agent did. It records what the agent was configured never to read, write or index,
and the vendor's own documentation is what says so. Two uses follow from that and both are
questions an analyst actually asks. A file somebody expected the agent to have touched, and
which it did not, may be explained here rather than by the agent's behaviour. And a pattern
added to one of these shortly before the period under investigation is a way to keep
material out of the agent's context and therefore out of every transcript it ever wrote. So
each pattern is an event of its own, because a pattern is what an analyst compares against
a path, and a file read as one blob would make that comparison a text search through prose.

**A worktree include list is an inventory of secrets somebody copied.** The vendor
documents it as the list of gitignored files to copy into every worktree the agent creates,
and documents .env and secrets configuration as the examples. So a name in this file is a
statement that copies of that file exist in every worktree on the machine, which is where
to look for them and is a finding in its own right. One event per entry, for the same
reason.

Nothing else is read out of any of these. A line is a line, and what a pattern would have
matched on the endpoint is not knowable from the file.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator

from agentforensics.model import Event, unparsed
from agentforensics.parsers.base import ParseContext, looks_binary, text_lines
from agentforensics.parsers.instructions import BINARY_FILE, MAX_TEXT

# Which artifact is read as what. Written out rather than derived from the catalogue at
# runtime, for the reason the other readers' sets are: a parser is handed an artifact id and
# not a catalogue entry. tests/unit/test_text_config.py holds this against the catalogue.
SOURCES = frozenset(
    {
        "claude_code.anthropic_active_config",
        "claude_code.worktreeinclude",
        "claude_desktop.device_identifier",
        "cline.data_dir_root",
        "cline.workspace_specs",
        "continue.aux_config",
        "ollama.env_overrides",
        "windsurf.ignore_files",
    }
)

# The entries whose files are read line by line rather than whole, and what a line is.
PER_LINE = {
    "claude_code.worktreeinclude": "include",
    "windsurf.ignore_files": "ignore",
}

# The name an ignore file has, for the one entry that holds both an ignore file and other
# things. Read from the name rather than the entry, because that entry claims a directory of
# configuration with the ignore file beside it.
_IGNORE_NAMES = (".continueignore", ".codeiumignore", ".devinignore", ".windsurfignore")

IGNORED = (
    "this is a pattern the agent was configured never to read, write or index. It is the "
    "inverse of the rest of this case: it does not say what the agent did, it says what it "
    "was kept away from. A file somebody expected the agent to have touched and which it "
    "did not may be explained by this rather than by the agent's behaviour, and a pattern "
    "added shortly before the period under investigation keeps material out of every "
    "transcript the agent wrote. When the pattern was added is not in this file: the "
    "filesystem event for it dates the last write to the whole file and nothing finer"
)

INCLUDED = (
    "this is a file the agent copies out of the main checkout into every worktree it "
    "creates. The vendor documents this list as gitignored files and names .env and "
    "secrets configuration as the examples, so a name here says copies of that file exist "
    "in every worktree on this machine, which is where to look for them"
)

CONFIGURATION = (
    "this is a configuration file read whole. Nothing is read out of it beyond the text it "
    "holds, because no parser has mapped this product's settings to an event"
)

TRUNCATED = (
    "the text is longer than the ingest limit of {limit} characters and is carried "
    "truncated. The whole file is in the bundle, at the path in this event's provenance"
)


class TextConfigParser:
    """The plain text configuration, and the two files that are about what did not happen."""

    name = "text_config"

    def handles(self, artifact_id: str | None) -> bool:
        return artifact_id in SOURCES

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

        if looks_binary(raw):
            yield unparsed(
                context.provenance("file"),
                context.agent,
                {
                    "file": context.local_path.name,
                    "bytes": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                },
                BINARY_FILE,
                user=context.user,
                host=context.host,
            )
            return

        kind = _per_line(context)
        if kind:
            yield from self._patterns(context, kind)
            return
        yield self._whole(context, raw)

    def _patterns(self, context: ParseContext, kind: str) -> Iterator[Event]:
        """One event per pattern, so a pattern can be compared against a path.

        Comments and blank lines are the file's own structure rather than patterns, and a
        comment is kept because somebody wrote it: a note saying why a directory was
        excluded is exactly the thing an analyst wants to read next to the exclusion.
        """
        reason = IGNORED if kind == "ignore" else INCLUDED
        for line in text_lines(context.local_path):
            text = line.text.strip()
            if not text:
                continue
            comment = text.startswith("#")
            yield Event(
                kind="config.snapshot",
                provenance=context.provenance(f"line:{line.number}"),
                agent=context.agent,
                actor="user",
                user=context.user,
                host=context.host,
                raw={"pattern": None if comment else text, "comment": text if comment else None},
                payload={"key": f"{kind}:{text}", "text": text},
                parse_problem=" ".join(
                    part
                    for part in (
                        line.problem,
                        "this line is a comment in the file rather than a pattern, and is "
                        "kept because somebody wrote it"
                        if comment
                        else reason,
                    )
                    if part
                ),
            )

    def _whole(self, context: ParseContext, raw: bytes) -> Event:
        """The file as it stands, which for most of these is one line."""
        text = raw.decode("utf-8", "replace")
        problems = [CONFIGURATION]
        if "�" in text:
            problems.append(
                "the file did not decode as UTF-8 and was read with replacement characters, "
                "so its content is not exact"
            )
        if len(text) > MAX_TEXT:
            problems.append(TRUNCATED.format(limit=MAX_TEXT))
            text = text[:MAX_TEXT]
        return Event(
            kind="config.snapshot",
            provenance=context.provenance("file"),
            agent=context.agent,
            actor="system",
            user=context.user,
            host=context.host,
            raw={"file": context.local_path.name, "content": text},
            payload={"key": f"file:{context.local_path.name}", "text": text},
            parse_problem=" ".join(problems),
        )


def _per_line(context: ParseContext) -> str | None:
    """Whether this file is a list of patterns, and of which sort.

    By the artifact first and by the name second. One entry claims a whole configuration
    directory with an ignore file among the things in it, so the entry alone cannot say,
    and a file named like an ignore file is one whichever entry claimed it.
    """
    declared = PER_LINE.get(str(context.artifact_id))
    if declared:
        return declared
    return "ignore" if context.local_path.name in _IGNORE_NAMES else None


__all__ = [
    "CONFIGURATION",
    "IGNORED",
    "INCLUDED",
    "PER_LINE",
    "SOURCES",
    "TRUNCATED",
    "TextConfigParser",
]
