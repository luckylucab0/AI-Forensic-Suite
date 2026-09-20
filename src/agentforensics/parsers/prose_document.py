"""Read a transcript that is prose: a chat export, a spilled tool result, a written plan.

Five catalogue entries hold a conversation, or a piece of one, as text rather than as
records: an exported chat, the bulk output of a tool that was too large to keep inline, the
output a background subagent wrote for its parent, a session file of one editor family, and
the plans one agent writes beside its conversations. All five were collected and none was
read, so the material an analyst most wants to quote reached a case as a file name.

They are read whole, as one event per file, which is the one decision worth explaining. The
readers for logs split a file line by line, and that is right for a line-delimited record
and wrong here: half a prompt reads in a report as what somebody asked, and a tool result
cut at a line boundary reads as what the agent saw. So the text stays in one piece and the
case holds the file as the file was.

Nothing is read out of that text. Where the record is a conversation nobody has mapped, the
event says so in the words the other generic readers use, so it is visible as evidence
somebody still has to look at. A plan is different: the file is the plan, there is nothing
further to read out of it, and the event is a plan rather than an unread record.

The one limit is length, and it is the instruction reader's: a file past it is carried
truncated and says so on the event, because a tool result can be a hundred megabytes of a
fetched page and a case should not be fillable by one of them.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator

from agentforensics.model import UNINTERPRETED_MARK, Event, unparsed
from agentforensics.parsers.base import ParseContext, looks_binary
from agentforensics.parsers.instructions import BINARY_FILE, MAX_TEXT

# Which artifact is read as what. Written out rather than derived from the catalogue at
# runtime, for the reason the other readers' sets are: a parser is handed an artifact id
# and not a catalogue entry. tests/unit/test_prose_document.py compares this against the
# catalogue, so a prose transcript added there fails CI until it is listed here.
SOURCES = {
    "amazonq.ide_chat_export": "unparsed.record",
    # The text behind a [Pasted text #N] placeholder. The transcript and the prompt history
    # carry the placeholder and not the text, and the vendor's own changelog notes that a
    # recalled paste can have aged out of here while the prompt that refers to it is still
    # in the transcript. So this is the only place what the user actually handed the agent
    # exists, and its entry says the commonest thing to find is a credential, a
    # configuration blob or third-party source somebody pasted rather than committed.
    # Filed as a prompt because that is what it is: text the user put in front of the
    # model. Which prompt is not knowable from this file, and the event says so.
    "claude_code.paste_cache": "user.prompt",
    "claude_code.tool_result_spills": "unparsed.record",
    "cursor.subagent_output": "unparsed.record",
    # The same shape as claude_code.paste_cache above, in a second product: a paste
    # longer than five lines or two thousand characters is written out and the prompt
    # keeps a placeholder naming it. Same reading, same reason.
    "hermes.pastes": "user.prompt",
    "hermes.session_exports": "unparsed.record",
    "hermes.spillover": "unparsed.record",
    "jetbrains_ai.aia_task_history": "unparsed.record",
    # The file is the plan. There is no further reading to do and no shape anybody has to
    # map, so this one is not marked as unread.
    "windsurf.plans": "plan.write",
}

# What an event out of an unmapped prose transcript says about itself, in the words the
# other generic readers use for the same situation.
UNINTERPRETED = (
    "this is a conversation in prose that no parser has mapped, so the record "
    f"{UNINTERPRETED_MARK}. The whole file is in raw. Re-read it once a parser for this "
    "product's export exists."
)

PASTED = (
    "this is the text behind a [Pasted text #N] placeholder in a prompt. Which prompt is "
    "not knowable from this file: the transcript refers to a paste by a number and this "
    "store is swept on its own schedule, so a paste can outlive its conversation or be "
    "gone while the prompt that used it is still there. It is filed as a prompt because "
    "that is what the user put in front of the model, and not as a prompt at a time"
)

TRUNCATED = (
    "the text is longer than the ingest limit of {limit} characters and is carried "
    "truncated. The whole file is in the bundle, at the path in this event's provenance"
)


class ProseDocumentParser:
    """One event per file, for the transcripts that are text rather than records."""

    name = "prose_document"

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

        if looks_binary(raw_bytes):
            # Not prose at all. A spilled tool result can be a downloaded archive and a
            # session file can be a container format, and a page of replacement characters
            # reads as what the agent saw, which is worse than saying nothing.
            yield unparsed(
                context.provenance("file"),
                context.agent,
                {
                    "file": context.local_path.name,
                    "bytes": len(raw_bytes),
                    "sha256": hashlib.sha256(raw_bytes).hexdigest(),
                },
                BINARY_FILE,
                user=context.user,
                host=context.host,
            )
            return

        text = raw_bytes.decode("utf-8", "replace")
        problems: list[str] = []
        if "�" in text:
            problems.append(
                "the file did not decode as UTF-8 and was read with replacement characters, "
                "so its content is not exact"
            )
        if len(text) > MAX_TEXT:
            problems.append(TRUNCATED.format(limit=MAX_TEXT))
            text = text[:MAX_TEXT]

        kind = SOURCES[str(context.artifact_id)]
        if kind == "unparsed.record":
            problems.append(UNINTERPRETED)
        elif kind == "user.prompt":
            problems.append(PASTED)
        yield Event(
            kind=kind,
            provenance=context.provenance("file"),
            agent=context.agent,
            raw={"file": context.local_path.name, "text": text},
            # No timestamp. These files carry none inside them that this reader can point
            # at, and the artifact event for the same path already carries the
            # filesystem's, attributed to the filesystem. Repeating an mtime here would
            # present it as the conversation's own time.
            ts_utc=None,
            ts_precision="absent",
            actor="unknown",
            user=context.user,
            host=context.host,
            payload={
                "text": text,
                "file": context.local_path.name,
                "bytes": len(raw_bytes),
            },
            parse_problem=" ".join(problems) if problems else None,
        )


__all__ = ["PASTED", "SOURCES", "TRUNCATED", "UNINTERPRETED", "ProseDocumentParser"]
