"""Read the files an agent wrote to remember things, which outlive every transcript.

A memory file is the agent's own note to itself, and the reason it matters is retention.
Every transcript store in this catalogue is swept, rotated or deleted by something, and
none of the memory directories is: the vendors document them as state to keep. So a machine
whose conversations are gone can still say what the agent concluded, which repository it
was working in and what it was told to remember, and for several agents it is the only such
text left on the endpoint.

It is also a persistence surface. The content is written back into the context of later
sessions, and it is written by the agent rather than by a person, so anything that reached
the agent once and was remembered reaches it again in every session afterwards, with no
file in the repository and no line in a settings file to show for it. An instruction
planted in a memory outlives the conversation that planted it.

The reading is the instruction reader's, because the files are the same shape: Markdown or
plain text, sometimes with front matter, and the question for both is what the model was
going to read. What differs is the kind. These events are `memory.write`, not
`instruction.source`, so the instruction surface view keeps answering the question it was
built for, which is what the agent was told to obey and by whom. A note the agent wrote
itself is a different question and belongs beside it rather than inside it.

What this module does not do is say who put the text there or when. The file has no time of
its own, and the filesystem's times are already carried by the artifact event for the same
path. Whether a line in a memory came from the user, from a document the agent read or from
a tool result is a question for the transcripts, and where those are gone it is a question
with no answer, which is a better report than a confident one.
"""

from __future__ import annotations

from collections.abc import Iterator

from agentforensics.model import Event
from agentforensics.parsers.base import ParseContext
from agentforensics.parsers.instructions import read_document

# Every catalogue artifact filed under memory whose content is prose. Written out rather
# than derived at runtime, for the reason the other readers' sets are: a parser is handed
# an artifact id and not a catalogue entry, and a new memory store should be read because
# somebody decided it should be. tests/unit/test_memory.py compares this against the
# catalogue, so adding an entry there fails CI until it is listed here.
#
# One memory entry is not prose: a directory of JSON task lists, which the document reader
# claims. One entry here is not prose either, and is read anyway: a directory whose file
# format the vendor documents nothing about, and where rendering the bytes as text with
# the reader's own note that they did not decode surfaces the readable strings inside them
# instead of leaving the file with nothing behind it.
SOURCES = frozenset(
    {
        "amazonq.memory_bank",
        "claude_code.agent_memory",
        "claude_code.auto_memory",
        "claude_desktop.cowork_memory",
        "goose.memory",
        "hermes.memories",
        "qwen_code.auto_memory",
        "windsurf.memories",
    }
)


class MemoryParser:
    """The agent's own notes, read the way its instruction files are."""

    name = "memory"

    def handles(self, artifact_id: str | None) -> bool:
        return artifact_id in SOURCES

    def parse(self, context: ParseContext) -> Iterator[Event]:
        yield from read_document(
            context,
            kind="memory.write",
            # Said on the event rather than left to the artifact id, because the one thing
            # an analyst has to carry away from a memory event is that the text was not
            # necessarily written by the person at the keyboard.
            extra={
                "memory": True,
                "authorship": (
                    "this file is a store the agent writes to itself, so its text is not "
                    "evidence that the user wrote it or asked for it"
                ),
            },
        )


__all__ = ["SOURCES", "MemoryParser"]
