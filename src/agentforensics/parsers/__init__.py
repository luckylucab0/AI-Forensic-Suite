"""One module per agent, turning collected files into events.

A parser is chosen by the catalogue entry that claimed the file, not by its name or its
contents. That is what ties the whole pipeline to one source of truth: adding an agent to
the catalogue makes its files collectable, exportable as collection rules, and parseable,
in that order, and a parser can never quietly disagree with the catalogue about what a file
is.

A file with no parser is not a problem to hide. It is recorded in the case with a parse
status of unsupported, which is how a case answers the question its own reliability rests
on: what did we collect and fail to read. That number appears every time a case is
summarised.
"""

from __future__ import annotations

from agentforensics.parsers.amazonq import AmazonQParser
from agentforensics.parsers.base import (
    Line,
    ParseContext,
    Parser,
    iter_lines,
    normalise_ts,
    read_json,
    text_of,
)
from agentforensics.parsers.claude_code import ClaudeCodeParser
from agentforensics.parsers.cline import ClineParser
from agentforensics.parsers.codex import CodexParser
from agentforensics.parsers.copilot import CopilotParser
from agentforensics.parsers.gemini import GeminiParser
from agentforensics.parsers.hermes import HermesParser
from agentforensics.parsers.instructions import InstructionsParser
from agentforensics.parsers.opencode import OpencodeParser
from agentforensics.parsers.pi import PiParser
from agentforensics.parsers.sqlite_generic import SqliteGenericParser
from agentforensics.parsers.zed import ZedParser

# Order matters only in that the first parser to claim an artifact wins, so a more specific
# parser has to come before a general one. Kept as a tuple rather than a registry decorator
# so that reading this file tells you the whole set.
PARSERS: tuple[Parser, ...] = (
    AmazonQParser(),
    ClaudeCodeParser(),
    ClineParser(),
    CodexParser(),
    CopilotParser(),
    GeminiParser(),
    HermesParser(),
    InstructionsParser(),
    # Ahead of the generic SQLite reader, which is what taking a store over looks like:
    # this one has a verified schema, so it claims opencode.db and the reader does not.
    OpencodeParser(),
    PiParser(),
    ZedParser(),
    # Last, and it has to stay last: it claims every SQLite store in the catalogue, so a
    # verified schema parser placed after it would never be reached.
    SqliteGenericParser(),
)


def for_artifact(artifact_id: str | None) -> Parser | None:
    """The parser for a catalogue entry, or None when nothing reads it yet."""
    for parser in PARSERS:
        if parser.handles(artifact_id):
            return parser
    return None


__all__ = [
    "PARSERS",
    "Line",
    "ParseContext",
    "Parser",
    "for_artifact",
    "iter_lines",
    "normalise_ts",
    "read_json",
    "text_of",
]
