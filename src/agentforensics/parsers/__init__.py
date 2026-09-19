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

from agentforensics.parsers.aider import AiderParser
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
from agentforensics.parsers.cline_cli import ClineCliParser
from agentforensics.parsers.codex import CodexParser
from agentforensics.parsers.codex_state import CodexStateParser
from agentforensics.parsers.continue_sessions import ContinueSessionsParser
from agentforensics.parsers.copilot import CopilotParser
from agentforensics.parsers.gemini import GeminiParser
from agentforensics.parsers.hermes import HermesParser
from agentforensics.parsers.instructions import InstructionsParser
from agentforensics.parsers.json_generic import JsonGenericParser
from agentforensics.parsers.jsonl_generic import JsonlGenericParser
from agentforensics.parsers.memory import MemoryParser
from agentforensics.parsers.opencode import OpencodeParser
from agentforensics.parsers.pi import PiParser
from agentforensics.parsers.prompt_history import PromptHistoryParser
from agentforensics.parsers.shell_history import ShellHistoryParser
from agentforensics.parsers.sqlite_generic import SqliteGenericParser
from agentforensics.parsers.text_log import TextLogParser
from agentforensics.parsers.toml_generic import TomlGenericParser
from agentforensics.parsers.vscode_state import VscodeStateParser
from agentforensics.parsers.yaml_generic import YamlGenericParser
from agentforensics.parsers.zed import ZedParser
from agentforensics.parsers.zed_sidebar import ZedSidebarParser

# Order matters only in that the first parser to claim an artifact wins, so a more specific
# parser has to come before a general one. Kept as a tuple rather than a registry decorator
# so that reading this file tells you the whole set.
PARSERS: tuple[Parser, ...] = (
    AiderParser(),
    AmazonQParser(),
    ClaudeCodeParser(),
    ClineParser(),
    # The SDK's own session store, which is a different product on disk from the editor
    # extension above: a directory per session with a versioned messages file, a manifest
    # that records how the run was started, and the hook log that dates a prompt.
    ClineCliParser(),
    CodexParser(),
    # The projection of those rollouts into rows, which is where a conversation still is
    # after its rollout file has gone.
    CodexStateParser(),
    # Continue's session store, which is the one transcript in this catalogue with no
    # timestamp anywhere in it: the only clock is the index beside it.
    ContinueSessionsParser(),
    CopilotParser(),
    GeminiParser(),
    HermesParser(),
    InstructionsParser(),
    # The same reading as the instruction files, for the notes the agent wrote itself.
    # A separate kind, because the instruction surface answers what the agent was told to
    # obey and these are not that, and a separate parser, because a memory outlives every
    # transcript store in this catalogue and is read for retention rather than for scope.
    MemoryParser(),
    # Ahead of the generic SQLite reader, which is what taking a store over looks like:
    # this one has a verified schema, so it claims opencode.db and the reader does not.
    OpencodeParser(),
    PiParser(),
    # What somebody typed at a prompt, from the line editor's own recall file. One
    # module because it is a format question and not an agent question: three agents,
    # three libraries, three file formats.
    PromptHistoryParser(),
    # The shell's own record of what was typed, which is where the flag that switched
    # the approvals off is written down. Four files, four formats, and until this parser
    # all four were collected and none was read.
    ShellHistoryParser(),
    # Five catalogue entries across three products are one file with one schema, read
    # here rather than by the generic reader, which had the key in raw and the value in
    # text and said nobody had read the store.
    VscodeStateParser(),
    ZedParser(),
    # The other half of Zed on disk: threads.db holds the conversations and this store
    # holds which agent ran them, which of them were archived out of the sidebar, and what
    # each one was left doing to a git worktree.
    ZedSidebarParser(),
    # The last six claim every store, every log and every whole document in
    # the catalogue, so they have to stay last: a parser with a verified schema placed after
    # one of them would never be reached. They read nothing out of a record but what it
    # literally says, and exist so that a file nobody has mapped is visible in a case as
    # records somebody has to look at rather than as a file name with nothing behind it.
    # The three for whole documents split them by structure alone, which is ADR 0027 for
    # JSON and ADR 0028 for the other two formats the catalogue's configurations are
    # written in.
    JsonGenericParser(),
    JsonlGenericParser(),
    SqliteGenericParser(),
    TextLogParser(),
    TomlGenericParser(),
    YamlGenericParser(),
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
