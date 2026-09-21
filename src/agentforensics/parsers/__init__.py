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
from agentforensics.parsers.file_snapshot import FileSnapshotParser
from agentforensics.parsers.gemini import GeminiParser
from agentforensics.parsers.git_checkpoints import GitCheckpointsParser
from agentforensics.parsers.goose import GooseParser
from agentforensics.parsers.hermes import HermesParser
from agentforensics.parsers.instructions import InstructionsParser
from agentforensics.parsers.json_generic import JsonGenericParser
from agentforensics.parsers.jsonl_generic import JsonlGenericParser
from agentforensics.parsers.leveldb_store import LevelDbStoreParser
from agentforensics.parsers.lmdb_generic import LmdbGenericParser
from agentforensics.parsers.memory import MemoryParser
from agentforensics.parsers.opencode import OpencodeParser
from agentforensics.parsers.pi import PiParser
from agentforensics.parsers.plist_generic import PlistGenericParser
from agentforensics.parsers.prompt_history import PromptHistoryParser
from agentforensics.parsers.prompt_library import PromptLibraryParser
from agentforensics.parsers.prose_document import ProseDocumentParser
from agentforensics.parsers.registry import RegistryParser
from agentforensics.parsers.shell_history import ShellHistoryParser
from agentforensics.parsers.shell_script import ShellScriptParser
from agentforensics.parsers.sqlite_generic import SqliteGenericParser
from agentforensics.parsers.text_config import TextConfigParser
from agentforensics.parsers.text_log import TextLogParser
from agentforensics.parsers.toml_generic import TomlGenericParser
from agentforensics.parsers.vscode_state import VscodeStateParser
from agentforensics.parsers.windsurf_cascade import WindsurfCascadeParser
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
    # The copy an agent kept of a file before it changed it, which for a change that was
    # never committed is the only place the original text exists. Read for its content,
    # because that is what a rule about a credential or an injected instruction has to
    # search, and honest about the fact that a snapshot usually does not name the file it
    # came from.
    FileSnapshotParser(),
    GeminiParser(),
    # The checkpoint references two agents write into a repository, which are the only
    # record on an endpoint that dates an agent's edits and survive the conversation.
    GitCheckpointsParser(),
    # One product's conversation in the two containers it has had: the database it moved to
    # and the file per session it stopped managing and left on disk. Both hold the same
    # message model, so one module reads them, and the older one is the half a user cannot
    # delete from the product's own interface.
    GooseParser(),
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
    # The transcripts that are prose rather than records: a chat export, a spilled tool
    # result, the output of a background subagent, a written plan. Read whole, because
    # half a prompt reads in a report as what somebody asked.
    ProseDocumentParser(),
    # The shell's own record of what was typed, which is where the flag that switched
    # the approvals off is written down. Four files, four formats, and until this parser
    # all four were collected and none was read.
    # The registry keys a Windows collection carried as documents. Two of them are the
    # managed policy that says what an agent was allowed to do, and on Windows that policy
    # can exist in the registry alone with no file anywhere.
    RegistryParser(),
    ShellHistoryParser(),
    # The copy one agent takes of the user's shell before it runs anything, which is the
    # environment its commands actually ran in rather than a record that somebody once
    # typed a line. It also outlives the product's own purge command.
    ShellScriptParser(),
    # The small text files that say how an agent was set up, and the two that say what it
    # was kept away from: an ignore file is the inverse of every other artifact here, and a
    # worktree include list is an inventory of the secrets somebody copied.
    TextConfigParser(),
    # Five catalogue entries across three products are one file with one schema, read
    # here rather than by the generic reader, which had the key in raw and the value in
    # text and said nobody had read the store.
    VscodeStateParser(),
    # The key-value stores the two Electron desktop products keep their windows' state
    # in, which for one of them is where the prompts are. A browser engine's format, so
    # one module for both, and the records come out with nobody claiming to know what the
    # bytes inside them mean.
    LevelDbStoreParser(),
    # The encrypted trajectory store, which is the whole conversation record of one
    # product. Read only when the analyst supplies the product's key, and reported as an
    # encrypted store otherwise. See ADR 0029.
    WindsurfCascadeParser(),
    # The one instruction artifact in this catalogue that is not a file: one editor keeps
    # the prompts a user wrote for the agent in a memory-mapped B-tree store, so the text
    # of them reaches a case through the format reader beside this module and not through
    # the one every other instruction file goes to.
    PromptLibraryParser(),
    ZedParser(),
    # The other half of Zed on disk: threads.db holds the conversations and this store
    # holds which agent ran them, which of them were archived out of the sidebar, and what
    # each one was left doing to a git worktree.
    ZedSidebarParser(),
    # The floor under the memory-mapped stores, which claims the one entry nobody has a
    # schema for. The prompt library above it has one, which is why it comes first.
    LmdbGenericParser(),
    # The last seven claim every store, every log and every whole document in
    # the catalogue, so they have to stay last: a parser with a verified schema placed after
    # one of them would never be reached. They read nothing out of a record but what it
    # literally says, and exist so that a file nobody has mapped is visible in a case as
    # records somebody has to look at rather than as a file name with nothing behind it.
    # The three for whole documents split them by structure alone, which is ADR 0027 for
    # JSON and ADR 0028 for the other two formats the catalogue's configurations are
    # written in.
    JsonGenericParser(),
    JsonlGenericParser(),
    PlistGenericParser(),
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
