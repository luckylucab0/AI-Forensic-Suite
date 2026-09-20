"""A Velociraptor artifact that normalizes on the endpoint and returns the unified log.

The short path into the suite. The other Velociraptor artifact, `.Collect`, uploads files
and leaves the reading to `afx ingest`. This one reads the agent logs where they are and
returns rows in the vendor-neutral format described in `docs/UNIFIED_FORMAT.md`, so a fleet
hunt comes back as one log rather than as a thousand uploads that still have to be parsed.

It is a second producer of the same format, which the format is built for: every record
says which producer wrote it, and `event_id` is derived rather than trusted, so the two
producers can be compared instead of having to agree.

Three properties of the generated VQL are decisions, not style.

**It does not use `parse_jsonl`.** That plugin skips a line it cannot decode, with only a
deduplicated message in the collection log. For this project that is disqualifying: a
skipped line reads as a line that was never there, and a truncated or deliberately
corrupted record is exactly the evidence a tampered transcript would hide behind. So the
query reads lines with `parse_lines` and decodes each one itself, and a line that does not
decode is emitted as an `unparsed.record` row carrying the line verbatim.

**It checks its own reading.** `parse_lines` is a `bufio.Scanner`, so a line longer than its
buffer stops the scan and the rest of the file is simply absent from the results. Agent
transcripts routinely carry lines of several megabytes when a tool output was large, so this
is not a theoretical limit. The buffer is a parameter with a generous default, and the query
compares the bytes it read against the file's size and emits a row saying so when they do
not add up. A collection that silently read half a transcript would be worse than one that
failed.

**It normalizes one row per record, not per content block.** The full analyzer splits an
assistant turn into its text, its reasoning and each of its tool calls. Doing that in VQL
would be a second, subtler implementation of the same mapping, and the two would drift. So
the endpoint producer stays coarse and stays lossless: `raw` holds the complete record, and
re-reading the log with `afx` refines it. What is coarse is the interpretation, never the
evidence.

The globs come from the same translation as the `.Collect` artifact, so the two cannot
disagree about where to look.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from agentforensics.catalog import Artifact, Catalogue
from agentforensics.exporters.common import (
    Rendered,
    Skip,
    agents,
    artifacts_for,
    catalogue_digest,
    dedupe,
    generated_note,
    header,
    skip_lines,
)

# Imported rather than reimplemented: one translation of a catalogue path into a
# Velociraptor glob, so the artifact that uploads files and the artifact that parses them
# look in exactly the same places. A second copy would drift, and the drift would show up
# as an agent that one artifact finds and the other does not.
from agentforensics.exporters.velociraptor import NAMESPACE, _covered

ARTIFACT = f"{NAMESPACE}.UnifiedLog"

# Bumped when the normalization changes in a way that could change a row. It travels in
# every record's `producer` field, so a case can be asked which version of this query read
# a file, and two collections taken months apart can be told apart.
PRODUCER_VERSION = 1
PRODUCER = f"{ARTIFACT}/{PRODUCER_VERSION}"

# Which catalogue artifact each VQL normalizer claims, keyed by artifact id rather than by
# agent. One agent can hold several formats: Claude Code's transcripts and its prompt
# history are both JSON Lines and share not one field name.
#
# These are the same artifacts the Python parsers claim. A test asserts that, because a
# parser added here and not there, or there and not here, is how the two producers would
# start disagreeing.
MAPPERS: dict[str, str] = {
    "claude_code.transcripts": "claude_transcript",
    "claude_code.transcripts_set_aside": "claude_transcript",
    "claude_code.subagent_transcripts": "claude_transcript",
    "claude_code.workflow_runs": "claude_transcript",
    "claude_code.history_jsonl": "claude_history",
    "codex.rollouts": "codex_rollout",
    "codex.archived_sessions": "codex_rollout",
    "codex.prompt_history": "codex_history",
    "copilot.session_event_log": "copilot_events",
}

# The categories worth normalizing. Everything else in the catalogue is configuration,
# credentials, caches and install traces: a hunt that wants those wants the file itself,
# which is what the .Collect artifact is for.
CATEGORIES = ("transcript", "prompt_history")

# A JSON Lines artifact with no verified mapping still goes into the log, record by record,
# marked as uninterpreted. Guessing at the semantics of a format nobody has verified would
# be the same defect as an invented catalogue path: it produces output that looks like an
# answer.
GENERIC = "generic_jsonl"

# Anything that is not line-delimited JSON. Still globbed, and still reported as one row
# per file, because the difference between "this agent left nothing" and "this agent left a
# database nobody has read" is the difference between two opposite conclusions.
NOT_NORMALIZED = "file_only"

# The formats the suite's own parsers read and this artifact does not, with the reason. The
# gap is real and it is listed rather than left to be discovered: an operator running a
# fleet hunt has to know that for these agents the rows say a file was there and nothing
# about what is in it, so the answer is to collect the files and ingest them.
#
# Every entry here is something VQL cannot read line by line: a whole JSON document, or a
# directory this artifact will not guess an extension for. A line-delimited log whose own
# path names a file needs no entry, because the generic normalizer already returns every
# one of its records. Two entries say "read in part", which is the honest shape where one
# artifact holds both: a named log this query reads and a subtree beside it that it will
# not narrow to an extension, so the session comes back and its subagents do not.
UNINTERPRETED: dict[str, str] = {
    "aider.chat_history": "a markdown log whose turns are blocks of lines rather than "
    "records, so a line of it is a fragment of one",
    "aider.input_history": "a line editor's history file whose entries span several lines, "
    "which this query reads one line at a time",
    "amazonq.cli_prompt_history": "a line editor's history file whose entries are escaped, "
    "so a line of it is not the text that was typed",
    "chatgpt_desktop.macos_codex_home": "a profile directory this artifact will not narrow "
    "to an extension",
    "chatgpt_desktop.windows_msix_localcache": "an application-data tree whose conversations "
    "are in a browser engine's key-value store, which is a set of binary table files and a "
    "write-ahead log rather than records this query can read a line at a time. The analyzer "
    "opens one key by key, so collect the tree and ingest it",
    "zed.flatpak_legacy_threads": "a memory-mapped B-tree database, which this query does "
    "not open: it reads a file line at a time and this one is a tree of pages. The suite "
    "analyzer reads every record of one, and the pages it no longer points at as well, so "
    "collect the directory whole and ingest it",
    "codex.sqlite_write_ahead_logs": "a database's write-ahead log and shared-memory "
    "index, which hold changed pages rather than records, so nothing comes out of one a "
    "line at a time. The analyzer names them for what they are and reads what is in the "
    "log through the database beside it, so collect all three files and ingest them "
    "together",
    "copilot.session_store_sidecars": "the same two files for another product's store, for "
    "the same reason",
    "codex.rollouts_compressed": "a transcript compressed in place after seven days, which "
    "this query cannot expand on the endpoint. Everything older than a week is in these "
    "files, so collect them and ingest them: the analyzer reads them line by line exactly "
    "as it reads an uncompressed one",
    "cline.cli_sessions": "a session directory of whole JSON documents. The hook log that "
    "dates this agent's prompts is a separate artifact and does come back record by record",
    "cline.data_tasks": "a task directory of whole JSON documents",
    "cline.vscode_task_transcripts": "a task directory of whole JSON documents",
    "claude_code.tool_result_spills": "the bulk output of one tool call in one file, which "
    "is prose rather than records: a line of it is a fragment of what the agent saw",
    "cursor.subagent_output": "what a background subagent wrote for its parent, in a format "
    "the vendor documents nothing about, so a line of it is a fragment of a report",
    "gemini_cli.chats": "a chats directory this artifact will not narrow to an extension",
    "jetbrains_ai.aia_task_history": "a session file of prose rather than records, so a "
    "line of it is a fragment of a conversation",
    "hermes.pastes": "the text behind a placeholder in a prompt, which is whatever the "
    "user pasted: a line of it is a fragment of what they handed the agent, and the "
    "analyzer carries the file whole as one prompt",
    "hermes.session_exports": "conversations exported to readable files, which are prose "
    "rather than records, in a directory this artifact will not narrow to an extension",
    "hermes.sessions_dir": "a sessions directory this artifact will not narrow to an extension",
    "hermes.spillover": "the bulk output of one tool call in one file, which is prose "
    "rather than records, for the same reason as the entry of another agent above",
    "junie.cli_sessions": "read in part: its own event log comes back record by record and "
    "the subagent transcripts beside it sit in a subtree this artifact will not narrow to "
    "an extension",
    "junie.matterhorn_project_logs": "read in part: the event and issue files come back "
    "record by record and the tree around them, which is where this product's Windows "
    "paths lead, is returned as files",
    "kilo_code.extension_id_legacy_tree": "a task directory of whole JSON documents",
    "goose.command_history": "a line editor's history file, which is a line each until the "
    "writer chooses its escaped format, and the analyzer reads whichever of the two the "
    "file is in",
    "ollama.cli_prompt_history": "a line editor's history file, which is a line each and "
    "carries no timestamp, agent or session for a record to be built from",
    "qwen_code.prompt_history_log": "one JSON document rewritten whole on every append",
    "qwen_code.subagent_transcripts": "a directory with no stated file format",
    "roo_code.tasks": "a task directory of whole JSON documents",
    "windsurf.cascade_trajectories": "an encrypted container around a protocol buffer. "
    "The analyzer opens one when the examiner supplies the product's key; this query does "
    "not carry a key and does not try, so it returns the files to be collected and read",
    "windsurf.implicit_trajectories": "the same encrypted container as the entry above, "
    "for the background work of the same agent",
}

# Whole formats this query returns as files rather than as records, with the reason.
#
# Per format rather than per artifact because the limit belongs to the format: the
# normalizers here read a file line by line, and a database is not lines. Naming the format
# also keeps the statement honest as the catalogue grows. Listing the SQLite stores one by
# one would mean a store added tomorrow becomes an unnamed gap, which is exactly the shape
# of omission this whole mechanism exists to prevent.
UNINTERPRETED_FORMATS: dict[str, str] = {
    "sqlite": "a database, which this query does not open. The suite analyzer reads every "
    "table of one, so collect the file and ingest it",
    "json": "a whole document, which this query does not read: it reads a file line by "
    "line and a document is one value. The suite analyzer splits one by its structure, so "
    "collect the file and ingest it",
}

_OS_SOURCES = (
    ("windows", "SELECT OS FROM info() WHERE OS = 'windows'"),
    ("macos", "SELECT OS FROM info() WHERE OS = 'darwin'"),
    ("linux", "SELECT OS FROM info() WHERE OS = 'linux'"),
)

# How to read a user name out of an absolute path, per platform. Named group so the query
# reads the name rather than a positional index. The second alternative in each case is the
# account whose home is not under the usual root, which is the one an agent is most likely
# to have been automated under.
_USER_REGEX = {
    "windows": r"(?i)^[A-Za-z]:\\\\Users\\\\(?P<User>[^\\\\]+)\\\\",
    "macos": r"^/(?:Users/(?P<User>[^/]+)|var/(?P<Root>root))",
    "linux": r"^/(?:home/(?P<User>[^/]+)|(?P<Root>root))",
}


@dataclass(frozen=True, slots=True)
class Target:
    """One catalogue glob, with the normalizer that will read what it finds."""

    agent: str
    artifact_id: str
    mapper: str
    glob: str


class UnsafeTarget(ValueError):
    """A catalogue value that cannot go into the query's data block.

    Raised rather than escaped. The block is CSV inside a VQL triple-quoted string, so a
    value carrying a comma, a quote, a newline or the closing quote sequence would not
    corrupt one row: it would shift every column after it, and a shifted column means
    globbing the wrong path under the wrong agent's name. Refusing to generate is the only
    safe answer, because a broken artifact that runs is worse than one nobody wrote.
    """


# What may not appear in a value written into the data block. Velociraptor's parse_csv sets
# TrimLeadingSpace unconditionally, which is what makes the block's indentation harmless,
# and is also why a path that begins with a space could not survive the round trip.
FORBIDDEN_IN_DATA_BLOCK = (",", '"', "'" * 3, "\n", "\r")


def _check(target: Target) -> None:
    for value in (target.agent, target.artifact_id, target.mapper, target.glob):
        for character in FORBIDDEN_IN_DATA_BLOCK:
            if character in value:
                raise UnsafeTarget(
                    f"{target.artifact_id}: the value {value!r} contains {character!r}, "
                    "which would shift every column after it in the query's data block. "
                    "Rewrite the catalogue path rather than escaping it here."
                )
        if value != value.strip():
            raise UnsafeTarget(
                f"{target.artifact_id}: the value {value!r} has leading or trailing "
                "whitespace, and parse_csv trims it, so the query would search a "
                "different path from the one the catalogue states."
            )


def _names_files(glob: str) -> bool:
    """Whether a glob names files rather than a whole subtree.

    This decides whether the query is allowed to read what the glob finds line by line, and
    it is a safety rule rather than a nicety. Several catalogue entries are recorded as
    `format: jsonl` while their paths are a directory recursion, because the agent keeps its
    line-delimited logs somewhere inside a tree that also holds SQLite databases, compressed
    rollouts and caches. Feeding that tree to a line reader would read a multi-gigabyte
    binary one line at a time, on a live endpoint, for nothing. A subtree glob is therefore
    always reported as a file rather than read, and the specific globs of the same agent
    pick up the logs that matter.
    """
    last = glob.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    return last not in ("**", "*") and last != ""


JSONL_TAIL = "**/*.jsonl"


def _restrict(glob: str) -> str:
    """Narrow a subtree glob to the line-delimited files inside it.

    Several agents' transcript stores are catalogued as a directory, which is right for a
    collection that takes the whole store away and wrong for a query that has to decide what
    to read. Codex is the clear case: the catalogue records `~/.codex/sessions/` because that
    is what the vendor documents, and the rollouts inside it sit under a dated directory
    tree alongside compressed copies of themselves.

    So a subtree glob belonging to an agent with a verified mapping is narrowed to the file
    extension rather than refused. That reads the store's logs and nothing else, which is
    both what the mapper is for and the only version of this that cannot end up reading a
    database one line at a time.
    """
    return glob.replace("\\", "/").rstrip("/").removesuffix("**").rstrip("/") + "/" + JSONL_TAIL


def _drop_subsumed(globs: list[str]) -> list[str]:
    """Remove a narrowed glob that another already covers.

    One artifact can list both a store and a dated subdirectory of it, and after narrowing
    both end in the same recursive tail, so the deeper one finds nothing the shallower one
    did not. Left in, it would return every record of that store twice, and a log that
    reports one prompt as two prompts is a log that cannot be counted.
    """
    prefixes = sorted({glob.removesuffix(JSONL_TAIL) for glob in globs})
    keep = [
        prefix
        for index, prefix in enumerate(prefixes)
        if not any(prefix.startswith(other) and other != prefix for other in prefixes[:index])
    ]
    return [prefix + JSONL_TAIL for prefix in keep]


def _mapper_for(artifact: Artifact, glob: str) -> str:
    """Which normalizer reads one target.

    Per target rather than per artifact, because one artifact's paths can be a mix: a
    specific log file, which can be read, and the directory around it, which cannot.
    """
    if artifact.id in MAPPERS:
        return MAPPERS[artifact.id]
    if artifact.format == "jsonl" and _names_files(glob):
        # An agent with no verified mapping keeps its subtree globs unread. Narrowing a
        # whole tree to an extension is a reasonable guess for a format somebody has read
        # against its vendor and a poor one otherwise, and this project does not make that
        # kind of guess.
        return GENERIC
    return NOT_NORMALIZED


def _targets(catalogue: Catalogue, os_name: str) -> tuple[list[Target], list[Skip]]:
    """Every glob this platform should read, and the artifacts it cannot express."""
    targets: list[Target] = []
    skipped: list[Skip] = []
    for agent in agents(catalogue):
        for artifact in artifacts_for(agent, os_name):
            if artifact.category not in CATEGORIES:
                continue
            globs, reason = _covered(artifact, os_name)
            if reason:
                skipped.append(Skip(artifact.id, reason))
                continue

            if artifact.id in MAPPERS:
                subtrees = [glob for glob in globs if not _names_files(glob)]
                globs = [glob for glob in globs if _names_files(glob)] + _drop_subsumed(
                    [_restrict(glob) for glob in subtrees]
                )

            for glob in globs:
                mapper = _mapper_for(artifact, glob)
                target = Target(agent.agent, artifact.id, mapper, glob)
                _check(target)
                targets.append(target)
    return targets, skipped


def render(catalogue: Catalogue) -> list[Rendered]:
    digest = catalogue_digest(catalogue)
    skipped: list[Skip] = []
    sources: list[str] = []
    for os_name, precondition in _OS_SOURCES:
        targets, os_skipped = _targets(catalogue, os_name)
        skipped.extend(os_skipped)
        if not targets:
            continue
        sources.append(_source(os_name, precondition, targets))

    text = "\n".join(
        [
            header(generated_note(digest, _header_notes(catalogue)) + skip_lines(dedupe(skipped))),
            f"name: {ARTIFACT}",
            "description: |",
            *(f"  {line}" if line else "" for line in _description()),
            "type: CLIENT",
            "parameters:",
            *_parameters(),
            "sources:",
            *sources,
            "",
        ]
    )
    return [Rendered(f"velociraptor/{ARTIFACT}.yaml", text, dedupe(skipped))]


def _description() -> list[str]:
    return [
        "Read the on-disk history of AI coding agents on this host and return it as a",
        "vendor-neutral agent log: one row per record, in the format documented at",
        "docs/UNIFIED_FORMAT.md, whichever agent wrote it.",
        "",
        "Uploads nothing. The records come back in the result set, which is the point: a",
        "fleet hunt gets the conversations without pulling gigabytes of transcripts off",
        "every endpoint.",
        "",
        "What it does not do, stated here because a collection tool that quietly does less",
        "than it appears to is worse than one that fails:",
        "",
        "  - It normalizes one row per record, never per content block. An assistant turn",
        "    that called three tools is one row. The complete record is in `raw`, so",
        "    nothing is lost; re-reading this log with the suite's own analyzer splits it",
        "    further. What is coarse is the interpretation, not the evidence.",
        "",
        "  - It interprets the formats that have been verified against their vendor: the",
        "    Claude Code transcript and prompt history, the Codex rollout and prompt",
        "    history, and the Copilot CLI event log. Any other line-delimited agent log is",
        "    returned record by record with kind `unparsed.record`, because guessing the",
        "    semantics of an unverified format produces output that looks like an answer.",
        "",
        "  - It does not read SQLite stores, JSON documents or binary session files. Those",
        "    come back as one `artifact.fs` row each, naming the path, the hash and the",
        "    timestamps, so that a store nobody has read is visible as a store nobody has",
        "    read rather than as an agent that left nothing behind.",
        "",
        "  - Some of what the suite's own analyzer reads is not read here, or is read",
        f"    only in part: {len(UNINTERPRETED)} artifacts, named in the notes below. Where",
        "    one of them is not read, a row says the file was there, with its hash and its",
        "    timestamps, and nothing about the conversation in it. Collect those files",
        "    with the Collect artifact and ingest them.",
        "",
        "  - Records carry no `event_id`. It is derived from provenance and the kind, and a",
        "    reader recomputes it, so emitting one here would only create something to",
        "    disagree with.",
    ]


def _header_notes(catalogue: Catalogue) -> list[str]:
    mapped = sorted({MAPPERS[key] for key in MAPPERS})
    covered = sorted(
        artifact.id
        for agent in agents(catalogue)
        for artifact in agent.artifacts
        if artifact.category in CATEGORIES
    )
    other = len(catalogue.artifacts) - len(covered)
    return [
        "",
        f"Scope: the {len(covered)} artifacts the catalogue files under "
        f"{' and '.join(CATEGORIES)}.",
        f"The other {other} are configuration, credentials, caches, logs and install",
        "traces. They are not left out by accident and they are not skipped for want of a",
        "glob: this artifact returns a conversation, and for a settings file or a",
        "credential store what an analyst wants is the file, which is what the Collect",
        "artifact in this same directory is for.",
        "",
        "This artifact returns rows, not files. Each row is one record of the unified",
        "agent log format; validate them against",
        "src/agentforensics/unified/agentlog.v1.schema.json.",
        "",
        f"Normalizers with a verified mapping: {', '.join(mapped)}.",
        "Every other line-delimited log is returned uninterpreted, and every other format",
        "is returned as one row per file. Both are visible in the output, never omitted.",
        "",
        "Read by the suite's own parsers and NOT interpreted here, in whole or for the",
        "paths each entry names, so for those a fleet hunt returns the file and not the",
        "conversation. Collect these and ingest them:",
        *[f"  - {key}: {reason}" for key, reason in sorted(UNINTERPRETED.items())],
        *[
            f"  - every artifact the catalogue records as {fmt}: {reason}"
            for fmt, reason in sorted(UNINTERPRETED_FORMATS.items())
        ],
        "",
        "It deliberately avoids parse_jsonl, which skips a line it cannot decode. A",
        "skipped line reads as a line that was never there, and that is the one failure",
        "this tooling must not have.",
    ]


def _parameters() -> list[str]:
    return [
        "- name: CollectionName",
        "  description: An identifier for this collection, written into every record's",
        "    provenance. Leave empty to derive one from the hostname and the current time.",
        "    Set it when several collections from one host have to be told apart.",
        "  default: ''",
        "- name: MaxFileSize",
        "  description: Do not read a file larger than this, in bytes. The file is still",
        "    reported as one row saying it was too large, because a transcript that was",
        "    skipped is not a transcript that was absent.",
        "  type: int64",
        "  default: '268435456'",
        "- name: MaxLineSize",
        "  description: The line buffer, in bytes. A transcript line carrying a large tool",
        "    output is routinely megabytes, and a line longer than this buffer stops the",
        "    scan, so the default is generous. The query reports a file whose bytes do not",
        "    add up rather than returning a partial read as if it were whole.",
        "  type: int64",
        "  default: '16777216'",
        "- name: HashFiles",
        "  description: Hash every file that is read, so a record can be shown to have come",
        "    from the file that was there. Turning this off makes a collection faster and",
        "    its records less defensible.",
        "  type: bool",
        "  default: 'Y'",
    ]


def _source(os_name: str, precondition: str, targets: list[Target]) -> str:
    lines = [
        f"- name: {os_name}",
        f"  precondition: {precondition}",
        "  query: |",
    ]
    lines.extend(f"    {line}" if line else "" for line in _query(os_name, targets))
    return "\n".join(lines)


def _query(os_name: str, targets: list[Target]) -> list[str]:
    body = [
        "-- The catalogue's globs for this platform, as data rather than as query text, so",
        "-- the query itself stays the same size whatever the catalogue grows to.",
        "LET Targets <= SELECT * FROM parse_csv(",
        "  accessor='data',",
        "  filename='''agent,artifact_id,mapper,glob",
    ]
    for target in sorted({(t.agent, t.artifact_id, t.mapper, t.glob) for t in targets}):
        body.append("  " + ",".join(target))
    body.extend(
        [
            "''')",
            "",
            "LET Me <= SELECT Hostname FROM info()",
            "",
            "-- Written into every record's provenance. Two collections from one host have",
            "-- to be distinguishable, and the operator should not have to remember to pass",
            "-- a name for that to be true.",
            "LET Collection <= if(condition=CollectionName != '',",
            "                     then=CollectionName,",
            "                     else=format(format='velociraptor-%v-%v',",
            f"                                 args=[Me[0].Hostname, {_now_expression()}]))",
            "",
            f"LET UserOf(Path) = parse_string_with_regex(string=Path, regex=['{_USER_REGEX[os_name]}'])",
            "",
            "-- One row per file the globs found. Hashed here, once, rather than per record.",
            "LET Files <= SELECT agent AS Agent, artifact_id AS ArtifactId, mapper AS Mapper,",
            "                    OSPath, Size, Mtime, Atime, Ctime, Btime, ProfileUser,",
            "                    if(condition=HashFiles AND Size <= MaxFileSize,",
            "                       then=hash(path=OSPath, hashselect=['SHA256']).SHA256,",
            "                       else='') AS FileHash,",
            "                    Size <= MaxFileSize AS Readable",
            "  FROM foreach(row=Targets, query={",
            "      SELECT agent, artifact_id, mapper, OSPath, Size, Mtime, Atime, Ctime, Btime,",
            "             UserOf(Path=OSPath.String).User AS ProfileUser",
            "      FROM glob(globs=glob, accessor='auto')",
            "      WHERE NOT IsDir",
            "    })",
            "",
            "-- Every file, once, whether or not anything could read it. For an artifact with",
            "-- no internal timestamps this is the only temporal evidence there is, and for a",
            "-- store nobody has parsed it is the difference between an agent that left",
            "-- nothing and an agent whose evidence has not been read.",
            "LET FileRows = SELECT",
            "    1 AS v, Agent AS agent, 'artifact.fs' AS kind,",
            f"    {_iso('Mtime')} AS ts_utc, 'filesystem' AS ts_precision, 'mtime' AS ts_source,",
            "    'system' AS actor, NULL AS client, Me[0].Hostname AS host,",
            "    ProfileUser AS user, NULL AS session_id, NULL AS project_path, NULL AS git_branch,",
            "    dict(files=array(a=dict(path=OSPath.String, operation='unknown', bytes=Size)),",
            f"         size=Size, mtime_utc={_iso('Mtime')}, atime_utc={_iso('Atime')},",
            f"         ctime_utc={_iso('Ctime')}, birthtime_utc={_iso('Btime')},",
            "         mapper=Mapper) AS payload,",
            "    if(condition=NOT Readable,",
            "       then='the file is larger than MaxFileSize, so its content was not read',",
            "       else=if(condition=Mapper = '" + NOT_NORMALIZED + "',",
            "               then='this format is not line-delimited JSON, so this collection "
            "reports the file and not its content',",
            "               else=NULL)) AS parse_problem,",
            "    dict(bundle_uuid=Collection, original_path=OSPath.String, sha256=FileHash,",
            "         artifact_id=ArtifactId, locator='fs') AS provenance,",
            "    dict(original_path=OSPath.String, size=Size, sha256=FileHash,",
            f"         mtime_utc={_iso('Mtime')}) AS raw,",
            f"    '{PRODUCER}' AS producer",
            "  FROM Files",
            "",
            "-- Numbering lines is a parameterised stored query for one specific reason:",
            "-- count() accumulates in the scope's aggregator context, and inside a foreach",
            "-- that context is shared, so the second file's first line would be numbered",
            "-- after the first file's last. Invoking a stored query gives a fresh context",
            "-- per call, which is the only spelling of this that numbers each file from one.",
            "-- Velociraptor's own shipped artifacts get this wrong; a locator that names the",
            "-- wrong line is worse than no locator, because it reads as a fact.",
            "--",
            "-- The blank-line filter is deliberately outside this query. count() runs after a",
            "-- WHERE in the same SELECT, so filtering here would number the records rather",
            "-- than the lines, and every locator after the first blank line would be short.",
            "LET NumberedLines(Path) = SELECT count() AS LineNumber, Line",
            "  FROM parse_lines(filename=Path, accessor='file', buffer_size=MaxLineSize)",
            "",
            "-- Lines, decoded here rather than by parse_jsonl, which skips what it cannot",
            "-- read. A line that does not decode arrives with Rec null and becomes an",
            "-- unparsed.record row further down, holding the line verbatim.",
            "LET LinesOf(Mapper_) = SELECT * FROM foreach(",
            "    row={ SELECT * FROM Files WHERE Mapper = Mapper_ AND Readable },",
            "    query={",
            "      SELECT Agent, ArtifactId, OSPath, FileHash, ProfileUser, Size,",
            "             LineNumber, Line, parse_json(data=Line) AS Rec",
            "      FROM NumberedLines(Path=OSPath)",
            "      WHERE Line != ''",
            "    })",
            "",
            "-- An agent's message content is a string in some records and a list of typed",
            "-- blocks in others, sometimes in the same file. This flattens the blocks the",
            "-- way the analyzer does and returns null rather than a guess for anything",
            "-- else, which matters more than it sounds: join() over a null list returns the",
            "-- four-character string 'Null', and a record whose text read 'Null' would be a",
            "-- fabricated value sitting in evidence. The discriminator is a block's own",
            "-- type field, because indexing a string in VQL yields a byte and would",
            "-- therefore pass any test for being indexable.",
            "LET TextOf(Content) = if(condition=Content.text,",
            "    then=join(array=Content.text, sep=''),",
            "    else=if(condition=Content[0].type, then=NULL, else=Content))",
            "",
            "-- A shell command is an argv list in some agents' records and one string in",
            "-- others. join() handles both, and is guarded because join() over a null",
            "-- returns the string 'Null', which would put a command nobody ran into the",
            "-- command facet of a case.",
            "LET CommandOf(Value) = if(condition=Value,",
            "    then=join(array=Value, sep=' '), else=NULL)",
            "",
            "-- The shared part of every record row, so eight normalizers cannot spell the",
            "-- envelope eight ways.",
            "LET Provenance(Path, Hash, ArtifactId_, Line_) = dict(",
            "    bundle_uuid=Collection, original_path=Path, sha256=Hash,",
            "    artifact_id=ArtifactId_, locator=format(format='line:%v', args=[Line_]))",
            "",
            "-- A record nothing could decode, or nothing has a verified mapping for. Its own",
            "-- normalizer so that every caller of it produces the same shape, and so that the",
            "-- rule that no record is dropped has exactly one implementation.",
            "LET Unreadable(Rows, Problem) = SELECT",
            "    1 AS v, Agent AS agent, 'unparsed.record' AS kind,",
            "    NULL AS ts_utc, 'absent' AS ts_precision, NULL AS ts_source,",
            "    'unknown' AS actor, NULL AS client, Me[0].Hostname AS host,",
            "    ProfileUser AS user, NULL AS session_id, NULL AS project_path, NULL AS git_branch,",
            "    dict() AS payload, Problem AS parse_problem,",
            "    Provenance(Path=OSPath.String, Hash=FileHash, ArtifactId_=ArtifactId,",
            "               Line_=LineNumber) AS provenance,",
            "    Line AS raw,",
            f"    '{PRODUCER}' AS producer",
            "  FROM Rows",
            "",
        ]
    )
    body.extend(_claude_transcript())
    body.extend(_claude_history())
    body.extend(_codex_rollout())
    body.extend(_codex_history())
    body.extend(_copilot_events())
    body.extend(_generic())
    body.extend(_truncation_check())
    body.extend(
        [
            "-- chain() rather than a union, which VQL does not have. Order is the order of",
            "-- the arguments; the log itself carries no ordering requirement, because every",
            "-- record stands alone and a consumer sorts by ts_utc.",
            "SELECT * FROM chain(",
            "    a=FileRows,",
            "    b=ClaudeTranscript, c=ClaudeTranscriptBad,",
            "    d=ClaudeHistory, e=ClaudeHistoryBad,",
            "    f=CodexRollout, g=CodexRolloutBad,",
            "    h=CodexHistory, i=CodexHistoryBad,",
            "    j=CopilotEvents, k=CopilotEventsBad,",
            "    l=GenericRecords,",
            "    m=Truncated)",
        ]
    )
    return body


def _now_expression() -> str:
    """The collection time, as something a record can be keyed by.

    Seconds rather than nanoseconds: the identifier goes in front of a human, and two
    collections of one host inside the same second are not a case this has to separate.
    """
    return "timestamp(epoch=now()).Unix"


def _iso(field: str) -> str:
    """A Velociraptor time as the format's own timestamp spelling.

    Velociraptor hands back a time object whose String is RFC3339 already. Taken through a
    field rather than formatted by hand so that a zero time stays a zero time instead of
    becoming a plausible-looking 1970.
    """
    return f"if(condition={field}.Unix > 0, then=timestamp(epoch={field}).UTC.String, else=NULL)"


def _if_chain(cases: Sequence[tuple[str, str]], default: str) -> str:
    """A nested VQL if() chain, from a list of (condition, result) pairs.

    Generated rather than written out because VQL has no case expression, so a mapping over
    eight record types is eight nested if() calls and eight closing parentheses in a row.
    Hand-counting those is how a generator ships a query that does not parse, which
    happened here before this function existed. The count is now arithmetic.

    The chain short-circuits in order, so a case that must be tested before another, such as
    a user record carrying a tool result being tested before user records in general, is
    expressed by putting it first.
    """
    result = default
    for condition, value in reversed(cases):
        result = f"if(condition={condition}, then={value}, else={result})"
    return result


def _envelope(
    *,
    kind: str,
    actor: str,
    ts: str,
    ts_precision: str = "'exact'",
    ts_source: str,
    payload: str,
    session: str = "NULL",
    project: str = "NULL",
    branch: str = "NULL",
    client: str = "NULL",
    problem: str = "NULL",
) -> list[str]:
    """One record row's column list, in the format's field order.

    Every normalizer goes through this, which is the only reason eight of them can be
    trusted to produce the same shape. A column added here appears in all of them; a column
    one of them spelled differently would be a silently missing field in one agent's rows.
    """
    return [
        f"    1 AS v, Agent AS agent, {kind} AS kind,",
        f"    {ts} AS ts_utc, {ts_precision} AS ts_precision, {ts_source} AS ts_source,",
        f"    {actor} AS actor, {client} AS client, Me[0].Hostname AS host,",
        f"    ProfileUser AS user, {session} AS session_id,",
        f"    {project} AS project_path, {branch} AS git_branch,",
        f"    {payload} AS payload,",
        f"    {problem} AS parse_problem,",
        "    Provenance(Path=OSPath.String, Hash=FileHash, ArtifactId_=ArtifactId,",
        "               Line_=LineNumber) AS provenance,",
        "    Rec AS raw,",
        f"    '{PRODUCER}' AS producer",
    ]


def _claude_transcript() -> list[str]:
    """Claude Code transcripts, and the three stores that share their record shape.

    Every record carries its own sessionId, cwd and gitBranch, so nothing has to be carried
    forward from a header record the way Codex and Copilot need.
    """
    return [
        "LET ClaudeLines = LinesOf(Mapper_='claude_transcript')",
        "",
        "-- A tool result arrives on a user record rather than on an assistant one, and the",
        "-- field that marks it is toolUseResult. Checked before the record type, because a",
        "-- user record carrying a tool result is not a prompt the user typed.",
        "LET ClaudeKind(Rec_) = "
        + _if_chain(
            [
                # Before the plain user case on purpose: a user record carrying a tool
                # result is not a prompt somebody typed.
                ("Rec_.type = 'user' AND Rec_.toolUseResult", "'tool.result'"),
                ("Rec_.type = 'user'", "'user.prompt'"),
                (
                    "Rec_.type = 'assistant' AND Rec_.message.stop_reason = 'refusal'",
                    "'safety.refusal'",
                ),
                ("Rec_.type = 'assistant'", "'assistant.text'"),
                ("Rec_.type = 'permission-mode'", "'permission.change'"),
                ("Rec_.type =~ '^(summary|compact|compact_boundary)$'", "'session.end'"),
                ("Rec_.type = 'system'", "'config.snapshot'"),
            ],
            "NULL",
        ),
        "",
        "LET ClaudeActor(Rec_) = "
        + _if_chain(
            [
                ("Rec_.type = 'user' AND Rec_.toolUseResult", "'tool'"),
                ("Rec_.type = 'user'", "'user'"),
                ("Rec_.type = 'assistant'", "'assistant'"),
            ],
            "'system'",
        ),
        "",
        "LET ClaudeTranscript = SELECT",
        *_envelope(
            kind="ClaudeKind(Rec_=Rec)",
            actor="ClaudeActor(Rec_=Rec)",
            ts="Rec.timestamp",
            ts_source="'timestamp'",
            session="Rec.sessionId",
            project="Rec.cwd",
            branch="Rec.gitBranch",
            client="Rec.entrypoint",
            payload="dict("
            "text=TextOf(Content=Rec.message.content), "
            "tool_calls=Rec.message.content, "
            "output=Rec.toolUseResult, "
            "models=if(condition=Rec.message.model, "
            "then=array(a=dict(model=Rec.message.model, "
            "input_tokens=Rec.message.usage.input_tokens, "
            "output_tokens=Rec.message.usage.output_tokens)), else=[]), "
            "permissions=if(condition=Rec.type = 'permission-mode', "
            "then=array(a=dict(mode=Rec.mode, previous=Rec.previousMode, scope='session')), else=[]), "
            "refusal=if(condition=Rec.message.stop_reason = 'refusal', "
            "then=Rec.message.stop_details.type || 'refusal', else=NULL), "
            "uuid=Rec.uuid, parent_uuid=Rec.parentUuid, "
            "is_sidechain=Rec.isSidechain, agent_id=Rec.agentId, "
            "version=Rec.version)",
        ),
        "  FROM ClaudeLines WHERE ClaudeKind(Rec_=Rec)",
        "",
        "-- The other half of the same set: a line that did not decode, and a record whose",
        "-- type this mapping does not know. Neither is dropped.",
        "LET ClaudeTranscriptBad = Unreadable(",
        "    Rows={ SELECT * FROM ClaudeLines WHERE NOT ClaudeKind(Rec_=Rec) },",
        "    Problem=format(format='%v',",
        "        args=['a Claude Code transcript line this collection could not map: "
        "either it did not decode as JSON, or its record type is not one this artifact "
        "knows. The line is in raw.']))",
        "",
    ]


def _claude_history() -> list[str]:
    """The prompt history file. It outlives the transcripts, which makes a prompt with no
    matching session one of the more interesting things a collection can hold."""
    return [
        "LET ClaudeHistoryLines = LinesOf(Mapper_='claude_history')",
        "",
        "LET ClaudeHistory = SELECT",
        *_envelope(
            kind="'prompt.history'",
            actor="'user'",
            # The file records milliseconds since the epoch, not an ISO string.
            ts="timestamp(epoch=Rec.timestamp / 1000).UTC.String",
            ts_precision="'second'",
            ts_source="'timestamp'",
            project="Rec.project",
            session="Rec.sessionId",
            payload="dict(text=Rec.display, pasted_contents=Rec.pastedContents)",
        ),
        "  FROM ClaudeHistoryLines WHERE Rec.display",
        "",
        "LET ClaudeHistoryBad = Unreadable(",
        "    Rows={ SELECT * FROM ClaudeHistoryLines WHERE NOT Rec.display },",
        "    Problem='a Claude Code history line with no display field, or one that did not "
        "decode as JSON. The line is in raw.')",
        "",
    ]


def _codex_rollout() -> list[str]:
    """Codex rollouts.

    Unlike Claude Code, only the first record carries the working directory and the model,
    so those are read once per file and applied to the rest. Without that the working
    directory would be absent from every record but the first, which is the field an analyst
    asks about most.
    """
    return [
        "LET CodexLines = LinesOf(Mapper_='codex_rollout')",
        "",
        "-- session_meta is the first record of a rollout and the only one that names the",
        "-- working directory. Read once per file and joined on, rather than left null on",
        "-- every record after the first.",
        "LET CodexMeta <= SELECT OSPath.String AS Path,",
        "                        Rec.payload.id AS SessionId,",
        "                        Rec.payload.cwd AS Cwd,",
        "                        Rec.payload.git.branch AS Branch,",
        "                        Rec.payload.model AS Model,",
        "                        Rec.payload.originator AS Originator",
        "  FROM CodexLines WHERE Rec.type = 'session_meta'",
        "",
        "LET CodexMetaFor(Path_) = SELECT * FROM CodexMeta WHERE Path = Path_ LIMIT 1",
        "",
        "-- Joined once per record rather than once per column. A stored query copies the",
        "-- scope on every call, so reading five fields through five calls copied the scope",
        "-- five times per line of every transcript, which vfilter itself warns about once",
        "-- the copies pile up.",
        "LET CodexRecords = SELECT *, CodexMetaFor(Path_=OSPath.String)[0] AS Meta",
        "  FROM CodexLines",
        "",
        "-- event_msg mirrors response_item: mapping both would double every turn. Counted",
        "-- in the payload of the record it duplicates rather than emitted as a turn of its",
        "-- own, so the records stay accounted for and the conversation stays honest.",
        "LET CodexKind(Rec_) = "
        + _if_chain(
            [
                ("Rec_.type = 'session_meta'", "'session.start'"),
                ("Rec_.type = 'compacted'", "'session.end'"),
                ("Rec_.type = 'turn_context'", "'config.snapshot'"),
                # Reported rather than mapped as a turn. It mirrors a response_item, so a
                # producer that mapped both would double every turn in the conversation.
                ("Rec_.type = 'event_msg'", "'config.snapshot'"),
                (
                    "Rec_.type = 'response_item' AND Rec_.payload.type = 'message' "
                    "AND Rec_.payload.role = 'user'",
                    "'user.prompt'",
                ),
                (
                    "Rec_.type = 'response_item' AND Rec_.payload.type = 'message'",
                    "'assistant.text'",
                ),
                (
                    "Rec_.type = 'response_item' AND Rec_.payload.type = 'reasoning'",
                    "'assistant.thinking'",
                ),
                (
                    "Rec_.type = 'response_item' AND Rec_.payload.type =~ "
                    "'^(local_shell_call|custom_tool_call|function_call)$'",
                    "'tool.call'",
                ),
                (
                    "Rec_.type = 'response_item' AND Rec_.payload.type =~ "
                    "'^(function_call_output|custom_tool_call_output)$'",
                    "'tool.result'",
                ),
            ],
            "NULL",
        ),
        "",
        "LET CodexActor(Rec_) = "
        + _if_chain(
            [
                ("Rec_.payload.role = 'user'", "'user'"),
                ("Rec_.type = 'response_item'", "'assistant'"),
            ],
            "'system'",
        ),
        "",
        "LET CodexRollout = SELECT",
        *_envelope(
            kind="CodexKind(Rec_=Rec)",
            actor="CodexActor(Rec_=Rec)",
            ts="Rec.timestamp",
            ts_source="'timestamp'",
            session="Meta.SessionId",
            project="Meta.Cwd",
            branch="Meta.Branch",
            client="'codex-cli'",
            payload="dict("
            "text=TextOf(Content=Rec.payload.content) || TextOf(Content=Rec.payload.summary) || Rec.payload.message, "
            "tool=Rec.payload.name, "
            "tool_use_id=Rec.payload.call_id, "
            "input=Rec.payload.arguments || Rec.payload.action, "
            "output=Rec.payload.output, "
            "commands=if(condition=Rec.payload.action.command, "
            "then=array(a=dict(command=CommandOf(Value=Rec.payload.action.command), "
            "cwd=Rec.payload.action.workdir)), else=[]), "
            "models=if(condition=Meta.Model, "
            "then=array(a=dict(model=Meta.Model)), else=[]), "
            "compaction=Rec.type = 'compacted', "
            "mirrored_event_msg=Rec.type = 'event_msg', "
            "item_type=Rec.payload.type)",
        ),
        "  FROM CodexRecords WHERE CodexKind(Rec_=Rec)",
        "",
        "LET CodexRolloutBad = Unreadable(",
        "    Rows={ SELECT * FROM CodexLines WHERE NOT CodexKind(Rec_=Rec) },",
        "    Problem='a Codex rollout line this collection could not map: either it did not "
        "decode as JSON, or its record or item type is not one this artifact knows. The line "
        "is in raw.')",
        "",
    ]


def _codex_history() -> list[str]:
    return [
        "LET CodexHistoryLines = LinesOf(Mapper_='codex_history')",
        "",
        "LET CodexHistory = SELECT",
        *_envelope(
            kind="'prompt.history'",
            actor="'user'",
            ts="timestamp(epoch=Rec.ts).UTC.String",
            ts_precision="'second'",
            ts_source="'ts'",
            session="Rec.session_id",
            client="'codex-cli'",
            payload="dict(text=Rec.text)",
        ),
        "  FROM CodexHistoryLines WHERE Rec.text",
        "",
        "LET CodexHistoryBad = Unreadable(",
        "    Rows={ SELECT * FROM CodexHistoryLines WHERE NOT Rec.text },",
        "    Problem='a Codex history line with no text field, or one that did not decode "
        "as JSON. The line is in raw.')",
        "",
    ]


def _copilot_events() -> list[str]:
    """The Copilot CLI event log.

    The session id is the name of the directory the file sits in, not a field in the
    records, so it is read off the path. Without it two sessions in one collection would be
    indistinguishable.
    """
    return [
        "LET CopilotLines = LinesOf(Mapper_='copilot_events')",
        "",
        "-- .../session-state/<id>/events.jsonl. The directory name is the session id.",
        "LET CopilotSession(Path) = parse_string_with_regex(string=Path,",
        "    regex=['session-state[/\\\\\\\\](?P<Session>[^/\\\\\\\\]+)[/\\\\\\\\]']).Session",
        "",
        "-- session.start names the model and the working directory once. Read per file for",
        "-- the same reason as the Codex header record.",
        "LET CopilotMeta <= SELECT OSPath.String AS Path, Rec.data.cwd AS Cwd,",
        "                          Rec.data.copilotVersion AS Version",
        "  FROM CopilotLines WHERE Rec.type = 'session.start'",
        "",
        "LET CopilotMetaFor(Path_) = SELECT * FROM CopilotMeta WHERE Path = Path_ LIMIT 1",
        "",
        "-- One lookup per record, for the same reason as the Codex join above.",
        "LET CopilotRecords = SELECT *, CopilotMetaFor(Path_=OSPath.String)[0] AS Meta,",
        "                            CopilotSession(Path=OSPath.String) AS SessionFromPath",
        "  FROM CopilotLines",
        "",
        "LET CopilotKind(Rec_) = "
        + _if_chain(
            [
                ("Rec_.type = 'session.start'", "'session.start'"),
                ("Rec_.type = 'user.message'", "'user.prompt'"),
                ("Rec_.type = 'assistant.message'", "'assistant.text'"),
                # The MCP case first: a tool call routed through a server is both, and the
                # server is the fact an analyst is asking about.
                (
                    "Rec_.type = 'tool.execution_start' AND Rec_.data.mcpServerName",
                    "'mcp.call'",
                ),
                ("Rec_.type = 'tool.execution_start'", "'tool.call'"),
                ("Rec_.type = 'tool.execution_complete'", "'tool.result'"),
                ("Rec_.type =~ '^session\\\\.(model_change|config)'", "'config.snapshot'"),
                # A subagent is a session of its own, and its work may never appear in this
                # file, so the log has to say to look elsewhere.
                ("Rec_.type =~ '^subagent\\\\.'", "'session.start'"),
                (
                    "Rec_.type =~ '^tool\\\\.(confirmation|permission)'",
                    "'permission.decision'",
                ),
            ],
            "NULL",
        ),
        "",
        "LET CopilotActor(Rec_) = "
        + _if_chain(
            [
                ("Rec_.type = 'user.message'", "'user'"),
                ("Rec_.type =~ '^assistant\\\\.'", "'assistant'"),
                ("Rec_.type =~ '^tool\\\\.'", "'tool'"),
            ],
            "'system'",
        ),
        "",
        "LET CopilotEvents = SELECT",
        *_envelope(
            kind="CopilotKind(Rec_=Rec)",
            actor="CopilotActor(Rec_=Rec)",
            ts="Rec.timestamp",
            ts_source="'timestamp'",
            session="SessionFromPath",
            project="Meta.Cwd",
            client="'copilot-cli'",
            payload="dict("
            "text=TextOf(Content=Rec.data.content) || Rec.data.message, "
            "tool=Rec.data.toolName, "
            "tool_use_id=Rec.data.toolCallId, "
            "input=Rec.data.arguments, "
            "output=Rec.data.result, "
            "is_error=Rec.data.success = false, "
            "mcp=if(condition=Rec.data.mcpServerName, "
            "then=array(a=dict(server=Rec.data.mcpServerName, tool=Rec.data.mcpToolName)), else=[]), "
            "commands=if(condition=Rec.data.arguments.command, "
            "then=array(a=dict(command=CommandOf(Value=Rec.data.arguments.command))), else=[]), "
            "models=if(condition=Rec.data.newModel, "
            "then=array(a=dict(model=Rec.data.newModel)), else=[]), "
            "permissions=if(condition=Rec.data.decision, "
            "then=array(a=dict(decision=Rec.data.decision, subject=Rec.data.toolName)), else=[]), "
            "subagent=Rec.data.agentName, "
            "version=Meta.Version, "
            "event_type=Rec.type)",
        ),
        "  FROM CopilotRecords WHERE CopilotKind(Rec_=Rec)",
        "",
        "LET CopilotEventsBad = Unreadable(",
        "    Rows={ SELECT * FROM CopilotLines WHERE NOT CopilotKind(Rec_=Rec) },",
        "    Problem='a Copilot CLI event line this collection could not map: either it did "
        "not decode as JSON, or its event type is not one this artifact knows. The line is "
        "in raw.')",
        "",
    ]


def _generic() -> list[str]:
    """Every other line-delimited agent log.

    Emitted as uninterpreted records rather than guessed at. A mapping invented for a
    format nobody has verified against its vendor is the same defect as an invented
    catalogue path: it produces output that looks like an answer. What is claimed here is
    only what the record literally says: a field named `timestamp`, `ts` or `createdAt` is a
    time, and a field named `text` or `content` holding a string is text. Everything else
    stays in raw for a human to read.
    """
    return [
        "LET GenericLines = LinesOf(Mapper_='" + GENERIC + "')",
        "",
        "LET GenericRecords = SELECT",
        "    1 AS v, Agent AS agent, 'unparsed.record' AS kind,",
        "    Rec.timestamp || Rec.ts || Rec.createdAt || Rec.time AS ts_utc,",
        "    if(condition=Rec.timestamp || Rec.ts || Rec.createdAt || Rec.time,",
        "       then='second', else='absent') AS ts_precision,",
        "    if(condition=Rec.timestamp || Rec.ts || Rec.createdAt || Rec.time,",
        "       then='a field the record names as a time', else=NULL) AS ts_source,",
        "    'unknown' AS actor, NULL AS client, Me[0].Hostname AS host,",
        "    ProfileUser AS user, Rec.sessionId || Rec.session_id AS session_id,",
        "    Rec.cwd || Rec.workspace AS project_path, NULL AS git_branch,",
        "    dict(text=TextOf(Content=Rec.text) || TextOf(Content=Rec.content)) AS payload,",
        "    format(format='%v: this collection has no verified mapping for this agent",
        " log format, so the record is returned uninterpreted. Everything it contained is",
        " in raw. Re-read this log with the suite analyzer once a parser exists.',",
        "           args=[ArtifactId]) AS parse_problem,",
        "    Provenance(Path=OSPath.String, Hash=FileHash, ArtifactId_=ArtifactId,",
        "               Line_=LineNumber) AS provenance,",
        "    Rec || Line AS raw,",
        f"    '{PRODUCER}' AS producer",
        "  FROM GenericLines",
        "",
    ]


def _truncation_check() -> list[str]:
    """The query checking its own reading.

    parse_lines is a buffered scanner: a line longer than its buffer ends the scan, and the
    rest of the file is simply not in the results. Agent transcripts carry multi-megabyte
    lines whenever a tool output was large, so this is a routine case rather than an edge
    one. Comparing the bytes read against the file's size is the only way the query can tell
    that it read a whole file, and a collection that returned half a transcript as though it
    were whole would be worse than one that failed outright.
    """
    return [
        "-- Through NumberedLines, the same reading path the normalizers use, so this",
        "-- measures the read that actually happened rather than a second one that might",
        "-- differ. max() over the line number rather than count(), because the number is",
        "-- already per file and does not depend on how the aggregator is scoped.",
        "LET BytesRead <= SELECT Path, Agent, ArtifactId, FileHash, ProfileUser, Size,",
        "                        max(item=LineNumber) AS Lines,",
        "                        sum(item=len(list=Line)) AS Bytes",
        # ruff reads the VQL below as SQL. It is VQL, and the interpolated value is a
        # module constant naming a normalizer, never anything a caller supplies.
        f"  FROM foreach(row={{ SELECT * FROM Files WHERE Mapper != '{NOT_NORMALIZED}'",  # noqa: S608
        "                       AND Readable },",
        "               query={",
        "      SELECT OSPath.String AS Path, Agent, ArtifactId, FileHash, ProfileUser, Size,",
        "             LineNumber, Line",
        "      FROM NumberedLines(Path=OSPath)",
        "    })",
        "  GROUP BY Path",
        "",
        "-- Bytes plus one newline per line is the whole file. A shortfall larger than that",
        "-- means the scan stopped early, which is a hole in the evidence and has to be a",
        "-- record in the log rather than a line in a collection log nobody reads.",
        "LET Truncated = SELECT",
        "    1 AS v, Agent AS agent, 'unparsed.record' AS kind,",
        "    NULL AS ts_utc, 'absent' AS ts_precision, NULL AS ts_source,",
        "    'system' AS actor, NULL AS client, Me[0].Hostname AS host,",
        "    ProfileUser AS user, NULL AS session_id, NULL AS project_path, NULL AS git_branch,",
        "    dict(size=Size, bytes_read=Bytes, lines_read=Lines) AS payload,",
        "    format(format='this collection read %v of %v bytes of this file in %v lines and",
        " then stopped. A line longer than MaxLineSize ends the scan, so the rest of the file",
        " is not in these results. Raise MaxLineSize and collect again.',",
        "           args=[Bytes + Lines, Size, Lines]) AS parse_problem,",
        "    dict(bundle_uuid=Collection, original_path=Path, sha256=FileHash,",
        "         artifact_id=ArtifactId, locator=format(format='line:%v', args=[Lines]))",
        "      AS provenance,",
        "    dict(original_path=Path, size=Size, bytes_read=Bytes, lines_read=Lines) AS raw,",
        f"    '{PRODUCER}' AS producer",
        "  FROM BytesRead WHERE Bytes + Lines < Size",
        "",
    ]


__all__ = [
    "ARTIFACT",
    "CATEGORIES",
    "FORBIDDEN_IN_DATA_BLOCK",
    "GENERIC",
    "MAPPERS",
    "NOT_NORMALIZED",
    "PRODUCER",
    "PRODUCER_VERSION",
    "UnsafeTarget",
    "render",
]
