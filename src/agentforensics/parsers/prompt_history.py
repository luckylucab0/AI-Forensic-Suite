"""Read the files that hold what a person typed at an agent's prompt.

A prompt history is the line-editor's recall file: the thing arrow-up walks through. It is
not a transcript and it does not know what the agent answered, which is exactly why it is
worth reading. These files are append-only, they live outside the transcript store, and
several of them survive a retention sweep or a deleted conversation, so a prompt here with
no session anywhere in the case is one of the more interesting things a collection can
hold. Until this module they were collected and never read.

Three files, three formats, one event kind. The formats are not a family and reading them
as one would lose content in two of the three, so each is read the way its own library
writes it.

**aider** uses prompt_toolkit's `FileHistory`. Every entry is written as a blank line, then
`# <timestamp>`, then one `+`-prefixed line per line of the entry. Reading it back, a line
starting with `+` contributes the rest of itself and anything else ends the entry, which is
how a multi-line prompt survives in a line-oriented file. Source, fetched and read:
https://raw.githubusercontent.com/prompt-toolkit/python-prompt-toolkit/master/src/prompt_toolkit/history.py
The timestamp is `datetime.now()`, so it is the endpoint's local time with no zone on it.
It is read the way this suite reads every naive timestamp, as UTC with the note saying so,
because the alternatives are to drop the record or to apply the analyst's own zone.
A line that is neither content, a stamp nor blank is not something that library writes, so a
run of them is reported rather than only closing the entry above it, and a file with no
content line anywhere is reported as holding no prompt in this format. Both statements exist
because the alternative is silence, and silence about a prompt history reads as a person who
never typed anything.

**Amazon Q's chat prompt history** is a rustyline file, and rustyline has two formats. A
file whose first line is `#V2` is the multiline-aware one: every later line is one entry
with `\\n` standing for a line feed and `\\\\` for a backslash. A file without that header is
the older one, where a line is an entry and nothing is escaped. Source, fetched and read:
https://raw.githubusercontent.com/kkawakam/rustyline/master/src/history.rs
Getting this wrong is silent in both directions: reading a v2 file as plain text shows a
multi-line prompt as one line with visible escapes and files the `#V2` header itself as a
prompt, and unescaping an old file corrupts any prompt that contained a backslash.

**ollama** writes one line per entry with no escaping and no timestamps at all, from its
own readline package. Source, cited by the catalogue entry and read there:
https://raw.githubusercontent.com/ollama/ollama/main/readline/history.go
The file is a ring with a default limit of 100 entries, so an absent early prompt is the
ring rather than a deletion. That limit is in the catalogue entry, where an analyst reading
the artifact list finds it.

What this module does not do is decide what a prompt meant. A line that begins with a slash
is the first token as the person typed it and is carried as such; whether that command ran
anything is a question for the agent's own records.
"""

from __future__ import annotations

from collections.abc import Iterator

from agentforensics.model import Event
from agentforensics.parsers.base import (
    NO_RECORD,
    ParseContext,
    TextLine,
    normalise_ts,
    text_lines,
    unreadable_lines,
)

# rustyline writes this as the first line of a file whose entries are escaped.
RUSTYLINE_V2 = "#V2"

# Which reading each artifact gets. Named rather than sniffed: the format is a property of
# the program that wrote the file, the catalogue says which program that is, and a reader
# that guessed from the content would eventually guess wrong on a prompt that happened to
# start with a hash.
SHAPES = {
    "aider.input_history": "prompt_toolkit",
    "amazonq.cli_prompt_history": "rustyline",
    "goose.command_history": "rustyline",
    "ollama.cli_prompt_history": "plain",
}

# The histories that sit in the working copy rather than in a profile. The vendor builds
# the path by joining the file name to the repository root, so the directory holding it is
# the project the prompts were typed in. That is the only project attribution these files
# carry, and it is worth having: a prompt history in a repository says which repository.
IN_THE_PROJECT = frozenset({"aider.input_history"})


# Said on a run of lines in an aider history that is neither an entry nor the header of
# one. prompt_toolkit writes three shapes and only three: a blank line, a `# ` stamp, and a
# `+` line per line of the prompt. Anything else was not written by the library that owns
# the file, so it is a partial write, a file somebody edited, or another program appending
# to it, and all three are worth a sentence. This reader used to let such a line close the
# open entry and say nothing about the line itself.
STRAY = (
    "these lines are neither an entry nor the header of one: this format writes an entry "
    "as a '# ' stamp and then one '+' line per line of the prompt, and a line that is "
    "neither ends whatever entry was open. They are kept here because the library that "
    "writes this file does not produce them"
)

# How this format announces the content of an entry, for the sentence a file with none of
# it gets.
MARKER = "begins with '+', which is how every line of every entry in this format begins"


class PromptHistoryParser:
    """The line-editor recall files, each read the way its own library writes it."""

    name = "prompt_history"

    def handles(self, artifact_id: str | None) -> bool:
        return artifact_id in SHAPES

    def parse(self, context: ParseContext) -> Iterator[Event]:
        shape = SHAPES[str(context.artifact_id)]
        lines = list(text_lines(context.local_path))
        if shape == "prompt_toolkit":
            yield from _prompt_toolkit(context, lines)
        elif shape == "rustyline":
            yield from _rustyline(context, lines)
        else:
            yield from _plain(context, lines)


def _event(
    context: ParseContext,
    number: int,
    text: str,
    *,
    when: str | None = None,
    precision: str = "absent",
    source: str | None = None,
    note: str | None = None,
) -> Event:
    """One prompt, as it was typed."""
    first = text.split("\n", 1)[0].strip()
    return Event(
        kind="prompt.history",
        provenance=context.provenance(f"line:{number}"),
        agent=context.agent,
        raw={"text": text},
        ts_utc=when,
        ts_precision=precision,  # type: ignore[arg-type]
        ts_source=source if when else None,
        actor="user",
        user=context.user,
        host=context.host,
        # The directory the file sits in, where the vendor puts the file in the repository
        # root. Not derived for a history in a profile: there the file says nothing about
        # which project a prompt belonged to, and guessing would attribute prompts to
        # whichever project happened to be open.
        project_path=(
            context.original_path.rsplit("/", 1)[0]
            if context.artifact_id in IN_THE_PROJECT and "/" in context.original_path
            else None
        ),
        payload={
            "text": text,
            # The first token as typed, where the person typed a slash command. It is what
            # the line says and not a claim that anything ran: what a command did is in the
            # agent's own records, if it kept any.
            "typed_command": first.split()[0] if first.startswith("/") and first.split() else None,
        },
        parse_problem=note,
    )


def _prompt_toolkit(context: ParseContext, lines: list[TextLine]) -> Iterator[Event]:
    """prompt_toolkit's FileHistory: `# <timestamp>` and then `+`-prefixed content lines.

    The entry is ended by any line that does not start with `+`, which is the library's own
    rule, so a stamp, a blank line or a corrupted line all close one. An entry with no stamp
    in front of it is still an entry: the file can begin part way through after a rotation
    or a partial copy, and dropping the prompt because its header is missing would lose the
    record over its metadata.
    """
    pending: list[str] = []
    problems: list[str] = []
    start = 0
    stamp: str | None = None
    # A run of lines this format does not contain, held until the run ends so that it is
    # one statement about a damaged region rather than one per line.
    stray: list[TextLine] = []
    reported = 0
    # Whether there is an entry anywhere in this file, read before the file is walked. It
    # decides which sentence a run of lines that is not an entry gets, and the two are
    # different findings: lines around entries are a damaged region in a history, and the
    # same lines with no entry anywhere mean the file at this path is not a history at all.
    # Knowable in advance because the reader holds the whole file, and worth knowing in
    # advance because the first run is reported before the last entry has been met.
    any_entry = any(line.text.startswith("+") for line in lines)

    def flush() -> Iterator[Event]:
        if not pending:
            return
        when, precision, note = normalise_ts(stamp)
        yield _event(
            context,
            start,
            "\n".join(pending),
            when=when,
            precision=precision,
            source="the history file's own header" if when else None,
            # Whatever was wrong with reading the lines this entry was built from travels
            # with the entry. A prompt assembled out of a line that did not decode is not
            # the prompt that was typed, and nothing else in the case would say so.
            note=" ".join([part for part in [note, *problems] if part]) or None,
        )

    def strays() -> Iterator[Event]:
        """Whatever has been held, in the place in the file where it sits."""
        nonlocal stray, reported
        if stray:
            reported += 1
            yield from unreadable_lines(context, stray, STRAY if any_entry else _nothing(lines))
            stray = []

    for line in lines:
        if line.text.startswith("+"):
            # Before the entry, so the events leave this reader in the order the file has
            # them and a locator read downwards still walks forwards through the file.
            yield from strays()
            if not pending:
                start = line.number
            pending.append(line.text[1:])
            if line.problem:
                problems.append(line.problem)
            continue
        yield from flush()
        pending = []
        problems = []
        # Only a `# ` line is a stamp. Every other non-content line simply ends the entry,
        # which is what the library does with it.
        stamp = line.text[1:].strip() if line.text.startswith("#") else None
        if line.text.startswith("#") or not line.text.strip():
            yield from strays()
        else:
            stray.append(line)
    yield from flush()
    yield from strays()
    if not any_entry and not reported:
        # No entry and nothing stray either, which leaves a file of stamps and blank lines:
        # readable, in this format, and holding no prompt. Silence for it would read as an
        # agent nobody typed at.
        yield from unreadable_lines(context, lines, _nothing(lines))


def _nothing(lines: list[TextLine]) -> str:
    """The sentence for a file at this path that holds no entry of this format."""
    return NO_RECORD.format(what="an aider prompt history", lines=len(lines), marker=MARKER)


def _rustyline(context: ParseContext, lines: list[TextLine]) -> Iterator[Event]:
    """A rustyline history, in whichever of its two formats this file is in."""
    v2 = bool(lines) and lines[0].text == RUSTYLINE_V2
    for index, line in enumerate(lines):
        if v2 and index == 0:
            continue
        if not line.text:
            # The vendor's reader skips an empty line rather than storing an empty entry.
            continue
        text, note = _unescape(line.text) if v2 else (line.text, None)
        yield _event(
            context, line.number, text, note=" ".join(p for p in (line.problem, note) if p) or None
        )


def _unescape(text: str) -> tuple[str, str | None]:
    """A v2 entry, with the two escapes rustyline writes turned back into their characters.

    A backslash before anything else is not something the writer produces. The vendor's own
    reader gives up on the line and keeps it exactly as written, so this does the same and
    says so: an entry that was tampered with, or written by something else, is evidence in
    the state it is in rather than in a repaired one.
    """
    if "\\" not in text:
        return text, None
    out: list[str] = []
    rest = text
    while (index := rest.find("\\")) >= 0:
        out.append(rest[:index])
        escaped = rest[index + 1 : index + 2]
        if escaped == "n":
            out.append("\n")
        elif escaped == "\\":
            out.append("\\")
        else:
            return (
                text,
                "this line carries a backslash before something other than n or a "
                "backslash, which the writer of this format does not produce, so it is "
                "kept exactly as it is on disk rather than unescaped",
            )
        rest = rest[index + 2 :]
    out.append(rest)
    return "".join(out), None


def _plain(context: ParseContext, lines: list[TextLine]) -> Iterator[Event]:
    """One line, one entry, nothing escaped and no times anywhere in the file."""
    for line in lines:
        if not line.text.strip():
            continue
        yield _event(context, line.number, line.text, note=line.problem)
