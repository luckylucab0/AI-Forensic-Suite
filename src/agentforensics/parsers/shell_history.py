"""Read the shell's own record of what was typed, which is where an agent's start line is.

The brief's first question about an agent is how it was invoked and with which flags, and
the answer is almost never inside the agent: the flag that switched the approvals off, the
environment variable that moved the configuration directory and the credential handed to a
tool on its command line are all in the shell's history file and nowhere else. Four such
files are in the catalogue and until this module all four were collected and none of them
was read, so a rule about a start line had nothing to match against in a real collection.

Four files, four formats, one event kind. They are not a family, and reading them as one
would lose content in three of the four.

**zsh** writes `: <start>:<elapsed>;<command>` per entry when EXTENDED_HISTORY is on and a
bare command line when it is not, and it ends a line with a backslash to say the command
continues on the next one. Both shapes appear in the same file, because the option can be
turned on at any point in a profile's life. A command that contains a byte above 0x7f is
metafied on the way out (0x83 followed by the byte with bit 5 flipped), which this reader
does not undo: the entry is carried as written, because inventing the original bytes would
put a command in the case that nobody can verify against the file.

**bash** writes one line per command, with `#<epoch>` on its own line in front of each one
only when HISTTIMEFORMAT was set. There is no escaping at all, so a command that spanned
several lines is several lines here, indistinguishable from several commands, and this
reader does not guess: each line is one entry. Source, fetched and read:
https://www.gnu.org/software/bash/manual/bash.html

**fish** writes a YAML-shaped record per entry, `- cmd:` then `when:`, an optional
`added_when:` and an optional `paths:` list, and escapes backslash and newline inside cmd.
`when` is the epoch of the last add and `added_when` of the first, so a command that was
run again carries both and a command that was typed once does not. It is read by hand rather than
with a YAML parser, because the format is fish's own and a strict parser refuses files a
fish still reads. Source, fetched and read:
https://raw.githubusercontent.com/fish-shell/fish-shell/master/doc_src/language.rst

**PSReadLine** writes plain lines with no timestamp anywhere in the file, and continues a
multi-line entry with a trailing backtick, which is PowerShell's line continuation.

Two agents keep a fifth file that is not a shell's history but their own: the commands the
agent itself ran through its shell tool, one per line, oldest first. Its quirks come from
the vendor's own reader and writer, and all three matter to an analyst. A line ending in an
odd number of backslashes continues on the next line, and the vendor rejoins the two with a
space rather than a line break, so this reader does the same. The file is a ring of a
hundred entries. And a command that is run again is REMOVED from its old position and added
at the end, so the file holds one line per distinct command and says nothing about how
often it ran; an analyst counting invocations there would undercount every repeated one.
Source, fetched and read:
https://raw.githubusercontent.com/google-gemini/gemini-cli/main/packages/cli/src/ui/hooks/useShellHistory.ts

What this module does not do is decide what a command did. A line here is what somebody
typed, or what a script typed, and not proof that it ran or that it succeeded: a history
file records submission. The exit status is in none of these formats except fish's, which
does not carry it either, so no event claims one.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from agentforensics.model import Event
from agentforensics.parsers.base import (
    ParseContext,
    TextLine,
    first_word,
    normalise_ts,
    text_lines,
)

# Which reading each artifact gets. Named rather than sniffed, for the reason the prompt
# history module gives: the format is a property of the program that wrote the file, the
# catalogue says which program that is, and a reader guessing from content would eventually
# meet a command that begins with a hash.
SHAPES = {
    "crosscutting.shell_bash_history": "bash",
    "crosscutting.shell_fish_history": "fish",
    "crosscutting.shell_psreadline_history": "psreadline",
    "crosscutting.shell_zsh_history": "zsh",
    # The agent's own shell tool rather than a shell: one product and the fork of it that
    # inherited the code, so the reading is the same for both.
    "gemini_cli.shell_history": "agent_recall",
    "qwen_code.shell_history": "agent_recall",
}

# Said on every entry from a file that carries no time. It is not a defect and it is not an
# absence of evidence: the format has no field for it, and an analyst who sees an undated
# command needs to know which of the two it is before reaching for the file's mtime.
NO_TIME = (
    "this history format stores no time for an entry, so the event is undated and the only "
    "clock for it is the file's own timestamps and the order of the lines"
)


class ShellHistoryParser:
    """The four shell history files, each read the way its own shell writes it."""

    name = "shell_history"

    def handles(self, artifact_id: str | None) -> bool:
        return artifact_id in SHAPES

    def parse(self, context: ParseContext) -> Iterator[Event]:
        shape = SHAPES[str(context.artifact_id)]
        lines = list(text_lines(context.local_path))
        if shape == "zsh":
            yield from _zsh(context, lines)
        elif shape == "bash":
            yield from _bash(context, lines)
        elif shape == "fish":
            yield from _fish(context, lines)
        elif shape == "agent_recall":
            yield from _agent_recall(context, lines)
        else:
            yield from _plain(context, lines)


def _event(
    context: ParseContext,
    number: int,
    command: str,
    *,
    when: str | None = None,
    precision: str = "absent",
    source: str | None = None,
    note: str | None = None,
    extra: dict[str, Any] | None = None,
    raw: dict[str, Any] | None = None,
) -> Event:
    """One line of history, as an execution record with the shell's own fields kept.

    `commands` is a list of one, which is the shape every other parser in this suite uses
    for a command, so a rule written against a transcript's tool call matches a shell line
    without knowing which it is reading.
    """
    entry: dict[str, Any] = {"command": command, "executable": first_word(command)}
    entry.update(extra or {})
    return Event(
        kind="command.exec",
        provenance=context.provenance(f"line:{number}"),
        agent=context.agent,
        raw=raw if raw is not None else {"command": command},
        ts_utc=when,
        ts_precision=precision,  # type: ignore[arg-type]
        ts_source=source if when else None,
        # Everything in these files was submitted at a prompt. A line written by a script
        # is still the user's shell submitting it, and nothing in the file tells the two
        # apart, so the actor is not narrowed further than that.
        actor="user",
        user=context.user,
        host=context.host,
        payload={"text": command, "commands": [entry]},
        parse_problem=note,
    )


def _zsh(context: ParseContext, lines: list[TextLine]) -> Iterator[Event]:
    """Extended and plain entries in one file, with backslash continuation."""
    pending: list[str] = []
    problems: list[str] = []
    start = 0
    stamp: Any = None
    elapsed: Any = None

    def flush() -> Iterator[Event]:
        if not pending:
            return
        command = "\n".join(pending)
        when, precision, note = normalise_ts(stamp) if stamp is not None else (None, "absent", None)
        yield _event(
            context,
            start,
            command,
            when=when,
            precision=precision,
            source="the extended history entry's own start time" if when else None,
            note=" ".join([part for part in [note, *problems] if part])
            or (None if when else NO_TIME),
            # The seconds the command ran for, which only the extended format has. Kept
            # because a long-running command is how an agent session shows up in a history
            # that has no other record of it.
            extra={"duration_s": elapsed} if elapsed is not None else None,
            raw={"command": command, "start_time": stamp, "elapsed_s": elapsed},
        )

    for line in lines:
        if pending:
            # A continuation of the entry above, which ended with a backslash.
            pending[-1] = pending[-1][:-1]
            pending.append(line.text)
            if line.problem:
                problems.append(line.problem)
            if not line.text.endswith("\\"):
                yield from flush()
                pending, problems = [], []
            continue
        if not line.text.strip():
            continue
        start = line.number
        stamp, elapsed, text = _zsh_fields(line.text)
        pending = [text]
        problems = [line.problem] if line.problem else []
        if not text.endswith("\\"):
            yield from flush()
            pending, problems = [], []
    yield from flush()


def _zsh_fields(text: str) -> tuple[Any, Any, str]:
    """Split `: <start>:<elapsed>;<command>` and leave a plain line alone.

    A command can itself begin with a colon, `: > file` being the shortest way to truncate
    one, so the shape is checked in full rather than by the first character: the header is
    a colon, digits, a colon, digits and a semicolon, and anything else is the command.
    """
    if not text.startswith(":"):
        return None, None, text
    head, _, rest = text[1:].partition(";")
    start, _, seconds = head.strip().partition(":")
    if not start.strip().isdigit() or not seconds.strip().isdigit():
        return None, None, text
    return int(start.strip()), int(seconds.strip()), rest


def _bash(context: ParseContext, lines: list[TextLine]) -> Iterator[Event]:
    """One command per line, dated only by a `#<epoch>` line in front of it."""
    stamp: int | None = None
    for line in lines:
        text = line.text
        if not text.strip():
            continue
        if text.startswith("#") and text[1:].strip().isdigit():
            stamp = int(text[1:].strip())
            continue
        when, precision, note = normalise_ts(stamp) if stamp is not None else (None, "absent", None)
        yield _event(
            context,
            line.number,
            text,
            when=when,
            precision=precision,
            source="the timestamp line written in front of the command" if when else None,
            note=" ".join([part for part in [note, line.problem] if part])
            or (None if when else NO_TIME),
            raw={"command": text, "timestamp": stamp},
        )
        # A stamp belongs to the one command behind it. Carrying it forward would date
        # every later command in a file where HISTTIMEFORMAT was set for one session only.
        stamp = None


def _fish(context: ParseContext, lines: list[TextLine]) -> Iterator[Event]:
    """fish's own record shape, read by hand rather than as YAML."""
    command: str | None = None
    when: Any = None
    added: Any = None
    paths: list[str] = []
    start = 0
    problems: list[str] = []

    def flush() -> Iterator[Event]:
        if command is None:
            return
        moment, precision, note = normalise_ts(when) if when is not None else (None, "absent", None)
        yield _event(
            context,
            start,
            command,
            when=moment,
            precision=precision,
            source="the record's own when field" if moment else None,
            note=" ".join([part for part in [note, *problems] if part])
            or (None if moment else NO_TIME),
            # The files fish itself associated with the command, which it records so that
            # its own history search can offer them. They are the shell's reading of the
            # line rather than files anything is known to have touched, so they travel
            # beside the command rather than as a file facet.
            extra={"fish_paths": list(paths)} if paths else None,
            raw={"cmd": command, "when": when, "added_when": added, "paths": list(paths)},
        )

    in_paths = False
    for line in lines:
        text = line.text
        if text.startswith("- cmd:"):
            yield from flush()
            command = _fish_unescape(text[len("- cmd:") :].strip())
            when, added, paths, in_paths = None, None, [], False
            start = line.number
            problems = [line.problem] if line.problem else []
            continue
        if command is None:
            # Anything before the first record, which a rotated or partially copied file
            # can begin with. Skipped rather than reported: there is no entry to attach it
            # to, and the file's own bytes are in the case either way.
            continue
        stripped = text.strip()
        if stripped.startswith("when:"):
            digits = stripped[len("when:") :].strip()
            when = int(digits) if digits.isdigit() else digits
            in_paths = False
        elif stripped.startswith("added_when:"):
            # The epoch the line was first added, where when is the last time it was. The
            # two differ for a command somebody ran again, and the pair is the only place
            # in any of these formats that says a line was repeated rather than retyped.
            digits = stripped[len("added_when:") :].strip()
            added = int(digits) if digits.isdigit() else digits
            in_paths = False
        elif stripped.startswith("paths:"):
            in_paths = True
        elif in_paths and stripped.startswith("- "):
            paths.append(_fish_unescape(stripped[2:]))
        if line.problem:
            problems.append(line.problem)
    yield from flush()


def _fish_unescape(text: str) -> str:
    """Undo the two escapes fish writes inside a value, in one pass.

    Two passes would be wrong: replacing `\\n` first and `\\\\` second turns a literal
    backslash followed by an n into a line feed, which changes a command that was never
    multi-line into one that looks like two.
    """
    out: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\\" and index + 1 < len(text):
            following = text[index + 1]
            if following == "n":
                out.append("\n")
                index += 2
                continue
            if following == "\\":
                out.append("\\")
                index += 2
                continue
        out.append(char)
        index += 1
    return "".join(out)


# Said on every entry of the agent's own recall file, because the absence it explains
# reads as evidence otherwise. A command that appears once may have run a hundred times,
# and a command that is missing may have been pushed out of the ring.
DEDUPLICATED = (
    "this file holds one line per distinct command, because the agent removes a repeated "
    "command from its old position rather than appending it again, and it keeps only the "
    "last hundred, so neither the number of times a command ran nor the absence of an "
    "older one can be read from it"
)


def _agent_recall(context: ParseContext, lines: list[TextLine]) -> Iterator[Event]:
    """The agent's own shell tool history: one command per line, oldest first.

    The continuation is the vendor's, not a shell's: a line ending in an odd number of
    backslashes is joined to the next one with a SPACE, which is what the product's own
    reader does with it. Rejoining with a line break instead would show an analyst a
    command the agent never assembled.
    """
    pending: list[str] = []
    problems: list[str] = []
    start = 0

    def flush() -> Iterator[Event]:
        if not pending:
            return
        yield _event(
            context,
            start,
            "".join(pending),
            note=" ".join([*problems, NO_TIME, DEDUPLICATED]),
            # The project this file belongs to is in the directory name above it, as a hash
            # the vendor does not reverse, so nothing here claims a project path.
            raw={"command": "".join(pending)},
        )

    for line in lines:
        if not line.text.strip():
            # The vendor's own reader skips a blank line rather than ending an entry on it.
            continue
        if pending:
            pending[-1] = pending[-1][:-1] + " "
            pending.append(line.text)
        else:
            start = line.number
            pending = [line.text]
        if line.problem:
            problems.append(line.problem)
        if not _continues(line.text):
            yield from flush()
            pending, problems = [], []
    yield from flush()


def _continues(text: str) -> bool:
    """Whether this line is continued on the next one, by the vendor's own rule.

    An odd number of trailing backslashes continues the command; an even number is a
    command that ends with escaped backslashes. Counting rather than looking at the last
    character is what the product does, and the difference is a command split in two.
    """
    trailing = len(text) - len(text.rstrip("\\"))
    return trailing % 2 == 1


def _plain(context: ParseContext, lines: list[TextLine]) -> Iterator[Event]:
    """PSReadLine: one line per entry, a trailing backtick continuing the entry."""
    pending: list[str] = []
    problems: list[str] = []
    start = 0

    def flush() -> Iterator[Event]:
        if not pending:
            return
        yield _event(
            context,
            start,
            "\n".join(pending),
            note=" ".join([part for part in [*problems] if part]) or NO_TIME,
            raw={"command": "\n".join(pending)},
        )

    for line in lines:
        if not line.text.strip() and not pending:
            continue
        if not pending:
            start = line.number
        else:
            pending[-1] = pending[-1][:-1]
        pending.append(line.text)
        if line.problem:
            problems.append(line.problem)
        if not line.text.endswith("`"):
            yield from flush()
            pending, problems = [], []
    yield from flush()
