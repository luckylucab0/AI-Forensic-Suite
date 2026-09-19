"""Read the copy of a shell environment one agent takes before it runs a command.

This product writes a snapshot of the user's interactive shell, as a script it can source
later, so that the commands it runs see the aliases and functions the user would have seen.
The file is the closest thing on the endpoint to the environment a command actually ran in,
and until this module a collection of one reached a case as a file name.

Three things make it worth its own reader rather than a line-per-record floor.

**It is the environment, not a mention of it.** A variable exported here was in force when
the agent ran. That is a stronger statement than the same line in a history file, which
only says somebody typed it once, and the variables that turn an agent's own prompts and
prompt history off are exactly the ones an investigation asks about.

**A function can carry what a command line never shows.** A wrapper the user wrote to add a
token, an internal host or a proxy is in here in full, and it is invisible in the command
the transcript records: the transcript shows the wrapper's name.

**The file being on disk is itself evidence.** The vendor's own documentation says a
snapshot is removed on a clean exit, so one that survived generally means the session
crashed or was killed, and the directory is explicitly left alone by the product's own
purge command. So it outlives the artifacts that command destroys, which makes it one of
the few places an agent's environment survives a deliberate clean-up.

What is read and what is not. Only the three declarations a generated shell script states
unambiguously are read as such: an export, an alias, and a function with its body. Every
other line is kept as a record of its own with the uninterpreted mark, because this is a
shell script and a reader that decided what an arbitrary line means would be writing a
shell. Quoting is undone only where a value is wrapped in one matching pair of quotes; no
expansion is attempted, since the value of `$HOME` on the endpoint is not knowable here.

Source for what the file is and when it is removed:
https://code.claude.com/docs/en/claude-directory
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from agentforensics.model import UNINTERPRETED_MARK, Event, unparsed
from agentforensics.parsers.base import ParseContext, TextLine, looks_binary, text_lines

SOURCES = frozenset({"claude_code.shell_snapshots"})

# `export NAME=value`, and `export NAME` on its own, which exports a variable the script set
# on an earlier line. The name rule is the shell's: letters, digits and underscore, not
# starting with a digit.
_EXPORT = re.compile(r"^\s*export\s+([A-Za-z_][A-Za-z0-9_]*)(?:=(.*))?$")

# `alias name=value`. An alias name may hold characters a variable name may not, so the
# rule is only that it has no whitespace and no equals sign in it.
_ALIAS = re.compile(r"^\s*alias\s+([^\s=]+)=(.*)$")

# A function, in the two spellings a shell accepts. The body runs until a closing brace on
# a line of its own, which is how these files are written; a body that ends otherwise is
# reported rather than guessed at.
_FUNCTION = re.compile(r"^(?:function\s+)?([A-Za-z_][A-Za-z0-9_:.-]*)\s*\(\s*\)\s*\{\s*$")
_FUNCTION_END = re.compile(r"^\}\s*$")

# How many lines of one snapshot are read. A shell environment with a large framework in it
# runs to thousands of lines, and a limit that is never said out loud is the one thing a
# truncating reader must not do.
MAX_LINES = 50_000

TRUNCATED = (
    f"this snapshot is longer than {MAX_LINES} lines and the reading stopped there. The "
    "file is in the bundle under this event's hash"
)

UNINTERPRETED = (
    "this is a line of a shell script that is not an export, an alias or a function "
    f"definition, so the line {UNINTERPRETED_MARK}: it is kept as the text it is and "
    "nothing was read out of it"
)

UNCLOSED = (
    "this function has no closing brace on a line of its own before the end of the file, "
    "so what is shown is everything from its first line to the end. A snapshot is written "
    "as a session starts, and a truncated one is what a session killed mid-write leaves"
)

# Said on the event for the file itself, because the file existing is a fact about the
# session rather than about its contents.
SURVIVED = (
    "this snapshot was on disk when the collection ran. The vendor's documentation states "
    "that a snapshot is removed when the session exits cleanly, so one that survived "
    "generally means the session crashed or was killed, and this directory is explicitly "
    "left alone by the product's own purge command. Neither is proof on its own, and both "
    "are worth explaining"
)

BINARY_FILE = (
    "this file is not text, so it is not the shell script this product writes here. It is "
    "recorded by size and hash rather than shown as a page of replacement characters"
)


class ShellSnapshotParser:
    """The shell environment an agent captured, read as the declarations it states."""

    name = "shell_snapshot"

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
                {"file": context.local_path.name, "bytes": len(raw)},
                BINARY_FILE,
                user=context.user,
                host=context.host,
            )
            return

        yield self._present(context, len(raw))
        yield from self._declarations(context)

    def _present(self, context: ParseContext, size: int) -> Event:
        """That the file was there at all, which is the part a timeline needs."""
        return Event(
            kind="config.snapshot",
            provenance=context.provenance("file"),
            agent=context.agent,
            actor="system",
            user=context.user,
            host=context.host,
            raw={"file": context.local_path.name, "bytes": size},
            payload={"text": SURVIVED},
            parse_problem=None,
        )

    def _declarations(self, context: ParseContext) -> Iterator[Event]:
        pending: list[TextLine] = []
        name = ""
        read = 0
        for line in text_lines(context.local_path):
            read += 1
            if read > MAX_LINES:
                yield unparsed(
                    context.provenance(f"line:{line.number}"),
                    context.agent,
                    None,
                    TRUNCATED,
                    user=context.user,
                    host=context.host,
                )
                return

            if pending:
                if _FUNCTION_END.match(line.text):
                    yield self._setting(context, pending[0], "function", name, _body(pending))
                    pending = []
                else:
                    pending.append(line)
                continue

            found = _FUNCTION.match(line.text)
            if found:
                name = found.group(1)
                pending = [line]
                continue

            found = _EXPORT.match(line.text)
            if found:
                # An export with no value carries the name and nothing else, which is a
                # different record from an export of the empty string and is kept as one.
                value = found.group(2)
                yield self._setting(
                    context,
                    line,
                    "export",
                    found.group(1),
                    None if value is None else _unquote(value),
                )
                continue

            found = _ALIAS.match(line.text)
            if found:
                yield self._setting(
                    context, line, "alias", found.group(1), _unquote(found.group(2))
                )
                continue

            if line.text.strip():
                yield unparsed(
                    context.provenance(f"line:{line.number}"),
                    context.agent,
                    {"line": line.text},
                    line.problem or UNINTERPRETED,
                    user=context.user,
                    host=context.host,
                    payload={"text": line.text},
                )

        if pending:
            yield self._setting(
                context, pending[0], "function", name, _body(pending), problem=UNCLOSED
            )

    def _setting(
        self,
        context: ParseContext,
        line: TextLine,
        kind: str,
        name: str,
        value: str | None,
        problem: str | None = None,
    ) -> Event:
        """One declaration, with the name searchable and the value beside it.

        The name is a field rather than something inside raw because the name is what a
        rule asks about: whether a particular variable was exported is a question with a
        yes or no answer, and the value only matters once the answer is yes.
        """
        # A function body already opens with the function's own name, so the text is the
        # body as it stands. Spelling it as name=body would put the name in twice and read
        # as a variable named after the function.
        if kind == "function":
            text = value or name
        elif value is None:
            text = f"{kind} {name}"
        else:
            text = f"{kind} {name}={value}"
        return Event(
            kind="config.snapshot",
            provenance=context.provenance(f"line:{line.number}"),
            agent=context.agent,
            actor="system",
            user=context.user,
            host=context.host,
            raw={"kind": kind, "name": name, "value": value},
            payload={"key": f"{kind}:{name}", "text": text},
            parse_problem=problem or line.problem,
        )


def _body(lines: list[TextLine]) -> str:
    """A function as it stands in the file, opening line included.

    Whole rather than summarised: the point of reading a function at all is that what it
    does is invisible in the command the transcript records, and a summary would put the
    reader back where they started.
    """
    return "\n".join(line.text for line in lines)


def _unquote(value: str) -> str:
    """A value with one surrounding pair of quotes removed, and nothing else done to it.

    Not an expansion. What `$HOME` or a command substitution would have produced on the
    endpoint is not knowable from the file, so the text is left as it is and an analyst
    reads the shell rather than this module's guess at it.
    """
    stripped = value.strip()
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in "'\"":
        return stripped[1:-1]
    return stripped


__all__ = [
    "BINARY_FILE",
    "MAX_LINES",
    "SOURCES",
    "SURVIVED",
    "TRUNCATED",
    "UNCLOSED",
    "UNINTERPRETED",
    "ShellSnapshotParser",
]
