"""What every parser shares.

A parser turns one collected file into events. The interesting part is not the mapping, it
is the failure handling, because the failures are where a forensic tool earns or loses its
answer: a line that will not parse, a record type nobody has seen before, a field nothing
maps. All three have to end up visible.

So the readers in here never skip a line. `iter_lines` yields every line of a file,
including the ones that are not valid JSON and the ones that are valid JSON but not an
object, and it says which. A parser's job is then to map what it recognises and hand the
rest to `unparsed`, which is one call, so that the failure branch stays shorter than the
success branch and nobody is tempted to leave it out.

The timestamp helpers refuse to guess. An agent that writes epoch milliseconds, one that
writes an ISO string with an offset and one that writes nothing at all are three different
situations, and the third is represented as an absent timestamp rather than as the ingest
time or as zero.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol

from agentforensics.model import Event, Provenance, TsPrecision


@dataclass(frozen=True, slots=True)
class ParseContext:
    """Everything a parser needs about the file it was handed."""

    bundle_uuid: str
    original_path: str
    local_path: Path
    sha256: str
    artifact_id: str | None
    agent: str
    user: str | None = None
    host: str | None = None
    # The working copies the collection recorded, where it recorded any. Carried because it
    # is the only non-guessing way to tell a project-scoped instruction file from a
    # profile-scoped one: both are absolute paths under the same home directory, and the
    # difference decides whether a poisoned CLAUDE.md came from the repository or from the
    # user's own configuration. An empty tuple means the source did not record them, which
    # is a different answer from "there were none" and is reported as an unknown scope
    # rather than filled in.
    project_roots: tuple[str, ...] = ()
    # Keys the analyst supplied on the command line, by agent. One product keeps its
    # conversations in an encrypted container whose key belongs to the vendor rather than
    # to the user, and this tool ships none: without a key such a file is reported as an
    # encrypted store rather than read. See ADR 0029 and parsers/encrypted.py.
    keys: Mapping[str, str] = field(default_factory=dict)

    def key_for(self, agent: str | None = None) -> str | None:
        """The key for this file's agent, if the analyst gave one."""
        return self.keys.get(agent or self.agent)

    def provenance(self, locator: str | None) -> Provenance:
        return Provenance(
            bundle_uuid=self.bundle_uuid,
            original_path=self.original_path,
            sha256=self.sha256,
            artifact_id=self.artifact_id,
            locator=locator,
        )


class Parser(Protocol):
    """One module per agent, or per format where agents share one."""

    name: str

    def handles(self, artifact_id: str | None) -> bool: ...

    def parse(self, context: ParseContext) -> Iterator[Event]: ...


@dataclass(frozen=True, slots=True)
class Line:
    """One line of a line-delimited file, whether or not it made sense."""

    number: int
    text: str
    value: Any = None
    problem: str | None = None

    @property
    def ok(self) -> bool:
        """Whether this line is a JSON object a parser can look at.

        An object specifically: every format in this suite writes one object per line, and
        a bare number or a list is as much a surprise as a syntax error. Treating it as
        usable would make a parser fail deeper in with a less useful message.
        """
        return self.problem is None and isinstance(self.value, dict)

    @property
    def locator(self) -> str:
        return f"line:{self.number}"


# What makes a file bytes rather than text, in two signals that are cheap and explainable.
#
# A NUL byte in the first few kilobytes is the test git itself uses to call a file binary,
# and nothing that is prose contains one. The share of characters that failed to decode is
# the second signal, and the threshold is high on purpose: a document written on a machine
# with another code page has a few of them, and losing that document over them would be the
# same kind of mistake in the other direction.
#
# It matters because an encrypted store or a protocol buffer decodes into a page of
# replacement characters, and that page reads as the content of the file. One agent in this
# catalogue keeps its memories exactly that way, so this is the difference between a case
# that says "this is a store we cannot read" and a case that shows somebody noise and calls
# it a memory.
BINARY_SNIFF_BYTES = 8000
BINARY_SHARE = 0.30


def looks_binary(raw_bytes: bytes) -> bool:
    """Whether a file is bytes wearing a text file's name."""
    if not raw_bytes:
        return False
    if b"\x00" in raw_bytes[:BINARY_SNIFF_BYTES]:
        return True
    text = raw_bytes.decode("utf-8", "replace")
    return bool(text) and text.count("\ufffd") / len(text) > BINARY_SHARE


@dataclass(frozen=True, slots=True)
class TextLine:
    """One line of a plain text file, with what was odd about reading it."""

    number: int
    text: str
    problem: str | None = None

    @property
    def locator(self) -> str:
        return f"line:{self.number}"


def text_lines(path: Path) -> Iterator[TextLine]:
    """Every line of a text file, blank ones included, decoded with replacement.

    Not `iter_lines`, which is for line-delimited JSON: that one drops blank lines, which
    are record separators in some of these formats, and marks every line that is not an
    object, which would put the same meaningless note on every event of a file that was
    never JSON. Three readers need the same thing instead, a history file, a recall file
    and a log, so they read it here.

    Decoded with replacement and the substitution reported, for the reason the JSON reader
    gives: a file that will not decode is usually a partial write or another encoding, and
    failing the read would lose the lines that are fine. A byte order mark on the first
    line is removed, because left in it makes the first record carry an invisible
    character.
    """
    with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        for number, raw in enumerate(handle, start=1):
            text = raw.rstrip("\r\n")
            if number == 1:
                text = text.lstrip("\ufeff")
            problem = (
                "the line did not decode as UTF-8 and was read with replacement characters, "
                "so its content is not exact"
                if "\ufffd" in text
                else None
            )
            yield TextLine(number, text, problem)


def iter_lines(path: Path, *, limit: int | None = None) -> Iterator[Line]:
    """Every line of a line-delimited file, none of them skipped.

    Blank lines are passed over, because a trailing newline is not a record. Everything
    else is yielded: a syntax error, a truncated line from a process that was killed
    mid-write, a value that is not an object. Each carries the original text, so the case
    stores what the parser choked on rather than a count of failures.

    Decoded with errors='replace' and the substitution reported. A transcript that will not
    decode is usually a partially written file or a different encoding than expected, and
    both are worth knowing; failing the read instead would lose the lines that are fine.
    """
    try:
        with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
            for number, raw in enumerate(handle, start=1):
                if limit is not None and number > limit:
                    yield Line(
                        number,
                        "",
                        problem=f"stopped after {limit} lines: the file is longer than the "
                        "ingest limit, so the rest of it has not been read",
                    )
                    return
                text = raw.rstrip("\r\n")
                if not text.strip():
                    continue
                if "�" in text:
                    yield Line(
                        number,
                        text,
                        problem="the line did not decode as UTF-8 and was read with "
                        "replacement characters, so its content is not exact",
                    )
                    continue
                # A byte order mark at the start of the first line. Written by a Windows
                # tool that produced the file, and it makes the first record of an
                # otherwise fine transcript unparseable if it is not stripped.
                if number == 1:
                    text = text.lstrip("﻿")
                try:
                    value = json.loads(text)
                except json.JSONDecodeError as exc:
                    yield Line(number, text, problem=f"not valid JSON: {exc}")
                    continue
                if not isinstance(value, dict):
                    yield Line(
                        number,
                        text,
                        value=value,
                        problem=f"a JSON {type(value).__name__} where an object was expected",
                    )
                    continue
                yield Line(number, text, value=value)
    except OSError as exc:
        yield Line(0, "", problem=f"could not be read: {exc}")


# Said on a document that is not strict JSON and reads as the shape its own vendor writes.
# The two relaxations are the ones every editor in this catalogue allows in a settings file,
# and they are the reason a settings file with a comment in it used to reach a case as one
# line saying it was not JSON, with the settings themselves in no event at all.
JSON_WITH_COMMENTS = (
    "this document is not strict JSON and was read the way the product that wrote it reads "
    "it: {relaxations}. The text as it stood on disk is on this event as well, because a "
    "comment in a settings file is somebody's note about why a setting is what it is"
)


def read_json(path: Path) -> tuple[Any, str | None, str | None]:
    """A whole JSON document, the reason it is not one, and what had to be relaxed to read it.

    Three answers rather than two, because there is a third state and it is common. Every
    editor here writes its settings in the dialect with comments and trailing commas in it,
    VS Code's own default settings file has comments in it, and a reader that insisted on
    strict JSON reported the most important configuration files in this catalogue as
    unreadable. The relaxed reading is offered second and it says so: a document that
    needed it is not the document its extension claims.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return None, f"could not be read: {exc}", None
    if "�" in text:
        return None, "the file did not decode as UTF-8", None
    text = text.lstrip("﻿")
    try:
        return json.loads(text), None, None
    except json.JSONDecodeError as strict:
        relaxed, relaxations = _relaxed_json(text)
        if relaxations:
            try:
                return (
                    json.loads(relaxed),
                    None,
                    JSON_WITH_COMMENTS.format(relaxations=" and ".join(relaxations)),
                )
            except json.JSONDecodeError:
                pass
        return None, f"not valid JSON: {strict}", None


def _relaxed_json(text: str) -> tuple[str, list[str]]:
    """The same document with the two things a strict reader refuses taken out.

    Comments are blanked rather than deleted so every offset stays where it was: a decoder
    error then points at the place in the file an analyst would open, not at a place in a
    string this function built.
    """
    out = list(text)
    done: list[str] = []
    index = 0
    in_string = False
    while index < len(text):
        character = text[index]
        if in_string:
            if character == "\\":
                index += 2
                continue
            in_string = character != '"'
            index += 1
            continue
        if character == '"':
            in_string = True
            index += 1
            continue
        if character == "/" and text[index + 1 : index + 2] == "/":
            while index < len(text) and text[index] not in "\r\n":
                out[index] = " "
                index += 1
            done.append("its line comments removed")
            continue
        if character == "/" and text[index + 1 : index + 2] == "*":
            end = text.find("*/", index + 2)
            end = len(text) if end < 0 else end + 2
            for at in range(index, end):
                if text[at] not in "\r\n":
                    out[at] = " "
            index = end
            done.append("its block comments removed")
            continue
        index += 1

    # A comma that has nothing after it but whitespace and a closing brace or bracket. Done
    # on the comment-free text, because a comma before a comment before a brace is the
    # commonest way this shape occurs.
    blanked = "".join(out)
    index = 0
    in_string = False
    trailing = False
    while index < len(blanked):
        character = blanked[index]
        if in_string:
            if character == "\\":
                index += 2
                continue
            in_string = character != '"'
            index += 1
            continue
        if character == '"':
            in_string = True
        elif character == ",":
            after = index + 1
            while after < len(blanked) and blanked[after].isspace():
                after += 1
            if after < len(blanked) and blanked[after] in "}]":
                out[index] = " "
                trailing = True
        index += 1
    if trailing:
        done.append("a trailing comma allowed")
    return "".join(out), sorted(set(done))


_ISO = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})"
    r"[T ](\d{2}):(\d{2})(?::(\d{2}))?(?:\.(\d{1,9}))?"
    r"(Z|[+-]\d{2}:?\d{2})?$"
)


def normalise_ts(value: Any) -> tuple[str | None, TsPrecision, str | None]:
    """Turn whatever an agent wrote into UTC, or say why it could not be.

    Returns the timestamp, how much of it is real, and a note when something had to be
    assumed. Nothing here invents a value: an unreadable timestamp comes back absent, with
    the note carried onto the event so an analyst sees a gap rather than a plausible date.

    A naive timestamp is read as UTC, and the note says so. That is the least bad of three
    bad options, the others being to drop the record or to apply the analyst's own
    workstation timezone, which would silently shift every event in a case.
    """
    if value is None or value == "":
        return None, "absent", None

    if isinstance(value, bool):
        return None, "absent", f"a boolean where a timestamp was expected: {value!r}"

    if isinstance(value, (int, float)):
        return _from_epoch(value)

    if isinstance(value, str):
        text = value.strip()
        if text.isdigit() or (text.startswith("-") and text[1:].isdigit()):
            return _from_epoch(int(text))
        found = _ISO.match(text)
        if not found:
            return None, "absent", f"unrecognised timestamp format: {text!r}"
        year, month, day, hour, minute, second, fraction, offset = found.groups()
        note = None
        if second is None:
            precision: TsPrecision = "minute"
            second = "0"
        elif fraction:
            precision = "exact"
        else:
            precision = "second"
        microsecond = int((fraction or "0").ljust(6, "0")[:6])
        if offset in (None, ""):
            tz = UTC
            note = "the record carried no timezone, so it is read as UTC"
        elif offset == "Z":
            tz = UTC
        else:
            sign = 1 if offset[0] == "+" else -1
            body = offset[1:].replace(":", "")
            tz = timezone(sign * timedelta(hours=int(body[:2]), minutes=int(body[2:4])))
        try:
            moment = datetime(
                int(year),
                int(month),
                int(day),
                int(hour),
                int(minute),
                int(second),
                microsecond,
                tzinfo=tz,
            )
        except ValueError as exc:
            return None, "absent", f"not a real date: {text!r} ({exc})"
        return _render(moment.astimezone(UTC)), precision, note

    return None, "absent", f"unrecognised timestamp type {type(value).__name__}"


def _from_epoch(value: float) -> tuple[str | None, TsPrecision, str | None]:
    """Seconds or milliseconds since the epoch, told apart by magnitude.

    The boundary is the year 2001 in milliseconds, which is also the year 33658 in seconds.
    Agents write both and label neither, so magnitude is the only signal there is; the note
    records the reading so a wrong one is visible rather than silent.
    """
    if value == 0:
        # Written by a field that was never set. A 1970 date on a timeline reads as evidence
        # and is not, so it is refused.
        return None, "absent", "the timestamp field was zero, which is not a time"
    unit = "seconds"
    seconds = float(value)
    if abs(value) > 1e11:
        seconds = value / 1000.0
        unit = "milliseconds"
    try:
        moment = datetime.fromtimestamp(seconds, UTC)
    except OverflowError, OSError, ValueError:
        return None, "absent", f"epoch value out of range: {value!r}"
    note = f"read as epoch {unit}"
    # Whole seconds from a millisecond field still only claim second precision, because the
    # trailing zeros are as likely to be a rounded value as a real one.
    precision: TsPrecision = "exact" if seconds % 1 else "second"
    return _render(moment), precision, note


def _render(moment: datetime) -> str:
    return moment.isoformat(timespec="microseconds").replace("+00:00", "Z")


def first_word(command: str) -> str:
    for token in command.split():
        if "=" in token and not token.startswith(("/", ".", "-")):
            continue
        return token
    return ""


def text_of(value: Any) -> str:
    """Flatten a content field into text without losing any of it.

    Agents write a message body as a string, as a list of typed blocks, or as a mapping,
    and the shapes change between versions. Anything unrecognised is rendered rather than
    dropped: a block type nobody mapped still has to reach the analyst, because a prompt
    that is quietly half shown is worse than one that is shown untidily.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "\n".join(text_of(item) for item in value if item is not None)
    if isinstance(value, dict):
        for key in ("text", "thinking", "content", "display", "message"):
            if key in value:
                return text_of(value[key])
        return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
    return str(value)


__all__ = [
    "BINARY_SHARE",
    "BINARY_SNIFF_BYTES",
    "JSON_WITH_COMMENTS",
    "Line",
    "ParseContext",
    "Parser",
    "TextLine",
    "first_word",
    "iter_lines",
    "looks_binary",
    "normalise_ts",
    "read_json",
    "text_lines",
    "text_of",
]
