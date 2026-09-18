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
from collections.abc import Iterator
from dataclasses import dataclass
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


def read_json(path: Path) -> tuple[Any, str | None]:
    """A whole JSON document, or the reason it is not one."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return None, f"could not be read: {exc}"
    if "�" in text:
        return None, "the file did not decode as UTF-8"
    try:
        return json.loads(text.lstrip("﻿")), None
    except json.JSONDecodeError as exc:
        return None, f"not valid JSON: {exc}"


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
    except (OverflowError, OSError, ValueError):
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
    "Line",
    "ParseContext",
    "Parser",
    "first_word",
    "iter_lines",
    "normalise_ts",
    "read_json",
    "text_of",
]
