"""The unified event model.

Every parser emits this shape, whatever agent produced the record. That is what makes a
device-wide timeline possible at all: twelve agents with twelve transcript formats become
one ordered sequence, and a rule written once matches all of them.

Three properties of this dataclass are load-bearing rather than convenient.

`raw` keeps the original record verbatim. It is not redundancy, it is the guarantee that a
mapping mistake in a parser costs interpretation and not evidence: whatever a parser got
wrong, the original is still there to re-read. Nothing in the pipeline is allowed to drop
it.

`event_id` is derived from provenance, never from a counter. The same evidence therefore
produces the same identifier, which makes re-ingest idempotent: ingesting a bundle twice
does not double a case, and a finding recorded last week still points at the same event.

`ts_utc` is nullable and always accompanied by `ts_precision` and `ts_source`. A great many
agent records carry no timestamp at all, and the honest representation of that is an absent
timestamp with a stated reason, not a zero, not the ingest time, and not the file's mtime
silently presented as the event's own.

Where it is present its shape is checked here rather than trusted, and the reason is one
layer further out than this module. The timeline exports a sketch-compatible log, and the
importer at the other end parses the date with a flexible parser and, when that fails,
coerces the value to the Unix epoch rather than refusing it. So a timestamp this suite
writes in some other shape does not arrive as an error anywhere: it arrives as an event
dated 1970, sorted into the wrong place in somebody's timeline, with nothing saying so.
A parser that produces one is wrong here, where it is a failing test, rather than there.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Literal

# Agent-neutral on purpose. A kind names what happened, not which agent it happened in, so
# a rule about a dangerous command is written once rather than twelve times.
EVENT_KINDS = (
    "session.start",
    "session.end",
    "user.prompt",
    "assistant.text",
    "assistant.thinking",
    "tool.call",
    "tool.result",
    "file.read",
    "file.write",
    "file.snapshot",
    "command.exec",
    "network.request",
    "mcp.call",
    "permission.decision",
    # A change to what the agent is allowed to do, as opposed to a single decision under
    # the rules in force. Separate because the two answer different questions: one is what
    # happened to a request, the other is who moved the goalposts and when.
    "permission.change",
    # The model declining a request on safety grounds. Only some agents record it, so its
    # absence is never evidence that nothing was refused. Kept distinct from a permission
    # denial: a denial is the harness saying no, a refusal is the model saying no, and an
    # analyst asking whether controls were bypassed needs to tell them apart.
    "safety.refusal",
    "config.snapshot",
    # An instruction that was in force on the endpoint: a CLAUDE.md, a skill, an output
    # style, a rules or steering file, a hook script. Its own kind rather than part of
    # config.snapshot because the two answer different questions and a timeline has to keep
    # them apart. A setting says how the agent was configured; an instruction is text the
    # model was told to obey, and the question of whether the agent was manipulated by
    # injected instructions is only about the second. The name says source rather than
    # prompt on purpose: the vendor's own base prompt is compiled into the agent or comes
    # from its server and is not on the endpoint at all, so this kind is the part of a
    # system prompt that can be evidence, never the whole of one.
    "instruction.source",
    "memory.write",
    "plan.write",
    "prompt.history",
    # The filesystem timestamps of an artifact file itself. Some artifacts carry no internal
    # timestamps at all, and for those this is the only temporal evidence there is: without
    # this kind they would be missing from every timeline.
    "artifact.fs",
    # A record the parsers could not read, or a record type none of them knows. It is an
    # event like any other so that it appears on the timeline and in every count, because a
    # record that is quietly dropped reads as a record that never existed.
    "unparsed.record",
)

# How much of the timestamp is real. An analyst reading a timeline has to be able to tell a
# millisecond from an agent's own clock apart from a date inferred from a directory name,
# and ordering two events inside the same minute is meaningless if both are minute-precise.
TsPrecision = Literal["exact", "second", "minute", "hour", "day", "filesystem", "absent"]

# Who acted. Separate from the kind because the same kind has different meaning depending
# on the actor: a file write by the agent is its work product, a file write by the user is
# context the agent then read.
Actor = Literal["user", "assistant", "tool", "system", "unknown"]


# ISO 8601 with a zone, which is what the whole pipeline states it writes: a date, a time,
# optional fractional seconds, and either Z or an explicit offset. Anything else is refused
# at construction, for the reason in the module docstring.
TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})")


@dataclass(frozen=True, slots=True)
class Provenance:
    """Where an event came from, precisely enough to go back and look.

    Every field here answers a question an analyst will be asked in a report: which
    collection this came from, which file on the endpoint, whether that file is still the
    one that was collected, and where in it this record sits.
    """

    bundle_uuid: str
    original_path: str
    sha256: str
    artifact_id: str | None = None
    # A line number for a line-delimited file, a byte offset for anything else, a table and
    # rowid for a database. Kept as text because those are three different things and
    # forcing them into an integer would lose which one it is.
    locator: str | None = None

    def key(self) -> str:
        """The string the event id is derived from."""
        return "\x00".join(
            (
                self.bundle_uuid,
                self.original_path,
                self.sha256,
                self.artifact_id or "",
                self.locator or "",
            )
        )


@dataclass(frozen=True, slots=True)
class Event:
    """One thing that happened, as the case database stores it."""

    kind: str
    provenance: Provenance
    agent: str
    raw: Any
    ts_utc: str | None = None
    ts_precision: TsPrecision = "absent"
    # Where the timestamp came from: the name of the record field, or which filesystem
    # timestamp. An analyst has to be able to tell the agent's own clock from the
    # filesystem's, because only one of the two is evidence of when the agent acted.
    ts_source: str | None = None
    actor: Actor = "unknown"
    client: str | None = None
    host: str | None = None
    user: str | None = None
    session_id: str | None = None
    project_path: str | None = None
    git_branch: str | None = None
    payload: dict[str, Any] = field(default_factory=dict)
    # Set when this event's kind is unparsed.record, or when a parser mapped the record but
    # could not map part of it. Surfaced in the analyzer's output either way.
    parse_problem: str | None = None

    def __post_init__(self) -> None:
        if self.kind not in EVENT_KINDS:
            raise ValueError(f"unknown event kind: {self.kind}")
        if self.ts_utc is None and self.ts_precision != "absent":
            raise ValueError("a precision was given for a timestamp that is not there")
        if self.ts_utc is not None and self.ts_precision == "absent":
            raise ValueError("a timestamp was given with no precision")
        if self.ts_utc is not None and not TIMESTAMP.fullmatch(self.ts_utc):
            raise ValueError(
                f"a timestamp that is not ISO 8601 with a zone: {self.ts_utc!r}. "
                "It would reach a timeline as text and an importer as a date it guessed at"
            )

    @property
    def event_id(self) -> str:
        """A stable identifier, derived from provenance and the kind.

        The kind is in the hash because one record can legitimately produce several events:
        a transcript turn that calls a tool is both an assistant turn and a tool call, and
        those need separate identities while sharing a locator.
        """
        digest = hashlib.sha256()
        digest.update(self.provenance.key().encode("utf-8"))
        digest.update(b"\x00")
        digest.update(self.kind.encode("utf-8"))
        return digest.hexdigest()[:32]

    def raw_json(self) -> str:
        """The original record as stored text.

        sort_keys so that re-ingesting the same evidence writes the same bytes, and
        ensure_ascii=False so a prompt in any language stays readable in the database
        rather than becoming escapes. default=str so that a value no JSON encoder knows
        still lands in the column instead of failing the ingest: losing the record would be
        worse than storing a coarse rendering of it.
        """
        return json.dumps(self.raw, sort_keys=True, ensure_ascii=False, default=str)

    def payload_json(self) -> str:
        return json.dumps(self.payload, sort_keys=True, ensure_ascii=False, default=str)


# The words every record carries that was read fine and that nobody has a verified mapping
# for. Both generic readers, the one for SQLite stores and the one for line-delimited logs,
# build their sentence out of it, and the case counts with it.
#
# It exists because the two populations under `unparsed.record` are opposite answers to the
# question an analyst asks of them. A line that would not decode, or a half-written record
# from a process that was killed, is a defect in the evidence and is worth opening before
# anything in the case is quoted. A row of a chat database nobody has read a schema for is
# intact evidence that simply has no reading yet, and there can be hundreds of thousands of
# those. Counted as one number the first disappears into the second, and the word
# "unreadable" in front of the total is then wrong about almost all of it.
#
# A phrase rather than a column because the alternative is a change to the event model and
# to the format on the wire, which is a heavier thing than the problem needs. A test asserts
# that only the two generic readers write it.
UNINTERPRETED_MARK = "is returned uninterpreted"


def is_uninterpreted(event: Event) -> bool:
    """Whether this record was read and is only waiting for somebody to map its format.

    The mark alone, not the kind. Most of these records are `unparsed.record`, but a
    document out of a catalogue entry the catalogue calls configuration is filed as a
    `config.snapshot` with exactly as thin a reading, and a count that went by the kind
    would report it as interpreted. The two questions are independent: what a record is,
    and whether anybody has read the format it is in.
    """
    return UNINTERPRETED_MARK in (event.parse_problem or "")


def unparsed(
    provenance: Provenance,
    agent: str,
    raw: Any,
    problem: str,
    ts_utc: str | None = None,
    ts_precision: TsPrecision = "absent",
    ts_source: str | None = None,
    **fields: Any,
) -> Event:
    """An event for a record nothing could read.

    A helper rather than a convention because this is the path that must never be skipped,
    and making it one call means a parser's failure branch is shorter than its success
    branch. The record itself is kept in raw, so an analyst reading the case sees the text
    the parser choked on rather than a count of failures.
    """
    return Event(
        kind="unparsed.record",
        provenance=provenance,
        agent=agent,
        raw=raw,
        ts_utc=ts_utc,
        ts_precision=ts_precision,
        ts_source=ts_source,
        parse_problem=problem,
        **fields,
    )


__all__ = [
    "EVENT_KINDS",
    "UNINTERPRETED_MARK",
    "Actor",
    "Event",
    "Provenance",
    "TsPrecision",
    "is_uninterpreted",
    "unparsed",
]
