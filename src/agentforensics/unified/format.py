"""The vendor-neutral log format: one record per line, and the two conversions.

This is the wire form of `agentforensics.model.event.Event`, not a second model. That is
the whole point of the module: a Velociraptor query on an endpoint, this suite's analyzer
reading a bundle, and the viewer in a browser all speak one shape, and there is exactly one
definition of it to disagree with. The schema is a file, `agentlog.v1.schema.json`, next to this
module rather than a dict inside it, so that a producer which is not Python, VQL above all,
and CI, can validate against it by reading a path without importing anything.

Three properties are load-bearing.

Every record carries its own version and stands alone. There is no file header and no
ordering requirement, so concatenating two logs gives a valid third one. That is not a
nicety: a fleet collection returns one row set per host, a row-based producer has nowhere
to put a header, and an analyst merges what comes back.

Nothing is dropped, including a line of a unified log that does not parse. Reading is
therefore total: `read()` yields an event for every line it is given, and a line it cannot
understand comes back as an `unparsed.record` event holding the original text. A reader
that skipped a bad line would let a tampered log look clean.

`event_id` travels but is never trusted. It is derived from provenance and kind, so a
reader recomputes it and reports a disagreement instead of correcting it. Which producer
read a file, and whether it agrees with ours, is itself evidence.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Iterator
from functools import lru_cache
from pathlib import Path
from typing import Any, TextIO, cast

import fastjsonschema

from agentforensics import __version__
from agentforensics.model.event import EVENT_KINDS, Event, Provenance, unparsed

FORMAT_VERSION = 1
FORMAT_NAME = "afx-unified-agent-log"

# What this build writes into `producer`. A Velociraptor artifact writes its own artifact
# name and version there instead, so a case can be asked which normalizer read a file.
PRODUCER = f"agentforensics/{__version__}"

# The fields a record may carry outside `payload`, in the order they are written. Ordered
# so that two runs produce byte-identical output and a diff of two logs is readable.
_FIELDS = (
    "v",
    "agent",
    "kind",
    "event_id",
    "ts_utc",
    "ts_precision",
    "ts_source",
    "actor",
    "client",
    "host",
    "user",
    "session_id",
    "project_path",
    "git_branch",
    "payload",
    "parse_problem",
    "provenance",
    "raw",
    "producer",
)

# Inside the package so that an installed wheel carries it: a validator that only works
# from a source checkout would silently stop validating for every other user.
SCHEMA_PATH = Path(__file__).resolve().parent / "agentlog.v1.schema.json"


class UnifiedFormatError(Exception):
    """The schema itself could not be loaded. Not raised for a bad record."""


@lru_cache(maxsize=1)
def schema() -> dict[str, Any]:
    """The JSON Schema, read from the file the other producers validate against.

    Read from disk rather than duplicated in Python so that VQL, CI and this module cannot
    drift: there is one file, and a change to it fails the tests here as well.
    """
    try:
        text = SCHEMA_PATH.read_text(encoding="utf-8")
    except OSError as exc:  # pragma: no cover - only when the install is broken
        raise UnifiedFormatError(f"cannot read {SCHEMA_PATH}: {exc}") from exc
    return cast(dict[str, Any], json.loads(text))


@lru_cache(maxsize=1)
def validator() -> Callable[[Any], Any]:
    """A compiled validator. Compiled once because a log has a record per line."""
    return cast(Callable[[Any], Any], fastjsonschema.compile(schema()))


def to_record(event: Event, *, producer: str | None = PRODUCER) -> dict[str, Any]:
    """One event as one record.

    Nulls are written rather than omitted. A field that is absent and a field that is
    present and empty are different claims about the evidence, and the schema's readers
    should not have to guess which one a missing key meant.
    """
    return {
        "v": FORMAT_VERSION,
        "agent": event.agent,
        "kind": event.kind,
        "event_id": event.event_id,
        "ts_utc": event.ts_utc,
        "ts_precision": event.ts_precision,
        "ts_source": event.ts_source,
        "actor": event.actor,
        "client": event.client,
        "host": event.host,
        "user": event.user,
        "session_id": event.session_id,
        "project_path": event.project_path,
        "git_branch": event.git_branch,
        "payload": event.payload,
        "parse_problem": event.parse_problem,
        "provenance": {
            "bundle_uuid": event.provenance.bundle_uuid,
            "original_path": event.provenance.original_path,
            "sha256": event.provenance.sha256,
            "artifact_id": event.provenance.artifact_id,
            "locator": event.provenance.locator,
        },
        "raw": event.raw,
        "producer": producer,
    }


def to_line(event: Event, *, producer: str | None = PRODUCER) -> str:
    """One event as one line of JSON.

    sort_keys is deliberately off: `_FIELDS` order puts the identifying fields first, which
    makes a log readable in a terminal without a JSON tool. ensure_ascii is off so a prompt
    in any language stays readable rather than becoming escapes. default=str so a value no
    encoder knows still lands in the line: a coarse rendering of a record beats losing it.
    """
    record = to_record(event, producer=producer)
    ordered = {key: record[key] for key in _FIELDS if key in record}
    return json.dumps(ordered, ensure_ascii=False, default=str)


def write(events: Iterable[Event], handle: TextIO, *, producer: str | None = PRODUCER) -> int:
    """Write a whole log. Returns how many records were written."""
    written = 0
    for event in events:
        handle.write(to_line(event, producer=producer) + "\n")
        written += 1
    return written


def from_record(record: Any, *, provenance_fallback: Provenance) -> Event:
    """One record as one event, for any record at all.

    Total on purpose. Anything this cannot map becomes an `unparsed.record` event carrying
    the record itself, because a reader that raised on a malformed line would turn one bad
    record into a lost file, and a reader that skipped it would make a tampered log look
    clean. `provenance_fallback` is where the event is attributed when the record's own
    provenance is missing or unusable: the log file being read, which is the truthful answer
    to "where did this come from" in that case.
    """
    if not isinstance(record, dict):
        return unparsed(
            provenance_fallback,
            "unknown",
            record,
            "a line of the unified log is not a JSON object",
        )

    problems: list[str] = []
    try:
        validator()(record)
    except fastjsonschema.JsonSchemaException as exc:
        # Recorded, not fatal. A record that fails the schema is still evidence, and the
        # code below salvages every field that is usable.
        problems.append(f"the record does not match the unified schema: {exc.message}")

    agent = record.get("agent")
    kind = record.get("kind")
    provenance = _provenance(record.get("provenance"), provenance_fallback, problems)
    # A record with no raw field, or one whose raw field is null, falls back to the whole
    # record. Something has to stand in for the original, and the record itself is the
    # closest thing to it there is.
    raw = record.get("raw")
    if raw is None:
        raw = record

    if not isinstance(agent, str) or not agent:
        problems.append("the record names no agent")
        return unparsed(provenance, "unknown", raw, "; ".join(problems))
    if kind not in EVENT_KINDS:
        problems.append(f"event kind {kind!r} is not one this build knows")
        return unparsed(
            provenance,
            agent,
            raw,
            "; ".join(problems),
            **_timing(record, problems),
            **_identity(record),
        )

    payload = record.get("payload")
    if not isinstance(payload, dict):
        if payload is not None:
            problems.append("the payload is not an object, so it is kept under 'payload'")
            payload = {"payload": payload}
        else:
            payload = {}

    event = Event(
        kind=kind,
        provenance=provenance,
        agent=agent,
        raw=raw,
        payload=payload,
        parse_problem=None,
        **_timing(record, problems),
        **_identity(record),
        **_actor(record, problems),
    )

    # Recomputed, never trusted. A producer whose id does not match ours read the same file
    # differently, or wrote the record by hand, and either is worth knowing before the
    # event is used to support a conclusion.
    claimed = record.get("event_id")
    if isinstance(claimed, str) and claimed and claimed != event.event_id:
        problems.append(
            f"the producer's event_id {claimed} does not match the one derived from this "
            f"record's provenance ({event.event_id})"
        )

    stated = record.get("parse_problem")
    if isinstance(stated, str) and stated:
        # The producer's own complaint comes first: it read the original file and we did
        # not, so what it could not map matters more than what we could not map about it.
        problems.insert(0, stated)

    if problems:
        return _with_problem(event, "; ".join(problems))
    return event


def read(
    handle: Iterable[str],
    *,
    bundle_uuid: str,
    original_path: str,
    sha256: str = "",
) -> Iterator[Event]:
    """Read a unified log, yielding one event per non-empty line.

    The three arguments describe the log file itself, and are used as provenance for any
    line whose own provenance is missing: an event has to be traceable to something, and
    the file it was read from is the honest answer when the record does not say.
    """
    for number, text in enumerate(handle, start=1):
        line = text.strip()
        if not line:
            continue
        fallback = Provenance(
            bundle_uuid=bundle_uuid,
            original_path=original_path,
            sha256=sha256,
            artifact_id=None,
            locator=f"line:{number}",
        )
        try:
            record = json.loads(line)
        except ValueError as exc:
            # The line is kept in full. A truncated write, a partially overwritten record
            # and a deliberately corrupted line all arrive here, and shortening any of them
            # would destroy the evidence of which it was.
            yield unparsed(
                fallback,
                "unknown",
                line,
                f"the line is not valid JSON: {exc}",
            )
            continue
        yield from_record(record, provenance_fallback=fallback)


def _provenance(value: Any, fallback: Provenance, problems: list[str]) -> Provenance:
    if not isinstance(value, dict):
        problems.append("the record carries no provenance, so the log file is used instead")
        return fallback
    path = value.get("original_path")
    if not isinstance(path, str) or not path:
        problems.append(
            "the record's provenance names no path on the endpoint, so the log file is used instead"
        )
        return fallback
    return Provenance(
        bundle_uuid=_text(value.get("bundle_uuid")) or fallback.bundle_uuid,
        original_path=path,
        sha256=_text(value.get("sha256")) or "",
        artifact_id=_text(value.get("artifact_id")),
        locator=_text(value.get("locator")),
    )


def _timing(record: dict[str, Any], problems: list[str]) -> dict[str, Any]:
    """The three timestamp fields, repaired into a consistent triple if need be.

    The event model refuses a time without a precision and a precision without a time,
    which is the right strictness for a parser writing new events. Here the record already
    exists, so an inconsistent pair is downgraded to the weaker claim and the downgrade is
    recorded, rather than the record being rejected.
    """
    ts = record.get("ts_utc")
    precision = record.get("ts_precision")
    source = _text(record.get("ts_source"))
    if not isinstance(ts, str) or not ts:
        if precision not in (None, "absent"):
            problems.append(
                f"the record states precision {precision!r} for a timestamp it does not have"
            )
        return {"ts_utc": None, "ts_precision": "absent", "ts_source": source}
    if precision not in ("exact", "second", "minute", "hour", "day", "filesystem"):
        problems.append(
            f"the record has a timestamp with precision {precision!r}, which this build "
            "does not know, so the timestamp is treated as second-precise"
        )
        precision = "second"
    return {"ts_utc": ts, "ts_precision": precision, "ts_source": source}


def _identity(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "client": _text(record.get("client")),
        "host": _text(record.get("host")),
        "user": _text(record.get("user")),
        "session_id": _text(record.get("session_id")),
        "project_path": _text(record.get("project_path")),
        "git_branch": _text(record.get("git_branch")),
    }


def _actor(record: dict[str, Any], problems: list[str]) -> dict[str, Any]:
    actor = record.get("actor")
    if actor in ("user", "assistant", "tool", "system", "unknown"):
        return {"actor": actor}
    if actor is not None:
        problems.append(f"actor {actor!r} is not one this build knows, so it reads as unknown")
    return {"actor": "unknown"}


def _with_problem(event: Event, problem: str) -> Event:
    """A copy of an event carrying a parse problem.

    Event is frozen with slots, so this rebuilds rather than mutates. Worth the few lines:
    an immutable event is what stops a later stage from quietly editing evidence.
    """
    return Event(
        kind=event.kind,
        provenance=event.provenance,
        agent=event.agent,
        raw=event.raw,
        ts_utc=event.ts_utc,
        ts_precision=event.ts_precision,
        ts_source=event.ts_source,
        actor=event.actor,
        client=event.client,
        host=event.host,
        user=event.user,
        session_id=event.session_id,
        project_path=event.project_path,
        git_branch=event.git_branch,
        payload=event.payload,
        parse_problem=problem,
    )


def _text(value: Any) -> str | None:
    """A field that should be text, or None. A number where a string belongs becomes text
    rather than being discarded: a session id written as an integer is still a session id."""
    if value is None:
        return None
    if isinstance(value, str):
        return value or None
    if isinstance(value, (int, float, bool)):
        return str(value)
    return None


__all__ = [
    "FORMAT_NAME",
    "FORMAT_VERSION",
    "PRODUCER",
    "SCHEMA_PATH",
    "UnifiedFormatError",
    "from_record",
    "read",
    "schema",
    "to_line",
    "to_record",
    "validator",
    "write",
]
