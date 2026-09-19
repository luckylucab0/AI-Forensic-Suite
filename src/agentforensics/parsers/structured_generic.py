"""The reading every whole-document reader shares: split by structure, never by meaning.

ADR 0027 decided how a document with no verified shape is read, for JSON. The same decision
answers the same question for the other two document formats in the catalogue, YAML and
TOML, so the reading lives here once and the three readers differ only in how they turn
bytes into a value and in which artifacts they claim. ADR 0028 records that.

The rule, unchanged from 0027:

- a root that is a list is one event per element, at `$[n]`
- a root that is a mapping is one event for the document, then one event per element of
  each **top-level** key whose value is a list of mappings, at `$.key[n]`
- anything else is one event, at `$`

One level deep and no further, because descending to find the records means deciding which
branch holds them, and a partial reading that is visible is worth more than a confident one
that is wrong. From a record only what the record literally names is read, in the field
names `jsonl_generic` uses, so the generic readers agree with each other about an unmapped
record and every event says on itself that nobody has read this format.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from agentforensics.model import UNINTERPRETED_MARK, Event
from agentforensics.parsers.base import ParseContext, normalise_ts
from agentforensics.parsers.jsonl_generic import (
    TIME_FIELDS,
    literal_field,
    literal_project,
    literal_session,
    literal_text,
)

# A list longer than this stays one event with all of it in `raw`, and the event says how
# many elements it holds and why it was not split. The rule ADR 0022 applies to an index or
# a cache store, moved from a list of artifact ids to the data itself: a machine-generated
# array of a hundred thousand chunks would bury a case's evidence under the agent's own
# index, and nothing about the array's name says which kind it is.
SPLIT_LIMIT = 10_000

# What every event out of a generic document reader says about itself, in the words the
# other generic readers use for the same situation. The format's own name goes in front of
# it, because "no verified shape for this document" is the same sentence whether the bytes
# were JSON, YAML or TOML and an analyst still wants to know which file they are holding.
UNINTERPRETED = (
    "this collection has no verified shape for this document, so the record "
    f"{UNINTERPRETED_MARK}. Everything it contained is in raw. Re-read this file once a "
    "parser for it exists."
)

# Said on a document that was not split, so a reader knows the records are inside the one
# event rather than missing from the case.
NOT_SPLIT = (
    "this list holds {count} elements, more than the {limit} this reader splits, so it is "
    "one record with all of it in raw rather than one event per element"
)

# Said where the document held nothing. An empty mapping in `raw` and an event that says
# nothing else reads as a parser that came back with nothing, and those are opposite
# answers: this one is a file that was read and was empty, which for a session marker or a
# configuration backup is itself a fact about the endpoint.
EMPTY = "this file was read and holds an empty {shape}, which is what is in raw"


def documents(
    context: ParseContext,
    value: Any,
    *,
    configuration: bool,
    at: str = "$",
    uninterpreted: str = UNINTERPRETED,
    note: str | None = None,
) -> Iterator[Event]:
    """Every event one loaded document produces, by the rule above.

    `configuration` decides the kind, and it is the one thing about these documents that
    rests on something checked: the catalogue says this file is a configuration, so the
    event says `config.snapshot` and a rule about a setting can reach it. Everything else
    is `unparsed.record`, and the reading is exactly as thin in both cases.

    `note` is what the format's own reader has to say about every record out of this
    document, such as a key it had to render as text. It goes in front of whatever this
    reader says about the individual record, so one event carries both.
    """
    if value in ([], {}):
        yield record(
            context,
            at,
            value,
            configuration=configuration,
            uninterpreted=uninterpreted,
            note=_joined(
                note, EMPTY.format(shape="list" if isinstance(value, list) else "mapping")
            ),
        )
        return
    if isinstance(value, list):
        yield from _elements(
            context, at, value, configuration=configuration, uninterpreted=uninterpreted, note=note
        )
        return
    if not isinstance(value, dict):
        # A bare string, number or boolean as the whole file. Unusual, and carried rather
        # than skipped: a file whose content is one word is a different answer from a file
        # nobody read.
        yield record(
            context,
            at,
            value,
            configuration=configuration,
            uninterpreted=uninterpreted,
            note=note,
        )
        return

    yield record(
        context, at, value, configuration=configuration, uninterpreted=uninterpreted, note=note
    )
    for key, nested in value.items():
        if splittable(nested):
            yield from _elements(
                context,
                f"{at}.{key}",
                nested,
                configuration=configuration,
                uninterpreted=uninterpreted,
                note=note,
            )


def _elements(
    context: ParseContext,
    at: str,
    value: list[Any],
    *,
    configuration: bool,
    uninterpreted: str,
    note: str | None = None,
) -> Iterator[Event]:
    """One event per element, unless the list is longer than a case can carry."""
    if len(value) > SPLIT_LIMIT:
        yield record(
            context,
            at,
            value,
            configuration=configuration,
            uninterpreted=uninterpreted,
            note=_joined(note, NOT_SPLIT.format(count=len(value), limit=SPLIT_LIMIT)),
        )
        return
    for index, element in enumerate(value):
        yield record(
            context,
            f"{at}[{index}]",
            element,
            configuration=configuration,
            uninterpreted=uninterpreted,
            note=note,
        )


def _joined(*parts: str | None) -> str | None:
    """Several notes as one sentence, keeping the order they were given in."""
    return " ".join(part for part in parts if part) or None


def record(
    context: ParseContext,
    at: str,
    value: Any,
    *,
    configuration: bool,
    uninterpreted: str = UNINTERPRETED,
    note: str | None = None,
) -> Event:
    """One record, with only what it plainly says read out of it."""
    # The literal readings apply to a mapping. A list or a scalar names no fields, so it
    # carries no time, no session and no text, and it is in `raw` whole.
    fields = value if isinstance(value, dict) else {}
    field, raw_time = literal_field(fields, TIME_FIELDS)
    when, precision, timing = normalise_ts(raw_time)
    text = literal_text(fields)
    return Event(
        kind="config.snapshot" if configuration else "unparsed.record",
        provenance=context.provenance(at),
        agent=context.agent,
        raw=value,
        parse_problem=" ".join(part for part in (note, timing, uninterpreted) if part),
        ts_utc=when,
        ts_precision=precision,
        ts_source=f"the field named {field}" if when and field else None,
        user=context.user,
        host=context.host,
        session_id=literal_session(fields),
        project_path=literal_project(fields),
        payload={"text": text} if text is not None else {},
    )


def splittable(value: Any) -> bool:
    """Whether a top-level value is a list of things rather than a list of loose values.

    A list of mappings is a list of things whatever those things are, which is a statement
    about the bytes. A list of strings is a setting with several values, and one event per
    string would put a case's evidence beside a list of enabled extensions.
    """
    return (
        isinstance(value, list)
        and bool(value)
        and all(isinstance(element, dict) for element in value)
    )


__all__ = [
    "EMPTY",
    "NOT_SPLIT",
    "SPLIT_LIMIT",
    "UNINTERPRETED",
    "documents",
    "record",
    "splittable",
]
