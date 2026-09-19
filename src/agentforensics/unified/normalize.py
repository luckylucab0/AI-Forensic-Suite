"""Turn a collection into a unified log, without building a case.

The short path. `afx ingest` builds a SQLite case, which is what an examiner wants for a
device they are going to work on for a week. This is for the other situation: a collection
came back from a fleet hunt, somebody wants the conversation in one ordered file they can
grep, hand to a colleague or load in the viewer, and a database is in the way.

It reads through the same source adapters and the same parsers as the ingest, deliberately.
Two code paths that both claim to normalize an agent's log would eventually disagree about
one, and there would be no way to tell which was right.

Ordering is stable and does not depend on a timestamp: an event with no time of its own is
still an event, and sorting by time alone would put every one of them in a heap at the top
with their file of origin lost. So the log is ordered by time where there is one, then by
the path and the position in the file, which is an order the same evidence always produces.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TextIO

from agentforensics.catalog import Catalogue
from agentforensics.ingest import events_for, open_source
from agentforensics.ingest.match import Matcher
from agentforensics.model import Event
from agentforensics.unified.format import PRODUCER, write


@dataclass
class NormalizeReport:
    """What one normalization did, in the terms a report will quote.

    The uncomfortable numbers are in here on purpose. A log of ten thousand events from a
    collection that also held forty files nobody could parse is a different piece of
    evidence from a log of ten thousand events from a collection that read cleanly, and
    only one of the two supports the sentence "this is what the agent did".
    """

    bundle_uuid: str
    source_kind: str
    source_path: str
    files: int = 0
    files_parsed: int = 0
    files_unsupported: int = 0
    files_failed: int = 0
    events: int = 0
    unparsed_records: int = 0
    # The part of that number which was read and has no verified mapping yet. Separate
    # because the endpoint query this log is compared against makes the same distinction:
    # a record it could not decode and a record it returned uninterpreted are different
    # answers, and a log summary that merged them would not match the hunt's.
    uninterpreted_records: int = 0
    agents: dict[str, int] = field(default_factory=dict)
    # Paths no catalogue entry claims. Each one is a lead: an agent nobody has catalogued,
    # or a gap in the catalogue. Kept in full rather than counted.
    unclaimed_paths: list[str] = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            f"{self.source_kind} source {self.source_path}",
            f"  collection {self.bundle_uuid}",
            f"  {self.files} file(s): {self.files_parsed} parsed, "
            f"{self.files_unsupported} with no parser, {self.files_failed} that failed",
            f"  {self.events} record(s) written",
        ]
        if self.agents:
            named = ", ".join(f"{name} {count}" for name, count in sorted(self.agents.items()))
            lines.append(f"  by agent: {named}")
        unreadable = self.unparsed_records - self.uninterpreted_records
        if unreadable:
            lines.append(
                f"  {unreadable} record(s) nothing could read, written to the log as "
                "unparsed.record rather than dropped"
            )
        if self.uninterpreted_records:
            lines.append(
                f"  {self.uninterpreted_records} record(s) read but in a format nobody has "
                "mapped, written to the log as unparsed.record with their content in raw"
            )
        if self.files_unsupported:
            lines.append(
                f"  {self.files_unsupported} file(s) were collected and have no parser. "
                "They are in the log as one artifact.fs record each, which says the file "
                "was there and when it was written, and nothing about its content."
            )
        if self.unclaimed_paths:
            shown = self.unclaimed_paths[:5]
            lines.append(
                f"  {len(self.unclaimed_paths)} path(s) no catalogue entry claims, "
                "which is a lead rather than a non-event:"
            )
            lines.extend(f"    {path}" for path in shown)
            if len(self.unclaimed_paths) > len(shown):
                lines.append(f"    ... and {len(self.unclaimed_paths) - len(shown)} more")
        return "\n".join(lines)


def normalize(
    path: Path,
    catalogue: Catalogue,
    *,
    kind: str | None = None,
) -> tuple[list[Event], NormalizeReport]:
    """Read a source and return its events in log order, plus what reading it cost.

    The events are collected into a list rather than streamed because they have to be
    ordered, and ordering needs all of them. A collection large enough for that to hurt is
    one that wants a case database instead, which is what `afx ingest` is for.
    """
    matcher = Matcher(catalogue)
    source = open_source(path, catalogue, kind, matcher)
    record = source.bundle()
    # Same source of truth as the case path, so a log and a case built from one collection
    # agree about the scope of an instruction file rather than disagreeing quietly.
    roots = tuple(getattr(source, "project_roots", ()) or ())
    report = NormalizeReport(
        bundle_uuid=record.bundle_uuid,
        source_kind=record.source_kind,
        source_path=record.source_path,
    )
    events: list[Event] = []

    for entry in source.entries():
        report.files += 1
        if entry.attribution == "none" and entry.collected:
            report.unclaimed_paths.append(entry.original_path)
        # The matcher goes in for the same reason it does on the case path: a file the
        # source attributed to a catalogue entry no parser handles is still read, under
        # another entry that claims it. A log that skipped those and a case that did not
        # would disagree about one collection, and this is the log the endpoint query is
        # compared against.
        read = events_for(record.bundle_uuid, entry, roots, matcher)
        if entry.collected and entry.local_path is not None:
            if read.parser is None:
                report.files_unsupported += 1
            elif read.detail:
                report.files_failed += 1
            else:
                report.files_parsed += 1
        report.unparsed_records += read.unparsed_records
        report.uninterpreted_records += read.uninterpreted_records
        events.extend(read.events)

    # A source can carry the same file twice, and re-reading a collection must not double a
    # log. Keyed by the event id, which is derived from provenance, so this is the same
    # idempotence the case database has.
    seen: set[str] = set()
    unique: list[Event] = []
    for event in events:
        if event.event_id in seen:
            continue
        seen.add(event.event_id)
        unique.append(event)

    unique.sort(key=_order)
    report.events = len(unique)
    for event in unique:
        report.agents[event.agent] = report.agents.get(event.agent, 0) + 1
    return unique, report


def write_log(
    path: Path,
    catalogue: Catalogue,
    handle: TextIO,
    *,
    kind: str | None = None,
    producer: str | None = PRODUCER,
) -> NormalizeReport:
    """Normalize a source straight into a handle."""
    events, report = normalize(path, catalogue, kind=kind)
    write(events, handle, producer=producer)
    return report


def _order(event: Event) -> tuple[int, str, str, str, str]:
    """The sort key, chosen so the same evidence always produces the same log.

    Undated events sort first rather than being dropped or given a made-up time. Their
    position is unknown, not early, and the leading flag is what says so: everything after
    the first dated record is in time order, and everything before it is not claimed to be.
    """
    return (
        0 if event.ts_utc is None else 1,
        event.ts_utc or "",
        event.provenance.original_path,
        event.provenance.locator or "",
        event.kind,
    )


__all__ = ["NormalizeReport", "normalize", "write_log"]
