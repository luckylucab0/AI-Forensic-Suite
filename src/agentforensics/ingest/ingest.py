"""Drive a source into a case.

The one function that owns the order of operations, because the order is what makes the
case trustworthy. Every file the source carried is recorded before any of it is parsed, so
that a case can always answer the question its own reliability rests on: what did we
collect and fail to read. A pipeline that only wrote rows for the files it understood would
make an unparsed transcript indistinguishable from an agent that was never used.

A parser is chosen by the catalogue entry that claimed the file, so the catalogue stays the
one source of truth: nothing here decides what a file is from its name or its contents. A
file no parser handles keeps a status of 'unsupported' and its filesystem event, which
already answers when an agent last wrote anything.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from agentforensics.catalog import Catalogue
from agentforensics.ingest.match import Matcher
from agentforensics.ingest.native import NativeBundle
from agentforensics.ingest.source import Source, SourceEntry
from agentforensics.ingest.tree import CollectedTree
from agentforensics.model import Case, Event, Provenance
from agentforensics.parsers import ParseContext, for_artifact


@dataclass
class IngestReport:
    """What one ingest did, in the terms a report will quote."""

    bundle_uuid: str
    source_kind: str
    source_path: str
    artifacts: int = 0
    collected: int = 0
    attributed_by_collector: int = 0
    attributed_by_path: int = 0
    unattributed: int = 0
    events: int = 0
    parsed_records: int = 0
    # Records a parser reached and could not read. Reported separately from the events
    # because it is the number that qualifies everything else: a case with a thousand
    # events and two hundred unreadable records is a different case from one with a
    # thousand events and none.
    unparsed_records: int = 0
    gaps: int = 0
    # Paths nothing in the catalogue claimed. Kept as a list rather than a count because
    # each one is a lead: an agent nobody has catalogued, or a gap in the catalogue.
    unclaimed_paths: list[str] = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            f"{self.source_kind} source {self.source_path}",
            f"  bundle {self.bundle_uuid}",
            f"  {self.artifacts} artifact(s) recorded, {self.collected} with content",
            f"  attribution: {self.attributed_by_collector} by the collector, "
            f"{self.attributed_by_path} matched from the path, {self.unattributed} unclaimed",
            f"  {self.events} event(s)",
        ]
        if self.unparsed_records:
            lines.append(
                f"  {self.unparsed_records} record(s) no parser could read, kept in the "
                "case as unparsed events"
            )
        if self.gaps:
            lines.append(f"  {self.gaps} gap(s) in the collection, recorded in the case")
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


@dataclass(frozen=True)
class EntryEvents:
    """Everything reading one collected file produced.

    Public because two callers need it: the ingest that writes a case, and the normalizer
    that writes a unified log without one. Sharing this rather than duplicating the loop is
    what stops the two paths from reading the same file differently, which would show up as
    a case and a log that disagree with no way to tell which is right.
    """

    events: list[Event]
    # How many of the events came from a parser rather than from the filesystem. Counted
    # separately because "records read out of this file" is a statement about the agent's
    # own log, and the one artifact.fs event per file is not one of them.
    parser_events: int
    unparsed_records: int
    parser: str | None
    detail: str | None

    @property
    def status(self) -> str:
        """How the file read, in the words the case and the report both use."""
        if self.parser is None:
            return "unsupported"
        if self.detail:
            return "failed"
        return "parsed"


def events_for(bundle_uuid: str, entry: SourceEntry) -> EntryEvents:
    """Read one collected file: its filesystem event, then whatever a parser makes of it.

    The filesystem event comes first and comes always. For an artifact with no internal
    timestamps it is the only temporal evidence there is, and a file no parser understands
    still has to appear on a timeline.
    """
    events = list(_filesystem_events(bundle_uuid, entry))
    parsed, unreadable, parser_name, detail = _parse(bundle_uuid, entry)
    events.extend(parsed)
    return EntryEvents(
        events=events,
        parser_events=len(parsed),
        unparsed_records=unreadable,
        parser=parser_name,
        detail=detail,
    )


def open_source(path: Path, catalogue: Catalogue, kind: str | None = None) -> Source:
    """The adapter for a path.

    The native one whenever a manifest is there, whatever the caller asked for: a manifest
    is the only record of what the endpoint knew, and reading a native bundle as a plain
    tree would throw that away and replace it with guesses.
    """
    from agentforensics.ingest import detect

    if NativeBundle.looks_like(path):
        return NativeBundle(path)
    resolved = kind or detect(path)
    return CollectedTree(path, Matcher(catalogue), source_kind=resolved)


def ingest(
    case: Case,
    path: Path,
    catalogue: Catalogue,
    *,
    kind: str | None = None,
) -> IngestReport:
    """Read one source into a case, and report what came of it."""
    source = open_source(path, catalogue, kind)
    record = source.bundle()
    report = IngestReport(
        bundle_uuid=record.bundle_uuid,
        source_kind=record.source_kind,
        source_path=record.source_path,
    )

    with case.transaction():
        case.add_bundle(record)
        for entry in source.entries():
            case.add_artifact(record.bundle_uuid, entry.manifest_entry())
            report.artifacts += 1
            if entry.collected and entry.local_path is not None:
                report.collected += 1
            if entry.attribution == "collector":
                report.attributed_by_collector += 1
            elif entry.attribution == "path":
                report.attributed_by_path += 1
            else:
                report.unattributed += 1
                if entry.collected:
                    report.unclaimed_paths.append(entry.original_path)

            read = events_for(record.bundle_uuid, entry)
            report.events += case.add_events(read.events)
            report.parsed_records += read.parser_events - read.unparsed_records
            report.unparsed_records += read.unparsed_records

            status, detail = read.status, read.detail
            if not entry.collected or entry.local_path is None:
                status, detail = (
                    "skipped",
                    (detail or entry.reason or "the collection did not carry this file's content"),
                )
            case.set_parse_result(
                record.bundle_uuid,
                entry.original_path,
                parser=read.parser,
                status=status,
                detail=detail,
                events=len(read.events),
                unparsed_records=read.unparsed_records,
            )

        for gap in source.gaps():
            case.add_gap(record.bundle_uuid, gap.kind, gap.detail, gap.reason)
            report.gaps += 1

        if report.unattributed:
            # Recorded as a gap as well as in the report, because the report is printed once
            # and the case is read for years.
            case.add_gap(
                record.bundle_uuid,
                "unattributed_files",
                f"{report.unattributed} file(s)",
                "No catalogue entry claims these paths. Either an agent that is not "
                "catalogued yet, or a gap in the catalogue. Both are findings.",
            )

    case.set_meta("last_ingest", record.bundle_uuid)
    return report


def _parse(bundle_uuid: str, entry: SourceEntry) -> tuple[list[Event], int, str | None, str | None]:
    """Run the parser for one file, if there is one.

    Returns its events, how many of them are unreadable records, the parser's name and a
    failure detail. A parser that raises is caught here: one malformed file must not abandon
    the rest of a collection, and the exception itself becomes a recorded parse failure
    rather than a traceback an analyst has to interpret.
    """
    if not entry.collected or entry.local_path is None:
        return [], 0, None, None
    parser = for_artifact(entry.artifact_id)
    if parser is None:
        return [], 0, None, None
    context = ParseContext(
        bundle_uuid=bundle_uuid,
        original_path=entry.original_path,
        local_path=entry.local_path,
        sha256=entry.sha256 or "",
        artifact_id=entry.artifact_id,
        agent=entry.agent or parser.name,
        user=entry.user,
    )
    try:
        events = list(parser.parse(context))
    except Exception as exc:
        return [], 0, parser.name, f"the parser raised {type(exc).__name__}: {exc}"
    unreadable = sum(1 for event in events if event.kind == "unparsed.record")
    return events, unreadable, parser.name, None


def _filesystem_events(bundle_uuid: str, entry: SourceEntry) -> list[Event]:
    """The artifact.fs event for one file.

    Its own event kind because a great many artifacts carry no internal timestamps at all,
    and for those the only temporal evidence is when the file was written. Without this the
    instruction files, the configuration snapshots and the credential stores would be
    absent from every timeline, and an analyst would see a gap where there was evidence.

    Modification time is preferred for the event's own timestamp because it is the one an
    agent's own write sets. Creation time is carried in the payload rather than used,
    because on a copied tree it is usually the copy's.
    """
    if not entry.collected and entry.local_path is None and entry.mtime_utc is None:
        # Nothing was collected and no timestamp was recorded: there is nothing to put on a
        # timeline. The artifacts row already says the path was there.
        return []
    provenance = Provenance(
        bundle_uuid=bundle_uuid,
        original_path=entry.original_path,
        sha256=entry.sha256 or "",
        artifact_id=entry.artifact_id,
        locator="fs",
    )
    ts = entry.mtime_utc
    return [
        Event(
            kind="artifact.fs",
            provenance=provenance,
            agent=entry.agent or "unknown",
            raw={
                "original_path": entry.original_path,
                "sha256": entry.sha256,
                "size": entry.size,
                "mtime_utc": entry.mtime_utc,
                "atime_utc": entry.atime_utc,
                "ctime_utc": entry.ctime_utc,
                "birthtime_utc": entry.birthtime_utc,
                "symlink": entry.symlink,
                "collected": entry.collected,
                "reason": entry.reason,
            },
            ts_utc=ts,
            ts_precision="filesystem" if ts else "absent",
            ts_source="mtime" if ts else None,
            actor="system",
            user=entry.user,
            payload={
                "path": entry.original_path,
                "artifact_status": entry.status,
                "attribution": entry.attribution,
                "also_claimed_by": list(entry.also_claimed_by),
                "size": entry.size,
                "atime_utc": entry.atime_utc,
                "ctime_utc": entry.ctime_utc,
                "birthtime_utc": entry.birthtime_utc,
                "files": [
                    {"path": entry.original_path, "operation": "snapshot", "bytes": entry.size}
                ],
            },
            parse_problem=None
            if entry.attribution != "none"
            else "no catalogue entry claims this path",
        )
    ]


__all__ = ["IngestReport", "ingest", "open_source"]
