"""Command line entry point.

Kept deliberately thin: it parses arguments, dispatches, and turns outcomes into exit
codes. Everything else lives in the subpackages, so behavior can be tested without going
through argv.

Exit codes are part of the interface, because this tool is driven from scripts and from
EDR live-response sessions where the only signal is the exit code:

    0  success
    1  the operation ran and found a problem (a verification mismatch, a rule hit)
    2  usage error, or the tool could not run at all
    3  nothing found, which is distinct from failure: a host with no agent artifacts is a
       valid and useful result, and a caller must be able to tell it apart from a crash
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import TextIO

from agentforensics import __version__
from agentforensics.bundle import BundleError, verify_bundle
from agentforensics.catalog import CatalogueError, load_catalogue
from agentforensics.exporters import FORMATS
from agentforensics.exporters import render as render_collection_rules
from agentforensics.ingest import ingest as ingest_source
from agentforensics.model import Case, CaseError
from agentforensics.rules import RuleError, ScanReport
from agentforensics.rules import load as load_rules
from agentforensics.rules import scan as run_scan
from agentforensics.rules import testing as rule_testing
from agentforensics.timeline import FORMATS as TIMELINE_FORMATS
from agentforensics.timeline import Filters, header_notes
from agentforensics.timeline import write as write_timeline
from agentforensics.unified import FORMAT_VERSION as UNIFIED_VERSION
from agentforensics.unified import write_log as write_unified_log
from agentforensics.webui import serve as serve_case

EXIT_OK = 0
EXIT_FINDING = 1
EXIT_ERROR = 2
EXIT_NOTHING_FOUND = 3

# Subcommands that do not exist yet, listed so --help describes the tool being built
# rather than only the fragment that exists. A user can then tell a missing capability
# apart from an undocumented one.
_PLANNED = [
    ("export", "export a case, including the viewer's event shape"),
]


def _write(stream: TextIO, text: str) -> None:
    """The single exit point for everything this CLI prints.

    Stray print() is forbidden by lint on purpose. A forensic tool's output is part of its
    interface: it is pasted into reports, captured by scripts and read in live-response
    sessions. Routing it through one place means a test can capture it, a future --quiet
    does not have to hunt for call sites, and nothing writes to stdout that was meant for
    stderr, which would corrupt a --json consumer.
    """
    stream.write(text + "\n")


def cmd_verify(args: argparse.Namespace) -> int:
    """Re-hash a bundle and report what does not match.

    Everything is re-derived from the bytes on disk, so a bundle can be checked by someone
    who did not collect it, offline, years later.
    """
    try:
        report = verify_bundle(Path(args.bundle))
    except BundleError as exc:
        _write(sys.stderr, f"verify: {exc}")
        return EXIT_ERROR

    if args.json:
        _write(
            sys.stdout,
            json.dumps(
                {
                    "bundle": str(report.bundle),
                    "collection_uuid": report.collection_uuid,
                    "format_version": report.format_version,
                    "ok": report.ok,
                    "checked": report.checked,
                    "skipped_by_policy": report.skipped_by_policy,
                    "missing": report.missing,
                    "mismatched": report.mismatched,
                    "unexpected": report.unexpected,
                    "inconsistent": report.inconsistent,
                    "custody_problems": report.custody_problems,
                    "changed_while_reading": report.changed_while_reading,
                },
                indent=2,
                sort_keys=True,
            ),
        )
    else:
        _write(sys.stderr, report.summary())
        for label, items in (
            ("missing from the bundle", report.missing),
            ("hash does not match", report.mismatched),
            ("present but not in the manifest", report.unexpected),
            ("manifest entry is inconsistent", report.inconsistent),
            ("custody chain", report.custody_problems),
        ):
            for item in items:
                _write(sys.stderr, f"  {label}: {item}")
        if report.changed_while_reading:
            _write(
                sys.stderr,
                f"  note: {len(report.changed_while_reading)} file(s) were being written "
                "while they were collected. The stored bytes match their recorded hash; "
                "the source was live.",
            )

    return EXIT_OK if report.ok else EXIT_FINDING


def cmd_catalog(args: argparse.Namespace) -> int:
    """Validate the catalogue and show what it covers."""
    try:
        catalogue = load_catalogue(Path(args.catalog))
    except CatalogueError as exc:
        _write(sys.stderr, f"catalog: {exc}")
        return EXIT_ERROR

    if args.json:
        _write(
            sys.stdout,
            json.dumps(
                {
                    "agents": [
                        {
                            "agent": agent.agent,
                            "title": agent.title,
                            "artifacts": len(agent.artifacts),
                            "verified": sum(1 for a in agent.artifacts if a.is_verified),
                            "parsed": sum(1 for a in agent.artifacts if a.parser),
                        }
                        for agent in catalogue
                    ],
                    "artifacts": len(catalogue.artifacts),
                    "parsed": sum(1 for a in catalogue.artifacts if a.parser),
                },
                indent=2,
                sort_keys=True,
            ),
        )
        return EXIT_OK

    for agent in catalogue:
        verified = sum(1 for a in agent.artifacts if a.is_verified)
        # Also how many of them anything can read. An analyst planning a collection needs
        # that number as much as the verified one: an artifact with no parser is collected
        # and lands in the case as a file, so a question it would have answered stays open.
        parsed = sum(1 for a in agent.artifacts if a.parser)
        _write(
            sys.stdout,
            f"{agent.title} ({agent.agent}): {len(agent.artifacts)} artifacts, "
            f"{verified} verified, {parsed} parsed",
        )
        if args.os:
            groups = catalogue.by_priority(args.os)
            for priority, items in groups.items():
                names = [a.id for a in items if a.agent == agent.agent]
                if names:
                    _write(sys.stdout, f"  {priority:<10} {len(names)}")
    parsed = sum(1 for a in catalogue.artifacts if a.parser)
    _write(
        sys.stdout,
        f"total: {len(catalogue.artifacts)} artifacts, {parsed} of them read by a parser. "
        "The rest are collected and land in a case as files.",
    )
    return EXIT_OK


def cmd_export_collection(args: argparse.Namespace) -> int:
    """Render the catalogue into other tools' collection-rule formats.

    Written to disk rather than to stdout because every format is several files, and the
    committed copy under exporters/generated is what CI checks for staleness.

    The exit code carries the one thing worth automating on: a format that could not
    express some of the catalogue exits 1, because a rule with gaps is still useful but
    whoever generated it needs to know it has them. The gaps are listed in each generated
    file's own header as well, since the person running the rule is not always the person
    who generated it.
    """
    try:
        catalogue = load_catalogue(Path(args.catalog))
    except CatalogueError as exc:
        _write(sys.stderr, f"export-collection: {exc}")
        return EXIT_ERROR

    try:
        rendered = render_collection_rules(catalogue, args.format)
    except ValueError as exc:
        _write(sys.stderr, f"export-collection: {exc}")
        return EXIT_ERROR

    out_dir = Path(args.out)
    written = []
    for item in rendered:
        target = out_dir / item.path
        target.parent.mkdir(parents=True, exist_ok=True)
        # newline="" so two platforms produce the same bytes: the committed copy is
        # compared byte for byte by the staleness check.
        with target.open("w", encoding="utf-8", newline="") as handle:
            handle.write(item.text)
        written.append(item)

    skipped = sum(len(item.skipped) for item in written)
    if args.json:
        _write(
            sys.stdout,
            json.dumps(
                {
                    "out": str(out_dir),
                    "files": [
                        {
                            "path": item.path,
                            "bytes": len(item.text.encode("utf-8")),
                            "not_covered": [
                                {"artifact_id": s.artifact_id, "reason": s.reason}
                                for s in item.skipped
                            ],
                        }
                        for item in written
                    ],
                },
                indent=2,
                sort_keys=True,
            ),
        )
    else:
        for item in written:
            note = f", {len(item.skipped)} not covered" if item.skipped else ""
            _write(sys.stdout, f"wrote {out_dir / item.path}{note}")
        _write(sys.stdout, f"total: {len(written)} file(s)")
        if skipped:
            _write(
                sys.stderr,
                f"note: {skipped} artifact/target pair(s) could not be expressed. Each "
                "generated file lists its own, with the reason. Run the suite's collector "
                "where the gap matters.",
            )

    return EXIT_FINDING if skipped else EXIT_OK


def cmd_ingest(args: argparse.Namespace) -> int:
    """Read a bundle, a collected tree or an exported profile into a case.

    Idempotent: the same evidence produces the same event identifiers, so re-running this
    after a parser is fixed rebuilds a case rather than doubling it.

    The exit code distinguishes the two results a caller has to tell apart. Nothing found
    exits 3, because a host with no agent artifacts is a valid and useful answer that must
    not look like a crash. A source that carried files nothing in the catalogue claims
    exits 1: that is a finding, either an agent nobody has catalogued or a gap in the
    catalogue, and it should not pass unnoticed in a script.
    """
    source = Path(args.source)
    if not source.exists():
        _write(sys.stderr, f"ingest: no such path: {source}")
        return EXIT_ERROR

    try:
        catalogue = load_catalogue(Path(args.catalog))
    except CatalogueError as exc:
        _write(sys.stderr, f"ingest: {exc}")
        return EXIT_ERROR

    try:
        case = Case.open(Path(args.case))
    except CaseError as exc:
        _write(sys.stderr, f"ingest: {exc}")
        return EXIT_ERROR

    try:
        report = ingest_source(case, source, catalogue, kind=args.kind)
    except (BundleError, OSError) as exc:
        _write(sys.stderr, f"ingest: {exc}")
        return EXIT_ERROR
    finally:
        case.close()

    if args.json:
        _write(
            sys.stdout,
            json.dumps(
                {
                    "case": str(args.case),
                    "bundle_uuid": report.bundle_uuid,
                    "source_kind": report.source_kind,
                    "source_path": report.source_path,
                    "artifacts": report.artifacts,
                    "collected": report.collected,
                    "attributed_by_collector": report.attributed_by_collector,
                    "attributed_by_path": report.attributed_by_path,
                    "unattributed": report.unattributed,
                    "events": report.events,
                    "gaps": report.gaps,
                    "unclaimed_paths": report.unclaimed_paths,
                },
                indent=2,
                sort_keys=True,
            ),
        )
    else:
        _write(sys.stdout, report.summary())

    if report.artifacts == 0:
        return EXIT_NOTHING_FOUND
    return EXIT_FINDING if report.unclaimed_paths else EXIT_OK


def cmd_normalize(args: argparse.Namespace) -> int:
    """Turn a collection into one vendor-neutral log, without building a case.

    The short path. `ingest` builds a SQLite case, which is what an examiner wants for a
    device they will work on for a week. This is for the other situation: a collection came
    back from a fleet hunt and somebody wants the conversation as one ordered file they can
    grep, hand over, or open in the viewer.

    It reads through the same adapters and the same parsers as `ingest`, so the two cannot
    disagree about what an agent's log says.

    The exit code distinguishes the answers a caller has to tell apart. Nothing found exits
    3, because a host with no agent artifacts is a valid result and must not look like a
    crash. A collection carrying paths nothing in the catalogue claims exits 1: an agent
    nobody has catalogued, or a gap in the catalogue, and either is a finding.
    """
    source = Path(args.source)
    if not source.exists():
        _write(sys.stderr, f"normalize: no such path: {source}")
        return EXIT_ERROR

    try:
        catalogue = load_catalogue(Path(args.catalog))
    except CatalogueError as exc:
        _write(sys.stderr, f"normalize: {exc}")
        return EXIT_ERROR

    try:
        if args.out:
            destination = Path(args.out)
            destination.parent.mkdir(parents=True, exist_ok=True)
            # newline="" so that two platforms produce the same bytes. A log gets hashed
            # and compared, and a CRLF translation would break that for no gain.
            with destination.open("w", encoding="utf-8", newline="") as handle:
                report = write_unified_log(source, catalogue, handle, kind=args.kind)
        else:
            report = write_unified_log(source, catalogue, sys.stdout, kind=args.kind)
    except (BundleError, OSError) as exc:
        _write(sys.stderr, f"normalize: {exc}")
        return EXIT_ERROR

    # On stderr always, even without --out, so that a log written to stdout stays a clean
    # stream while the numbers that qualify it still reach the operator.
    _write(sys.stderr, f"normalize: unified agent log, format version {UNIFIED_VERSION}")
    for line in report.summary().splitlines():
        _write(sys.stderr, f"normalize: {line}")

    if report.files == 0:
        return EXIT_NOTHING_FOUND
    return EXIT_FINDING if report.unclaimed_paths else EXIT_OK


def cmd_case(args: argparse.Namespace) -> int:
    """Show what a case holds, including the numbers that qualify it.

    The uncomfortable counts are here on purpose. How many files were collected and not
    read, how many records no parser could parse, how many events have no timestamp, and
    how many holes the collection itself reported. A case summary that showed only what
    was understood would read as completeness.
    """
    try:
        case = Case.open(Path(args.case), create=False)
    except CaseError as exc:
        _write(sys.stderr, f"case: {exc}")
        return EXIT_ERROR

    try:
        counts = case.counts()
        bundles = case.query(
            "SELECT bundle_uuid, source_kind, source_path, collected_host, collected_os, "
            "started_utc FROM bundles ORDER BY bundle_uuid"
        )
        agents = case.query(
            "SELECT agent, count(*) AS events FROM events GROUP BY agent ORDER BY events DESC"
        )
    finally:
        case.close()

    if args.json:
        _write(
            sys.stdout,
            json.dumps(
                {
                    "counts": counts,
                    "bundles": [dict(row) for row in bundles],
                    "agents": [dict(row) for row in agents],
                },
                indent=2,
                sort_keys=True,
            ),
        )
        return EXIT_OK

    for row in bundles:
        host = row["collected_host"] or "unknown host"
        _write(
            sys.stdout,
            f"{row['bundle_uuid']}  {row['source_kind']:<12} {host} ({row['collected_os'] or '?'})",
        )
    for row in agents:
        _write(sys.stdout, f"  {row['agent']:<18} {row['events']} event(s)")
    _write(
        sys.stdout,
        f"total: {counts['events']} event(s) from {counts['artifacts_collected']} "
        f"collected file(s) of {counts['artifacts']} recorded",
    )
    # Said on stderr so that a --json consumer and a piped summary stay clean, and said
    # every time rather than only when it looks bad.
    _write(
        sys.stderr,
        f"qualifications: {counts['artifacts_unparsed']} collected file(s) no parser read, "
        f"{counts['events_unparsed']} record(s) that could not be parsed, "
        f"{counts['events_without_timestamp']} event(s) with no timestamp, "
        f"{counts['collection_gaps']} gap(s) reported by the collection itself",
    )
    return EXIT_OK


def cmd_timeline(args: argparse.Namespace) -> int:
    """Export a device-wide timeline from a case.

    One ordered sequence across every agent, which is what the unified event model is for.
    Events with no timestamp are listed first rather than omitted: their position is
    unknown, not early, and leaving them out would make them invisible in the view an
    analyst reads first.

    The notes printed on stderr are not decoration. A timeline is the view that gets
    trusted most and questioned least, so the counts that qualify it, unreadable records,
    files with no parser, holes the collection reported, travel with it.
    """
    try:
        case = Case.open(Path(args.case), create=False)
    except CaseError as exc:
        _write(sys.stderr, f"timeline: {exc}")
        return EXIT_ERROR

    filters = Filters(
        agents=tuple(args.agent or ()),
        kinds=tuple(args.kind or ()),
        since=args.since,
        until=args.until,
        session_id=args.session,
        exclude_artifact_fs=args.no_filesystem_events,
    )

    try:
        if args.out:
            destination = Path(args.out)
            destination.parent.mkdir(parents=True, exist_ok=True)
            # newline="" because csv writes its own line terminator, and so that two
            # platforms produce the same bytes: a timeline gets hashed and compared.
            with destination.open("w", encoding="utf-8", newline="") as handle:
                written, undated = write_timeline(case, handle, args.format, filters)
        else:
            written, undated = write_timeline(case, sys.stdout, args.format, filters)
        notes = header_notes(case, written, undated, args.format)
    except (OSError, ValueError) as exc:
        _write(sys.stderr, f"timeline: {exc}")
        return EXIT_ERROR
    finally:
        case.close()

    for note in notes:
        _write(sys.stderr, f"timeline: {note}")
    if written == 0:
        return EXIT_NOTHING_FOUND
    return EXIT_OK


def cmd_scan(args: argparse.Namespace) -> int:
    """Run the rule packs over a case, and record what they found.

    Every rule that ran is recorded whether or not it fired, because a case with no
    findings and a case nobody scanned look identical otherwise, and those are opposite
    conclusions. The same reason the collector records a glob it declined to search.

    Re-running is safe: a finding is keyed by the rule and the events it rests on, so a
    second scan of one case leaves it unchanged rather than doubling its findings. That is
    what lets an analyst re-scan after a rule is fixed without wondering whether the counts
    are now wrong.

    --self-test runs each rule's own positive and negative samples and nothing else. It
    reads no case and needs none, so an operator handed a rule pack can check it with the
    same runner that checked it here.

    The exit code says which of three things happened. A finding exits 1, because a scan
    whose whole purpose is to find something should be distinguishable in a script from one
    that found nothing. Nothing found exits 3. A case that could not be read exits 2.
    """
    try:
        rules = load_rules(Path(args.rules) if args.rules else None, packs=args.pack)
    except RuleError as exc:
        _write(sys.stderr, f"scan: {exc}")
        return EXIT_ERROR

    if args.self_test:
        problems: list[str] = []
        for rule in rules:
            problems.extend(rule_testing.run(rule))
        samples = sum(len(rule.tests) for rule in rules)
        _write(
            sys.stdout,
            f"scan: {len(rules)} rule(s), {samples} sample(s) from the rules' own files",
        )
        for line in problems:
            _write(sys.stderr, f"scan: {line}")
        if problems:
            return EXIT_FINDING
        _write(sys.stdout, "scan: every rule agrees with its own tests")
        return EXIT_OK

    if not args.case:
        _write(sys.stderr, "scan: --case is required unless --self-test is given")
        return EXIT_ERROR

    try:
        case = Case.open(Path(args.case), create=False)
    except CaseError as exc:
        _write(sys.stderr, f"scan: {exc}")
        return EXIT_ERROR

    try:
        report = run_scan(case, rules, store=not args.no_store)
    except (OSError, CaseError) as exc:
        _write(sys.stderr, f"scan: {exc}")
        return EXIT_ERROR
    finally:
        case.close()

    if args.out:
        try:
            _write_findings(report, Path(args.out), args.format)
        except OSError as exc:
            _write(sys.stderr, f"scan: {exc}")
            return EXIT_ERROR

    if args.json:
        _write(sys.stdout, json.dumps(_scan_json(report), indent=2, sort_keys=True))
    else:
        _write(sys.stdout, report.summary())
        for finding in report.findings:
            _write(sys.stdout, f"  [{finding.rule.severity}] {finding.rule.id} {finding.summary}")

    if not report.findings:
        return EXIT_NOTHING_FOUND
    return EXIT_FINDING


def _scan_json(report: ScanReport) -> dict[str, object]:
    return {
        "run_id": report.run_id,
        "started_utc": report.started_utc,
        "finished_utc": report.finished_utc,
        "events_read": report.events_read,
        "rules_run": report.rules_run,
        "by_severity": report.by_severity(),
        # Named, not counted. A rule that ran and matched nothing is what makes an empty
        # result a statement rather than an absence.
        "rules_that_matched_nothing": report.silent,
        "events_no_rule_applied": report.events_no_rule_applied,
        "findings": [
            {
                "finding_id": finding.finding_id,
                "rule_id": finding.rule.id,
                "pack": finding.rule.pack,
                "severity": finding.rule.severity,
                "title": finding.rule.title,
                "ts_utc": finding.ts_utc,
                "agent": finding.agent,
                "user": finding.user,
                "session_id": finding.session_id,
                "summary": finding.summary,
                "matched": finding.matched,
                "event_ids": list(finding.event_ids),
                "rule_sha256": finding.rule.sha256,
            }
            for finding in report.findings
        ],
    }


def _write_findings(report: ScanReport, destination: Path, fmt: str) -> None:
    """Write the findings to a file, as JSON or as CSV.

    CSV because a findings list gets opened in a spreadsheet and sorted by severity more
    often than it gets parsed, and JSON because the same list gets fed to a ticketing
    system. Both carry the event ids, so a row in either can be taken back to the evidence.
    """
    destination.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "json":
        destination.write_text(
            json.dumps(_scan_json(report), indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return

    import csv

    columns = [
        "finding_id",
        "severity",
        "rule_id",
        "pack",
        "title",
        "ts_utc",
        "agent",
        "user",
        "session_id",
        "summary",
        "matched",
        "event_count",
        "event_ids",
        "rule_sha256",
    ]
    # newline="" because csv writes its own terminator, and so that two platforms produce
    # the same bytes: a findings export gets hashed and attached to a report.
    with destination.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(columns)
        for finding in report.findings:
            writer.writerow(
                [
                    finding.finding_id,
                    finding.rule.severity,
                    finding.rule.id,
                    finding.rule.pack,
                    finding.rule.title,
                    finding.ts_utc or "",
                    finding.agent or "",
                    finding.user or "",
                    finding.session_id or "",
                    finding.summary,
                    json.dumps(finding.matched, sort_keys=True, ensure_ascii=False),
                    len(finding.event_ids),
                    " ".join(finding.event_ids),
                    finding.rule.sha256,
                ]
            )


def _announce(lines: Iterable[str]) -> None:
    """The startup notice, on stderr so a piped stdout stays clean."""
    for line in lines:
        _write(sys.stderr, line)


def cmd_serve(args: argparse.Namespace) -> int:
    """Serve one case to a browser on 127.0.0.1, read-only, and nothing else.

    The viewer is the same single file an analyst can open on its own; served from here it
    reads the case through a local API instead of a directory of transcripts, which is what
    lets one page show every agent in the case, the device-wide timeline, the rule findings
    and the list of what was collected and never read.

    Three properties are the point, and all three are enforced rather than promised. The
    socket binds loopback and there is no option to change it. The case is opened read-only,
    so SQLite itself refuses a write. Every URL lives under a token generated for this run
    and printed below, so a page already open in the analyst's browser cannot read the case
    by guessing the address.

    Nothing leaves the machine: no telemetry, no update check, and a content security
    policy that forbids the page from loading or contacting anything off this server.
    """
    case_path = Path(args.case)
    try:
        serve_case(
            case_path,
            port=args.port,
            viewer=Path(args.viewer) if args.viewer else None,
            log=(lambda line: _write(sys.stderr, f"serve: {line}")) if args.access_log else None,
            announce=_announce,
        )
    except (CaseError, FileNotFoundError) as exc:
        _write(sys.stderr, f"serve: {exc}")
        return EXIT_ERROR
    except OSError as exc:
        # Almost always the port being taken. Said with the remedy, because this is the
        # kind of failure that gets read once and acted on immediately.
        _write(
            sys.stderr,
            f"serve: cannot listen on 127.0.0.1:{args.port}: {exc}. "
            "Use --port to pick another, or --port 0 to let the system choose one.",
        )
        return EXIT_ERROR
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentforensics",
        description=(
            "Offline forensic suite for the on-disk history of AI coding agents. "
            "Use requires proper authorization; see the README."
        ),
        epilog=(
            "Planned but not implemented yet: " + ", ".join(name for name, _ in _PLANNED) + "."
        ),
    )
    parser.add_argument("--version", action="version", version=f"agentforensics {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    verify = sub.add_parser(
        "verify",
        help="re-hash an evidence bundle and report mismatches",
        description=cmd_verify.__doc__,
    )
    verify.add_argument("bundle", help="path to the bundle directory")
    verify.add_argument("--json", action="store_true", help="machine-readable report")
    verify.set_defaults(func=cmd_verify)

    catalog = sub.add_parser(
        "catalog",
        help="validate the artifact catalogue and summarise its coverage",
        description=cmd_catalog.__doc__,
    )
    catalog.add_argument("--catalog", default="catalog", help="catalogue directory")
    catalog.add_argument(
        "--os",
        choices=("macos", "windows", "linux"),
        help="also break the count down by collection priority for one platform",
    )
    catalog.add_argument("--json", action="store_true")
    catalog.set_defaults(func=cmd_catalog)

    export = sub.add_parser(
        "export-collection",
        help="generate collection rules for other tooling from the artifact catalogue",
        description=cmd_export_collection.__doc__,
    )
    export.add_argument("--catalog", default="catalog", help="catalogue directory")
    export.add_argument(
        "--out",
        default="exporters/generated",
        help="directory to write into. The committed copy lives at the default.",
    )
    export.add_argument(
        "--format",
        action="append",
        choices=sorted(FORMATS),
        help="only this format, repeatable. Default: every format.",
    )
    export.add_argument("--json", action="store_true", help="machine-readable report")
    export.set_defaults(func=cmd_export_collection)

    ingest = sub.add_parser(
        "ingest",
        help="read a bundle, a collected tree or an exported profile into a case",
        description=cmd_ingest.__doc__,
    )
    ingest.add_argument("source", help="bundle directory, collected tree, or profile")
    ingest.add_argument("--case", required=True, help="case database to create or add to")
    ingest.add_argument("--catalog", default="catalog", help="catalogue directory")
    ingest.add_argument(
        "--kind",
        choices=("native", "kape", "velociraptor", "directory"),
        help="override the detected source kind. A bundle with a manifest is always read "
        "as native whatever this says, because the manifest is the only record of what "
        "the endpoint knew.",
    )
    ingest.add_argument("--json", action="store_true", help="machine-readable report")
    ingest.set_defaults(func=cmd_ingest)

    normalize = sub.add_parser(
        "normalize",
        help="turn a collection into one vendor-neutral agent log",
        description=cmd_normalize.__doc__,
    )
    normalize.add_argument("source", help="bundle directory, collected tree, or profile")
    normalize.add_argument("--catalog", default="catalog", help="catalogue directory")
    normalize.add_argument(
        "--out", help="write to a file instead of stdout. The summary goes to stderr either way."
    )
    normalize.add_argument(
        "--kind",
        choices=("native", "kape", "velociraptor", "directory"),
        help="override the detected source kind",
    )
    normalize.set_defaults(func=cmd_normalize)

    case = sub.add_parser(
        "case",
        help="show what a case holds, and the counts that qualify it",
        description=cmd_case.__doc__,
    )
    case.add_argument("--case", required=True, help="case database")
    case.add_argument("--json", action="store_true")
    case.set_defaults(func=cmd_case)

    scan = sub.add_parser(
        "scan",
        help="run the YAML rule packs over a case",
        description=cmd_scan.__doc__,
    )
    scan.add_argument("--case", help="case database to scan. Not needed with --self-test.")
    scan.add_argument(
        "--rules",
        help="rule directory. Defaults to rules/ next to the working directory.",
    )
    scan.add_argument(
        "--pack",
        action="append",
        help="only this pack, repeatable. Default: every pack in the directory.",
    )
    scan.add_argument(
        "--self-test",
        action="store_true",
        help="run each rule's own positive and negative samples and exit. Reads no case.",
    )
    scan.add_argument("--out", help="write the findings to this file as well")
    scan.add_argument(
        "--format",
        choices=("csv", "json"),
        default="csv",
        help="format for --out. Default csv, because a findings list is sorted in a "
        "spreadsheet more often than it is parsed.",
    )
    scan.add_argument(
        "--no-store",
        action="store_true",
        help="do not write the findings into the case. For trying a rule out against a "
        "case somebody else will read later.",
    )
    scan.add_argument("--json", action="store_true", help="machine-readable report on stdout")
    scan.set_defaults(func=cmd_scan)

    serve = sub.add_parser(
        "serve",
        help="serve the case and the viewer to a browser on 127.0.0.1",
        description=cmd_serve.__doc__,
    )
    serve.add_argument("--case", required=True, help="case database to serve")
    serve.add_argument(
        "--port",
        type=int,
        default=8765,
        help="port on 127.0.0.1. 0 lets the system pick one, which is printed. Default 8765.",
    )
    serve.add_argument(
        "--viewer",
        help="path to the viewer HTML file. Defaults to the copy shipped with this build.",
    )
    serve.add_argument(
        "--access-log",
        action="store_true",
        help="log every request to stderr. Off by default: a request line carries the "
        "access token, and a terminal scrollback is a place a token gets left behind.",
    )
    serve.set_defaults(func=cmd_serve)

    timeline = sub.add_parser(
        "timeline",
        help="export a device-wide timeline from a case",
        description=cmd_timeline.__doc__,
    )
    timeline.add_argument("--case", required=True, help="case database")
    timeline.add_argument(
        "--format", choices=sorted(TIMELINE_FORMATS), default="csv", help="output format"
    )
    timeline.add_argument("--out", help="write to a file instead of stdout")
    timeline.add_argument("--agent", action="append", help="only this agent, repeatable")
    timeline.add_argument("--kind", action="append", help="only this event kind, repeatable")
    timeline.add_argument("--session", help="only this session id")
    timeline.add_argument("--since", help="only events at or after this UTC timestamp")
    timeline.add_argument("--until", help="only events at or before this UTC timestamp")
    timeline.add_argument(
        "--no-filesystem-events",
        action="store_true",
        help="leave out the one-per-file artifact.fs events. They can outnumber the "
        "conversation on a large collection, and for an artifact with no internal "
        "timestamps they are the only temporal evidence there is.",
    )
    timeline.set_defaults(func=cmd_timeline)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help(sys.stderr)
        return EXIT_ERROR

    handler = getattr(args, "func", None)
    if handler is None:
        parser.error(f"unknown command: {args.command}")
    result: int = handler(args)
    return result


if __name__ == "__main__":
    sys.exit(main())
