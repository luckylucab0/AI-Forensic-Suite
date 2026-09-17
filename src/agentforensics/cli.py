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
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from agentforensics import __version__
from agentforensics.bundle import BundleError, verify_bundle
from agentforensics.catalog import CatalogueError, load_catalogue
from agentforensics.exporters import FORMATS
from agentforensics.exporters import render as render_collection_rules
from agentforensics.ingest import ingest as ingest_source
from agentforensics.model import Case, CaseError

EXIT_OK = 0
EXIT_FINDING = 1
EXIT_ERROR = 2
EXIT_NOTHING_FOUND = 3

# Subcommands that do not exist yet, listed so --help describes the tool being built
# rather than only the fragment that exists. A user can then tell a missing capability
# apart from an undocumented one.
_PLANNED = [
    ("timeline", "build and export a device-wide timeline"),
    ("scan", "run the YAML rule packs against a case"),
    ("export", "export a case, including the viewer's event shape"),
    ("serve", "serve the local read-only API and the viewer on 127.0.0.1"),
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
                        }
                        for agent in catalogue
                    ],
                    "artifacts": len(catalogue.artifacts),
                },
                indent=2,
                sort_keys=True,
            ),
        )
        return EXIT_OK

    for agent in catalogue:
        verified = sum(1 for a in agent.artifacts if a.is_verified)
        _write(
            sys.stdout,
            f"{agent.title} ({agent.agent}): {len(agent.artifacts)} artifacts, {verified} verified",
        )
        if args.os:
            groups = catalogue.by_priority(args.os)
            for priority, items in groups.items():
                names = [a.id for a in items if a.agent == agent.agent]
                if names:
                    _write(sys.stdout, f"  {priority:<10} {len(names)}")
    _write(sys.stdout, f"total: {len(catalogue.artifacts)} artifacts")
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

    case = sub.add_parser(
        "case",
        help="show what a case holds, and the counts that qualify it",
        description=cmd_case.__doc__,
    )
    case.add_argument("--case", required=True, help="case database")
    case.add_argument("--json", action="store_true")
    case.set_defaults(func=cmd_case)

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
