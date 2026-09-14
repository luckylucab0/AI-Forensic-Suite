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

EXIT_OK = 0
EXIT_FINDING = 1
EXIT_ERROR = 2
EXIT_NOTHING_FOUND = 3

# Subcommands that do not exist yet, listed so --help describes the tool being built
# rather than only the fragment that exists. A user can then tell a missing capability
# apart from an undocumented one.
_PLANNED = [
    ("ingest", "read a bundle, a KAPE tree or a Velociraptor collection into a case"),
    ("timeline", "build and export a device-wide timeline"),
    ("scan", "run the YAML rule packs against a case"),
    ("export", "export a case, including the viewer's event shape"),
    ("export-collection", "generate collection rules from the artifact catalogue"),
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
