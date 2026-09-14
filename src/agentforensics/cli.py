"""Command line entry point.

Kept deliberately thin: it parses arguments, dispatches, and turns exceptions into exit
codes. Everything else lives in the subpackages, so the behavior can be tested without
going through argv.

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
import sys
from collections.abc import Sequence

from agentforensics import __version__

EXIT_OK = 0
EXIT_FINDING = 1
EXIT_ERROR = 2
EXIT_NOTHING_FOUND = 3

# Subcommands arrive with the phase that implements them. Listing them here, unimplemented,
# is intentional: `--help` then describes the tool that is being built rather than only the
# fragment that exists, and there is one obvious place to register each one.
_PLANNED = [
    ("verify", "re-hash an evidence bundle and report mismatches"),
    ("ingest", "read a bundle, a KAPE tree or a Velociraptor collection into a case"),
    ("timeline", "build and export a device-wide timeline"),
    ("scan", "run the YAML rule packs against a case"),
    ("export", "export a case, including the viewer's event shape"),
    ("export-collection", "generate collection rules from the artifact catalogue"),
    ("serve", "serve the local read-only API and the viewer on 127.0.0.1"),
]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentforensics",
        description=(
            "Offline forensic suite for the on-disk history of AI coding agents. "
            "Use requires proper authorization; see the README."
        ),
        epilog=(
            "Planned subcommands: "
            + ", ".join(name for name, _ in _PLANNED)
            + ". None are implemented yet."
        ),
    )
    parser.add_argument("--version", action="version", version=f"agentforensics {__version__}")
    parser.add_subparsers(dest="command", metavar="<command>")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help(sys.stderr)
        return EXIT_ERROR

    # Not reachable while no subcommand is registered, since argparse rejects an unknown
    # positional before this point. It stays as the single place a dispatch table goes as
    # each phase lands, and parser.error() exits, so nothing follows it.
    parser.error(f"unknown command: {args.command}")


if __name__ == "__main__":
    sys.exit(main())
