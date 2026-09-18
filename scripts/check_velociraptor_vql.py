#!/usr/bin/env python3
"""Run the generated Velociraptor unified-log artifact and check what it returns.

The rest of this repository's tests read the generated VQL as text. That catches a query
that does not parse and a column that is spelled two ways, and it cannot catch what only
an engine knows: that `count()` accumulates across a `foreach` unless it is called through
a stored query, that `parse_jsonl` skips a line it cannot decode, that a buffered line
reader stops at a long line and takes the rest of the file with it. Every one of those
produces a collection that runs clean and reports less than was there, which is the single
failure this project exists to prevent. So this script exists to run the thing.

It needs a VQL engine, which this repository does not ship and cannot: Velociraptor is a
separate project with its own release binaries. There are two ways to give it one.

  * `--velociraptor <binary>`, a Velociraptor release binary. This script builds the
    command line itself, from the vendor's own command definition.
  * `--runner <program>`, anything that takes a file of VQL and a JSON Lines output path,
    which is what a local build of the VQL library gives you.

Without either the script exits 0 and says it did nothing, so it can sit in CI
unconditionally and start checking the moment a binary is available.

**The sandbox is the important part of this file.** A collection artifact's whole job is to
go and find agent data wherever it lives, so running one on a developer's machine would read
that developer's own agent history, and this project's second rule is that real agent data
never reaches a test, a fixture, a log or a summary. The protection here is not a filter
applied afterwards. Every glob in the artifact is rewritten to sit under one sandbox
directory, and the sandbox holds nothing but a synthetic profile. A path that came back from
outside it would mean the rewrite missed a glob, which is a defect in this script, so the
script fails on the first such path rather than reporting a result.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import yaml

REPO = Path(__file__).resolve().parent.parent
ARTIFACT = (
    REPO / "exporters" / "generated" / "velociraptor" / "Custom.Forensics.AIAgents.UnifiedLog.yaml"
)
SCHEMA = REPO / "src" / "agentforensics" / "unified" / "agentlog.v1.schema.json"

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_ERROR = 2

# The profile roots the artifact's globs are anchored at, per platform. Every one of them
# has to be rewritten, because a single one left alone is a glob pointing at the real
# machine. The list is asserted against the artifact itself below, so a new root added to
# the exporter fails here rather than quietly escaping the sandbox.
PROFILE_ROOTS = (
    "/Users/*/",
    "/var/root/",
    "/home/*/",
    "/root/",
    "C:/Users/*/",
)

# Where the synthetic profile is placed inside the sandbox, one per platform root, so that
# the rewritten globs have something to match.
PROFILE_PLACEMENTS = {
    "macos": ("Users/alice", "var/root"),
    "linux": ("home/alice", "root"),
    # A directory literally named "C:" is legal on a POSIX filesystem, which is what lets
    # the Windows source's drive-letter globs be exercised from Linux. The user-name regex
    # in that source is spelled with backslashes and will not resolve here, so ProfileUser
    # comes back null for Windows rows in this harness. That is the harness, not the query.
    "windows": ("C:/Users/alice",),
}


def parameters(document: dict[str, Any]) -> str:
    """The artifact's parameters as VQL, for a runner that evaluates a bare query.

    Read from the artifact rather than hardcoded, so a parameter added to the exporter
    reaches this script without anybody remembering to.
    """
    lines = []
    for parameter in document.get("parameters", []):
        name = parameter["name"]
        default = parameter.get("default", "")
        if parameter.get("type") == "bool":
            value = "TRUE" if str(default).upper() in ("Y", "TRUE", "1") else "FALSE"
        elif parameter.get("type") in ("int", "int64"):
            value = str(int(default or 0))
        else:
            value = "'" + str(default).replace("'", "") + "'"
        lines.append(f"LET {name} = {value}")
    return "\n".join(lines)


def sandbox_query(document: dict[str, Any], os_name: str, sandbox: Path) -> str:
    """One platform's query, with every glob moved under the sandbox."""
    source = next(s for s in document["sources"] if s["name"] == os_name)
    query = str(source["query"])

    found = [root for root in PROFILE_ROOTS if root in query]
    if not found:
        raise SystemExit(
            f"{os_name}: none of the known profile roots appear in this query, so the "
            "rewrite below would not move anything and the run would read the real "
            "machine. Update PROFILE_ROOTS in this script to match the exporter."
        )
    # One pass, longest root first. Replacing them one after another is wrong and was wrong
    # here: rewriting /var/root/ to <sandbox>/var/root/ puts the string /root/ into the
    # result, and the next replacement then matched inside its own predecessor's output and
    # destroyed the path. The symptom was a macOS run that silently returned nothing for the
    # second profile, which is precisely the shape of failure this script exists to find.
    pattern = re.compile("|".join(re.escape(root) for root in sorted(found, key=len, reverse=True)))

    def move(match: re.Match[str]) -> str:
        root = match.group(0)
        # A prefix, never a substitution of the root itself. Prefixing cannot turn one
        # absolute path into a different absolute path, which is what makes the sandbox a
        # guarantee rather than a hope. A drive-letter root has no leading separator of its
        # own, so one is added, which is also why the sandbox holds a directory named "C:".
        return f"{sandbox}{root}" if root.startswith("/") else f"{sandbox}/{root}"

    query = pattern.sub(move, query)

    # The user-name regexes are anchored at the start of an absolute path, which the prefix
    # has just moved. Anchor them after the sandbox instead so ProfileUser still resolves.
    query = query.replace("regex=['^/", f"regex=['^{sandbox}/")
    query = query.replace(r"regex=['(?i)^[A-Za-z]:", f"regex=['(?i)^{sandbox}/[A-Za-z]:")
    return parameters(document) + "\n\n" + query


def build_sandbox(root: Path, os_name: str) -> None:
    """Fill the sandbox with a synthetic profile at every place the globs will look."""
    sys.path.insert(0, str(REPO / "tests" / "fixtures"))
    from generate import build_home

    first: Path | None = None
    for placement in PROFILE_PLACEMENTS[os_name]:
        home = root / placement
        home.parent.mkdir(parents=True, exist_ok=True)
        if first is None:
            build_home(home)
            first = home
        else:
            # Copied rather than generated twice, so the two profiles are identical and a
            # difference in the results can only come from the query.
            shutil.copytree(first, home)


def velociraptor_command(binary: Path, query: Path, out: Path) -> list[str]:
    """The command line a Velociraptor release binary takes for this.

    Read out of the vendor's own command definition rather than guessed, because a wrong
    flag here does not fail loudly: `query` would treat the file name as the query itself
    and return one row of nothing, which looks like a clean run over an empty machine.

    `query` takes its queries as positional arguments; `--from_files` says those arguments
    are file names holding the VQL; `--format jsonl` with `--output` writes one JSON object
    per row, which is the shape this script reads. `--nocolor` is an application flag and
    goes before the command, because escape codes in the output would reach the parser.
    Source: https://raw.githubusercontent.com/Velocidex/velociraptor/master/bin/query.go
    """
    return [
        str(binary),
        "--nocolor",
        "query",
        "--from_files",
        "--format",
        "jsonl",
        "--output",
        str(out),
        str(query),
    ]


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, check=False)


def check(rows: list[dict[str, Any]], sandbox: Path, problems: list[str]) -> None:
    """Everything the returned rows have to satisfy."""
    import fastjsonschema

    validate = fastjsonschema.compile(json.loads(SCHEMA.read_text(encoding="utf-8")))

    if not rows:
        problems.append("the query returned no rows at all against a profile that has agent data")
        return

    for index, row in enumerate(rows, start=1):
        path = str(row.get("provenance", {}).get("original_path", ""))
        if not path.startswith(str(sandbox)):
            problems.append(
                f"row {index} came from {path!r}, which is outside the sandbox. The glob "
                "rewrite in this script missed a profile root, and the run has just read "
                "the real machine. Fix the rewrite before trusting any result here."
            )
            return
        try:
            validate(row)
        except Exception as exc:
            problems.append(f"row {index} ({row.get('kind')}) does not match the schema: {exc}")

    kinds = {str(row.get("kind")) for row in rows}
    for required in ("user.prompt", "assistant.text", "artifact.fs"):
        if required not in kinds:
            problems.append(
                f"no {required} row came back, so the query is reading less of the "
                "synthetic profile than it should"
            )
    if not any(row.get("kind") == "unparsed.record" for row in rows):
        problems.append(
            "no unparsed.record row came back. The synthetic profile contains a line that "
            "is not valid JSON on purpose, and a query that returns nothing for it is "
            "dropping records"
        )
    if not all(row.get("agent") for row in rows):
        problems.append("a row came back with no agent, which the format does not allow")

    # Locators have to be per file and start at one. A shared counter across files is the
    # defect this whole script was written after finding.
    starts = {}
    for row in rows:
        provenance = row.get("provenance") or {}
        match = re.fullmatch(r"line:(\d+)", str(provenance.get("locator", "")))
        if match:
            path = str(provenance.get("original_path"))
            starts[path] = min(starts.get(path, 10**9), int(match.group(1)))
    wrong = {path: first for path, first in starts.items() if first != 1}
    if len(starts) > 1 and wrong:
        problems.append(
            "these files' first record is not numbered line:1, so the line counter is "
            f"shared across files and every locator after the first file is wrong: {wrong}"
        )


def differential(rows: list[dict[str, Any]], sandbox: Path, problems: list[str]) -> str:
    """Compare the query's reading against the analyzer's, record for record.

    The strongest claim this script can make, and the one worth making: the endpoint query
    and the analyzer read the same files, and for the artifacts both of them understand they
    must agree on which records exist. The two disagree about interpretation on purpose,
    because the query emits one row per record where the analyzer splits a turn into its
    parts, so what is compared is the set of source records each one reached, keyed by the
    file and the line it came from. A record the analyzer read and the query did not is a
    hole in the collection.

    This is the same shape of test the two collectors have, for the same reason: two
    implementations of one reading will eventually differ, and the difference has to be
    visible rather than discovered in a case.
    """
    from agentforensics.catalog import load_catalogue
    from agentforensics.exporters.velociraptor_unified import MAPPERS
    from agentforensics.unified import normalize

    events, _ = normalize(sandbox, load_catalogue(REPO / "catalog"))

    def base(locator: str | None) -> str:
        # A parser can emit several events for one record, each with its own suffix on the
        # line locator. The record is the line.
        return str(locator or "").split("#", 1)[0]

    def absolute(path: str) -> str:
        # The analyzer reports a path read from an exported profile as tilde-relative,
        # because that is the honest form when the profile's own location on the endpoint is
        # not known. The query reports the absolute path it globbed. Same file, two truthful
        # spellings, so one is converted before they are compared.
        return str(sandbox) + path[1:] if path.startswith("~/") else path

    # Only events whose locator names a line. A parser may also emit a summary of its own,
    # such as the count of the Codex records that mirror another record, and those are the
    # parser's reading rather than a record on disk, so demanding one back from the query
    # would be asking it to invent something.
    mine = {
        (absolute(event.provenance.original_path), base(event.provenance.locator))
        for event in events
        if event.provenance.artifact_id in MAPPERS
        and event.kind != "artifact.fs"
        and base(event.provenance.locator).startswith("line:")
    }
    # Only the rows from the one profile the analyzer was pointed at. The sandbox holds
    # a copy per platform root, and counting the other copy's records as records the query
    # invented would make this comparison useless.
    theirs = {
        (
            str(row.get("provenance", {}).get("original_path")),
            base(str(row.get("provenance", {}).get("locator"))),
        )
        for row in rows
        if str(row.get("provenance", {}).get("artifact_id")) in MAPPERS
        and row.get("kind") != "artifact.fs"
        and str(row.get("provenance", {}).get("original_path", "")).startswith(str(sandbox))
    }

    missing = sorted(mine - theirs)
    if missing:
        problems.append(
            f"{len(missing)} record(s) the analyzer read did not come back from the query, "
            "which means the collection returned less than was on disk. First few: "
            f"{missing[:5]}"
        )
    extra = sorted(theirs - mine)
    return (
        f"{len(mine)} record(s) read by the analyzer, {len(theirs)} by the query, "
        f"{len(missing)} missing from the query, {len(extra)} the query saw and the "
        "analyzer did not"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--runner",
        help="a program taking a VQL file and a JSON Lines output path. Without it, and "
        "without --velociraptor, this script does nothing and exits 0.",
    )
    parser.add_argument(
        "--velociraptor",
        help="a Velociraptor release binary, which this script knows how to invoke. Use "
        "this rather than wrapping the binary in a shell script: the command line lives "
        "next to the reason for each flag, and a wrapper in a workflow file is the kind of "
        "thing that rots without anybody noticing it stopped checking.",
    )
    parser.add_argument(
        "--os",
        dest="os_name",
        default="linux",
        choices=sorted(PROFILE_PLACEMENTS),
        help="which of the artifact's per-platform sources to run",
    )
    parser.add_argument("--keep", action="store_true", help="leave the sandbox in place")
    args = parser.parse_args(argv)

    if args.runner and args.velociraptor:
        print(
            "check-velociraptor-vql: give one of --runner and --velociraptor, not both",
            file=sys.stderr,
        )
        return EXIT_ERROR

    if not args.runner and not args.velociraptor:
        print(
            "check-velociraptor-vql: no --runner and no --velociraptor given, so the "
            "generated VQL was not executed. The static checks in "
            "tests/unit/test_velociraptor_unified.py still ran; what is not checked here "
            "is engine behaviour."
        )
        return EXIT_OK

    runner = Path(args.runner or args.velociraptor)
    if not runner.exists():
        print(f"check-velociraptor-vql: no such runner: {runner}", file=sys.stderr)
        return EXIT_ERROR
    if not ARTIFACT.exists():
        print(
            f"check-velociraptor-vql: {ARTIFACT} is missing. Run "
            "scripts/gen_collection_rules.py first.",
            file=sys.stderr,
        )
        return EXIT_ERROR

    document = yaml.safe_load(ARTIFACT.read_text(encoding="utf-8"))
    work = Path(tempfile.mkdtemp(prefix="afx-vql-"))
    try:
        sandbox = work / "sandbox"
        sandbox.mkdir()
        build_sandbox(sandbox, args.os_name)

        query = work / "query.vql"
        query.write_text(sandbox_query(document, args.os_name, sandbox), encoding="utf-8")
        out = work / "rows.jsonl"

        command = (
            velociraptor_command(runner, query, out)
            if args.velociraptor
            else [str(runner), str(query), str(out)]
        )
        result = run(command)
        if result.returncode != 0:
            print(
                f"check-velociraptor-vql: the runner exited {result.returncode}\n"
                + result.stderr[-4000:],
                file=sys.stderr,
            )
            return EXIT_FAILED

        rows = []
        problems: list[str] = []
        for number, line in enumerate(out.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except ValueError as exc:
                problems.append(f"output line {number} is not valid JSON: {exc}")

        check(rows, sandbox, problems)

        print(f"check-velociraptor-vql: {args.os_name}, {len(rows)} row(s) returned")
        # Per profile, because the sandbox holds one synthetic profile per place the globs
        # look and they are copies of each other. A count that is not the same for each one
        # means a glob for that root did not match, which is exactly the silent failure
        # this script is for.
        for placement in PROFILE_PLACEMENTS[args.os_name]:
            under = sum(
                1
                for row in rows
                if str(row.get("provenance", {}).get("original_path", "")).startswith(
                    f"{sandbox}/{placement}"
                )
            )
            print(f"check-velociraptor-vql:   {placement}: {under} row(s)")

        # Only where the sandbox's profile sits at a path the analyzer also reads as a
        # profile root, which is the POSIX placements. The Windows drive-letter placement
        # is a device of this harness and not a shape the analyzer expects.
        if args.os_name == "linux":
            print(
                "check-velociraptor-vql: "
                + differential(rows, sandbox / "home" / "alice", problems)
            )

        if problems:
            for problem in problems:
                print(f"check-velociraptor-vql: {problem}", file=sys.stderr)
            return EXIT_FAILED
        print("check-velociraptor-vql: ok")
        return EXIT_OK
    finally:
        if args.keep:
            print(f"check-velociraptor-vql: sandbox left at {work}")
        else:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
