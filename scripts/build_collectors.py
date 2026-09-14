#!/usr/bin/env python3
"""Embed the artifact catalogue into both single-file collectors.

The collectors must have no dependencies and must be one file each, so they cannot read
catalog/*.yaml at run time. The catalogue is therefore rendered into a literal between
marker comments, and CI runs this with --check and fails if the embedded copy is stale.
That check is the only thing standing between "the catalogue was updated" and "the
collector is still looking in last month's location".

Only the fields a collector actually uses are embedded. The prose, the sources and the
notes stay out: they would triple the size of a file that has to be pasted into a live
response session, and nothing in the collector reads them.

Written to stay inside this directory's Python 3.8 lint target, though importing the
analyzer package means it runs on 3.11 or newer.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from agentforensics.catalog import CatalogueError, load_catalogue  # noqa: E402

CATALOG_DIR = REPO_ROOT / "catalog"

PY_BEGIN = "# --- BEGIN EMBEDDED CATALOGUE ---"
PY_END = "# --- END EMBEDDED CATALOGUE ---"
PS1_BEGIN = "# --- BEGIN EMBEDDED CATALOGUE ---"
PS1_END = "# --- END EMBEDDED CATALOGUE ---"

TARGETS = [
    (REPO_ROOT / "collector" / "collect.py", "python"),
    (REPO_ROOT / "collector" / "collect.ps1", "powershell"),
]


def catalogue_payload() -> dict:
    """The subset of the catalogue a collector needs, in a deterministic order."""
    catalogue = load_catalogue(CATALOG_DIR)
    agents = []
    for agent in catalogue:
        artifacts = []
        for artifact in sorted(agent.artifacts, key=lambda a: a.id):
            artifacts.append(
                {
                    "id": artifact.id,
                    "category": artifact.category,
                    "root": artifact.root,
                    "os": list(artifact.os),
                    # Angle-bracket paths are the human-readable form and have a glob
                    # sibling, except for project-anchored ones where the bracket is
                    # substituted with a discovered root. Both are kept: the collector
                    # turns any leftover bracket into a wildcard.
                    "paths": list(artifact.paths),
                    "sensitivity": artifact.sensitivity,
                    "collect_priority": artifact.collect_priority,
                    "status": artifact.status,
                }
            )
        agents.append({"agent": agent.agent, "artifacts": artifacts})

    payload = {"agents": agents}
    # The hash covers the payload as embedded, so a manifest's catalogue_version ties a
    # collection to exactly these definitions.
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    payload["sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return payload


def render_python(payload: dict) -> str:
    body = json.dumps(payload, sort_keys=True, indent=4, ensure_ascii=False)
    # A Python dict literal and JSON agree on everything used here, so json.dumps output
    # is valid Python. Verified by the byte-compile step in CI.
    return "EMBEDDED_CATALOGUE = " + body


def render_powershell(payload: dict) -> str:
    body = json.dumps(payload, sort_keys=True, indent=4, ensure_ascii=False)
    # A here-string keeps the JSON verbatim, so both collectors embed byte-identical data
    # and the differential test compares like with like. ConvertFrom-Json needs an
    # explicit -Depth on PowerShell 5.1, where the default would flatten the nesting.
    return (
        "$EmbeddedCatalogueJson = @'\n"
        + body
        + "\n'@\n"
        + "$script:EmbeddedCatalogue = $EmbeddedCatalogueJson | ConvertFrom-Json"
    )


def replace_block(text: str, begin: str, end: str, replacement: str, path: Path) -> str:
    pattern = re.compile(re.escape(begin) + r".*?" + re.escape(end), re.S)
    if not pattern.search(text):
        raise SystemExit(
            "build-collectors: %s has no %s / %s marker pair" % (path.name, begin, end)
        )
    # The marker comments and the note between them are preserved; only the literal is
    # replaced, so a reader of the collector still sees where the data came from.
    note = {
        "python": "# Rendered from catalog/*.yaml by scripts/build_collectors.py. Do not "
        "edit by hand: CI\n# regenerates it and fails if this block is stale.",
        "powershell": "# Rendered from catalog/*.yaml by scripts/build_collectors.py. Do "
        "not edit by hand: CI\n# regenerates it and fails if this block is stale.",
    }
    kind = "python" if path.suffix == ".py" else "powershell"
    block = "%s\n%s\n%s\n%s" % (begin, note[kind], replacement, end)
    return pattern.sub(lambda _m: block, text, count=1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="do not write; fail if an embedded copy is stale (the CI mode)",
    )
    args = parser.parse_args(argv)

    try:
        payload = catalogue_payload()
    except CatalogueError as exc:
        sys.stderr.write("build-collectors: %s\n" % exc)
        return 2

    stale = []
    for path, kind in TARGETS:
        if not path.exists():
            sys.stderr.write("build-collectors: %s does not exist yet, skipping\n" % path.name)
            continue
        text = path.read_text(encoding="utf-8")
        rendered = render_python(payload) if kind == "python" else render_powershell(payload)
        begin, end = (PY_BEGIN, PY_END) if kind == "python" else (PS1_BEGIN, PS1_END)
        updated = replace_block(text, begin, end, rendered, path)
        if updated == text:
            continue
        if args.check:
            stale.append(path.name)
        else:
            path.write_text(updated, encoding="utf-8")
            sys.stderr.write("build-collectors: updated %s\n" % path.name)

    if stale:
        sys.stderr.write(
            "build-collectors: the embedded catalogue is stale in %s.\n"
            "Run scripts/build_collectors.py and commit the result. A stale copy means the "
            "collector looks for artifacts where they used to be.\n" % ", ".join(stale)
        )
        return 1

    counts = sum(len(a["artifacts"]) for a in payload["agents"])
    sys.stderr.write(
        "build-collectors: %d artifacts across %d agent(s), catalogue %s\n"
        % (counts, len(payload["agents"]), payload["sha256"][:12])
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
