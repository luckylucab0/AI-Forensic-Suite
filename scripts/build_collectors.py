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
analyzer package means it runs on 3.14 or newer.
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

# The registry keys a collection carries, with the reason each one is worth the trouble.
# Six of the catalogue's eight, and the two left out are left out on purpose.
#
# Reading the registry is something only the PowerShell collector can do and only on the
# host itself: a key cannot be read from a mounted image without a hive parser and this
# suite has none. It is worth doing for these four because they are agent-specific and no
# other tool knows to look at them. It is not worth doing for the platform's own execution
# evidence or an installer's persistence keys, which every general purpose registry tool
# reads better than this one would, and duplicating those would put a second, worse answer
# next to an examiner's existing one.
#
# The list is here rather than in the catalogue because it is a statement about this
# collector's reach and not about where an agent keeps its data. The analyzer's reader for
# these documents holds the same four, and tests/unit/test_registry.py binds the two.
REGISTRY_KEYS = {
    "claude_code.managed_settings_registry": "the managed settings document, which on "
    "Windows can exist here and in no file at all. The user hive is the tamper path: a "
    "non-administrator can put a policy there when no real one exists, so both hives are "
    "read and the difference is the finding",
    "cursor.url_handler": "the URL scheme this product registers under the user's own "
    "class keys, which its uninstaller does not remove. The command value names the "
    "executable, so on a host where everything else is gone the key says the product was "
    "installed on this account and the path says where it was",
    "claude_desktop.managed_policy_windows": "the desktop product's own policy key, which "
    "the vendor documents as separate from the one above and which a collector globbing "
    "the policies branch would conflate with it",
    "ollama.env_overrides_registry": "where this product's relocation variables live on "
    "Windows, so an empty model directory can be told from a moved one",
    "windsurf.enterprise_policy": "the policy branch this product reads, where an "
    "administrator can enable hooks and rules for every user on the machine",
    "windsurf.url_handlers": "the two URL schemes this product registers, one of them "
    "under the name it had before the rename, which a plain installation of the current "
    "product creates. Neither is removed by the uninstaller",
}

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
            if artifact.id in REGISTRY_KEYS:
                # Computed rather than catalogued: which keys this collector reaches is a
                # property of the collector. Only the entries carrying this are read from
                # the registry, so a key added to the catalogue is collected by nobody
                # until somebody decides it should be and says why above.
                artifacts[-1]["read_registry"] = True
        agents.append({"agent": agent.agent, "artifacts": artifacts})

    payload = {"agents": agents}
    # The hash covers the payload as embedded, so a manifest's catalogue_version ties a
    # collection to exactly these definitions.
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    payload["sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return payload


def render_json(payload: dict) -> str:
    """The one JSON rendering both collectors embed, with the quoting hazards checked.

    A Python raw triple-quoted string and a PowerShell here-string each have exactly one
    sequence they cannot contain. Neither can occur in this data, but a catalogue entry is
    the kind of thing that changes without anyone thinking about the quoting of a generated
    file, and a broken collector is found at collection time, on someone's evidence.
    """
    # ensure_ascii=True, which is not about the manifest. The manifest is written at
    # collection time and stays UTF-8; this is the literal embedded in a collector's own
    # source. Windows PowerShell 5.1 reads a script with no byte order mark as the ANSI
    # code page, so one catalogue path with a non-ASCII character in it would be parsed as
    # something else and the collector would search a path that does not exist, on the
    # platform most endpoints run, with nothing saying so. Escapes cost readability in a
    # generated block and remove the failure mode.
    #
    # The catalogue hash is unaffected: it is computed over the payload with fixed
    # separators in catalogue_payload, not over this rendering, so both collectors still
    # report the same catalogue_version and still embed the same data.
    body = json.dumps(payload, sort_keys=True, indent=4, ensure_ascii=True)
    if '"""' in body:
        raise SystemExit(
            "build-collectors: the catalogue contains a triple quote, which would end the "
            "embedded string in collect.py. Change the catalogue entry."
        )
    if "\n'@" in body:
        raise SystemExit(
            "build-collectors: the catalogue contains a line starting with '@, which would "
            "end the here-string in collect.ps1. Change the catalogue entry."
        )
    if body.endswith("\\"):
        raise SystemExit("build-collectors: the rendered JSON ends with a backslash")
    return body


def render_python(payload: dict) -> str:
    body = render_json(payload)
    # A raw triple-quoted string rather than a Python dict literal, for two reasons.
    #
    # The first is that both collectors then embed byte-identical data, so the differential
    # test compares like with like and one hash describes both.
    #
    # The second is that a code formatter rewrites a dict literal and leaves a string
    # alone. json.dumps output is valid Python, but ruff format collapses its one-item-per
    # -line lists, and this script would then report the block as stale: two CI steps that
    # cannot both pass, decided by whichever ran last. A string ends that.
    #
    # Raw, because catalogue paths contain Windows separators that JSON escapes as \\ and
    # a non-raw string would turn back into a single backslash, breaking the JSON.
    return (
        'EMBEDDED_CATALOGUE_JSON = r"""\n'
        + body
        + '\n"""\n'
        + "EMBEDDED_CATALOGUE = json.loads(EMBEDDED_CATALOGUE_JSON)"
    )


def render_powershell(payload: dict) -> str:
    body = render_json(payload)
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
