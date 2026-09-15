#!/usr/bin/env python3
"""Generate the committed collection rules from the artifact catalogue.

The output lives under exporters/generated/ and is committed, so that somebody can take a
Velociraptor artifact or a KAPE target out of this repository without installing anything.
CI runs this with --check and fails if the committed copy is stale, for the same reason the
embedded catalogue in the collectors is checked: a rule that lags the catalogue searches
last month's locations and reports a clean host.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from agentforensics.catalog import CatalogueError, load_catalogue  # noqa: E402
from agentforensics.exporters import FORMATS, render  # noqa: E402

CATALOG_DIR = REPO_ROOT / "catalog"
OUT_DIR = REPO_ROOT / "exporters" / "generated"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--format",
        action="append",
        choices=sorted(FORMATS),
        help="only this format, repeatable. Default: every format.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="do not write; exit non-zero if the committed output is stale.",
    )
    args = parser.parse_args(argv)

    try:
        catalogue = load_catalogue(CATALOG_DIR)
    except CatalogueError as exc:
        sys.stderr.write(f"gen-collection-rules: {exc}\n")
        return 2

    rendered = render(catalogue, args.format)

    if args.check:
        stale = []
        for item in rendered:
            target = OUT_DIR / item.path
            if not target.exists() or target.read_text(encoding="utf-8") != item.text:
                stale.append(item.path)
        # A file that is committed but no longer generated is just as wrong as a stale one:
        # it will be picked up and run against paths the catalogue no longer claims.
        expected = {item.path for item in rendered}
        if args.format is None:
            orphans = sorted(
                str(p.relative_to(OUT_DIR))
                for p in OUT_DIR.rglob("*")
                if p.is_file() and str(p.relative_to(OUT_DIR)) not in expected
            )
        else:
            orphans = []
        if stale or orphans:
            for path in stale:
                sys.stderr.write(f"gen-collection-rules: stale: {path}\n")
            for path in orphans:
                sys.stderr.write(f"gen-collection-rules: no longer generated: {path}\n")
            sys.stderr.write("gen-collection-rules: run scripts/gen_collection_rules.py\n")
            return 1
        sys.stdout.write(f"gen-collection-rules: {len(rendered)} file(s) current\n")
        return 0

    for item in rendered:
        target = OUT_DIR / item.path
        target.parent.mkdir(parents=True, exist_ok=True)
        # newline="" so the bytes are identical on every platform: a CRLF checkout would
        # otherwise make the --check comparison fail for no reason.
        with target.open("w", encoding="utf-8", newline="") as handle:
            handle.write(item.text)
    skipped = sum(len(item.skipped) for item in rendered)
    sys.stdout.write(
        f"gen-collection-rules: wrote {len(rendered)} file(s), "
        f"{skipped} artifact/target pair(s) reported as not covered\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
