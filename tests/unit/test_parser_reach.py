"""Every reader, reached the way an examiner reaches it: through a file on a disk.

A reader's own tests build a file and hand it to the reader. That is the right way to test
what it does with what it is given, and it says nothing about whether it is ever given
anything. Between a catalogue entry and a reader sit the pattern, the expansion of whatever
the path is rooted at, the glob, the claim order when more than one entry wants a file, and
the attribution that picks one. A reader whose agent is in the catalogue and in no fixture
is a reader nothing has ever handed a collected file to.

That is not hypothetical here. One rule was written against a store two products keep, its
own samples passed, and when a fixture finally put the evidence in front of it the catalogue
turned out to be wrong about one operating system and the reader had never set the field the
rule grouped by. The same gap, one layer down, is this file.

So: build all three fixtures, ingest each, and collect the readers that produced an event.
Every shipped reader has to be in that set or be named below with the reason it is not.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from agentforensics.catalog import load_catalogue
from agentforensics.ingest import ingest
from agentforensics.model import Case
from agentforensics.parsers import PARSERS, for_artifact

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tests" / "fixtures"))

from generate import (  # noqa: E402
    build_home,
    build_registry_bundle,
    build_windows_home,
    write_agent_stores,
)

# Readers no fixture reaches, with what it would take. One entry, and the reason is a
# format rather than an oversight: writing the file would mean writing a memory-mapped
# B-tree by hand, since the library that reads it is not a dependency of this package and
# the reader exists precisely so that it need not be.
#
# The cost of leaving it is bounded and worth naming. What goes untested is the path from
# the catalogue entry to this reader, not the reader, which has its own tests against
# stores built byte by byte. What would close it is a small committed store rather than a
# generator, which is the same trade another fixture here already makes for a sealed
# container it cannot encrypt on the fly.
UNREACHED = {
    "lmdb_generic": "the store is a memory-mapped B-tree and no fixture writes one. The "
    "single catalogue entry that uses this reader is one product's older container format "
    "under a sandboxed application directory, so a fixture for it would be a committed "
    "binary rather than something this generator can produce"
}


@pytest.fixture(scope="module")
def readers_that_ran(tmp_path_factory: pytest.TempPathFactory) -> set[str]:
    """Every reader that produced at least one event over the three synthetic collections."""
    catalogue = load_catalogue(REPO_ROOT / "catalog")
    root = tmp_path_factory.mktemp("fixtures")
    build_home(root / "home")
    build_windows_home(root / "image" / "Users" / "alice")
    build_registry_bundle(root / "bundle")
    # A profile of its own for the six stores that were in no fixture. See the generator
    # for why they are not in the main one: it is curated, several tests assert what is in
    # it, and one of them builds a store at one of these paths itself.
    write_agent_stores(root / "stores")

    seen: set[str] = set()
    for name, source in (
        ("posix", root / "home"),
        ("windows", root / "image"),
        ("bundle", root / "bundle"),
        ("stores", root / "stores"),
    ):
        with Case.open(root / f"{name}.db") as case:
            ingest(case, source, catalogue)
            rows = case.query(
                "SELECT DISTINCT artifact_id FROM events WHERE artifact_id IS NOT NULL"
            )
            for row in rows:
                parser = for_artifact(row["artifact_id"])
                if parser is not None:
                    seen.add(parser.name)
    return seen


@pytest.mark.slow
def test_every_reader_is_reached_by_a_collection_or_declared_unreached(
    readers_that_ran: set[str],
) -> None:
    shipped = {parser.name for parser in PARSERS}
    missing = shipped - readers_that_ran - set(UNREACHED)
    assert not missing, (
        "no fixture puts a collected file in front of these readers, so the path from a "
        "catalogue entry to them is untested and a mistake in it would look like an agent "
        f"that was never used: {sorted(missing)}"
    )
    stale = set(UNREACHED) & readers_that_ran
    assert not stale, (
        f"these are declared unreached and a fixture now reaches them: {sorted(stale)}. "
        "Remove the entry, because the reason beside it has stopped being true"
    )
    assert set(UNREACHED) <= shipped, (
        f"these declarations name readers that no longer exist: {sorted(set(UNREACHED) - shipped)}"
    )
    for name, reason in UNREACHED.items():
        assert reason.strip(), f"{name} is declared unreached with no reason given"
