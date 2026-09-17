"""Read evidence into a case.

Four sources, one shape. A native bundle from this suite's collectors, a KAPE output tree,
a Velociraptor offline collection and a mounted image or exported profile all reduce to a
root plus original paths, which is why the bundle format mirrors those paths in the first
place.

`detect` picks the adapter, and it prefers the native one whenever a manifest is present,
because a manifest is the only source that knows what the endpoint knew: which catalogue
entry claimed a file, what its hash was at collection time, what the endpoint's own
timestamps were, and which globs the collector declined to search. Everything a tree
adapter produces is an inference made afterwards, and the case says so on every row.
"""

from __future__ import annotations

from pathlib import Path

from agentforensics.ingest.ingest import IngestReport, ingest
from agentforensics.ingest.match import Match, Matcher
from agentforensics.ingest.native import NativeBundle
from agentforensics.ingest.source import Attribution, Gap, Source, SourceEntry
from agentforensics.ingest.tree import CollectedTree


def detect(path: Path) -> str:
    """Name the kind of source at a path, without reading all of it.

    Returns one of the adapter names, or raises nothing: an unrecognized directory is a
    tree, because a directory of collected files is exactly what a mounted image and an
    exported profile look like, and refusing them would rule out the two sources an analyst
    most often has.
    """
    if NativeBundle.looks_like(path):
        return "native"
    if (path / "uploads").is_dir() and any(path.glob("*.json")):
        # A Velociraptor offline collection container, unpacked. Still a tree to this code,
        # named separately so the case records what it was.
        return "velociraptor"
    if any(child.is_dir() and len(child.name) == 1 for child in _safe_iterdir(path)):
        # KAPE writes one directory per drive letter at the top of its output.
        return "kape"
    return "directory"


def _safe_iterdir(path: Path) -> list[Path]:
    try:
        return sorted(path.iterdir())
    except OSError:
        return []


__all__ = [
    "Attribution",
    "CollectedTree",
    "Gap",
    "IngestReport",
    "Match",
    "Matcher",
    "NativeBundle",
    "Source",
    "SourceEntry",
    "detect",
    "ingest",
]
