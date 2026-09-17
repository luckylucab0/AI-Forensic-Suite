"""The one shape every evidence source presents to the analyzer.

A native bundle, a KAPE output tree, a Velociraptor offline collection and a mounted image
are all the same thing seen from here: a root, plus files that each remember where they
came from on the endpoint. That is why the bundle format mirrors original paths in the
first place, and it is what lets the parsers be written once instead of four times.

What differs between sources is how much they know about themselves. A native bundle has a
manifest that names the catalogue entry, the hash and the original timestamps for every
file, because the collector knew them. A KAPE tree has a directory layout and nothing else.
The adapters exist to close that gap, and to be explicit about what they had to infer:
`attribution` on each entry says whether the catalogue entry was recorded by the collector
or guessed from the path here, because an analyst reading a finding needs to know which.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Protocol

from agentforensics.model import BundleRecord

# Where the agent and artifact id on an entry came from.
#
# 'collector' means the collector recorded it: it matched the path against the catalogue on
# the endpoint itself, with the environment and the agent's own state files in front of it.
# 'path' means this adapter matched the path against the catalogue after the fact, with
# neither. 'none' means nothing claimed the file, which is a finding rather than a
# non-event: either an agent nobody has catalogued, or a gap in the catalogue.
Attribution = Literal["collector", "path", "none"]


@dataclass(frozen=True, slots=True)
class SourceEntry:
    """One collected file, with everything the parsers and the case need."""

    original_path: str
    # Where the bytes are now, or None when the source recorded the file's existence
    # without its content: a credential store collected as metadata only, or a file the
    # collector could not read. Both are real entries and both belong in the case.
    local_path: Path | None
    sha256: str | None = None
    size: int | None = None
    agent: str | None = None
    artifact_id: str | None = None
    category: str | None = None
    status: str | None = None
    attribution: Attribution = "none"
    user: str | None = None
    collected: bool = True
    reason: str | None = None
    mtime_utc: str | None = None
    atime_utc: str | None = None
    ctime_utc: str | None = None
    birthtime_utc: str | None = None
    symlink: str | None = None
    reparse_point: bool | None = None
    changed_while_reading: bool | None = None
    # Every catalogue entry that claims this path, not only the one chosen for attribution.
    # A file can be covered by a directory-level entry and a file-level one, and a report
    # that says which entries cover a file is more useful than one that picks silently.
    also_claimed_by: tuple[str, ...] = field(default_factory=tuple)

    def manifest_entry(self) -> dict[str, object]:
        """The artifacts-table row for this entry."""
        return {
            "artifact_id": self.artifact_id,
            "agent": self.agent,
            "category": self.category,
            "original_path": self.original_path,
            "bundle_path": None if self.local_path is None else str(self.local_path),
            "sha256": self.sha256,
            "size": self.size,
            "status": self.status,
            "collected": self.collected,
            "reason": self.reason,
            "user": self.user,
            "mtime_utc": self.mtime_utc,
            "atime_utc": self.atime_utc,
            "ctime_utc": self.ctime_utc,
            "birthtime_utc": self.birthtime_utc,
            "symlink": self.symlink,
            "reparse_point": self.reparse_point,
            "changed_while_reading": self.changed_while_reading,
        }


@dataclass(frozen=True, slots=True)
class Gap:
    """Something the collection did not get, carried forward into the case.

    A refused glob, a read error, an agent state file that would not parse. The manifest
    records these and the case has to as well, because the case is what somebody reads a
    year later and a hole in the evidence must be visible from there.
    """

    kind: str
    detail: str
    reason: str | None = None


class Source(Protocol):
    """What an ingest adapter provides."""

    def bundle(self) -> BundleRecord: ...

    def entries(self) -> Iterator[SourceEntry]: ...

    def gaps(self) -> Iterator[Gap]: ...


__all__ = ["Attribution", "Gap", "Source", "SourceEntry"]
