"""Ingest a tree of collected files that has no manifest of its own.

A KAPE output tree, a Velociraptor offline collection, a mounted image, an exported user
profile. Four different tools and one problem: the files are there, the original paths are
recoverable from the layout, and nothing says which agent any of it belongs to. This
adapter walks the tree, reconstructs each original path, matches it against the catalogue,
and hashes what it finds.

Everything it produces is attributed to a path match rather than to a collector, and that
distinction is carried all the way into the case. It matters because a path match is made
without the endpoint in front of it: the relocation variables are gone, the agents' own
state files were never read, and a file under a directory nobody catalogued looks exactly
like a file that is not evidence. So this adapter carries every file forward, matched or
not, and the case records which.

The hashes are computed here rather than taken on trust. A tree has no manifest to compare
against, so the only hash that means anything is one this process derived from the bytes it
actually read.
"""

from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from agentforensics.ingest.match import Matcher
from agentforensics.ingest.source import Gap, SourceEntry
from agentforensics.model import BundleRecord

# Directory names a collecting tool puts above the reconstructed path. KAPE writes one
# directory per drive letter, Velociraptor's container puts everything under a fixed
# prefix, and this suite's own bundles use files/. Stripping them is what turns a local
# path back into the endpoint path the catalogue is written in.
_ROOT_PREFIXES = (
    "files",  # this suite's bundles, and anything that copied the layout
    "uploads",  # Velociraptor offline collection container
    "collection",
)

_DRIVE_DIRECTORY = re.compile(r"^([A-Za-z])(?:%3A|:)?$")


def _hash_and_size(path: Path) -> tuple[str | None, int | None, str | None]:
    """The digest and size of one file, or the reason neither could be had.

    Read in chunks because a session database or a VM disk image in a collection can be
    larger than the memory of the workstation reading it, and an ingest that dies on one
    large file loses the whole tree.
    """
    digest = hashlib.sha256()
    total = 0
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                total += len(chunk)
    except OSError as exc:
        return None, None, f"could not be read: {exc}"
    return digest.hexdigest(), total, None


def _stamp(value: float | None) -> str | None:
    if value is None:
        return None
    try:
        return (
            datetime.fromtimestamp(value, UTC)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z")
        )
    except (OverflowError, OSError, ValueError):
        # A timestamp a filesystem cannot represent, which happens with a zeroed or a
        # deliberately corrupted inode. Reported as absent rather than as an epoch date,
        # because a 1970 timestamp on a timeline reads as evidence and is not.
        return None


class CollectedTree:
    """A root of collected files, with original paths recoverable from the layout."""

    def __init__(
        self,
        root: Path,
        matcher: Matcher,
        *,
        source_kind: str = "directory",
        bundle_uuid: str | None = None,
    ) -> None:
        self.root = root
        self.matcher = matcher
        self.source_kind = source_kind
        # Derived from the root path so that re-ingesting the same tree lands on the same
        # bundle row and therefore the same event ids. A random identifier would make
        # re-ingest duplicate a case, which is the property the event model exists to have.
        self._uuid = bundle_uuid or (
            "tree-" + hashlib.sha256(str(root.resolve()).encode("utf-8")).hexdigest()[:24]
        )
        self._gaps: list[Gap] = []
        self._profile_rooted = _is_profile_root(root)

    @staticmethod
    def looks_like(root: Path) -> bool:
        return root.is_dir()

    def bundle(self) -> BundleRecord:
        return BundleRecord(
            bundle_uuid=self._uuid,
            source_kind=self.source_kind,
            source_path=str(self.root),
        )

    def original_path(self, local: Path) -> str:
        """Turn a path inside the tree back into the endpoint path it came from.

        Three layers to undo. A container prefix that the collecting tool added, a
        per-drive directory that KAPE writes, and the percent-encoding this suite's own
        bundle format applies to a character a filesystem will not hold. The encoding is
        one way by design, which is why a native bundle's manifest is authoritative and
        this is the fallback.
        """
        relative = local.relative_to(self.root)
        parts = list(relative.parts)
        while parts and parts[0].lower() in _ROOT_PREFIXES:
            parts.pop(0)
        drive = ""
        if parts:
            found = _DRIVE_DIRECTORY.match(parts[0])
            if found:
                drive = found.group(1).upper() + ":"
                parts.pop(0)
        decoded = [_decode_segment(part) for part in parts]
        if self._profile_rooted and not drive:
            # The root is somebody's home directory, so these paths have no profile
            # directory above them and presenting them as absolute would assert a
            # filesystem root that is not there. They are profile-relative instead, which
            # is also the spelling the catalogue is written in.
            return "~/" + "/".join(decoded)
        return drive + "/" + "/".join(decoded)

    def entries(self) -> Iterator[SourceEntry]:
        for local in sorted(_walk(self.root, self._gaps)):
            original = self.original_path(local)
            sha256, size, problem = _hash_and_size(local)
            if problem:
                self._gaps.append(Gap("unreadable_file", str(local), problem))
            match = self.matcher.best(original)
            others = tuple(m.artifact.id for m in self.matcher.matches(original))
            try:
                stat = local.stat()
            except OSError:
                stat = None
            yield SourceEntry(
                original_path=original,
                local_path=local,
                sha256=sha256,
                size=size,
                agent=match.artifact.agent if match else None,
                artifact_id=match.artifact.id if match else None,
                category=match.artifact.category if match else None,
                status=match.artifact.status if match else None,
                attribution="path" if match else "none",
                user=_user_from_path(original),
                collected=problem is None,
                reason=problem,
                # The timestamps of the copy, not of the original. A collecting tool that
                # preserved them makes these the endpoint's; one that did not makes them
                # the copy's. Nothing in the tree says which, so the ingest records them
                # and the report says where they came from rather than asserting they are
                # the endpoint's own.
                mtime_utc=_stamp(stat.st_mtime if stat else None),
                atime_utc=_stamp(stat.st_atime if stat else None),
                ctime_utc=_stamp(stat.st_ctime if stat else None),
                symlink=str(local.readlink()) if local.is_symlink() else None,
                also_claimed_by=others,
            )

    def gaps(self) -> Iterator[Gap]:
        # Yielded after entries() has run, since walking the tree is what discovers them.
        yield from self._gaps
        if self._profile_rooted:
            yield Gap(
                "profile_root",
                str(self.root),
                "The root of this source is a single user's profile, so its paths are "
                "recorded relative to that profile. Which account it belongs to is not "
                "recoverable from the tree, and neither is anything outside it: the "
                "machine-wide configuration, the other profiles, and the execution "
                "evidence are all above this root and were not collected.",
            )
        yield Gap(
            "no_manifest",
            str(self.root),
            "This source carries no manifest, so every catalogue attribution in it was "
            "matched from the path after the fact rather than recorded on the endpoint. A "
            "relocated data tree, and any file under a directory the catalogue does not "
            "know, is therefore unattributed rather than absent.",
        )


def _walk(root: Path, gaps: list[Gap]) -> Iterator[Path]:
    """Every regular file under a root, without following directory symlinks.

    A collected tree can contain a link that points back above the root, and following it
    would walk the analyst's own workstation into the case. The link itself is still
    yielded, so the fact that it was there is recorded.
    """
    for current, directories, filenames in os.walk(root, followlinks=False):
        directories.sort()
        here = Path(current)
        for name in sorted(filenames):
            candidate = here / name
            try:
                if candidate.is_symlink() or candidate.is_file():
                    yield candidate
            except OSError as exc:
                gaps.append(Gap("unreadable_file", str(candidate), str(exc)))


_ENCODED = re.compile(r"%([0-9A-Fa-f]{2})")


def _decode_segment(segment: str) -> str:
    """Undo the bundle format's percent-encoding of one path segment.

    Only the escapes the format writes are undone. A literal percent sign in a real
    filename is left alone rather than being read as the start of an escape, because
    inventing a character that was not in the original name is worse than keeping one that
    looks odd.
    """
    return _ENCODED.sub(lambda m: chr(int(m.group(1), 16)), segment)


# Directories that only appear at the top of a user profile. Enough of them together is
# what distinguishes an exported home directory from a filesystem root, which matters
# because the two reconstruct into different paths.
_PROFILE_MARKERS = (
    "Library",
    "AppData",
    ".config",
    ".local",
    ".cache",
    "Desktop",
    "Documents",
    "Downloads",
)


def _is_profile_root(root: Path) -> bool:
    """Whether this root is one user's home directory rather than a filesystem root.

    Decided from what is directly under it. A filesystem root has Users or home; a profile
    has the directories a profile has. A tree with neither is treated as a filesystem root,
    because that is the reading that leaves the paths as they were found rather than
    rewriting them.
    """
    try:
        names = {child.name for child in root.iterdir() if child.is_dir()}
    except OSError:
        return False
    if {"Users", "home", "users"} & names:
        return False
    if names & set(_PROFILE_MARKERS):
        return True
    # A profile that holds nothing but agent directories, which is what an export made for
    # this purpose looks like. Two or more dot-directories and no system directory.
    dotted = [name for name in names if name.startswith(".")]
    system = {"etc", "var", "usr", "bin", "opt", "Windows", "ProgramData", "Program Files"}
    return len(dotted) >= 2 and not (names & system)


def _user_from_path(original: str) -> str | None:
    """The account a profile-anchored path belongs to.

    Recovered from the path because a tree has nothing else to say it, and because almost
    every question in a case is asked about one user. A path outside a profile returns
    nothing rather than a guess.
    """
    found = re.match(r"^(?:[A-Za-z]:)?/(?:Users|home)/([^/]+)/", original)
    if found:
        return found.group(1)
    if original.startswith(("/root/", "/var/root/")):
        return "root"
    return None


__all__ = ["CollectedTree"]
