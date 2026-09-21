"""Read a git index, which is a listing of a working copy with a clock on every line.

One agent writes one of these beside each checkpoint, in a scratch directory it keeps out
of the system temporary directory on purpose: its own source comment says the reason is
that the index and the path list enumerate workspace paths. So this file is a listing of
the working copy the agent was pointed at, at the moment of a checkpoint, untracked files
included, and each line carries the size, the mode and the modification time git saw. That
is a picture of somebody's machine taken by the agent, which no other artifact in this
catalogue provides.

It is also short lived. The entry records that these directories are reaped after two weeks
of idleness and removed outright when the checkpoint references are deleted, so an index
that survived to a collection is evidence about a recent session and there will not be
another chance at it.

**The format.** A header of DIRC, a version and a count, then one entry per path: two
timestamps, the device and inode, the mode, the owner, the size, the object id, a flags
field, and the path itself. Versions two and three pad each path to an eight byte boundary;
version four drops that and stores each path as the number of characters to strip from the
previous one plus the rest, which is the one thing in here that cannot be read entry by
entry without keeping the previous path. All three are read.

**What is not read.** Everything after the entries: the tree cache, the resolve-undo data
and whatever else a git version put there. Those are extensions with their own formats and
they describe git's bookkeeping rather than the working copy. The count in the header is
what says where the entries stop, so ignoring the rest costs nothing and guessing at it
would gain nothing.

Format reference, read while writing this:
https://raw.githubusercontent.com/git/git/master/Documentation/gitformat-index.adoc
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass
from itertools import islice

# The first four bytes of every index, and the versions this reader knows.
MAGIC = b"DIRC"
VERSIONS = (2, 3, 4)

# Everything in one entry before the path, in the order the format lists it. Two timestamps
# of a second and a nanosecond each, the device, the inode, the mode, the owner and group,
# the size, then the object id and the flags, which are read separately because the id's
# length depends on the repository and the flags decide whether another field follows.
_FIXED = struct.Struct(">10I")
_FIXED_LENGTH = _FIXED.size

# The two hash lengths git uses, in bytes.
_SHA1, _SHA256 = 20, 32

# Set in the flags when a second flags field follows, which only versions three and four
# have. Its own bits are about assume-valid and skip-worktree, neither of which this reader
# needs, but its two bytes have to be stepped over.
_EXTENDED = 0x4000

# The low twelve bits of the flags are the path's length, capped: a longer path stores this
# value and is then read to its terminator instead.
_NAME_MASK = 0x0FFF
_NAME_CAPPED = 0x0FFF

# How many entries one index turns into records. A working copy can hold hundreds of
# thousands of files and a case should not be fillable by one listing. The caller reports
# reaching this rather than stopping quietly.
MAX_ENTRIES = 50_000


class GitIndexError(ValueError):
    """The file is not an index this reader knows."""


@dataclass(frozen=True, slots=True)
class IndexEntry:
    """One path in the working copy, as git last saw it."""

    path: str
    mode: int
    size: int
    object_id: str
    # Seconds since the epoch, from git's own stat cache. The modification time is the
    # file's; the change time is the inode's, and the two differ when metadata was touched
    # without the content changing.
    mtime: int
    ctime: int

    @property
    def executable(self) -> bool:
        # git stores a regular file as 100644 or 100755 and nothing else.
        return bool(self.mode & 0o111)


def looks_like_index(raw: bytes) -> bool:
    """Whether the bytes begin the way an index does."""
    return raw[:4] == MAGIC


def read(raw: bytes, limit: int = MAX_ENTRIES) -> Iterator[IndexEntry]:
    """Every entry the header says is there, in the order the file stores them."""
    if not looks_like_index(raw):
        raise GitIndexError("this file does not begin with an index signature")
    if len(raw) < 12:
        raise GitIndexError("this file is shorter than an index header")
    version, count = struct.unpack(">II", raw[4:12])
    if version not in VERSIONS:
        raise GitIndexError(f"this index is version {version}, which this reader does not know")

    # The object id length is not in the file. It is derived by reading with each hash in
    # turn, which is the only way to read an index written with either one without being
    # told which, and it is decided once for the whole file rather than per entry.
    width = _width(raw, version, count)
    # islice rather than a counter, because it stops without asking the walk for the entry
    # after the last one it wants. A counted loop that checked afterwards would parse that
    # entry, and an index trimmed by the limit precisely because it is enormous is also the
    # one likeliest to be damaged past the point this reader stops caring about.
    for entry, _ in islice(_walk(raw, version, width, count), limit):
        yield entry


def _walk(raw: bytes, version: int, width: int, count: int) -> Iterator[tuple[IndexEntry, int]]:
    """The entries, read with one object id width, each with where it ended.

    The offset travels with the entry because `_width` reads the file with each hash and
    has to know where the walk landed, and a second copy of this arithmetic to answer that
    would be a second copy that drifts.
    """
    at = 12
    previous = ""
    for index in range(count):
        if at + _FIXED_LENGTH + width + 2 > len(raw):
            raise GitIndexError(f"entry {index + 1} of {count} runs off the end of the file")
        # The ten fields in the order the format lists them: the change time in seconds
        # and nanoseconds, the modification time the same way, the device, the inode, the
        # mode, the owner, the group and the size. Named by index here rather than unpacked
        # into ten variables, and the indices are worth reading twice: the mode sat on the
        # device's place in the first version of this and every file came out as a device
        # number, which looks like a mode until somebody prints it in octal.
        fields = _FIXED.unpack_from(raw, at)
        cursor = at + _FIXED_LENGTH
        object_id = raw[cursor : cursor + width].hex()
        cursor += width
        (flags,) = struct.unpack_from(">H", raw, cursor)
        cursor += 2
        if version >= 3 and flags & _EXTENDED:
            cursor += 2
        path, cursor, previous = _path(raw, cursor, flags, version, previous)
        if version < 4:
            # Padded with NUL bytes to the next eight byte boundary, counted from the
            # start of the entry rather than from the start of the file.
            cursor += (8 - ((cursor - at) % 8)) % 8
        at = cursor
        yield (
            IndexEntry(
                path=path,
                mode=fields[6],
                size=fields[9],
                object_id=object_id,
                mtime=fields[2],
                ctime=fields[0],
            ),
            at,
        )


# How many entries a probe reads before it accepts a width. Enough that a wrong width has
# run out of plausible paths long before, and few enough that deciding this on a large
# index is not a second pass over the whole of it.
_PROBE = 64


def _width(raw: bytes, version: int, count: int) -> int:
    """Which hash this index was written with, decided by reading it with each in turn.

    The file does not say. Git knows from the repository's configuration, and that is not
    in the index and may not have been collected with it, so the only way to read an index
    written with either hash is to try one and see whether it reads.

    With the wrong width every field after the fixed part is taken from the middle of
    another one: the object id swallows the start of the path, the flags are two bytes of
    path, and the length they claim runs the walk into the next entry's timestamps. That
    stops looking like an index within a few entries, which is what this checks. Where the
    whole file is read, the landing point is checked too: the entries are followed either
    by the file's own trailing hash, which is as long as the ids in it, or by an extension
    whose signature is four capital letters.

    What was here before decided from one entry's length instead, and got the answer wrong
    for every SHA-256 repository. Version four has no padding to measure against, so it
    returned the first candidate unconditionally; and the padded versions compared a
    remainder against seven, which every remainder satisfies, leaving a check that a byte
    somewhere in the middle of an object id happened to be zero. An index from such a
    repository was read with twelve bytes too few and refused as damaged.
    """
    if not count:
        # No entry to read, and nothing that depends on the answer either.
        return _SHA1
    for width in (_SHA1, _SHA256):
        if _reads_as(raw, version, width, count):
            return width
    # Neither read. The older hash is the answer that was right for every index written
    # before the newer one existed, and the walk in `read` reports what it runs into.
    return _SHA1


def _reads_as(raw: bytes, version: int, width: int, count: int) -> bool:
    """Whether the entries read cleanly when the object ids are this long."""
    landed = 12
    seen = 0
    try:
        for _, at in _walk(raw, version, width, count):
            landed = at
            seen += 1
            if seen >= _PROBE:
                break
    except GitIndexError, struct.error, IndexError:
        return False
    if seen < count:
        # Stopped at the probe limit rather than at the end, so there is no landing point
        # to check and the clean walk is the whole of the answer.
        return True
    rest = raw[landed:]
    return len(rest) == width or (rest[:4].isalpha() and rest[:4].isupper())


def _path(raw: bytes, cursor: int, flags: int, version: int, previous: str) -> tuple[str, int, str]:
    """One entry's path, and the path the next entry will measure itself against.

    Version four stores a path as the number of characters to strip from the end of the
    previous one and then the rest of it, so an entry cannot be read on its own. That is
    the whole of the difference between the versions here.
    """
    if version >= 4:
        strip, cursor = _varint(raw, cursor)
        end = raw.find(b"\x00", cursor)
        if end == -1:
            raise GitIndexError("a version four path has no terminator")
        if strip > len(previous):
            raise GitIndexError("a version four path strips more than the previous one holds")
        path = previous[: len(previous) - strip] + raw[cursor:end].decode("utf-8", "replace")
        return path, end + 1, path
    length = flags & _NAME_MASK
    if length == _NAME_CAPPED:
        end = raw.find(b"\x00", cursor)
        if end == -1:
            raise GitIndexError("a long path has no terminator")
    else:
        end = cursor + length
    if end > len(raw):
        raise GitIndexError("a path runs off the end of the file")
    return raw[cursor:end].decode("utf-8", "replace"), end + 1, previous


def _varint(raw: bytes, at: int) -> tuple[int, int]:
    """The offset encoding version four uses, which is not the ordinary one.

    Each byte after the first adds one before shifting, so the same number has one
    spelling. Written out here rather than shared with the protocol buffer reader beside
    it, which uses the ordinary encoding and would give a different answer.
    """
    if at >= len(raw):
        raise GitIndexError("a length ran off the end of the file")
    value = raw[at] & 0x7F
    while raw[at] & 0x80:
        at += 1
        if at >= len(raw):
            raise GitIndexError("a length ran off the end of the file")
        value = ((value + 1) << 7) | (raw[at] & 0x7F)
    return value, at + 1


__all__ = [
    "MAGIC",
    "MAX_ENTRIES",
    "VERSIONS",
    "GitIndexError",
    "IndexEntry",
    "looks_like_index",
    "read",
]
