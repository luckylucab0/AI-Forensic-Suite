"""Read a git object out of a repository an agent kept for its own undo.

Two of the agents here snapshot the files they are about to change by committing them into
a repository of their own, one per working copy or one per conversation, and the catalogue
collects those repositories whole. So the commits, the trees and the file contents behind
every checkpoint are in the bundle already. Until this module the reader above it said on
every event that they were not, and sent the analyst back to the endpoint for something
they were holding.

The format is documented and small enough to read without a dependency, which matters for
the same reason it did for the browser engine's store: a compiled git binding cannot be
vendored into an air-gapped environment (ADR 0012), and a reader that shelled out to git
would need git on the examiner's machine and would touch evidence with a tool that writes.

**A loose object** is one file, zlib compressed, holding a type, a byte length, a NUL, and
then the body. Three of the four types are worth reading and this module reads all four:

  commit   the tree it points at, its parents, and the two identities with their times.
           Those times are the find: the reference log dates when a checkpoint was written
           and a commit dates when the content was captured, by the clock of the machine
           that captured it.
  tree     one entry per file, with the mode, the name and the object under it. A tree is
           the listing of what the agent had in front of it at that moment.
  blob     the file itself, which is the whole point.
  tag      read as far as the object it points at, because an agent's checkpoint namespace
           can hold one and a reader that stopped there would lose the chain.

**A packed object is read by the module beside this one.** Once git packs a repository the
objects move into one file as a stream, most of them stored as a difference against another
object in the same file, which is a format of its own and lives in `git_pack`. What the two
share is this module's `interpret`, which takes a type and the bytes and reads the commit,
the tree or the tag out of them: a pack stores the same content without the loose wrapper,
and two implementations of the commit header, one of them exercised only by packed
repositories, is how the two would come to disagree.

One catalogue entry states the part of this that is sourced: an agent's checkpoint
repository is never garbage collected by the agent, so what it wrote stays. Nothing
anywhere says the objects stay loose, and a repository somebody ran git in is packed like
any other, which is why both readers exist.

Format reference, read while writing this:
https://raw.githubusercontent.com/git/git/master/Documentation/gitformat-pack.adoc
https://git-scm.com/book/en/v2/Git-Internals-Git-Objects
"""

from __future__ import annotations

import re
import zlib
from collections.abc import Iterator
from dataclasses import dataclass, field

# How much one object may expand to. A blob is somebody's file and a repository an agent
# filled can hold a large one, so the cap is generous and is reported rather than silent.
MAX_OBJECT = 64 * 1024 * 1024

# The header of every loose object: a type, a space, the body's length in decimal, a NUL.
_HEADER = re.compile(rb"^(?P<type>blob|tree|commit|tag) (?P<size>\d+)\x00")

# The two hash lengths git uses, in bytes, so a repository written with either is read.
_SHA1, _SHA256 = 20, 32

# An identity line: a name, an address, the seconds since the epoch and the zone the
# machine was in. The zone is kept because it is the only statement in a checkpoint about
# where the machine thought it was.
_IDENTITY = re.compile(
    r"^(?P<who>.*?)\s+(?P<when>\d+)\s+(?P<zone>[+-]\d{4})$",
)


class GitObjectError(ValueError):
    """The file is not the shape a git object has."""


@dataclass(frozen=True, slots=True)
class TreeEntry:
    """One line of a tree: what a file was called and which object held it."""

    mode: str
    name: str
    object_id: str

    @property
    def is_directory(self) -> bool:
        # Git spells a directory as mode 40000, which has no leading zero in the object.
        return self.mode == "40000"


@dataclass(frozen=True, slots=True)
class GitObject:
    """One object, read as far as its type allows."""

    kind: str
    size: int
    body: bytes
    # Set for a commit or a tag: the object it points at, and for a commit its parents.
    tree: str | None = None
    parents: tuple[str, ...] = ()
    target: str | None = None
    # Set for a commit: the two identities, each as text, with the time pulled out.
    author: str | None = None
    author_time: str | None = None
    author_zone: str | None = None
    committer: str | None = None
    commit_time: str | None = None
    commit_zone: str | None = None
    message: str | None = None
    # Set for a tree.
    entries: tuple[TreeEntry, ...] = field(default_factory=tuple)


def looks_like_loose_object(raw: bytes) -> bool:
    """Whether the bytes begin the way a zlib stream holding an object begins.

    Checked on the compressed bytes, because a file under `objects/` that is not one is a
    thing this reader has to be able to say rather than raise about. Only the first block is
    expanded, which is enough for the header and cheap for a large blob.
    """
    try:
        head = zlib.decompressobj().decompress(raw, 64)
    except zlib.error:
        return False
    return bool(_HEADER.match(head))


def read(raw: bytes, limit: int = MAX_OBJECT) -> GitObject:
    """One loose object, expanded and read according to its own type."""
    stream = zlib.decompressobj()
    try:
        body = stream.decompress(raw, limit)
    except zlib.error as error:
        raise GitObjectError(
            f"this file is under objects/ and is not a zlib stream: {error}"
        ) from error
    if not stream.eof:
        # The stream did not finish, which with a byte limit means exactly one thing: the
        # object is larger than the limit and what came back is its first part. Returning
        # that would put the beginning of a file into a case as the file.
        raise GitObjectError(f"this object expands past the {limit} byte limit")
    found = _HEADER.match(body)
    if not found:
        raise GitObjectError("this file expanded and does not begin with an object header")
    kind = found.group("type").decode("ascii")
    size = int(found.group("size"))
    return interpret(kind, body[found.end() :], size)


def interpret(kind: str, content: bytes, size: int | None = None) -> GitObject:
    """One object read according to its type, from its content without the loose header.

    Split out from the reader above because a pack stores the type and the length in its
    own header and only the content in the stream, so the reader for packs needs this
    without the wrapper. Two implementations of the commit and the tree, one of them only
    ever exercised by packed repositories, is how the two would come to disagree.
    """
    if size is None:
        size = len(content)
    if kind == "tree":
        return GitObject(kind=kind, size=size, body=content, entries=tuple(_tree(content)))
    if kind in ("commit", "tag"):
        return _headers(kind, size, content)
    return GitObject(kind=kind, size=size, body=content)


# The modes git writes into a tree, and the whole set of them: a file, an executable
# file, a symbolic link, a directory and a submodule. Used to tell the two hash lengths
# apart rather than to refuse anything, because a tree carrying a mode outside this set
# is still a tree and its entries still belong in the case.
_TREE_MODES = frozenset({"100644", "100755", "120000", "40000", "160000"})


def _tree(content: bytes) -> Iterator[TreeEntry]:
    """Every entry of a tree, with the object id rendered the way git prints it."""
    yield from _tree_entries(content, _tree_width(content))


def _tree_width(content: bytes) -> int:
    """Which hash this tree was written with, decided by reading it with each.

    The length is not in the object and the repository's configuration, which is where git
    reads it from, is not necessarily in the collection. What was here instead was one
    piece of arithmetic on the first entry: the longer hash was chosen when what remained
    after that entry's name divided by thirty-two and not by twenty. Both hold whenever
    the remainder divides by a hundred and sixty, which a two entry tree reaches with an
    eight character second name, and such a tree from a SHA-256 repository was read twelve
    bytes short per entry and refused.

    Reading the whole tree with each length answers it instead. With the wrong one an
    entry's mode is taken from the middle of an object id, so requiring every mode to be
    one git writes separates the two even in the rare case where both lengths happen to
    consume the object exactly.
    """
    clean = []
    for width in (_SHA1, _SHA256):
        try:
            entries = list(_tree_entries(content, width))
        except GitObjectError:
            continue
        clean.append((width, bool(entries) and all(e.mode in _TREE_MODES for e in entries)))
    for width, plausible in clean:
        if plausible:
            return width
    # Either neither length reads the object, or one does and its modes are not ones git
    # writes. The older hash is the answer that was right for every repository written
    # before the newer one existed, and the walk reports whatever it then runs into.
    return clean[0][0] if clean else _SHA1


def _tree_entries(content: bytes, width: int) -> Iterator[TreeEntry]:
    """The entries, read with one object id length.

    The entries are packed rather than delimited: a mode, a space, the name, a NUL, and
    then the raw hash.
    """
    at = 0
    while at < len(content):
        space = content.find(b" ", at)
        nul = content.find(b"\x00", space + 1)
        if space == -1 or nul == -1:
            raise GitObjectError("a tree entry has no mode or no name")
        mode = content[at:space].decode("ascii", "replace")
        name = content[space + 1 : nul].decode("utf-8", "replace")
        if len(content) - (nul + 1) < width:
            raise GitObjectError("a tree entry runs off the end of the object")
        object_id = content[nul + 1 : nul + 1 + width].hex()
        at = nul + 1 + width
        yield TreeEntry(mode=mode, name=name, object_id=object_id)


def _headers(kind: str, size: int, content: bytes) -> GitObject:
    """A commit or a tag, which are a block of headers, a blank line and a message."""
    head, _, message = content.partition(b"\n\n")
    fields: dict[str, list[str]] = {}
    for line in head.decode("utf-8", "replace").split("\n"):
        name, _, value = line.partition(" ")
        if name:
            fields.setdefault(name, []).append(value)

    author, author_time, author_zone = _identity(fields.get("author"))
    committer, commit_time, commit_zone = _identity(fields.get("tagger") or fields.get("committer"))
    return GitObject(
        kind=kind,
        size=size,
        body=content,
        tree=_first(fields, "tree"),
        parents=tuple(fields.get("parent", ())),
        target=_first(fields, "object"),
        author=author,
        author_time=author_time,
        author_zone=author_zone,
        committer=committer,
        commit_time=commit_time,
        commit_zone=commit_zone,
        message=message.decode("utf-8", "replace") or None,
    )


def _first(fields: dict[str, list[str]], name: str) -> str | None:
    """The first value of a header, or nothing when the object has none of that header."""
    values = fields.get(name)
    return values[0] if values else None


def _identity(values: list[str] | None) -> tuple[str | None, str | None, str | None]:
    """A name, an address and a time out of one identity line.

    The time is returned as the seconds string git wrote rather than as a date, because
    turning it into one is the caller's normalisation and this module does not own it.
    """
    if not values:
        return None, None, None
    found = _IDENTITY.match(values[0])
    if not found:
        return values[0], None, None
    return found.group("who"), found.group("when"), found.group("zone")


__all__ = [
    "MAX_OBJECT",
    "GitObject",
    "GitObjectError",
    "TreeEntry",
    "interpret",
    "looks_like_loose_object",
    "read",
]
