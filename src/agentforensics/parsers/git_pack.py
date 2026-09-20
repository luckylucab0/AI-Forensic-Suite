"""Expand a git pack file, deltas and all, so a packed checkpoint is readable.

The reader beside this one reads a loose object: one file, zlib, a header and a body. That
is what a repository an agent just created holds, and it was enough until it was not. Once
git packs a repository the objects move into one file as a stream, most of them stored as a
difference against another object in the same file, and the module that named a pack and
did not open it said so on the event: the objects are in there and this suite did not
expand them. That is honest and it is still a gap, because these repositories are the only
place the pre-edit content of a checkpointed file exists.

**The stream.** A header of PACK, a version and a count, then that many objects, then a
trailing hash. Each object begins with its own variable-length header carrying a type in
three bits and a size in the rest, followed by zlib. Four of the types are the objects
themselves. The other two are deltas, and they are the reason this file is not thirty
lines: an offset delta names its base by how far back in this same pack it is, and a
reference delta names it by object id. Both are resolved here.

**The delta encoding.** A base size, a result size, then instructions: copy a run from the
base, or insert the bytes that follow. The copy instruction's offset and length are spelled
in whichever bytes the flag bits say are present, which is the one part of this format that
cannot be read by looking at it.

**Nothing is resolved recursively, and that is deliberate.** A base always comes earlier in
the file than the delta against it, so one pass in file order has every base in hand by the
time it is needed. Each expanded object remembers how many deltas it took to get there, and
a delta inherits that number plus one, which enforces the chain limit without following a
chain and makes a cycle unrepresentable.

**The object ids are computed, and that is what tells the hash apart.** A pack does not
carry ids; git derives one by hashing the type, the length and the content. Which hash a
repository uses is not in the pack header either, so it is read off the end: whatever is
left after the last object is the trailing hash, and its length says which. A repository
written with either hash therefore reads without being told which, and the ids come out the
way git prints them.

**An object that does not expand is returned as the delta it is, with the reason.** A pack
can be thin, naming a base the receiver already has, and one stored in a repository
normally is not. Guessing at such an object would put plausible wrong bytes into a case,
and dropping it, or letting it end the read of the objects after it, would make a case say
a repository held less than it did. So the object comes back carrying its problem, and the
rest of the pack is read.

Format reference, read while writing this:
https://raw.githubusercontent.com/git/git/master/Documentation/gitformat-pack.adoc
"""

from __future__ import annotations

import hashlib
import struct
import zlib
from dataclasses import dataclass, field

MAGIC = b"PACK"
VERSIONS = (2, 3)

# The type in an object's header, in the three bits the format puts it in. Zero and five
# are unused: zero is invalid and five is reserved and has never been used, so meeting
# either means this is not a pack this reader understands.
_TYPE_NAMES = {1: "commit", 2: "tree", 3: "blob", 4: "tag"}
_OFS_DELTA, _REF_DELTA = 6, 7

# What a delta is called on an event when it could not be expanded. It is the type as the
# pack spells it, so the event says which of the two kinds of base reference went unfound.
_DELTA_NAMES = {_OFS_DELTA: "offset_delta", _REF_DELTA: "reference_delta"}

# How long a delta chain may be. git's own default when packing is fifty, so a longer one
# means a pack built with other settings, and expanding it would cost more than the object
# can be worth.
MAX_DEPTH = 64

# How much one object may expand to, how many a pack may yield, and how much of a pack may
# be held at once. The last one exists because every base has to stay in memory until the
# deltas against it are done, so a pack of a working copy could otherwise be read into a
# case one object at a time and still exhaust the host. All three are reported where they
# bite rather than passed over.
MAX_OBJECT = 64 * 1024 * 1024
MAX_OBJECTS = 20_000
MAX_TOTAL = 256 * 1024 * 1024

# Why a walk ended before the header's own count of objects. Each one is written for an
# analyst reading the event rather than for a log, because what is missing and where the
# rest of it still is decides what they do next.
STOPPED_COUNT = (
    "this pack holds {count} objects and the reading stopped after {limit}. The pack "
    "itself is in the bundle, whole, at the path in this event's provenance"
)
STOPPED_TOTAL = (
    "the objects of this pack passed {budget} bytes together and the reading stopped "
    "after {read} of {count}. The pack itself is in the bundle, whole, at the path in "
    "this event's provenance"
)
STOPPED_BROKEN = (
    "object {read} of this pack's {count} could not be read and the reading stopped "
    "there: {reason}. What came before it is in this case and the pack itself is in the "
    "bundle, whole"
)

# Why one object did not expand while the rest of the pack did.
NO_BASE = (
    "this object is a delta against {base}, which is not in this pack. A pack can name a "
    "base the receiver already holds, and one stored in a repository normally does not, "
    "so this is worth a look. The delta's own bytes are in this file at this event's "
    "offset, and applying them needs the base object"
)
UNRESOLVED_BASE = (
    "this object is a delta against {base}, which is in this pack and did not expand "
    "either, so the chain it belongs to has no readable root here. Its own bytes are in "
    "this file at this event's offset"
)
TOO_DEEP = (
    "this object is a delta at the end of a chain longer than {limit}, which is past what "
    "this reader follows. Its own bytes are in this file at this event's offset"
)

# An object whose type is not one of the six the format uses. Zero is invalid and five is
# reserved and has never been used, so this is a pack written by something this reader does
# not know. Reported on the object rather than raised, because the walk validated this
# object's own length against its header and is therefore still in step: the objects around
# it are readable and an analyst should have them.
UNKNOWN_TYPE = (
    "this object's header gives it type {kind}, which is not one of the six the pack "
    "format uses, so this reader does not know what its bytes are. They are in this file "
    "at this event's offset"
)


class GitPackError(ValueError):
    """The file is not a pack this reader understands."""


@dataclass(frozen=True, slots=True)
class PackedObject:
    """One object out of a pack, expanded and identified the way git identifies it."""

    kind: str
    body: bytes
    # Where in the file this object's header begins, which is also how a delta in the same
    # pack names it. Carried so an event can be tied back to a byte offset.
    offset: int
    # The id git would print for this object, and empty when it did not expand: an id is
    # the hash of the content, and there is no content to hash.
    object_id: str = ""
    # How many deltas had to be resolved to get here. Zero for an object stored whole.
    depth: int = 0
    # What a delta names as its base, as the pack spells it: an offset in this file, or an
    # object id. Empty for an object stored whole.
    base: str = ""
    # Empty when this object expanded. Otherwise why it did not, in which case `body` holds
    # the delta's own bytes rather than the object's.
    problem: str = ""


@dataclass(frozen=True, slots=True)
class Pack:
    """Everything one pack file yielded, and whether that was all of it."""

    version: int
    # How many objects the pack's own header claims. Compared against the objects below by
    # the caller, because a difference is the whole point of reporting both.
    count: int
    objects: tuple[PackedObject, ...] = field(default_factory=tuple)
    # Empty when every object the header counted was read. Otherwise why the walk ended.
    stopped: str = ""


@dataclass(frozen=True, slots=True)
class _Header:
    """One object's place in the file and its uncompressed bytes, before it is interpreted."""

    kind: int
    start: int
    end: int
    data: bytes
    # How far back an offset delta reaches, and the base's id for a reference delta. Kept
    # apart from `data` because both are binary and either can hold a NUL byte, so a pack
    # that put them in one buffer would split in the wrong place on roughly one object in
    # every fourteen.
    distance: int = 0
    reference: bytes = b""


def looks_like_pack(raw: bytes) -> bool:
    return raw[:4] == MAGIC


def read(raw: bytes, limit: int = MAX_OBJECTS, budget: int = MAX_TOTAL) -> Pack:
    """Every object in the pack, in the order the file stores them."""
    if not looks_like_pack(raw):
        raise GitPackError("this file does not begin with a pack signature")
    if len(raw) < 12:
        raise GitPackError("this file is shorter than a pack header")
    version, count = struct.unpack(">II", raw[4:12])
    if version not in VERSIONS:
        raise GitPackError(f"this pack is version {version}, which this reader does not know")

    # Walked once to find where every object starts and what its bytes are, before anything
    # is identified. Which hash the repository uses is not in the pack header and is read
    # off the end, so the walk has to finish before an id can be computed.
    found: list[_Header] = []
    at = 12
    spent = 0
    stopped = ""
    for index in range(count):
        if index >= limit:
            stopped = STOPPED_COUNT.format(count=count, limit=limit)
            break
        try:
            header = _one(raw, at)
        except GitPackError as error:
            stopped = STOPPED_BROKEN.format(read=index + 1, count=count, reason=error)
            break
        spent += len(header.data)
        if spent > budget:
            stopped = STOPPED_TOTAL.format(budget=budget, read=index, count=count)
            break
        found.append(header)
        at = header.end

    # Whatever is left after the last object is the trailing hash, and its length is the
    # only statement in the file of which hash the repository uses. A walk that stopped
    # early leaves something else there, so the ordinary hash is assumed and the ids of
    # such a pack are as good as that assumption.
    trailer = len(raw) - at if len(found) == count else 0
    width = 32 if trailer == 32 else 20

    objects: list[PackedObject] = []
    by_offset: dict[int, tuple[str, bytes, int]] = {}
    by_id: dict[str, tuple[str, bytes, int]] = {}
    # The objects that are in this pack and did not expand, so a delta against one of them
    # can say that rather than that its base is absent. The two are different findings: an
    # absent base means a pack that was never complete, and this means a chain whose root
    # this reader could not read.
    unresolved: set[int] = set()
    for header in found:
        kind, body, depth, problem = _resolve(header, by_offset, by_id, unresolved)
        object_id = "" if problem else _identify(width, kind, body)
        if problem:
            unresolved.add(header.start)
        else:
            by_offset[header.start] = (kind, body, depth)
            by_id[object_id] = (kind, body, depth)
        objects.append(
            PackedObject(
                kind=kind,
                body=body,
                offset=header.start,
                object_id=object_id,
                depth=depth,
                base=_base_of(header),
                problem=problem,
            )
        )
    return Pack(version=version, count=count, objects=tuple(objects), stopped=stopped)


def _identify(width: int, kind: str, body: bytes) -> str:
    """The id git would give this object: the hash of its type, its length and its bytes.

    Neither hash is used here for anything a hash protects, only to spell the name git
    spells for the same bytes, which is why the one that is no longer a security primitive
    says so rather than failing on a host that forbids it.
    """
    digest = hashlib.sha256() if width == 32 else hashlib.sha1(usedforsecurity=False)
    digest.update(f"{kind} {len(body)}".encode("ascii") + b"\x00")
    digest.update(body)
    return digest.hexdigest()


def _base_of(header: _Header) -> str:
    """What a delta names as its base, in the words the pack names it with."""
    if header.kind == _OFS_DELTA:
        return f"offset {header.start - header.distance}"
    if header.kind == _REF_DELTA:
        return header.reference.hex()
    return ""


def _one(raw: bytes, at: int) -> _Header:
    """One object's place in the file and its uncompressed bytes, without interpreting them."""
    start = at
    if at >= len(raw):
        raise GitPackError("an object header runs off the end of the pack")
    byte = raw[at]
    kind = (byte >> 4) & 0x07
    # The size, spelled little end first: four bits in the type byte and seven in each byte
    # that follows. It is the uncompressed length of what the stream holds, which for a
    # delta is the delta and not the object it produces.
    size = byte & 0x0F
    shift = 4
    at += 1
    while byte & 0x80:
        if at >= len(raw):
            raise GitPackError("an object size runs off the end of the pack")
        byte = raw[at]
        size |= (byte & 0x7F) << shift
        shift += 7
        at += 1

    distance = 0
    reference = b""
    if kind == _OFS_DELTA:
        distance, at = _distance(raw, at)
    elif kind == _REF_DELTA:
        # The base's id, in whichever hash the repository uses. Its length is not stated
        # here either, and the only lengths git uses are twenty and thirty-two; a pack of
        # the other kind reports the base as not found rather than reading a wrong one,
        # because a repository written with the long hash is still rare enough that
        # guessing from the byte that follows would be the less reliable of the two.
        reference = raw[at : at + 20]
        if len(reference) < 20:
            raise GitPackError("a delta's base reference runs off the end of the pack")
        at += 20

    stream = zlib.decompressobj()
    try:
        # One byte past the limit, so an object of exactly the limit is not reported as
        # being past it.
        data = stream.decompress(raw[at:], MAX_OBJECT + 1)
    except zlib.error as error:
        raise GitPackError(f"an object's stream at {at} does not decompress: {error}") from error
    if len(data) > MAX_OBJECT or not stream.eof:
        raise GitPackError(f"an object at {at} expands past the {MAX_OBJECT} byte limit")
    if len(data) != size:
        # The header's own count of what the stream holds. A disagreement means the file is
        # not what it says it is, and going on from here would read the next object's header
        # out of the middle of this one.
        raise GitPackError(f"an object at {at} says it holds {size} bytes and holds {len(data)}")
    consumed = len(raw) - at - len(stream.unused_data)
    return _Header(
        kind=kind, start=start, end=at + consumed, data=data, distance=distance, reference=reference
    )


def _distance(raw: bytes, at: int) -> tuple[int, int]:
    """How far back an offset delta reaches, in the encoding the pack format uses.

    Not the ordinary variable-length integer: each byte after the first adds one before
    shifting, so every distance has exactly one spelling. The index file uses the ordinary
    one, which is why this is written out rather than shared.
    """
    if at >= len(raw):
        raise GitPackError("a delta offset runs off the end of the pack")
    value = raw[at] & 0x7F
    while raw[at] & 0x80:
        at += 1
        if at >= len(raw):
            raise GitPackError("a delta offset runs off the end of the pack")
        value = ((value + 1) << 7) | (raw[at] & 0x7F)
    return value, at + 1


def _resolve(
    header: _Header,
    by_offset: dict[int, tuple[str, bytes, int]],
    by_id: dict[str, tuple[str, bytes, int]],
    unresolved: set[int],
) -> tuple[str, bytes, int, str]:
    """One object as its type, its bytes, its chain length and whatever kept it from being
    read.

    A base is always earlier in the file than a delta against it, so the two indexes hold
    every base this can need by the time it is asked for. Nothing recurses and nothing is
    looked up twice.
    """
    whole = _TYPE_NAMES.get(header.kind)
    if whole is not None:
        return whole, header.data, 0, ""
    name = _DELTA_NAMES.get(header.kind)
    if name is None:
        return f"type_{header.kind}", header.data, 0, UNKNOWN_TYPE.format(kind=header.kind)

    base = _base_of(header)
    found = (
        by_offset.get(header.start - header.distance)
        if header.kind == _OFS_DELTA
        else by_id.get(header.reference.hex())
    )
    if found is None:
        if header.start - header.distance in unresolved:
            return name, header.data, 0, UNRESOLVED_BASE.format(base=base)
        return name, header.data, 0, NO_BASE.format(base=base)
    base_kind, base_body, base_depth = found
    if base_depth >= MAX_DEPTH:
        return name, header.data, base_depth + 1, TOO_DEEP.format(limit=MAX_DEPTH)
    try:
        return base_kind, _apply(base_body, header.data), base_depth + 1, ""
    except GitPackError as error:
        return name, header.data, base_depth + 1, str(error)


def _apply(base: bytes, delta: bytes) -> bytes:
    """A delta against its base: copy runs from the base, insert the bytes that follow."""
    at = 0
    stated, at = _varint(delta, at)
    if stated != len(base):
        raise GitPackError(
            f"a delta is against a base of {stated} bytes and its base has {len(base)}"
        )
    size, at = _varint(delta, at)
    if size > MAX_OBJECT:
        raise GitPackError(f"a delta produces {size} bytes, which is past the {MAX_OBJECT} limit")
    out = bytearray()
    while at < len(delta):
        instruction = delta[at]
        at += 1
        if instruction & 0x80:
            # A copy. Which of the offset's four bytes and the length's three are present
            # is spelled by the low bits, one flag each, lowest first.
            offset = 0
            for shift in (0, 8, 16, 24):
                if instruction & (1 << (shift // 8)):
                    offset |= delta[at] << shift
                    at += 1
            length = 0
            for shift in (0, 8, 16):
                if instruction & (1 << (4 + shift // 8)):
                    length |= delta[at] << shift
                    at += 1
            if length == 0:
                # Zero means the whole of the three byte field's range, which is the one
                # value the encoding cannot spell.
                length = 0x10000
            if offset + length > len(base):
                raise GitPackError("a delta copies past the end of its base")
            out += base[offset : offset + length]
        elif instruction:
            if at + instruction > len(delta):
                raise GitPackError("a delta inserts more bytes than it carries")
            out += delta[at : at + instruction]
            at += instruction
        else:
            raise GitPackError("a delta instruction is zero, which the format does not use")
    if len(out) != size:
        raise GitPackError(f"a delta produced {len(out)} bytes and its header said {size}")
    return bytes(out)


def _varint(data: bytes, at: int) -> tuple[int, int]:
    """The ordinary variable-length integer, which the delta header uses."""
    value = 0
    shift = 0
    while True:
        if at >= len(data):
            raise GitPackError("a delta header ran off the end")
        byte = data[at]
        at += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, at
        shift += 7


__all__ = [
    "MAGIC",
    "MAX_DEPTH",
    "MAX_OBJECT",
    "MAX_OBJECTS",
    "MAX_TOTAL",
    "NO_BASE",
    "STOPPED_BROKEN",
    "STOPPED_COUNT",
    "STOPPED_TOTAL",
    "TOO_DEEP",
    "UNKNOWN_TYPE",
    "UNRESOLVED_BASE",
    "VERSIONS",
    "GitPackError",
    "Pack",
    "PackedObject",
    "looks_like_pack",
    "read",
]
