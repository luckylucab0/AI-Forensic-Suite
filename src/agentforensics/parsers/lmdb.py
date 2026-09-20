"""Read a memory-mapped B-tree store, because one agent keeps its instruction surface in one.

One editor's prompt library, the text a user wrote for the agent to obey, is an LMDB
environment and nothing else on the endpoint holds it. A thread records that a prompt was
used; this is what the prompt said. It is implemented here rather than depended on for the
same reason the browser engine's store was (ADR 0031): a forensic tool that has to be
vendorable into an air-gapped environment does not take a C library for one artifact, and
the format is a page format that reads cleanly with `struct`.

**The file is an array of pages and the first two are the map.** Page zero and page one are
both meta pages, written alternately, so the one with the higher transaction id is the
current state of the store and the other one is the state before it. Each names the root
page of the main tree and the page size, which is the only place the page size is written
down.

**A tree is branch pages over leaf pages.** Every page carries an array of two-byte offsets
to its nodes, and a node is a four-field header, a key, and then either a value, a page
number, or a nested page. Which of those it is comes from the node's own flags, and getting
that wrong is how a reader would put a page of binary into a case as somebody's prompt:

- an ordinary leaf node carries its value inline
- a big value is written to its own run of pages and the node carries the page number
- a named sub-database is a leaf node of the main tree whose value is a tree descriptor, so
  the store is a tree of trees and the names are keys in the outer one
- a key with several values carries them as a nested page, or, once they outgrow one page,
  as a tree descriptor of their own. In both shapes a duplicate is stored as a node's key
  with no value, which is the one part of this format that cannot be guessed at

**The pages the tree no longer points at are read too, and marked.** Every write in this
format copies the page it changes and leaves the old one for reuse, so a store carries
earlier versions of live records and the records of deleted ones until the space is taken
again. That is evidence, and it is the reason this reader exists in a forensic tool rather
than a database client: a prompt somebody removed from the library is likely still in the
file. It cannot be told apart from an earlier version of a prompt that is still there, so
every such record says so on its own event and none of them is presented as live.

Format reference, read while writing this, and checked against stores liblmdb 0.9.35 wrote:
https://raw.githubusercontent.com/LMDB/lmdb/mdb.master/libraries/liblmdb/mdb.c
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass, field

# The number at the start of a meta page, and the format version this reader knows.
MAGIC = 0xBEEFC0DE
VERSION = 1

# The page header: a page number, two bytes of padding, the flags, and then either the two
# offsets bounding the free space in the middle of the page or, for a run of pages holding
# one big value, the length of the run.
PAGE_HEADER = 16

# A node header: the low and high half of a size or a page number, the flags, and the key
# length. The key follows, then whatever the flags say comes after it.
NODE_HEADER = 8

# A tree descriptor, which is what a meta page holds two of and a sub-database node holds
# one of: a key size for fixed-width pages, flags, the depth, three page counts, the number
# of entries and the root page.
DB_DESCRIPTOR = 48
_DESCRIPTOR = struct.Struct("<IHHQQQQQ")

# The page flags. A page is a branch or a leaf; an overflow page is the start of a run
# holding one value too big for a leaf; a sub-page is a leaf nested inside a node.
P_BRANCH, P_LEAF, P_OVERFLOW, P_META = 0x01, 0x02, 0x04, 0x08
P_LEAF2, P_SUBP = 0x20, 0x40

# The node flags.
F_BIGDATA, F_SUBDATA, F_DUPDATA = 0x01, 0x02, 0x04

# An empty root, which is what a tree descriptor carries for a database with no records.
NO_PAGE = 0xFFFFFFFFFFFFFFFF

# What one store may yield. A prompt library is a few dozen records of a few kilobytes; a
# store of another kind could be gigabytes, and a case should not be fillable by one of
# them. Every limit is reported where it bites rather than passed over.
MAX_RECORDS = 200_000
MAX_VALUE = 16 * 1024 * 1024
MAX_DEPTH = 32

# Said on a record found in a page the current tree does not reach. Written for the analyst
# who has to decide what it means, because this reader cannot decide it for them.
STALE = (
    "this record is in a page the store no longer points at. Every write in this format "
    "copies the page it changes and leaves the old one to be reused, so this is either a "
    "record that was deleted or an earlier version of one that is still there. The file "
    "cannot tell those apart: compare it against the live records on the other events from "
    "this store"
)

# Said on a record whose value ran past the end of the file, which is what a store copied
# while it was being written looks like.
TRUNCATED = "this record's value runs past the end of the file, so what is here is a fragment"


class LmdbError(ValueError):
    """The file is not a store this reader understands."""


@dataclass(frozen=True, slots=True)
class Meta:
    """One of the two meta pages: the store as one transaction left it."""

    page: int
    page_size: int
    transaction: int
    last_page: int
    # The root of the main tree, which holds the records of the unnamed database and one
    # node per named sub-database.
    root: int
    entries: int
    depth: int
    # The root of the tree of freed pages. Its records are the store's own bookkeeping, one
    # per transaction, listing the pages that transaction released. They are not read as
    # records, and the root is kept for one reason: those pages are exactly the ones a
    # reader can recover data from, and this tree's own pages are not among them. A reader
    # that did not know this root returned the free list itself as recovered evidence.
    free_root: int = NO_PAGE


@dataclass(frozen=True, slots=True)
class Database:
    """One tree in the store: the unnamed main one, or a named sub-database."""

    # Empty for the main database, which has no name because it is the one the names are in.
    name: str
    root: int
    entries: int
    depth: int
    flags: int

    @property
    def duplicates_allowed(self) -> bool:
        """Whether this database was created to hold several values under one key.

        Read from the descriptor rather than from what the records look like, because a
        database that allows duplicates and happens to have none reads exactly like one
        that does not, and the difference decides how a node's value is laid out.
        """
        return bool(self.flags & 0x04)


@dataclass(frozen=True, slots=True)
class Record:
    """One key and value out of a store, with whatever has to be said about it."""

    key: bytes
    value: bytes
    # The page the node sits in, so an event can be tied back to a place in the file.
    page: int
    # The name of the database it came from, empty for the main one.
    database: str = ""
    # Empty when the record is live and whole. Otherwise why it is not.
    problem: str = ""
    # For a key with several values: which of them this is, counted from one. Zero for a
    # key with a single value.
    duplicate: int = 0


@dataclass(frozen=True, slots=True)
class Store:
    """What one store yielded, and whether that was all of it."""

    current: Meta
    # The other meta page, which describes the transaction before the current one. Carried
    # because its root is a readable earlier state of the same store.
    previous: Meta | None
    databases: tuple[Database, ...] = field(default_factory=tuple)
    records: tuple[Record, ...] = field(default_factory=tuple)
    # Empty when everything the store points at was read. Otherwise why the reading stopped.
    stopped: str = ""


def looks_like_lmdb(raw: bytes) -> bool:
    """Whether the bytes begin with a meta page, which is how this format is recognised."""
    if len(raw) < PAGE_HEADER + 8:
        return False
    flags = struct.unpack_from("<H", raw, 10)[0]
    magic = struct.unpack_from("<I", raw, PAGE_HEADER)[0]
    return bool(flags & P_META) and magic == MAGIC


# The page sizes a store can have, which is the page size of the machine that wrote it.
# Needed only when the first meta page is unreadable: the page size is written in that page
# and nowhere else, so the second one cannot be found without either it or this list.
_PAGE_SIZES = (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536)


def read(raw: bytes, limit: int = MAX_RECORDS) -> Store:
    """Every live record of every database in the store, in key order within each."""
    first = _meta(raw, 0)
    second = _meta(raw, first.page_size) if first is not None else _second_meta(raw)
    if first is None and second is None:
        raise LmdbError("this file does not begin with a meta page this reader knows")
    if first is None:
        # The first page is torn, which is what a store copied while it was being written
        # can look like. The second one is a whole transaction of its own and reading it is
        # the difference between a case with this store in it and a case without.
        current, previous = second, None
    elif second is None or second.transaction <= first.transaction:
        current, previous = first, second
    else:
        current, previous = second, first
    if current is None:  # pragma: no cover - the two checks above leave one of them set
        raise LmdbError("this file has no readable meta page")

    found: list[Record] = []
    stopped = ""
    listed: list[Database] = [
        Database(name="", root=current.root, entries=current.entries, depth=current.depth, flags=0)
    ]
    for record in _walk(raw, current.page_size, current.root, MAX_DEPTH):
        if record.problem == _IS_A_DATABASE:
            listed.append(_database(record.key, record.value))
            continue
        if len(found) >= limit:
            stopped = _stopped(limit)
            break
        found.append(record)

    for database in listed[1:]:
        if stopped:
            break
        for record in _walk(raw, current.page_size, database.root, MAX_DEPTH):
            if len(found) >= limit:
                stopped = _stopped(limit)
                break
            found.append(
                Record(
                    key=record.key,
                    value=record.value,
                    page=record.page,
                    database=database.name,
                    problem="" if record.problem == _IS_A_DATABASE else record.problem,
                    duplicate=record.duplicate,
                )
            )
    return Store(
        current=current,
        previous=previous,
        databases=tuple(listed),
        records=tuple(found),
        stopped=stopped,
    )


def stale(raw: bytes, live: Store, limit: int = MAX_RECORDS) -> Iterator[Record]:
    """Every record in a page the current tree does not reach.

    The pages are walked once to learn which ones the store still points at, and then every
    other page in the file that looks like a leaf is read node by node. What comes back is
    labelled and never mixed with the live records: it is either a deleted record or an
    earlier version of a live one, and nothing in the file says which.
    """
    size = live.current.page_size
    reached = set(_reachable(raw, size, live))
    count = 0
    for page in range(len(raw) // size):
        if page in reached or count >= limit:
            continue
        flags = _flags(raw, size, page)
        if flags is None or not flags & P_LEAF or flags & (P_SUBP | P_META):
            continue
        for record in _nodes_of(raw, size, page, MAX_DEPTH):
            if count >= limit:
                return
            if record.problem == _IS_A_DATABASE:
                continue
            count += 1
            yield Record(
                key=record.key,
                value=record.value,
                page=page,
                database="",
                problem=" ".join(part for part in (record.problem, STALE) if part),
                duplicate=record.duplicate,
            )


# The marker a walk puts on a node that describes a sub-database rather than holding a
# value. It never reaches a caller: `read` turns it into an entry in `databases` and
# `stale` drops it, because a descriptor out of a page nobody points at names a root that
# may since have become something else entirely.
_IS_A_DATABASE = "\x00database"


def _stopped(limit: int) -> str:
    return (
        f"this store holds more than {limit} records and the reading stopped there. The "
        "file itself is in the bundle, whole, at the path in this event's provenance"
    )


def _second_meta(raw: bytes) -> Meta | None:
    """The second meta page, when the first one is unreadable and cannot say where it is.

    The page size is in the first meta page, so with that page gone the only way to the
    second one is to try the sizes a machine can have. Each candidate is checked against
    the page's own statement of the page size, so a match is the page and not a guess.
    """
    for size in _PAGE_SIZES:
        found = _meta(raw, size)
        if found is not None and found.page_size == size:
            return found
    return None


def _meta(raw: bytes, at: int) -> Meta | None:
    """One meta page, or None when there is no readable one at that offset.

    Both meta pages are checked rather than assumed: a store copied while it was being
    written can have one of them torn, and the other one is then the whole of what is
    readable. Refusing the file for the sake of the bad half would throw away the store.
    """
    if at + PAGE_HEADER + 136 > len(raw):
        return None
    flags = struct.unpack_from("<H", raw, at + 10)[0]
    magic, version = struct.unpack_from("<II", raw, at + PAGE_HEADER)
    if not flags & P_META or magic != MAGIC or version != VERSION:
        return None
    # The page size lives in the key-size field of the free-page tree's descriptor, which
    # is where this format keeps it and the reason a reader cannot find the second meta
    # page without reading the first.
    free = _DESCRIPTOR.unpack_from(raw, at + PAGE_HEADER + 24)
    main = _DESCRIPTOR.unpack_from(raw, at + PAGE_HEADER + 24 + DB_DESCRIPTOR)
    last_page, transaction = struct.unpack_from(
        "<QQ", raw, at + PAGE_HEADER + 24 + 2 * DB_DESCRIPTOR
    )
    page_size = free[0]
    if page_size < PAGE_HEADER + 8 or page_size > 1 << 20:
        return None
    return Meta(
        page=at // page_size,
        page_size=page_size,
        transaction=transaction,
        last_page=last_page,
        root=main[7],
        entries=main[6],
        depth=main[2],
        free_root=free[7],
    )


def _database(name: bytes, descriptor: bytes) -> Database:
    """A named sub-database, out of the descriptor a node of the main tree carries."""
    fields = _DESCRIPTOR.unpack_from(descriptor, 0)
    return Database(
        name=name.decode("utf-8", "replace"),
        root=fields[7],
        entries=fields[6],
        depth=fields[2],
        flags=fields[1],
    )


def _flags(raw: bytes, size: int, page: int) -> int | None:
    at = page * size
    if at + PAGE_HEADER > len(raw):
        return None
    return int(struct.unpack_from("<H", raw, at + 10)[0])


def _walk(
    raw: bytes, size: int, root: int, depth: int, seen: set[int] | None = None
) -> Iterator[Record]:
    """Every node under one root, following branch pages down to the leaves."""
    if root in (NO_PAGE, 0) or depth <= 0:
        return
    seen = set() if seen is None else seen
    if root in seen:
        # A page that points at itself, or at one already on this path. It cannot happen in
        # a store this format wrote and it can happen in a damaged file, and following it
        # would be the one way this reader could fail to return at all.
        return
    seen.add(root)
    flags = _flags(raw, size, root)
    if flags is None:
        return
    if flags & P_LEAF:
        yield from _nodes_of(raw, size, root, depth)
        return
    if not flags & P_BRANCH:
        return
    for child in _children(raw, size, root):
        yield from _walk(raw, size, child, depth - 1, seen)


def _children(raw: bytes, size: int, page: int) -> Iterator[int]:
    """The page numbers a branch page's nodes point at."""
    for _, low, high, flags, key_at, key_size in _headers(raw, size, page):
        if key_at is None:
            continue
        # A page number is spelled across three of the header's fields, because the format
        # reuses the flags field for the top bits rather than growing the header.
        yield low | (high << 16) | (flags << 32)
        del key_size, key_at


def _headers(
    raw: bytes, size: int, page: int
) -> Iterator[tuple[int, int, int, int, int | None, int]]:
    """Every node of a page, as (offset, low, high, flags, key offset, key size)."""
    at = page * size
    if at + PAGE_HEADER > len(raw):
        return
    lower = struct.unpack_from("<H", raw, at + 12)[0]
    if lower < PAGE_HEADER or lower > size:
        return
    for index in range((lower - PAGE_HEADER) // 2):
        (offset,) = struct.unpack_from("<H", raw, at + PAGE_HEADER + index * 2)
        node = at + offset
        if offset < PAGE_HEADER or node + NODE_HEADER > len(raw):
            continue
        low, high, flags, key_size = struct.unpack_from("<HHHH", raw, node)
        key_at = node + NODE_HEADER
        if key_at + key_size > len(raw):
            yield node, low, high, flags, None, key_size
            continue
        yield node, low, high, flags, key_at, key_size


def _nodes_of(raw: bytes, size: int, page: int, depth: int) -> Iterator[Record]:
    """Every record of one leaf page, with the nested shapes a node's value can take."""
    flags = _flags(raw, size, page) or 0
    if flags & P_LEAF2:
        yield from _packed(raw, size, page)
        return
    for _, low, high, node_flags, key_at, key_size in _headers(raw, size, page):
        if key_at is None:
            continue
        key = raw[key_at : key_at + key_size]
        value_at = key_at + key_size
        stated = low | (high << 16)
        if node_flags & F_SUBDATA:
            if value_at + DB_DESCRIPTOR > len(raw):
                continue
            yield Record(
                key=key,
                value=raw[value_at : value_at + DB_DESCRIPTOR],
                page=page,
                problem=_IS_A_DATABASE,
            )
            continue
        if node_flags & F_DUPDATA:
            yield from _duplicates(raw, size, page, key, value_at, stated, depth)
            continue
        if node_flags & F_BIGDATA:
            yield _big(raw, size, page, key, value_at, stated)
            continue
        value = raw[value_at : value_at + min(stated, MAX_VALUE)]
        problem = "" if len(value) == stated else TRUNCATED
        yield Record(key=key, value=value, page=page, problem=problem)


def _big(raw: bytes, size: int, page: int, key: bytes, value_at: int, stated: int) -> Record:
    """A value too big for a leaf, which lives in its own run of pages."""
    if value_at + 8 > len(raw):
        return Record(key=key, value=b"", page=page, problem=TRUNCATED)
    (start,) = struct.unpack_from("<Q", raw, value_at)
    at = start * size + PAGE_HEADER
    value = raw[at : at + min(stated, MAX_VALUE)]
    problem = "" if len(value) == min(stated, MAX_VALUE) else TRUNCATED
    if stated > MAX_VALUE:
        problem = (
            f"this record's value is {stated} bytes, and the first {MAX_VALUE} of it are "
            "here. The whole of it is in the file, in the bundle"
        )
    return Record(key=key, value=value, page=page, problem=problem)


def _duplicates(
    raw: bytes, size: int, page: int, key: bytes, value_at: int, stated: int, depth: int
) -> Iterator[Record]:
    """The several values stored under one key.

    Two shapes, and the node's own size is what tells them apart: while they fit they are a
    whole leaf page nested inside the node, and once they do not they become a tree of
    their own and the node carries its descriptor. In both shapes a value is stored as a
    node's key with nothing after it, which is the piece of this format that has to be read
    from its source rather than inferred.
    """
    if stated == DB_DESCRIPTOR and not _looks_like_page(raw, value_at):
        nested = _database(b"", raw[value_at : value_at + DB_DESCRIPTOR])
        for index, record in enumerate(_walk(raw, size, nested.root, depth - 1), start=1):
            yield Record(key=key, value=record.key, page=record.page, duplicate=index)
        return
    # A nested page, which is laid out exactly like a page in the file except that it sits
    # inside this node. It is copied out so the same node reader can be used on it, which
    # keeps one implementation of the layout rather than two.
    nested_page = raw[value_at : value_at + stated]
    if len(nested_page) < PAGE_HEADER:
        yield Record(key=key, value=b"", page=page, problem=TRUNCATED)
        return
    for index, record in enumerate(_nodes_of(nested_page, len(nested_page), 0, depth - 1), start=1):
        yield Record(key=key, value=record.key, page=page, duplicate=index)


def _looks_like_page(raw: bytes, at: int) -> bool:
    """Whether what a node carries is a nested page rather than a tree descriptor."""
    if at + PAGE_HEADER > len(raw):
        return False
    flags = struct.unpack_from("<H", raw, at + 10)[0]
    return bool(flags & P_SUBP)


def _packed(raw: bytes, size: int, page: int) -> Iterator[Record]:
    """A page of fixed-width keys with no values, which is how duplicates of one size are
    stored: no node headers at all, just the keys end to end after the page header."""
    at = page * size
    # The key width sits in the field an ordinary page uses for padding, and the count is
    # still the offset array's length even though such a page keeps no offsets: the format
    # uses that field as a counter here rather than growing the header.
    width, lower = (
        struct.unpack_from("<H", raw, at + 8)[0],
        struct.unpack_from("<H", raw, at + 12)[0],
    )
    if width == 0 or lower < PAGE_HEADER or lower > size:
        return
    for index in range((lower - PAGE_HEADER) // 2):
        start = at + PAGE_HEADER + index * width
        if start + width > len(raw):
            return
        yield Record(key=raw[start : start + width], value=b"", page=page, duplicate=index + 1)


def _reachable(raw: bytes, size: int, live: Store) -> Iterator[int]:
    """Every page the current state of the store points at, meta pages included."""
    yield 0
    yield 1
    # The free list's own tree, so its bookkeeping records do not come back as recovered
    # evidence. What it lists is the pages a reader can recover from; where it lives is not
    # one of them.
    yield from _pages(raw, size, live.current.free_root, MAX_DEPTH, set())
    if live.previous is not None:
        yield from _pages(raw, size, live.previous.free_root, MAX_DEPTH, set())
    for database in live.databases:
        yield from _pages(raw, size, database.root, MAX_DEPTH, set())


def _pages(raw: bytes, size: int, root: int, depth: int, seen: set[int]) -> Iterator[int]:
    if root in (NO_PAGE, 0) or depth <= 0 or root in seen:
        return
    seen.add(root)
    flags = _flags(raw, size, root)
    if flags is None:
        return
    yield root
    if flags & P_BRANCH:
        for child in _children(raw, size, root):
            yield from _pages(raw, size, child, depth - 1, seen)
        return
    if not flags & P_LEAF:
        return
    # A leaf's own overflow runs and nested trees count as reached, or every big value in
    # the store would come back a second time as a stale record.
    for _, low, high, node_flags, key_at, key_size in _headers(raw, size, root):
        if key_at is None:
            continue
        value_at = key_at + key_size
        if node_flags & F_BIGDATA and value_at + 8 <= len(raw):
            (start,) = struct.unpack_from("<Q", raw, value_at)
            run = (
                struct.unpack_from("<I", raw, start * size + 12)[0]
                if start * size + 16 <= len(raw)
                else 1
            )
            yield from range(start, start + max(run, 1))
        elif node_flags & F_SUBDATA:
            yield from _pages(raw, size, _database(b"", raw[value_at:]).root, depth - 1, seen)
        elif node_flags & F_DUPDATA and (low | (high << 16)) == DB_DESCRIPTOR:
            if not _looks_like_page(raw, value_at):
                yield from _pages(raw, size, _database(b"", raw[value_at:]).root, depth - 1, seen)


__all__ = [
    "DB_DESCRIPTOR",
    "MAGIC",
    "MAX_DEPTH",
    "MAX_RECORDS",
    "MAX_VALUE",
    "STALE",
    "TRUNCATED",
    "VERSION",
    "Database",
    "LmdbError",
    "Meta",
    "Record",
    "Store",
    "looks_like_lmdb",
    "read",
    "stale",
]
