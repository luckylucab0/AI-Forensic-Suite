"""Tests for the memory-mapped B-tree reader.

The reader was written against stores liblmdb 0.9.35 produced, and every record it returned
was compared against what that library returned for the same file: two stores, one of them
with a two-level tree, a hundred duplicates under one key and a five-kilobyte value in an
overflow page, and all 2772 records came back identical. That comparison needs the library,
which this project does not depend on, so it runs here only where somebody has it installed
and the rest of these tests build their pages by hand.

Building them by hand is not a weaker test of the same thing. It is a test of a different
thing: what this reader does with a store that is damaged, truncated, or shaped in a way no
writer produces. Those are the cases a collection actually presents, because a file copied
off a running endpoint is a file copied mid-write.

The one store that is neither is the fixture generator's, which is checked here as well:
the generator writes a real store, so what it writes has to read back.
"""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

import pytest

from agentforensics.parsers import lmdb

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tests" / "fixtures"))

from generate import write_prompt_library  # noqa: E402

PAGE = 4096
NO_PAGE = 0xFFFFFFFFFFFFFFFF


# ------------------------------------------------------------- pages, by hand


def _leaf(number: int, rows: list, *, flags: int = 0x02) -> bytes:
    """One page of nodes: the offsets from the top, the nodes from the bottom.

    A row is a key and a value, with the node's flags where a test needs them.
    """
    page = bytearray(PAGE)
    struct.pack_into("<QHH", page, 0, number, 0, flags)
    upper = PAGE
    offsets = []
    for row in rows:
        key, value, node_flags, stated = (*tuple(row), 0, 0)[:4]
        stated = stated or len(value)
        upper -= (8 + len(key) + len(value) + 1) & ~1
        struct.pack_into("<HHHH", page, upper, stated & 0xFFFF, stated >> 16, node_flags, len(key))
        page[upper + 8 : upper + 8 + len(key)] = key
        page[upper + 8 + len(key) : upper + 8 + len(key) + len(value)] = value
        offsets.append(upper)
    for index, offset in enumerate(offsets):
        struct.pack_into("<H", page, 16 + index * 2, offset)
    struct.pack_into("<HH", page, 12, 16 + 2 * len(offsets), upper)
    return bytes(page)


def _branch(number: int, children: list[tuple[bytes, int]]) -> bytes:
    """A branch page, whose nodes carry a page number across three header fields."""
    rows = []
    for key, child in children:
        rows.append((key, b"", (child >> 32) & 0xFFFF))
    page = bytearray(_leaf(number, [], flags=0x01))
    upper = PAGE
    offsets = []
    for (key, child), (_, _, high) in zip(children, rows, strict=True):
        upper -= (8 + len(key) + 1) & ~1
        struct.pack_into(
            "<HHHH", page, upper, child & 0xFFFF, (child >> 16) & 0xFFFF, high, len(key)
        )
        page[upper + 8 : upper + 8 + len(key)] = key
        offsets.append(upper)
    for index, offset in enumerate(offsets):
        struct.pack_into("<H", page, 16 + index * 2, offset)
    struct.pack_into("<HH", page, 12, 16 + 2 * len(offsets), upper)
    return bytes(page)


def _descriptor(entries: int, root: int, *, pad: int = 0, flags: int = 0, depth: int = 1) -> bytes:
    return struct.pack("<IHHQQQQQ", pad, flags, depth, 0, 1, 0, entries, root)


def _meta(
    number: int, root: int, entries: int, last: int, txnid: int, *, magic: int = lmdb.MAGIC
) -> bytes:
    page = bytearray(PAGE)
    struct.pack_into("<QHH", page, 0, number, 0, 0x08)
    struct.pack_into("<II", page, 16, magic, lmdb.VERSION)
    struct.pack_into("<QQ", page, 24, 0, 1 << 30)
    page[40:88] = _descriptor(0, NO_PAGE, pad=PAGE, depth=0)
    page[88:136] = _descriptor(entries, root)
    struct.pack_into("<QQ", page, 136, last, txnid)
    return bytes(page)


def _store(pages: list[bytes], root: int, entries: int, *, txnid: int = 1) -> bytes:
    """A whole file: two meta pages naming the same root, then the pages given."""
    last = 1 + len(pages)
    return b"".join(
        [_meta(0, root, entries, last, txnid), _meta(1, root, entries, last, txnid), *pages]
    )


def _named(
    databases: dict[str, list[tuple[bytes, bytes]]], extra: list[bytes] | None = None
) -> bytes:
    """A store of named sub-databases, the shape every store in this project has."""
    pages: list[bytes] = []
    main: list[tuple[bytes, bytes, int]] = []
    number = 2
    for name in sorted(databases):
        rows = sorted(databases[name])
        pages.append(_leaf(number, [(key, value, 0) for key, value in rows]))
        main.append((name.encode(), _descriptor(len(rows), number), 0x02))
        number += 1
    main_page = number
    pages.append(_leaf(main_page, main))
    pages.extend(extra or [])
    return _store(pages, main_page, len(main))


# ------------------------------------------------------------------ the reading


def test_a_store_is_recognised_by_its_meta_page() -> None:
    raw = _named({"a": [(b"k", b"v")]})
    assert lmdb.looks_like_lmdb(raw)
    assert not lmdb.looks_like_lmdb(b"SQLite format 3\x00" + bytes(200))
    assert not lmdb.looks_like_lmdb(b"")
    # The right flags and the wrong number: a page that says it is a meta page and is not.
    assert not lmdb.looks_like_lmdb(_store([], 2, 0)[:10] + struct.pack("<H", 0x08) + bytes(64))


def test_every_named_database_and_every_record_comes_back() -> None:
    raw = _named(
        {
            "bodies.v2": [(b"one", b"first"), (b"two", b"second")],
            "metadata.v2": [(b"one", b'{"title": "One"}')],
        }
    )
    store = lmdb.read(raw)
    assert [database.name for database in store.databases] == ["", "bodies.v2", "metadata.v2"]
    assert [(record.database, record.key, record.value) for record in store.records] == [
        ("bodies.v2", b"one", b"first"),
        ("bodies.v2", b"two", b"second"),
        ("metadata.v2", b"one", b'{"title": "One"}'),
    ]
    assert store.stopped == ""


def test_the_meta_page_with_the_higher_transaction_is_the_current_one() -> None:
    """Both pages are written, alternately, and the older one is the state before this one.
    A reader that took page zero would answer with a store one transaction out of date."""
    pages = [_leaf(2, [(b"new", b"current")]), _leaf(3, [(b"old", b"previous")])]
    raw = bytearray(_store(pages, 2, 1))
    raw[:PAGE] = _meta(0, 3, 1, 3, 4)
    raw[PAGE : 2 * PAGE] = _meta(1, 2, 1, 3, 9)
    store = lmdb.read(bytes(raw))
    assert store.current.transaction == 9
    assert store.previous is not None and store.previous.transaction == 4
    assert [record.key for record in store.records] == [b"new"]


def test_a_value_too_big_for_a_page_is_read_out_of_its_own_pages() -> None:
    """A value over about half a page goes into a run of pages of its own and the node
    keeps the page number. A reader that took the node's bytes would return eight bytes of
    a page number as the value, which for a prompt library is somebody's prompt."""
    body = b"x" * 9000
    overflow = bytearray(PAGE * 3)
    struct.pack_into("<QHHI", overflow, 0, 4, 0, 0x04, 3)
    overflow[16 : 16 + len(body)] = body
    pages = [
        _leaf(2, [(b"big", struct.pack("<Q", 4), 0x01, len(body))]),
        _leaf(3, [(b"bodies", _descriptor(1, 2), 0x02)]),
        bytes(overflow),
    ]
    store = lmdb.read(_store(pages, 3, 1))
    assert [record.value for record in store.records] == [body]
    assert not store.records[0].problem


def test_a_key_with_several_values_gives_one_record_each() -> None:
    """Duplicates live in a page nested inside the node, and a duplicate is stored as that
    page's key with no value. Returning the nested page as the value would put a page
    header into a case as a record."""
    nested = _leaf(0, [(b"first", b"", 0), (b"second", b"", 0)], flags=0x02 | 0x40)
    # A sub-page is only as long as it needs to be, and the node's size says how long.
    trimmed = nested[: 16 + 4] + nested[struct.unpack_from("<H", nested, 14)[0] :]
    packed = bytearray(trimmed)
    struct.pack_into("<HH", packed, 12, 16 + 4, 16 + 4)
    offsets = [16 + 4 + 0, 16 + 4 + ((8 + len(b"second") + 1) & ~1)]
    struct.pack_into("<HH", packed, 16, offsets[0], offsets[1])
    pages = [
        _leaf(2, [(b"same", bytes(packed), 0x04)]),
        _leaf(3, [(b"dup", _descriptor(2, 2), 0x02)]),
    ]
    store = lmdb.read(_store(pages, 3, 1))
    assert [(record.value, record.duplicate) for record in store.records] == [
        (b"second", 1),
        (b"first", 2),
    ]


def test_a_file_that_is_not_a_store_is_refused_rather_than_read() -> None:
    with pytest.raises(lmdb.LmdbError, match="meta page"):
        lmdb.read(b"not a store at all")
    # Both meta pages, because one of them is enough to read the store and a test that
    # broke only the first would pass on a reader that ignored them both.
    with pytest.raises(lmdb.LmdbError, match="meta page"):
        lmdb.read(
            _store([_leaf(2, [(b"k", b"v")])], 2, 1).replace(
                b"\xde\xc0\xef\xbe", b"\x00\x00\x00\x00"
            )
        )


def test_one_torn_meta_page_does_not_cost_the_store() -> None:
    """A file copied while it was being written can have one meta page half-written.

    The first page is the harder half, because the page size is written there and nowhere
    else, so the second meta page cannot even be found without it. The reader tries the
    page sizes a machine can have and checks each candidate against the page's own
    statement of it. Refusing the file instead would throw away every record in it.
    """
    raw = bytearray(_named({"a": [(b"k", b"v")]}))
    raw[:PAGE] = bytes(PAGE)
    store = lmdb.read(bytes(raw))
    assert store.previous is None
    assert store.current.page_size == PAGE
    assert [record.value for record in store.records] == [b"v"]


def test_a_value_running_past_the_end_of_the_file_is_reported() -> None:
    """What a file copied out from under a writer looks like: the last page is short."""
    pages = [_leaf(2, [(b"a", _descriptor(1, 3), 0x02)]), _leaf(3, [(b"k", b"v" * 40)])]
    raw = _store(pages, 2, 1)
    # Cut into the node at the bottom of the last page, where its value sits.
    store = lmdb.read(raw[:-20])
    assert store.records
    assert lmdb.TRUNCATED in store.records[0].problem


def test_a_page_that_points_at_itself_returns_rather_than_hanging() -> None:
    """It cannot happen in a store a writer produced and it can happen in a damaged file."""
    pages = [_branch(2, [(b"", 2)])]
    store = lmdb.read(_store(pages, 2, 1))
    assert store.records == ()


def test_a_tree_of_two_levels_is_followed_down() -> None:
    pages = [
        _leaf(2, [(b"a", b"1"), (b"b", b"2")]),
        _leaf(3, [(b"c", b"3")]),
        _branch(4, [(b"", 2), (b"c", 3)]),
    ]
    store = lmdb.read(_store(pages, 4, 3))
    assert [record.value for record in store.records] == [b"1", b"2", b"3"]


def test_the_limit_reports_itself_rather_than_trimming_quietly() -> None:
    raw = _named({"a": [(f"k{n}".encode(), b"v") for n in range(20)]})
    store = lmdb.read(raw, limit=5)
    assert len(store.records) == 5
    assert "more than 5 records" in store.stopped


# ----------------------------------------------------- the pages nothing points at


def test_a_record_in_an_unreferenced_page_is_recovered_and_marked() -> None:
    """The reason this reader exists in a forensic tool. This format never overwrites a
    page, so a deleted record stays in the file until its space is reused, and a reader
    that only walked the tree would report the store as it is and say nothing about what
    was taken out of it."""
    # Page four, because nought and one are the meta pair, two is the database's leaf and
    # three is the main page: a page's number is where it is in the file.
    orphan = _leaf(4, [(b"gone", b"the record somebody deleted")])
    raw = _named({"a": [(b"here", b"live")]}, extra=[orphan])
    store = lmdb.read(raw)
    assert [record.value for record in store.records] == [b"live"]
    found = list(lmdb.stale(raw, store))
    assert [record.value for record in found] == [b"the record somebody deleted"]
    assert lmdb.STALE in found[0].problem
    assert found[0].page == 4


def test_a_live_record_is_not_returned_a_second_time_as_a_recovered_one() -> None:
    """Every page the current tree reaches is left out of the scan, the pages of a big
    value included. Without that, every record in the store would come back twice and half
    of a case would be labelled as possibly deleted."""
    raw = _named({"a": [(b"here", b"live"), (b"also", b"live too")]})
    store = lmdb.read(raw)
    assert list(lmdb.stale(raw, store)) == []


def test_the_free_list_is_not_returned_as_recovered_evidence() -> None:
    """The store keeps its own bookkeeping in a tree of its own: one record per
    transaction, listing the pages that transaction released. Those pages are exactly where
    recovered records come from, and the tree that lists them is not one of them. A reader
    that did not know its root returned the free list itself as somebody's data."""
    free = _leaf(4, [(struct.pack("<Q", 3), struct.pack("<QQ", 1, 7))])
    raw = bytearray(_named({"a": [(b"here", b"live")]}, extra=[free]))
    # Point both meta pages' free tree at that page, which is what a store that has freed
    # something looks like.
    for page in (0, 1):
        raw[page * PAGE + 40 : page * PAGE + 88] = _descriptor(1, 4, pad=PAGE)
    store = lmdb.read(bytes(raw))
    assert list(lmdb.stale(bytes(raw), store)) == []


# ------------------------------------------- the store the fixture generator writes


def test_the_generators_store_reads_back(tmp_path: Path) -> None:
    """The fixture generator writes this format by hand, so what it writes has to read.

    It is checked here as well as by the parser's own tests because the generator is the
    only writer of this format in the project: a defect in it would make every test that
    uses the synthetic profile agree with a file no real store looks like.
    """
    ids = write_prompt_library(tmp_path / "prompts")
    raw = (tmp_path / "prompts" / "prompts-library-db.0.mdb" / "data.mdb").read_bytes()
    store = lmdb.read(raw)
    assert [database.name for database in store.databases] == ["", "bodies.v2", "metadata.v2"]
    assert len(store.records) == 4
    titles = [
        json.loads(record.value)["title"]
        for record in store.records
        if record.database == "metadata.v2"
    ]
    assert titles == ["Release notes", "House rules"]

    recovered = list(lmdb.stale(raw, store))
    assert ids["removed_prompt"] in "".join(record.value.decode() for record in recovered)
    assert all(lmdb.STALE in record.problem for record in recovered)


# --------------------------------------------- the cross-check, where it can run


@pytest.mark.skipif(
    __import__("importlib.util", fromlist=["util"]).find_spec("lmdb") is None,
    reason="the C library this cross-checks against is not installed, and is not a dependency",
)
def test_the_reader_agrees_with_the_c_library(tmp_path: Path) -> None:
    """The strongest form this test can take, where the library happens to be present.

    This is how the reader was written: every record out of two stores that library wrote,
    including a two-level tree, a hundred duplicates under one key and a value in an
    overflow page, compared against what it returned for the same file. Kept as a skipped
    test rather than dropped, so anybody who has the library can re-run the comparison the
    reader was built on.
    """
    import lmdb as liblmdb  # type: ignore[import-not-found]

    where = tmp_path / "store"
    environment = liblmdb.open(str(where), max_dbs=4, map_size=8 * 1024 * 1024)
    first = environment.open_db(b"metadata.v2")
    second = environment.open_db(b"bodies.v2")
    with environment.begin(write=True) as transaction:
        for number in range(200):
            transaction.put(f"key-{number:04d}".encode(), b"value " * 12, db=first)
        transaction.put(b"big", b"z" * 9000, db=second)
    with environment.begin(write=True) as transaction:
        transaction.delete(b"key-0000", db=first)

    raw = (where / "data.mdb").read_bytes()
    store = lmdb.read(raw)
    mine: dict[str, list[tuple[bytes, bytes]]] = {}
    for record in store.records:
        mine.setdefault(record.database, []).append((record.key, record.value))
    for name in (b"metadata.v2", b"bodies.v2"):
        database = environment.open_db(name, create=False)
        with environment.begin(db=database) as transaction:
            theirs = list(transaction.cursor().iternext(keys=True, values=True))
        assert mine[name.decode()] == theirs
    environment.close()

    # And the record the library no longer returns is in the pages it left behind.
    assert any(record.key == b"key-0000" for record in lmdb.stale(raw, store))


# ------------------------------------------- the floor under a store nobody has mapped


def _floor(raw: bytes, tmp_path: Path, name: str = "data.mdb") -> list:
    """The generic reader, over a store written to a file the way a collection holds one."""
    from agentforensics.parsers import ParseContext, for_artifact

    where = tmp_path / "threads-db.1.mdb"
    where.mkdir(parents=True, exist_ok=True)
    (where / name).write_bytes(raw)
    parser = for_artifact("zed.flatpak_legacy_threads")
    assert parser is not None and parser.name == "lmdb_generic"
    return list(
        parser.parse(
            ParseContext(
                bundle_uuid="b1",
                original_path=f"/home/alice/.var/app/dev.zed.Zed/data/zed/threads/threads-db.1.mdb/{name}",
                local_path=where / name,
                sha256="aa",
                artifact_id="zed.flatpak_legacy_threads",
                agent="zed",
                user="alice",
            )
        )
    )


def test_a_store_nobody_has_a_schema_for_gives_up_its_records_anyway(tmp_path: Path) -> None:
    """The floor, and the whole reason the entry stopped saying it needs a reader.

    Nothing in this suite has a source for what is in this store, so nothing is decided
    about a record: the key and the value come out as they are, the value is offered as
    text where it is text, and every event says the reading is uninterpreted. A case with
    that in it is evidence somebody has to look at; a case with a directory in it and
    nothing else reads as a store that held nothing.
    """
    raw = _named({"threads": [(b"thread-1", b"what did we decide"), (b"thread-2", b"\x00\x01")]})
    events = _floor(raw, tmp_path)

    described, records = events[0], events[1:]
    assert "2 record(s) in threads" in (described.parse_problem or "")
    assert all(event.kind == "unparsed.record" for event in events)
    assert [event.raw["key"] for event in records] == ["thread-1", "thread-2"]
    assert records[0].payload["text"] == "what did we decide"
    assert all("is returned uninterpreted" in (event.parse_problem or "") for event in records)
    # A value that is not text is not offered as text, and its bytes are still in the case.
    assert records[1].raw["value"] == "0001"
    assert records[1].payload["text"] is None


def test_the_floor_reads_the_pages_the_store_no_longer_points_at(tmp_path: Path) -> None:
    """For a store nobody has a schema for this matters more rather than less: if the entry
    is what its notes say, those pages hold conversations somebody deleted."""
    orphan = _leaf(4, [(b"thread-0", b"the conversation that was deleted")])
    raw = _named({"threads": [(b"thread-1", b"live")]}, extra=[orphan])
    events = _floor(raw, tmp_path)

    recovered = [event for event in events if lmdb.STALE in (event.parse_problem or "")]
    assert [event.raw["value"] for event in recovered] == ["the conversation that was deleted"]
    assert "is returned uninterpreted" in (recovered[0].parse_problem or "")


def test_every_record_of_one_store_has_its_own_identity(tmp_path: Path) -> None:
    """A key is unique within a database and not within a store, and the same key can be in
    a freed page as well. Two events with one locator are one row in a case."""
    orphan = _leaf(4, [(b"same", b"the earlier one")])
    raw = _named(
        {"a": [(b"same", b"one")], "b": [(b"same", b"two")]},
        extra=[orphan],
    )
    events = _floor(raw, tmp_path)
    identities = [(event.provenance.locator, event.kind) for event in events]
    assert len(set(identities)) == len(identities)


def test_the_lock_file_and_a_stranger_in_the_directory_are_named(tmp_path: Path) -> None:
    lock = _floor(b"", tmp_path, "lock.mdb")
    assert len(lock) == 1
    assert "lock file" in (lock[0].parse_problem or "")

    stranger = _floor(b"not a database\n", tmp_path, "notes.txt")
    assert len(stranger) == 1
    assert "is not one" in (stranger[0].parse_problem or "")
