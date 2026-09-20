"""Tests for the pack reader, against packs git itself wrote.

Every pack here is produced by running git, and every object that comes out is compared
against what `git cat-file` prints for the same id. That is the only test worth having for
a format like this one: a reader that agrees with git on the bytes and on the ids agrees
with git, while a fixture built from the format documentation would only prove the
documentation was read the same way twice. The delta encodings in particular cannot be
checked any other way, because whether a copy instruction was read correctly shows up as
plausible wrong bytes rather than as an error.

The three packs are the three shapes a repository can be in: offset deltas, which is what
git writes by default; reference deltas, which it writes when told not to use offsets; and
a repository using the long hash, which the reader is not told about and has to see for
itself. Below them are the cases git will not produce on request, built by hand from the
format, and each of those is about what this reader does rather than about the format.

git is not always installed, so the cases that need it skip without it.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import struct
import subprocess
import zlib
from pathlib import Path

import pytest

from agentforensics.parsers import ParseContext, for_artifact, git_pack

SESSION = "4f8c1e2a-0000-4000-8000-000000000001"
ARTIFACT = "amazonq.cli_checkpoints"

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")

# A fixed instant and identity, so the objects are the same on two runs. The address is the
# documentation's placeholder.
_ENV = {
    "GIT_AUTHOR_NAME": "alice",
    "GIT_AUTHOR_EMAIL": "alice@example.org",
    "GIT_COMMITTER_NAME": "alice",
    "GIT_COMMITTER_EMAIL": "alice@example.org",
    "GIT_AUTHOR_DATE": "1788912000 +0000",
    "GIT_COMMITTER_DATE": "1788912000 +0000",
}


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        env={**os.environ, **_ENV},
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def _build(root: Path, *configuration: str, hash_: str = "sha1") -> Path:
    """A repository with a delta chain in it, packed the way a real one would be.

    One file long enough for git to prefer a delta, then six edits to it, each of which
    gives git a version to store as a difference against the one before. Anything shorter
    is stored whole and the interesting half of the format is never exercised.
    """
    _git(root, "init", "-q", "-b", "main", f"--object-format={hash_}")
    body = "".join(f"line {number}\n" for number in range(400))
    (root / "notes.txt").write_text(body, encoding="utf-8", newline="")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "checkpoint 0")
    for number in range(1, 7):
        lines = (root / "notes.txt").read_text(encoding="utf-8").splitlines(True)
        lines[number * 10] = f"the agent edited this at run {number}\n"
        (root / "notes.txt").write_text("".join(lines), encoding="utf-8", newline="")
        _git(root, "commit", "-q", "-am", f"checkpoint {number}")
    # The configuration goes in front of the subcommand, which is where git takes it.
    _git(root, *configuration, "repack", "-a", "-d", "-q")
    return root


@pytest.fixture(scope="module")
def packed(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The default shape: deltas that name their base by its offset in the same file."""
    return _build(tmp_path_factory.mktemp("offsets"))


@pytest.fixture(scope="module")
def by_reference(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The other shape, which git writes when told not to use offsets. Older git versions
    and anything that received a pack over the wire produce it."""
    root = tmp_path_factory.mktemp("references")
    return _build(root, "-c", "repack.usedeltabaseoffset=false")


@pytest.fixture(scope="module")
def long_hash(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A repository using the long hash, which the pack does not state anywhere."""
    return _build(tmp_path_factory.mktemp("sha256"), hash_="sha256")


def _pack_bytes(root: Path) -> bytes:
    found = sorted((root / ".git" / "objects" / "pack").glob("*.pack"))
    assert len(found) == 1, found
    return found[0].read_bytes()


def _agrees_with_git(root: Path) -> git_pack.Pack:
    """Read the repository's pack and hold every object against git's own answer."""
    pack = git_pack.read(_pack_bytes(root))
    assert pack.stopped == ""
    assert len(pack.objects) == pack.count
    for found in pack.objects:
        assert not found.problem, found.problem
        printed = subprocess.run(
            ["git", "-C", str(root), "cat-file", found.kind, found.object_id],
            capture_output=True,
            check=True,
        ).stdout
        # The bytes and the id together. Either one alone would pass a reader that got the
        # deltas wrong and then hashed what it produced.
        assert printed == found.body
    return pack


# ------------------------------------------------------- against git's own packs


@needs_git
def test_every_object_of_a_packed_repository_comes_out_as_git_prints_it(packed: Path) -> None:
    """The whole of it: a repository the agent owns, packed, read back object for object.

    This is the evidence the reader exists for. Once a repository is packed the objects are
    in this one file and nowhere else, so the pre-edit content of every checkpointed file
    is either read out of here or is not in the case at all.
    """
    pack = _agrees_with_git(packed)
    assert pack.version in git_pack.VERSIONS
    kinds = {found.kind for found in pack.objects}
    assert {"commit", "tree", "blob"} <= kinds


@needs_git
def test_a_chain_of_deltas_is_followed_to_the_end(packed: Path) -> None:
    """A delta against a delta against a delta. git packs the versions of one file that
    way, so a reader that resolved only one level would return most of a repository's file
    contents as wrong bytes rather than as an error."""
    pack = _agrees_with_git(packed)
    assert max(found.depth for found in pack.objects) >= 2
    # Every delta says what it was against, so an analyst can see which objects were read
    # out of the file and which this suite computed.
    for found in pack.objects:
        assert bool(found.base) == bool(found.depth)


@needs_git
def test_a_delta_that_names_its_base_by_id_reads_the_same(by_reference: Path) -> None:
    pack = _agrees_with_git(by_reference)
    assert max(found.depth for found in pack.objects) >= 1


@needs_git
def test_the_hash_a_repository_uses_is_read_off_the_end_of_the_pack(long_hash: Path) -> None:
    """The pack does not say which hash the repository uses, so the reader is never told:
    it takes the length of the trailing hash as the answer. Getting this wrong produces
    ids of the right shape that name nothing, which is the worst kind of wrong here."""
    pack = _agrees_with_git(long_hash)
    assert {len(found.object_id) for found in pack.objects} == {64}


@needs_git
def test_a_reference_delta_whose_base_is_absent_is_reported_and_the_rest_is_read(
    packed: Path,
) -> None:
    """A thin pack, which is what git writes when told the receiver already holds the base.

    The rule this is about: a record that cannot be read is surfaced and the reading goes
    on. Raising here would have cost an analyst every object after this one, and guessing
    at a base would have put plausible wrong bytes into a case.
    """
    thin = subprocess.run(
        ["git", "-C", str(packed), "pack-objects", "--thin", "--stdout", "--revs"],
        input=b"HEAD\n^HEAD~1\n",
        capture_output=True,
        check=True,
    ).stdout
    pack = git_pack.read(thin)
    assert len(pack.objects) == pack.count
    unresolved = [found for found in pack.objects if found.problem]
    assert len(unresolved) == 1
    assert "not in this pack" in unresolved[0].problem
    # No id, because an id is the hash of content this reader does not have.
    assert unresolved[0].object_id == ""
    assert unresolved[0].base
    # And the objects around it are still here, read the ordinary way.
    assert {found.kind for found in pack.objects if not found.problem} == {"commit", "tree"}


@needs_git
def test_a_pack_cut_short_keeps_what_it_had_and_says_where_it_stopped(packed: Path) -> None:
    """A truncated file is what a collection of a repository mid-write can hold. What came
    out before the cut is evidence and is kept."""
    pack = git_pack.read(_pack_bytes(packed)[:1500])
    assert 0 < len(pack.objects) < pack.count
    assert "could not be read" in pack.stopped
    assert str(pack.count) in pack.stopped


@needs_git
def test_the_limits_report_themselves_rather_than_trimming_quietly(packed: Path) -> None:
    raw = _pack_bytes(packed)
    counted = git_pack.read(raw, limit=3)
    assert len(counted.objects) == 3
    assert "stopped after 3" in counted.stopped

    budgeted = git_pack.read(raw, budget=600)
    assert len(budgeted.objects) < counted.count
    assert "600 bytes together" in budgeted.stopped


# ------------------------------------------------- the cases git will not produce


def _pack(*objects: bytes, version: int = 2, count: int | None = None) -> bytes:
    """A pack file around bodies already in the on-disk shape, with its trailing hash."""
    head = git_pack.MAGIC + struct.pack(
        ">II", version, count if count is not None else len(objects)
    )
    body = head + b"".join(objects)
    return body + hashlib.sha1(body, usedforsecurity=False).digest()


def _whole(kind: int, content: bytes) -> bytes:
    """One object stored whole, with the header the format gives it."""
    return _object_header(kind, len(content)) + zlib.compress(content)


def _object_header(kind: int, size: int) -> bytes:
    out = bytearray([(kind << 4) | (size & 0x0F)])
    size >>= 4
    while size:
        out[-1] |= 0x80
        out.append(size & 0x7F)
        size >>= 7
    return bytes(out)


def _delta(distance: int, base: bytes, instructions: bytes) -> bytes:
    """An offset delta, with the distance in the one encoding this format uses for it."""
    content = _varint(len(base)) + _varint(len(instructions)) + instructions
    return _object_header(6, len(content)) + _back(distance) + zlib.compress(content)


def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _back(value: int) -> bytes:
    """The distance encoding: each byte after the first adds one before shifting."""
    out = [value & 0x7F]
    value >>= 7
    while value:
        value -= 1
        out.insert(0, (value & 0x7F) | 0x80)
        value >>= 7
    return bytes(out)


def test_a_file_that_is_not_a_pack_is_refused_rather_than_read() -> None:
    with pytest.raises(git_pack.GitPackError, match="pack signature"):
        git_pack.read(b"DIRC\x00\x00\x00\x02")
    with pytest.raises(git_pack.GitPackError, match="version 7"):
        git_pack.read(git_pack.MAGIC + struct.pack(">II", 7, 0))
    assert git_pack.looks_like_pack(git_pack.MAGIC + b"\x00")
    assert not git_pack.looks_like_pack(b"DIRC")
    with pytest.raises(git_pack.GitPackError, match="shorter than a pack header"):
        git_pack.read(git_pack.MAGIC + b"\x00\x00")


def test_an_object_whose_header_lies_about_its_length_stops_the_walk() -> None:
    """The length in the header is what says where the next object begins, so a reader that
    took the stream's word for it would read the rest of the file out of alignment and
    report objects that are not there."""
    lying = _object_header(3, 99) + zlib.compress(b"eight!!!")
    pack = git_pack.read(_pack(_whole(3, b"first"), lying))
    assert [found.kind for found in pack.objects] == ["blob"]
    assert "says it holds 99 bytes and holds 8" in pack.stopped


def test_a_delta_that_copies_past_its_base_is_reported_and_not_truncated() -> None:
    """A copy instruction reaching past the base means the delta and the base do not belong
    together. Returning the part that fit would be content this suite invented."""
    base = _whole(3, b"0123456789")
    # One copy instruction: the flags say one byte of offset and one of length.
    copy = bytes([0x80 | 0x01 | 0x10, 0, 200])
    objects = _pack(base, _delta(len(base), b"0123456789", copy))
    pack = git_pack.read(objects)
    assert len(pack.objects) == 2
    assert pack.objects[1].problem == "a delta copies past the end of its base"
    assert pack.objects[1].kind == "offset_delta"


def test_a_delta_against_a_base_of_another_length_is_refused() -> None:
    """The delta's first number is the length of the base it was made against. A base of a
    different length is a different object, and applying the instructions anyway would put
    bytes in a case that no version of the file ever held."""
    base = _whole(3, b"0123456789")
    wrong = _delta(len(base), b"01234", bytes([0x80 | 0x01 | 0x10, 0, 5]))
    pack = git_pack.read(_pack(base, wrong))
    assert "is against a base of 5 bytes" in pack.objects[1].problem


def test_an_insert_that_runs_off_the_end_of_the_delta_is_refused() -> None:
    base = _whole(3, b"0123456789")
    short = _delta(len(base), b"0123456789", bytes([20]) + b"three")
    pack = git_pack.read(_pack(base, short))
    assert "inserts more bytes than it carries" in pack.objects[1].problem


def test_an_offset_delta_reaching_outside_the_pack_is_reported_where_it_is() -> None:
    lonely = _delta(4096, b"0123456789", bytes([0x80 | 0x01 | 0x10, 0, 4]))
    pack = git_pack.read(_pack(lonely))
    assert len(pack.objects) == 1
    assert "not in this pack" in pack.objects[0].problem
    assert pack.objects[0].base.startswith("offset -")


def test_an_object_of_a_type_the_format_does_not_use_is_reported_where_it_is() -> None:
    """Type five is reserved and has never been used, and zero is invalid. Either one means
    a pack written by something this reader does not know, and the objects around it are
    still readable: the walk checks each object's length against its own header, so it is
    in step whether or not it understands the type it just passed."""
    pack = git_pack.read(_pack(_whole(3, b"a blob"), _whole(5, b"reserved")))
    assert [found.kind for found in pack.objects] == ["blob", "type_5"]
    assert pack.stopped == ""
    assert "not one of the six" in pack.objects[1].problem
    assert pack.objects[1].body == b"reserved"


def test_the_object_ids_are_the_ones_git_would_print() -> None:
    """Checked against the hash by hand as well as against git, because the id is what ties
    a packed object to the reference that names it, and a reference log full of ids that
    match nothing in the case is the failure this guards."""
    content = b"the file as it stood before the agent changed it\n"
    pack = git_pack.read(_pack(_whole(3, content)))
    want = hashlib.sha1(b"blob %d\x00" % len(content) + content, usedforsecurity=False).hexdigest()
    assert pack.objects[0].object_id == want
    assert pack.objects[0].body == content


# --------------------------------------------- the parser over a packed repository


def parse(root: Path, relative: str) -> list:
    parser = for_artifact(ARTIFACT)
    assert parser is not None
    return list(
        parser.parse(
            ParseContext(
                bundle_uuid="b1",
                original_path=f"/home/alice/.aws/amazonq/cli-checkouts/{SESSION}/.git/{relative}",
                # A repository the agent owns is bare, so its files sit at the root rather
                # than under a `.git` directory. Both shapes reach this parser.
                local_path=(
                    root / ".git" / relative if (root / ".git").is_dir() else root / relative
                ),
                sha256="aa",
                artifact_id=ARTIFACT,
                agent="amazonq",
                user="alice",
            )
        )
    )


def _relative(root: Path, suffix: str) -> str:
    found = sorted((root / ".git" / "objects" / "pack").glob(f"*{suffix}"))
    assert found, suffix
    return f"objects/pack/{found[0].name}"


@needs_git
def test_a_packed_repository_gives_the_checkpoint_parser_one_event_per_object(
    packed: Path,
) -> None:
    """What the reader is for, end to end. Before this the parser named the pack and said
    it was not expanded, which was honest and was still a repository's worth of file
    contents that no event in the case carried."""
    events = parse(packed, _relative(packed, ".pack"))
    kinds = [event.raw.get("type") for event in events]
    assert kinds.count("commit") == 7
    assert "blob" in kinds
    assert all(event.provenance.locator.startswith("offset:") for event in events)
    assert all("expanded out of the pack file" in (event.parse_problem or "") for event in events)

    commits = [event for event in events if event.raw.get("type") == "commit"]
    # The commit's own clock survives the trip through the pack: it is the machine's time at
    # the moment the content was captured, and for a packed repository this is the only
    # place it exists.
    assert all(event.ts_utc == "2026-09-09T00:00:00.000000Z" for event in commits)
    assert {event.raw["object_id"] for event in commits} == {
        _git(packed, "rev-parse", f"HEAD~{number}") for number in range(7)
    }

    blobs = [event for event in events if event.raw.get("type") == "blob"]
    assert any(
        "the agent edited this at run 6" in (event.raw.get("content") or "") for event in blobs
    )
    # An object this suite computed rather than read says so with the chain it came from.
    assert any(event.raw.get("delta_depth") for event in blobs)
    assert all(event.raw.get("pack_offset") is not None for event in events)


@needs_git
def test_the_index_beside_a_pack_is_named_as_derived_from_it(packed: Path) -> None:
    """It holds where in the pack each object is and no content of its own. Saying so keeps
    a file in the bundle from going unmentioned in the case."""
    events = parse(packed, _relative(packed, ".idx"))
    assert len(events) == 1
    assert "belongs to the pack file beside it" in (events[0].parse_problem or "")


@needs_git
def test_a_pack_that_counts_no_objects_is_still_an_event(packed: Path) -> None:
    """A pack yields one event per object, so one that yields none would leave a file in the
    bundle that nothing in the case mentions, and a case that says nothing about a file
    reads as a file that held nothing."""
    empty = packed / ".git" / "objects" / "pack" / "pack-0000000000000000.pack"
    empty.write_bytes(_pack(count=0))
    events = parse(packed, f"objects/pack/{empty.name}")
    assert len(events) == 1
    assert "counts no objects" in (events[0].parse_problem or "")


@needs_git
def test_a_file_named_as_a_pack_that_is_not_one_says_so(packed: Path) -> None:
    broken = packed / ".git" / "objects" / "pack" / "pack-1111111111111111.pack"
    broken.write_bytes(b"this is not a pack at all\n")
    events = parse(packed, f"objects/pack/{broken.name}")
    assert len(events) == 1
    assert "does not read as one" in (events[0].parse_problem or "")


def test_a_chain_whose_root_did_not_expand_says_that_and_not_that_it_is_absent() -> None:
    """Two findings that must not read the same. A base that is not in the pack means a
    pack that was never complete; a base that is in the pack and did not expand means a
    chain this reader could not read the root of, and an analyst chasing the first would go
    looking for a file that is already in their hands."""
    absent = _delta(4096, b"0123456789", bytes([0x80 | 0x01 | 0x10, 0, 4]))
    against_it = _delta(len(absent), b"0123", bytes([0x80 | 0x01 | 0x10, 0, 4]))
    pack = git_pack.read(_pack(absent, against_it))
    assert "not in this pack" in pack.objects[0].problem
    assert "did not expand either" in pack.objects[1].problem


# ------------------------------------------ the pack the fixture generator writes


def test_the_synthetic_profile_carries_a_packed_repository_and_it_reads(tmp_path: Path) -> None:
    """The fixture's own shadow repository, read the way a case reads one.

    This is the case that needs no git, which is the point of it: the suite's synthetic
    profile is what the conformance run, the rule packs and the end to end tests are built
    on, and until this repository was in it the whole pack path was exercised only where
    git happened to be installed. It also holds the generator to its word, because a
    fixture that writes a pack nothing can read is a fixture that proves nothing.

    The blob asserted on is the version of the file before the agent changed it, and in the
    pack it is a difference against the version after. What the agent changed is that it
    took a credential out of a configuration file, so that token is in no other file in the
    profile, and on an endpoint it would be in no other file either.
    """
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tests" / "fixtures"))
    from generate import write_shadow_repository

    ids = write_shadow_repository(tmp_path / "repository")
    found = sorted((tmp_path / "repository" / "objects" / "pack").glob("*.pack"))
    pack = git_pack.read(found[0].read_bytes())
    assert [object_.problem for object_ in pack.objects] == [""] * 6
    # The ids the generator says it wrote are the ids this reader computes from the bytes.
    # The generator hashes what it is about to store and this hashes what came back out, so
    # agreeing means the round trip through the pack and its delta kept the content.
    assert set(ids.values()) - {ids["pack"]} <= {object_.object_id for object_ in pack.objects}

    events = parse(tmp_path / "repository", f"objects/pack/{found[0].name}")
    before = [event for event in events if event.raw.get("object_id") == ids["blob_before"]]
    assert len(before) == 1
    # It came out of a delta, so these bytes were computed here and read nowhere.
    assert before[0].raw["delta_depth"] == 1
    # The credential the agent took out of the file. After that edit it is in no file on
    # the endpoint, so this delta inside this pack is the only copy of it there is.
    assert "Bearer sk_live_examplekey0123456789" in before[0].raw["content"]
    after = [event for event in events if event.raw.get("object_id") == ids["blob_after"]]
    assert "sk_live" not in after[0].raw["content"]
    assert "${SERVICE_TOKEN}" in after[0].raw["content"]
