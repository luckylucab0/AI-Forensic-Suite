"""Tests for the prompt library reader.

The store is the synthetic profile's, written by the fixture generator to the page format
by hand, because the library that writes these is a C one this project does not depend on.
What that store holds is the state a real one is left in: two prompts in the library, and a
third in the pages the tree no longer points at, which is where a prompt goes when somebody
deletes it.

The question every test here is a form of: what does a case say about the text a user told
this agent to obey, and does it say the right thing about the parts of it that are no longer
in the library.
"""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

from agentforensics.parsers import ParseContext, for_artifact, prompt_library

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tests" / "fixtures"))

from generate import write_prompt_library  # noqa: E402

ARTIFACT = "zed.prompt_library"
STORE = "/home/alice/.local/share/zed/prompts/prompts-library-db.0.mdb"


def read(local: Path, name: str = "data.mdb") -> list:
    parser = for_artifact(ARTIFACT)
    assert parser is not None
    return list(
        parser.parse(
            ParseContext(
                bundle_uuid="b1",
                original_path=f"{STORE}/{name}",
                local_path=local / name,
                sha256="aa",
                artifact_id=ARTIFACT,
                agent="zed",
                user="alice",
            )
        )
    )


def library(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    ids = write_prompt_library(tmp_path / "prompts")
    return tmp_path / "prompts" / "prompts-library-db.0.mdb", ids


def test_the_prompts_in_the_library_are_instruction_sources(tmp_path: Path) -> None:
    """What the agent was told to obey, out of a database rather than out of a file.

    Every other instruction artifact in this catalogue is a file, so until this reader
    existed a case recorded that a directory was there and said nothing about the text in
    it. The title and the time each prompt was last saved come from the store as well,
    which is more than a file gives: a CLAUDE.md has only the filesystem's clock.
    """
    where, _ = library(tmp_path)
    events = read(where)
    prompts = [event for event in events if event.kind == "instruction.source"]
    live = [event for event in prompts if not event.raw.get("recovered")]

    assert [event.raw["title"] for event in live] == ["Release notes", "House rules"]
    assert live[0].ts_utc == "2026-09-01T09:00:00.000000Z"
    assert live[0].ts_source == "the prompt's own saved_at"
    assert "name the ticket id" in live[0].raw["text"]
    assert live[0].payload["instructions"] == [
        {"path": f"{STORE}/data.mdb#3a7f1e2c-0000-4000-8000-000000000001", "scope": "user"}
    ]
    assert not live[0].parse_problem


def test_a_prompt_that_was_deleted_comes_back_and_says_it_is_gone(tmp_path: Path) -> None:
    """The reason the reader walks the pages the tree does not point at.

    A prompt somebody removed from the library is part of the answer to what the agent was
    told to obey, and it is in no other artifact on the endpoint: the library is the only
    copy. So it is read, it is filed as an instruction source like the rest, and every
    event carries the sentence that says it is not in the library any more. Presenting it
    beside the live ones without that would be worse than not reading it.
    """
    where, ids = library(tmp_path)
    events = read(where)
    recovered = [
        event
        for event in events
        if event.kind == "instruction.source" and event.raw.get("recovered")
    ]

    texts = [event.raw.get("text") or "" for event in recovered]
    assert any(ids["removed_prompt"] in text for text in texts)
    titles = [event.raw.get("title") for event in recovered]
    assert ids["removed_title"] in titles

    for event in recovered:
        # In the payload rather than in parse_problem: such a record was read completely,
        # and a view that counted it as unreadable would say the collection had failed.
        note = event.payload["recovery_note"]
        assert prompt_library.REMOVED in note
        assert "no longer points at" in note
        assert not event.parse_problem
    # The two halves of one prompt, which live in different databases and therefore in
    # different pages. Each says which half it is rather than claiming the other is missing.
    notes = [event.payload["recovery_note"] for event in recovered]
    assert any(prompt_library.RECOVERED_METADATA in note for note in notes)
    assert any(prompt_library.RECOVERED_BODY in note for note in notes)


def test_every_event_out_of_one_store_has_its_own_identity(tmp_path: Path) -> None:
    """An event is identified by its provenance and its kind, so two events from one file
    that share a locator are one row in a case and the second is dropped without a word.

    A prompt id does not identify a record here: the live prompt, an earlier version of it
    and the two halves of a recovered one all carry the same id. This is the guard that
    caught that, and it is the reason the recovered events carry their page.
    """
    where, _ = library(tmp_path)
    events = read(where)
    identities = [(event.provenance.locator, event.kind) for event in events]
    assert len(set(identities)) == len(identities)
    assert len({event.event_id for event in events}) == len(events)


def test_the_store_itself_is_one_record_saying_what_it_is(tmp_path: Path) -> None:
    """So a case can show the file and its state without an analyst opening it."""
    where, _ = library(tmp_path)
    events = read(where)
    described = [event for event in events if event.kind == "unparsed.record"]
    assert len(described) == 1
    assert "2 prompt(s) live" in (described[0].parse_problem or "")
    assert "bodies.v2, metadata.v2" in (described[0].parse_problem or "")


def test_the_lock_file_is_named_rather_than_read(tmp_path: Path) -> None:
    """It holds the table of readers and no records, and it is in the bundle because the
    catalogue collects the store whole. A file in a bundle that no event mentions reads as
    a file that held nothing."""
    where, _ = library(tmp_path)
    events = read(where, "lock.mdb")
    assert len(events) == 1
    assert "lock file" in (events[0].parse_problem or "")


def test_a_file_in_the_directory_that_is_not_the_store_says_so(tmp_path: Path) -> None:
    where, _ = library(tmp_path)
    (where / "notes.txt").write_text("not a database\n", encoding="utf-8", newline="")
    events = read(where, "notes.txt")
    assert len(events) == 1
    assert "is not the database" in (events[0].parse_problem or "")


def test_a_prompt_whose_text_is_missing_is_a_finding_not_a_silence(tmp_path: Path) -> None:
    """Metadata with no body: the title and the save time are evidence and the prompt is
    not in the case. A reader that dropped the pair would lose the fact that the prompt
    existed at all."""
    where, _ = library(tmp_path)
    raw = bytearray((where / "data.mdb").read_bytes())
    # Empty the bodies database, which is the page the main tree's first node points at.
    # Its node count is in the page header, so zero there is a database with no records.
    struct.pack_into("<HH", raw, 2 * 4096 + 12, 16, 4096)
    (where / "data.mdb").write_bytes(bytes(raw))

    live = [
        event
        for event in read(where)
        if event.kind == "instruction.source" and not event.raw.get("recovered")
    ]
    assert live
    for event in live:
        assert prompt_library.NO_BODY in (event.parse_problem or "")
        assert event.raw.get("text") is None
        assert event.raw["title"]


def test_a_record_in_a_database_nobody_mapped_is_still_a_record(tmp_path: Path) -> None:
    """The store is opened with room for four databases and this reader knows two of them.
    A third is either a version written after this reader or something the editor added,
    and either way the record is kept with its key and value as they came out."""
    where, _ = library(tmp_path)
    raw = bytearray((where / "data.mdb").read_bytes())
    # Rename the metadata database in the main page, which leaves its records where they
    # are and makes them records of a database this reader does not know.
    raw = bytes(raw).replace(b"metadata.v2", b"metadata.v9")
    (where / "data.mdb").write_bytes(raw)

    events = read(where)
    unknown = [
        event
        for event in events
        if event.kind == "unparsed.record"
        and "is not one of the two this reader knows" in (event.parse_problem or "")
    ]
    assert len(unknown) == 2
    assert all("metadata.v9" in (event.parse_problem or "") for event in unknown)
    assert json.loads(unknown[0].raw["value"])["title"]
