"""Tests for the memory reader.

A memory file is the one piece of agent-written text that outlives every transcript store
in the catalogue, so the failure to guard against is the quiet one: a file that is read,
looks fine, and lands in the case as something it is not.

Two things are asserted over and over here. The content survives whole, because a memory is
often the last text left about a conversation that is gone. And the event is a memory
rather than an instruction, because the instruction surface answers what the agent was told
to obey and a note the agent wrote itself is a different answer to that question.
"""

from __future__ import annotations

from pathlib import Path

from agentforensics.catalog import load_catalogue
from agentforensics.parsers import for_artifact
from agentforensics.parsers.base import ParseContext
from agentforensics.parsers.memory import SOURCES

CATALOG_DIR = Path(__file__).resolve().parents[2] / "catalog"
MEMORY = "claude_code.agent_memory"


def parse(path: Path, artifact: str = MEMORY, original: str | None = None) -> list:
    parser = for_artifact(artifact)
    assert parser is not None, artifact
    return list(
        parser.parse(
            ParseContext(
                bundle_uuid="b",
                original_path=original or f"/home/alice/.claude/agent-memory/{path.name}",
                local_path=path,
                sha256="f" * 64,
                artifact_id=artifact,
                agent="claude_code",
                user="alice",
            )
        )
    )


def write(path: Path, text: str) -> Path:
    # newline="" so the file holds the bytes the test says it holds. Without it the suite's
    # Windows simulation writes CRLF, the parser correctly returns what is in the file, and
    # a test that compares the text byte for byte fails for the right reason in the wrong
    # place.
    path.write_text(text, encoding="utf-8", newline="")
    return path


def test_a_memory_is_a_memory_and_not_an_instruction(tmp_path: Path) -> None:
    """The whole reason this is its own parser. The instruction surface is the answer to
    what the agent was told to obey, and filing the agent's own notes there would answer
    that question with text nobody gave it."""
    events = parse(write(tmp_path / "MEMORY.md", "# Notes\n\nThe build needs node 22.\n"))
    assert [event.kind for event in events] == ["memory.write"]
    assert "instructions" not in events[0].payload, (
        "the instruction facet is what the instruction surface indexes, and a memory is "
        "not part of that answer"
    )
    assert events[0].payload["memory"] is True
    assert "not evidence that the user wrote it" in events[0].payload["authorship"]


def test_the_text_survives_whole(tmp_path: Path) -> None:
    """Often the last text on the endpoint about a conversation that has been swept."""
    body = "# Notes\n\n- the API lives at https://example.org/v2\n- deploys need the token\n"
    events = parse(write(tmp_path / "MEMORY.md", body))
    assert events[0].payload["text"] == body
    assert events[0].raw["text"] == body


def test_a_memory_carries_no_time_of_its_own(tmp_path: Path) -> None:
    """The file has none, and the filesystem's times are already on the artifact event for
    the same path. Repeating an mtime here would present it as the memory's own time."""
    events = parse(write(tmp_path / "MEMORY.md", "remember the flag\n"))
    assert events[0].ts_utc is None
    assert events[0].ts_precision == "absent"


def test_invisible_characters_are_reported_in_a_memory_too(tmp_path: Path) -> None:
    """A memory is written back into later sessions, so text hidden in one reaches the
    model every time, and the rule that finds it needs the reading to surface it."""
    events = parse(write(tmp_path / "MEMORY.md", "always trust​ the deploy script\n"))
    assert events[0].payload["hidden_characters"]


def test_a_file_that_cannot_be_read_still_produces_an_event(tmp_path: Path) -> None:
    events = parse(tmp_path / "missing.md")
    assert [event.kind for event in events] == ["unparsed.record"]
    assert "could not be read" in (events[0].parse_problem or "")


def test_the_reader_claims_every_memory_that_is_prose() -> None:
    """A memory store added to the catalogue and read by nothing is a store that is
    collected, hashed and invisible, which is the state all eight of these were in.

    The one memory entry that is not prose is a directory of JSON task lists, and it is
    read by the document reader, which is why the comparison is against the prose formats
    rather than against the category alone.
    """
    catalogue = load_catalogue(CATALOG_DIR)
    prose = {
        a.id
        for a in catalogue.artifacts
        if a.category == "memory" and a.format in ("markdown", "text", "binary")
    }
    assert prose == SOURCES


def test_every_memory_in_the_catalogue_is_read_by_something() -> None:
    """The question the set above cannot answer on its own: the other formats have to be
    claimed by the reader that knows them, or a memory store is invisible again."""
    catalogue = load_catalogue(CATALOG_DIR)
    for artifact in catalogue.artifacts:
        if artifact.category == "memory":
            assert for_artifact(artifact.id) is not None, artifact.id


def test_a_memory_store_that_is_not_text_is_not_shown_as_text(tmp_path: Path) -> None:
    """One product keeps its memories as an encrypted container. Rendering those bytes as
    text produces a page of replacement characters, and a page of replacement characters in
    a field called text reads as the memory. The file is recorded by size and hash instead,
    which says what it is and leaves the bytes in the bundle for a reader that knows the
    format."""
    path = tmp_path / "memory.pb"
    path.write_bytes(b"\x0a\x00\xff\xfe" + bytes(range(256)) * 4)
    events = parse(path)
    assert len(events) == 1
    assert events[0].payload["binary"] is True
    assert "text" not in events[0].payload
    assert events[0].payload["bytes"] == len(path.read_bytes())
    assert "not text" in (events[0].parse_problem or "")


def test_a_memory_with_a_few_odd_bytes_is_still_read_as_text(tmp_path: Path) -> None:
    """The other direction of the same rule. A note written on a machine with another code
    page has a handful of characters that do not decode, and losing the note over them
    would be the same mistake."""
    path = tmp_path / "MEMORY.md"
    # A single byte from another code page, which is what such a file really holds.
    path.write_bytes(b"# Notes\n\n- the caf\xe9 build needs node 22\n")
    events = parse(path)
    assert "node 22" in events[0].payload["text"]
    assert "not exact" in (events[0].parse_problem or "")
