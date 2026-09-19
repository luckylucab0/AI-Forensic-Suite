"""Tests for the prose transcript reader.

These files hold the material an analyst most wants to quote: an exported conversation, the
bulk output of a tool too large to keep inline, what a background subagent reported to its
parent, a written plan. The two failures to guard against are the file reaching the case as
a name with nothing behind it, and the text reaching it in pieces.
"""

from __future__ import annotations

from pathlib import Path

from agentforensics.catalog import load_catalogue
from agentforensics.model import UNINTERPRETED_MARK
from agentforensics.parsers import for_artifact
from agentforensics.parsers.base import ParseContext
from agentforensics.parsers.prose_document import SOURCES

CATALOG_DIR = Path(__file__).resolve().parents[2] / "catalog"
EXPORT = "amazonq.ide_chat_export"
PLAN = "windsurf.plans"


def parse(path: Path, artifact: str = EXPORT) -> list:
    parser = for_artifact(artifact)
    assert parser is not None, artifact
    return list(
        parser.parse(
            ParseContext(
                bundle_uuid="b",
                original_path=f"/home/alice/src/app/{path.name}",
                local_path=path,
                sha256="f" * 64,
                artifact_id=artifact,
                agent="amazonq",
                user="alice",
            )
        )
    )


def write(path: Path, text: str) -> Path:
    # newline="" so the file holds the bytes the test says it holds, which is what the
    # comparison below is about.
    path.write_text(text, encoding="utf-8", newline="")
    return path


def test_a_conversation_arrives_in_one_piece(tmp_path: Path) -> None:
    """Split line by line, a prompt becomes fragments, and a fragment reads in a report as
    what somebody asked."""
    body = "# Chat\n\n## Human\n\nwhat does this script do,\nand is it safe to run\n"
    events = parse(write(tmp_path / "q-dev-chat-2026-09-07.md", body))
    assert len(events) == 1
    assert events[0].payload["text"] == body
    assert events[0].raw["text"] == body


def test_an_unmapped_conversation_says_it_is_unread(tmp_path: Path) -> None:
    events = parse(write(tmp_path / "q-dev-chat-2026-09-07.md", "# Chat\n"))
    assert events[0].kind == "unparsed.record"
    assert UNINTERPRETED_MARK in (events[0].parse_problem or "")


def test_a_plan_is_a_plan_rather_than_an_unread_record(tmp_path: Path) -> None:
    """The file is the plan. Marking it unread would put an event in the case that says
    somebody still has to map a format that has nothing left to map."""
    events = parse(write(tmp_path / "plan.md", "# Plan\n\n1. read the code\n"), PLAN)
    assert events[0].kind == "plan.write"
    assert UNINTERPRETED_MARK not in (events[0].parse_problem or "")


def test_the_file_carries_no_time_of_its_own(tmp_path: Path) -> None:
    """The artifact event for the same path already carries the filesystem's times, and
    repeating an mtime here would present it as the conversation's own."""
    events = parse(write(tmp_path / "q-dev-chat.md", "# Chat\n"))
    assert events[0].ts_utc is None
    assert events[0].ts_precision == "absent"


def test_a_long_file_is_truncated_out_loud(tmp_path: Path) -> None:
    from agentforensics.parsers import prose_document

    body = "x" * 5000
    original = prose_document.MAX_TEXT
    prose_document.MAX_TEXT = 1000
    try:
        events = parse(write(tmp_path / "spill.txt", body), "claude_code.tool_result_spills")
    finally:
        prose_document.MAX_TEXT = original
    assert len(events[0].payload["text"]) == 1000
    assert "carried truncated" in (events[0].parse_problem or "")
    assert events[0].payload["bytes"] == 5000, "the size on disk is still the size on disk"


def test_a_file_that_did_not_decode_is_kept_and_said_to_be_inexact(tmp_path: Path) -> None:
    path = tmp_path / "spill.txt"
    path.write_bytes(b"output \xff\xfe more output\n")
    events = parse(path, "claude_code.tool_result_spills")
    assert len(events) == 1
    assert "did not decode" in (events[0].parse_problem or "")


def test_a_file_that_cannot_be_read_still_produces_an_event(tmp_path: Path) -> None:
    events = parse(tmp_path / "missing.md")
    assert [event.kind for event in events] == ["unparsed.record"]
    assert "could not be read" in (events[0].parse_problem or "")


def test_the_reader_claims_every_prose_transcript_in_the_catalogue() -> None:
    """A conversation in a format nobody mapped, collected and read by nothing, is the
    state all five of these were in."""
    catalogue = load_catalogue(CATALOG_DIR)
    prose = {
        a.id
        for a in catalogue.artifacts
        if a.category == "transcript" and a.format in ("text", "markdown")
    }
    claimed = set(SOURCES)
    # One of them has a verified parser of its own and keeps it: that product's chat log is
    # a format somebody read against its source, and a floor under it would be a step back.
    assert prose - claimed == {"aider.chat_history"}
    # The paste cache is read here too and is not a transcript. It is the text behind a
    # placeholder in a prompt, filed under cache because that is what its product sweeps it
    # as, and it belongs to this reader for the same reason the others do: it is one file
    # holding text that has to stay in one piece.
    assert claimed - prose == {"claude_code.paste_cache"}


def test_a_spill_that_is_not_prose_is_recorded_as_bytes(tmp_path: Path) -> None:
    """A tool result can be a downloaded archive, and a page of replacement characters in
    a field called text reads as what the agent saw."""
    path = tmp_path / "spill.bin"
    path.write_bytes(b"PK\x03\x04\x00\x00" + bytes(range(256)) * 4)
    events = parse(path, "claude_code.tool_result_spills")
    assert len(events) == 1
    assert events[0].kind == "unparsed.record"
    assert "not text" in (events[0].parse_problem or "")
    assert "text" not in events[0].payload
