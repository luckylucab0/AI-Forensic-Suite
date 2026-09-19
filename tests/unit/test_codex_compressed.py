"""Tests for reading a transcript that the agent's own housekeeping compressed.

This is the single most likely way for a collection to miss almost everything: the product
compresses any rollout at least seven days old, in place, so a reader that takes the plain
files shows the last week of a machine with a year of conversations on it and says nothing
is missing. Every test here is about that failure or about the ways the expansion can go
wrong without anybody being told.
"""

from __future__ import annotations

import compression.zstd as zstd
import json
import os
from pathlib import Path

from agentforensics.parsers import for_artifact
from agentforensics.parsers.base import ParseContext

COMPRESSED = "codex.rollouts_compressed"
PLAIN = "codex.rollouts"


def rollout(turns: int = 3) -> str:
    """A rollout in the shape the parser reads, long enough to be worth compressing."""
    records: list[dict] = [
        {
            "timestamp": "2026-07-02T09:00:00.000Z",
            "type": "session_meta",
            "payload": {
                "id": "4f8c1e2a-0000-4000-8000-000000000002",
                "cwd": "/home/alice/src/app",
                "originator": "codex_cli_rs",
            },
        }
    ]
    for index in range(turns):
        records.append(
            {
                "timestamp": f"2026-07-02T09:0{index}:00.000Z",
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": "user",
                    "content": [{"type": "input_text", "text": f"question {index}"}],
                },
            }
        )
    return "".join(json.dumps(record) + "\n" for record in records)


def parse(path: Path, artifact: str = COMPRESSED) -> list:
    parser = for_artifact(artifact)
    assert parser is not None, artifact
    return list(
        parser.parse(
            ParseContext(
                bundle_uuid="b",
                original_path=f"/home/alice/.codex/sessions/2026/07/02/{path.name}",
                local_path=path,
                sha256="f" * 64,
                artifact_id=artifact,
                agent="codex",
                user="alice",
            )
        )
    )


def test_a_compressed_transcript_reads_like_a_plain_one(tmp_path: Path) -> None:
    """The whole point. A conversation from before the compression window has to produce
    the same events as one from this week, or a case is a week deep on a machine that has
    been in use for a year."""
    body = rollout()
    plain = tmp_path / "rollout-2026-07-02T09-00-00-x.jsonl"
    plain.write_text(body, encoding="utf-8", newline="")
    packed = tmp_path / "rollout-2026-07-02T09-00-00-x.jsonl.zst"
    packed.write_bytes(zstd.compress(body.encode("utf-8")))

    from_plain = parse(plain, PLAIN)
    from_packed = parse(packed)
    assert [event.kind for event in from_packed] == [event.kind for event in from_plain]
    assert [event.payload for event in from_packed] == [event.payload for event in from_plain]


def test_the_locator_is_the_line_of_the_expanded_transcript(tmp_path: Path) -> None:
    """The only line number these records have. Checking a finding means expanding the file
    the same way and counting, which is why the events say line and not something invented
    for the compressed form."""
    packed = tmp_path / "rollout.jsonl.zst"
    packed.write_bytes(zstd.compress(rollout().encode("utf-8")))
    events = parse(packed)
    assert events[0].provenance.locator == "line:1"
    assert events[0].provenance.original_path.endswith(".zst")


def test_a_file_left_by_an_interrupted_compression_is_read_by_its_bytes(tmp_path: Path) -> None:
    """Such a file can be either form depending on when it was interrupted, and the
    catalogue collects it on purpose. Deciding by the name would leave a whole conversation
    unread on the strength of an extension."""
    temporary = tmp_path / "rollout-compress-1234.tmp"
    temporary.write_text(rollout(), encoding="utf-8", newline="")
    events = parse(temporary)
    assert [event.kind for event in events][:2] == ["session.start", "user.prompt"]


def test_a_transcript_cut_off_part_way_keeps_what_expanded(tmp_path: Path) -> None:
    """The case an investigation most needs this to get right: a file that was being
    compressed when the machine went down. Everything before the break is evidence, and a
    reader that lost it because the end was damaged would throw away the conversation to
    report the damage."""
    body = "".join(
        json.dumps(
            {
                "timestamp": "2026-07-02T09:00:00.000Z",
                "type": "event_msg",
                "payload": {"type": "agent_message", "message": os.urandom(24).hex()},
            }
        )
        + "\n"
        for _ in range(20000)
    )
    packed = zstd.compress(body.encode("utf-8"))
    cut = tmp_path / "rollout.jsonl.zst"
    cut.write_bytes(packed[: len(packed) // 2])

    events = parse(cut)
    assert len(events) > 1000, "the records before the break have to survive"
    assert "stopped part way through" in (events[-1].parse_problem or "")


def test_a_file_that_is_not_a_transcript_at_all_says_so(tmp_path: Path) -> None:
    path = tmp_path / "rollout.jsonl.zst"
    path.write_bytes(b"\x28\xb5\x2f\xfd not really a frame")
    events = parse(path)
    assert [event.kind for event in events] == ["unparsed.record"]
    problem = events[0].parse_problem or ""
    assert "stopped part way through" in problem or "could not" in problem


def test_the_expansion_limit_is_reported_rather_than_applied_quietly(tmp_path: Path) -> None:
    from agentforensics.parsers import codex

    body = "".join(
        json.dumps({"timestamp": "2026-07-02T09:00:00.000Z", "type": "event_msg", "payload": {}})
        + "\n"
        for _ in range(5000)
    )
    packed = tmp_path / "rollout.jsonl.zst"
    packed.write_bytes(zstd.compress(body.encode("utf-8")))

    original = codex.MAX_EXPANDED
    codex.MAX_EXPANDED = 2000
    try:
        events = parse(packed)
    finally:
        codex.MAX_EXPANDED = original
    assert "expands past the ingest limit" in (events[-1].parse_problem or "")
    assert len(events) > 1, "what was expanded before the limit is still read"
