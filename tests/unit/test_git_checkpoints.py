"""Tests for the checkpoint reference reader.

An agent that can undo its own edits writes a snapshot before it changes a file, and three
of the agents here do it with git. The modern shape puts the commit in the developer's own
repository under a private reference namespace, so a collection of those paths carries the
references and not the objects. A third keeps one shared repository of its own and names
each project by a hash of its working directory.

That gap is the thing to get right. The events have to be a timeline of when checkpoints
were taken and for which conversation, and they have to say that the content behind them is
not in the case, because a snapshot event an analyst reads as recoverable content is worse
than no event at all.
"""

from __future__ import annotations

from pathlib import Path

from agentforensics.parsers import for_artifact
from agentforensics.parsers.base import ParseContext
from agentforensics.parsers.git_checkpoints import NO_CONTENT

STORE = "cline.checkpoint_refs_in_workspace"
COMMIT = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
SESSION = "4f8c1e2a-0000-4000-8000-000000000001"


def parse(path: Path, original: str) -> list:
    parser = for_artifact(STORE)
    assert parser is not None
    return list(
        parser.parse(
            ParseContext(
                bundle_uuid="b",
                original_path=original,
                local_path=path,
                sha256="f" * 64,
                artifact_id=STORE,
                agent="cline",
                user="alice",
            )
        )
    )


def write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8", newline="")
    return path


def test_a_reference_names_the_conversation_and_the_run(tmp_path: Path) -> None:
    """The namespace is the join. Without it a checkpoint is an object id nobody can tie
    to a conversation, and the conversation is what an analyst is reading."""
    events = parse(
        write(tmp_path / "3", COMMIT + "\n"),
        f"/home/alice/src/app/.git/refs/cline/checkpoints/{SESSION}/3",
    )
    assert [event.kind for event in events] == ["file.snapshot"]
    assert events[0].session_id == SESSION
    assert events[0].raw["run"] == "3"
    assert events[0].raw["object_id"] == COMMIT


def test_every_event_says_the_content_is_not_in_the_case(tmp_path: Path) -> None:
    """A snapshot event an analyst reads as recoverable content is worse than no event."""
    events = parse(
        write(tmp_path / "3", COMMIT + "\n"),
        f"/home/alice/src/app/.git/refs/cline/checkpoints/{SESSION}/3",
    )
    assert NO_CONTENT in (events[0].parse_problem or "")


def test_the_reference_log_is_what_dates_a_checkpoint(tmp_path: Path) -> None:
    """The reference file carries no time at all. The log beside it is the only record on
    the endpoint that says when an agent's edit happened, and it survives the deletion of
    the conversation that made it."""
    events = parse(
        write(
            tmp_path / "3",
            "0" * 40 + f" {COMMIT} Alice <alice@example.org> 1788912300 +0000"
            "\tcline checkpoint: run 3\n",
        ),
        f"/home/alice/src/app/.git/logs/refs/cline/checkpoints/{SESSION}/3",
    )
    assert events[0].ts_utc == "2026-09-09T00:05:00.000000Z"
    assert events[0].ts_source == "the reference log's own timestamp"
    assert events[0].raw["previous_object_id"] == "0" * 40
    assert events[0].raw["written_by"] == "Alice <alice@example.org>"
    assert events[0].payload["text"] == "cline checkpoint: run 3"


def test_a_packed_reference_is_read_and_the_branches_are_not(tmp_path: Path) -> None:
    """Git moves a reference into this file when it packs them, so a checkpoint can be
    absent from refs and still exist. The same file holds every branch in the repository,
    and a developer's branch list is not this artifact's evidence."""
    events = parse(
        write(
            tmp_path / "packed-refs",
            "# pack-refs with: peeled fully-peeled sorted\n"
            f"{COMMIT} refs/heads/main\n"
            f"{COMMIT} refs/heads/feature/private-thing\n"
            f"{COMMIT} refs/cline/checkpoints/{SESSION}/1\n",
        ),
        "/home/alice/src/app/.git/packed-refs",
    )
    assert len(events) == 1
    assert events[0].raw["ref"].startswith("refs/cline/")


def test_an_empty_reference_file_says_what_it_is(tmp_path: Path) -> None:
    """Which is what a partially written or a deleted reference leaves behind."""
    events = parse(
        write(tmp_path / "3", ""),
        f"/home/alice/src/app/.git/refs/cline/checkpoints/{SESSION}/3",
    )
    assert [event.kind for event in events] == ["unparsed.record"]
    assert "empty" in (events[0].parse_problem or "")


def test_a_line_that_is_not_a_reference_log_entry_is_kept(tmp_path: Path) -> None:
    events = parse(
        write(tmp_path / "3", "this is not a reflog line\n"),
        f"/home/alice/src/app/.git/logs/refs/cline/checkpoints/{SESSION}/3",
    )
    assert [event.kind for event in events] == ["unparsed.record"]
    assert events[0].raw == "this is not a reflog line"


def test_a_shared_store_names_the_project_and_not_a_conversation(tmp_path: Path) -> None:
    """The third shape's reference segment is a project, not a session.

    Read as a session id it would put a working directory into the case as a conversation,
    and every checkpoint the agent ever took in that directory would join to it. The hash
    travels under its own name, which is what the store's project index resolves.
    """
    parser = for_artifact("hermes.checkpoints")
    assert parser is not None
    events = list(
        parser.parse(
            ParseContext(
                bundle_uuid="b",
                original_path="/home/alice/.hermes/checkpoints/store/refs/hermes/0123456789abcdef",
                local_path=write(tmp_path / "0123456789abcdef", COMMIT + "\n"),
                sha256="f" * 64,
                artifact_id="hermes.checkpoints",
                agent="hermes",
                user="alice",
            )
        )
    )
    assert [event.kind for event in events] == ["file.snapshot"]
    assert events[0].raw["project_hash"] == "0123456789abcdef"
    assert events[0].session_id is None
    # And the objects came with it, so the event must not send the analyst back to the host.
    assert NO_CONTENT not in (events[0].parse_problem or "")
