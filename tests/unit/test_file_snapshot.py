"""Tests for the reader over the copies an agent keeps of the files it changes.

These files are somebody's file, not a format, so the tests are about two things. That the
content reaches the case in a place a rule can search, because a credential in a file the
agent overwrote is in no transcript and in no git history and was previously in nothing at
all. And that the event says what the snapshot does not tell you, because the commonest
shape here is a copy that does not name the file it came from, and a reader that filled
that in would put a filename in a report nobody could check.
"""

from __future__ import annotations

from pathlib import Path

from agentforensics.parsers import ParseContext, for_artifact
from agentforensics.parsers.file_snapshot import SOURCES

SESSION = "4f8c1e2a-0000-4000-8000-000000000001"


def parse(path: Path, artifact_id: str, original: str) -> list:
    parser = for_artifact(artifact_id)
    assert parser is not None, artifact_id
    return list(
        parser.parse(
            ParseContext(
                bundle_uuid="b1",
                original_path=original,
                local_path=path,
                sha256="aa",
                artifact_id=artifact_id,
                agent=artifact_id.split(".")[0],
                user="alice",
            )
        )
    )


def claude(path: Path, name: str = "config.json.0") -> list:
    return parse(
        path,
        "claude_code.file_history_snapshots",
        f"/home/alice/.claude/file-history/{SESSION}/{name}",
    )


def test_the_content_of_an_overwritten_file_reaches_the_case(tmp_path: Path) -> None:
    """The whole reason to read these at all. What was in the file before the agent changed
    it is in no transcript and in no git history when the change was never committed."""
    path = tmp_path / "config.json.0"
    path.write_text('{"token": "sk_live_examplekey0123456789"}', encoding="utf-8", newline="")
    events = claude(path)
    assert len(events) == 1
    assert events[0].kind == "file.snapshot"
    assert "sk_live_examplekey0123456789" in events[0].payload["text"]
    assert "sk_live_examplekey0123456789" in events[0].raw["content"]


def test_the_session_comes_from_the_path_and_the_filename_does_not_become_a_claim(
    tmp_path: Path,
) -> None:
    """The vendor documents the directory and not the naming inside it, so the session is
    read and the original path is not. Inventing one would be the worst kind of wrong here:
    checkable-looking and unverifiable."""
    path = tmp_path / "config.json.0"
    path.write_text("before\n", encoding="utf-8", newline="")
    event = claude(path)[0]
    assert event.session_id == SESSION
    assert event.raw["session_id"] == SESSION
    assert "original_path" not in event.raw
    assert "does not say which one" in (event.parse_problem or "")


def test_a_backup_named_by_a_digest_gives_up_the_digest_and_the_version(
    tmp_path: Path,
) -> None:
    """That product names a backup by the first sixteen hex characters of the SHA-256 of
    the original absolute path. The digest is one way, so it is not the file name, but an
    analyst can match it against a candidate path, which is more than nothing."""
    path = tmp_path / "a1b2c3d4e5f60718@v3"
    path.write_text("the original text\n", encoding="utf-8", newline="")
    event = parse(
        path,
        "qwen_code.file_history_backups",
        f"/home/alice/.qwen/file-history/{SESSION}/a1b2c3d4e5f60718@v3",
    )[0]
    assert event.raw["original_path_sha256_prefix"] == "a1b2c3d4e5f60718"
    assert event.raw["version"] == 3
    assert event.session_id == SESSION
    assert "cannot be reversed" in (event.parse_problem or "")


def test_a_scratch_copy_says_it_could_be_either_side_of_the_edit(tmp_path: Path) -> None:
    """The apply flow's directory holds the text before the change and the text proposed,
    and nothing in the path says which. Both are evidence; claiming one would be a guess."""
    path = tmp_path / "abc123"
    path.write_text("proposed\n", encoding="utf-8", newline="")
    event = parse(path, "continue.diffs", "/home/alice/.continue/.diffs/abc123")[0]
    assert "before the change or the text proposed" in (event.parse_problem or "")
    assert event.session_id is None


def test_a_snapshot_that_is_not_text_is_recorded_rather_than_shown_as_noise(
    tmp_path: Path,
) -> None:
    """An agent edits binary files too, and a page of replacement characters reads as the
    content of the file it is standing in for."""
    path = tmp_path / "icon.png.0"
    path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00\x01\x02" * 200)
    event = claude(path, "icon.png.0")[0]
    assert "content" not in event.raw
    assert event.payload.get("text") is None
    assert event.raw["bytes"] == len(path.read_bytes())
    assert event.raw["sha256"]


def test_a_snapshot_is_attributed_to_the_agent_rather_than_to_the_user(
    tmp_path: Path,
) -> None:
    """The agent took the copy. A timeline that showed it as a user action would read as
    somebody making a backup before letting the agent loose, which is the opposite."""
    path = tmp_path / "config.json.0"
    path.write_text("before\n", encoding="utf-8", newline="")
    event = claude(path)[0]
    assert event.actor == "assistant"
    # And no timestamp of its own: the copy carries none, and the artifact event for the
    # same path already carries the filesystem's.
    assert event.ts_utc is None


# ------------------------------------------------- the set, against the catalogue


# The file_snapshot entries this reader deliberately does not claim, each with the reason.
# Held against the catalogue below so that a snapshot store added there has to be decided
# about rather than quietly left unread.
NOT_CLAIMED = {
    "amazonq.cli_checkpoints": "a bare git repository per conversation, so the content is "
    "in an object store rather than in the files, and reading it needs a git reader",
    "claude_code.worktrees": "a whole working copy, not a copy of one file",
    "claude_desktop.cowork_session_files": "a session working directory of arbitrary files",
    "claude_desktop.cowork_vm_bundle": "a virtual machine disk image",
    "claude_desktop.user_output_folder": "what the agent produced for the user, which is "
    "its output rather than a copy of something it replaced",
    "claude_desktop.ssh_remote_artifacts": "what the agent left on another host",
    "cline.checkpoint_scratch": "an index and a pathspec, which are a listing of the "
    "workspace rather than the contents of a file",
    "cline.chat_workspace": "a working directory of arbitrary files",
    "cursor.worktrees": "a whole working copy, not a copy of one file",
    "hermes.sandboxes": "a sandbox tree of arbitrary files",
    "ollama.backup_dir": "a backup of the product's own data, not of a user's file",
    "opencode.repos_cache": "a clone the agent made, not a copy of a file it replaced",
    "windsurf.worktrees": "a whole working copy, not a copy of one file",
}


def test_every_snapshot_store_is_either_read_or_declared_unread() -> None:
    """Asserted in both directions over the catalogue's whole file_snapshot category.

    Some of these are read elsewhere: the checkpoint references by the reader for those,
    two of them as JSON documents. What must not happen is a snapshot store arriving in the
    catalogue and being read by nothing with nobody having decided that, which is how the
    largest unread category in this project would grow quietly.
    """
    from agentforensics.catalog import load_catalogue
    from agentforensics.parsers import for_artifact as reader

    catalogue = load_catalogue(Path(__file__).resolve().parents[2] / "catalog")
    every = {a.id for a in catalogue.artifacts if a.category == "file_snapshot"}
    assert every >= SOURCES, sorted(SOURCES - every)

    unread = {name for name in every if reader(name) is None}
    assert unread == set(NOT_CLAIMED), {
        "read by nothing and not declared": sorted(unread - set(NOT_CLAIMED)),
        "declared unread and now read, or gone": sorted(set(NOT_CLAIMED) - unread),
    }
    for artifact_id, reason in NOT_CLAIMED.items():
        assert reason.strip(), artifact_id
