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
    "claude_code.worktrees": "a whole working copy, not a copy of one file",
    "claude_desktop.cowork_session_files": "a session working directory of arbitrary files",
    "claude_desktop.cowork_vm_bundle": "a virtual machine disk image",
    "claude_desktop.user_output_folder": "what the agent produced for the user, which is "
    "its output rather than a copy of something it replaced",
    "claude_desktop.ssh_remote_artifacts": "what the agent left on another host",
    "cline.chat_workspace": "a working directory of arbitrary files",
    "cursor.worktrees": "a whole working copy, not a copy of one file",
    "factory_droid.worktrees": "a whole working copy, not a copy of one file",
    "hermes.browser_agent_profiles": "browser profiles the agent created for itself, "
    "which are that product's own storage rather than a copy of a user's file",
    "hermes.browser_profile": "a copy of a whole browser profile, which is a tree of "
    "that product's own databases rather than a copy of one file the agent replaced",
    "hermes.backups": "a zip of the whole home, which is a container of copies of "
    "artifacts this catalogue lists individually rather than a copy of one file",
    "hermes.sandboxes": "a sandbox tree of arbitrary files",
    "hermes.state_snapshots": "the product's own copy of its critical state, whose one "
    "readable member has an entry and a reader of its own",
    "ollama.backup_dir": "a backup of the product's own data, not of a user's file",
    "opencode.repos_cache": "a clone the agent made, not a copy of a file it replaced",
    "qwen_code.arena_worktrees": "one whole working copy per model, which is what the "
    "head-to-head mode makes rather than a copy of one file. The copies matter and are "
    "collected: each mirrors the working directory including what was never committed",
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


# ------------------------------------------- the editor family's local history

# The layout, from the editor's own source: a directory per file named by a hash of the
# file's URI, an index naming the original resource and listing each copy with the moment
# it was taken and the save source that caused it, and the copies themselves named by four
# random characters plus the original extension. This is the only snapshot store in the
# catalogue where the attribution exists on disk, which is what these tests are about.
HISTORY_DIR = "/home/alice/.config/Code/User/History/1f2e3d4c"


def history(path: Path, name: str, artifact_id: str = "vscode.local_history") -> list:
    return parse(path, artifact_id, f"{HISTORY_DIR}/{name}")


def with_index(tmp_path: Path, *entries: dict, resource: str | None = "file:///srv/app/api.ts"):
    """A history directory with an index and nothing else in it yet."""
    import json as _json

    document: dict = {"version": 1, "entries": list(entries)}
    if resource is not None:
        document["resource"] = resource
    (tmp_path / "entries.json").write_text(_json.dumps(document), encoding="utf-8", newline="")


def test_a_copy_is_attributed_from_the_index_beside_it(tmp_path: Path) -> None:
    """The point of reading this layout at all.

    Every other snapshot store in this catalogue produces content nobody can attribute.
    Here the original path and the moment the copy was taken are one file away, so a case
    that reported the copy as unnamed would be throwing away an answer the collection
    already had.
    """
    with_index(tmp_path, {"id": "ab12.ts", "timestamp": 1764547200000, "source": "undoRedo.source"})
    copy = tmp_path / "ab12.ts"
    copy.write_text("const token = 'sk_live_examplekey0123456789'\n", encoding="utf-8", newline="")

    events = history(copy, "ab12.ts")
    assert len(events) == 1
    event = events[0]
    assert event.kind == "file.snapshot"
    assert event.raw["original_path"] == "/srv/app/api.ts"
    assert event.raw["version_source"] == "undoRedo.source"
    assert "sk_live_examplekey0123456789" in event.payload["text"]
    # The time came out of the index rather than off the file, and the event says which.
    assert event.ts_utc is not None and event.ts_utc.startswith("2025-12-01")
    assert event.ts_source is not None and "index" in event.ts_source
    # The only note is how the number was read, which is provenance rather than a gap.
    assert event.parse_problem == "read as epoch milliseconds"


def test_a_copy_with_no_index_says_so_and_still_carries_its_content(tmp_path: Path) -> None:
    """A collection that took the copies and not the index still has the content.

    The directory name is a hash of the file's URI and cannot be reversed, so without the
    index there is no path and no time. What must not happen is the content going missing
    as well, or the event implying an attribution it does not have.
    """
    copy = tmp_path / "cd34.ts"
    copy.write_text("export const answer = 42\n", encoding="utf-8", newline="")

    events = history(copy, "cd34.ts")
    assert len(events) == 1
    assert "export const answer = 42" in events[0].payload["text"]
    assert "original_path" not in events[0].raw
    assert events[0].ts_utc is None
    assert "index" in (events[0].parse_problem or "")


def test_a_copy_the_index_has_forgotten_is_reported_rather_than_attributed(
    tmp_path: Path,
) -> None:
    """The editor prunes the index and the copies on different schedules.

    So a copy with no row is a real state rather than a corrupt one, and it is the
    interesting one: content on the endpoint that nothing else accounts for. Attributing it
    to whatever the index does name would be the wrong answer rather than no answer.
    """
    with_index(tmp_path, {"id": "ab12.ts", "timestamp": 1764547200000})
    orphan = tmp_path / "zz99.ts"
    orphan.write_text("old contents\n", encoding="utf-8", newline="")

    events = history(orphan, "zz99.ts")
    assert len(events) == 1
    assert "old contents" in events[0].payload["text"]
    assert "original_path" not in events[0].raw
    assert "does not list it" in (events[0].parse_problem or "")


def test_the_index_is_an_event_of_its_own(tmp_path: Path) -> None:
    """Because it is the only thing that maps the directory's hash back to a path.

    It also names copies that may have been pruned before the collection, so the index is
    evidence that a version existed even where the version itself is gone.
    """
    with_index(
        tmp_path,
        {"id": "ab12.ts", "timestamp": 1764547200000, "source": "default.source"},
        {"id": "cd34.ts", "timestamp": 1764550800000, "source": "searchReplace.source"},
    )
    events = history(tmp_path / "entries.json", "entries.json")
    assert len(events) == 1
    event = events[0]
    assert event.raw["index"] is True
    assert event.raw["original_path"] == "/srv/app/api.ts"
    assert [row["id"] for row in event.raw["versions"]] == ["ab12.ts", "cd34.ts"]
    assert [row["source"] for row in event.raw["versions"]] == [
        "default.source",
        "searchReplace.source",
    ]
    # The index is rewritten on every copy, so its own time would be the last copy's.
    assert event.ts_utc is None


def test_an_index_that_names_no_resource_does_not_get_one_invented(tmp_path: Path) -> None:
    with_index(tmp_path, {"id": "ab12.ts", "timestamp": 1764547200000}, resource=None)
    events = history(tmp_path / "entries.json", "entries.json")
    assert events[0].raw["original_path"] is None
    assert "does not name the file" in (events[0].parse_problem or "")


def test_a_remote_resource_is_not_reported_as_a_local_path(tmp_path: Path) -> None:
    """The copy is local and the file it came from never was, which changes the finding."""
    with_index(
        tmp_path,
        {"id": "ab12.ts", "timestamp": 1764547200000},
        resource="vscode-remote://ssh-remote+buildhost/srv/app/api.ts",
    )
    copy = tmp_path / "ab12.ts"
    copy.write_text("x\n", encoding="utf-8", newline="")
    events = history(copy, "ab12.ts")
    assert events[0].raw["original_path"].startswith("vscode-remote://")
    assert "another machine" in (events[0].parse_problem or "")


def test_an_unreadable_index_is_surfaced_and_not_skipped(tmp_path: Path) -> None:
    """Without it nothing in the directory can be attributed, so it is a finding."""
    (tmp_path / "entries.json").write_text("{not json", encoding="utf-8", newline="")
    events = history(tmp_path / "entries.json", "entries.json")
    assert len(events) == 1
    assert events[0].kind == "unparsed.record"
    assert "could not be read as JSON" in (events[0].parse_problem or "")


def test_a_copy_that_is_not_text_is_recorded_by_hash(tmp_path: Path) -> None:
    """A page of replacement characters reads as content, so it is refused."""
    with_index(tmp_path, {"id": "ab12.png", "timestamp": 1764547200000})
    copy = tmp_path / "ab12.png"
    copy.write_bytes(b"\x89PNG\r\n\x1a\n" + bytes(range(64)))
    events = history(copy, "ab12.png")
    assert "content" not in events[0].raw
    assert events[0].raw["sha256"]
    assert events[0].raw["original_path"] == "/srv/app/api.ts"


def test_all_three_editors_of_the_family_use_the_same_reading(tmp_path: Path) -> None:
    """One layout, three products, one reader, which was the argument for writing it."""
    with_index(tmp_path, {"id": "ab12.ts", "timestamp": 1764547200000})
    copy = tmp_path / "ab12.ts"
    copy.write_text("shared\n", encoding="utf-8", newline="")
    for artifact_id in (
        "vscode.local_history",
        "cursor.local_file_history",
        "windsurf.local_file_history",
    ):
        events = history(copy, "ab12.ts", artifact_id)
        assert len(events) == 1, artifact_id
        assert events[0].raw["original_path"] == "/srv/app/api.ts", artifact_id
        assert events[0].agent == artifact_id.split(".")[0], artifact_id
