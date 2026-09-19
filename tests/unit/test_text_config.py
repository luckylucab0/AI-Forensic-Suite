"""Tests for the reader over the plain text configuration files.

Most of what it does is uninteresting on purpose: a small file is read whole and filed as
configuration. The tests are about the two entries that are not that, because both answer a
question no other artifact in this suite answers, and both answer it per line.
"""

from __future__ import annotations

from pathlib import Path

from agentforensics.parsers import ParseContext, for_artifact
from agentforensics.parsers.text_config import SOURCES


def parse(path: Path, artifact_id: str, original: str | None = None) -> list:
    parser = for_artifact(artifact_id)
    assert parser is not None, artifact_id
    return list(
        parser.parse(
            ParseContext(
                bundle_uuid="b1",
                original_path=original or f"/home/alice/src/app/{path.name}",
                local_path=path,
                sha256="aa",
                artifact_id=artifact_id,
                agent=artifact_id.split(".")[0],
                user="alice",
            )
        )
    )


def write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8", newline="")
    return path


def keys(events: list) -> list[str]:
    return [event.payload["key"] for event in events]


def test_an_ignore_pattern_is_an_event_of_its_own(tmp_path: Path) -> None:
    """A pattern is what an analyst compares against a path. Read as one blob, that
    comparison becomes a text search through prose."""
    path = write(tmp_path / ".codeiumignore", "vendor/\ncustomer-data/\n*.pem\n")
    events = parse(path, "windsurf.ignore_files")
    assert keys(events) == ["ignore:vendor/", "ignore:customer-data/", "ignore:*.pem"]
    assert all(event.kind == "config.snapshot" for event in events)


def test_an_ignore_pattern_says_it_is_about_what_did_not_happen(tmp_path: Path) -> None:
    """The inverse of every other artifact here: it records what the agent was kept away
    from, which is how a file the agent did not touch gets explained."""
    path = write(tmp_path / ".codeiumignore", "customer-data/\n")
    problem = parse(path, "windsurf.ignore_files")[0].parse_problem or ""
    assert "never to read, write or index" in problem
    # And it does not claim to date the change, because the file cannot.
    assert "dates the last write to the whole file" in problem


def test_a_comment_in_an_ignore_file_is_kept(tmp_path: Path) -> None:
    """Somebody wrote it. A note saying why a directory was excluded is exactly what an
    analyst wants to read next to the exclusion."""
    path = write(tmp_path / ".codeiumignore", "# vendor drop, do not index\nvendor/\n")
    events = parse(path, "windsurf.ignore_files")
    assert events[0].raw["comment"] == "# vendor drop, do not index"
    assert events[0].raw["pattern"] is None
    assert "is a comment in the file" in (events[0].parse_problem or "")
    assert events[1].raw["pattern"] == "vendor/"


def test_an_ignore_file_is_recognised_by_its_name_too(tmp_path: Path) -> None:
    """One entry claims a whole configuration directory with an ignore file among the
    things in it, so the entry alone cannot say which file is which."""
    path = write(tmp_path / ".continueignore", "secrets/\n")
    events = parse(path, "continue.aux_config", "/home/alice/.continue/.continueignore")
    assert keys(events) == ["ignore:secrets/"]


def test_a_worktree_entry_says_where_copies_of_that_file_are(tmp_path: Path) -> None:
    """The vendor documents this list as the gitignored files to copy into every worktree,
    so a name here is an inventory of what was duplicated and where to look for it."""
    path = write(tmp_path / ".worktreeinclude", ".env.local\nconfig/secrets.yaml\n")
    events = parse(path, "claude_code.worktreeinclude")
    assert keys(events) == ["include:.env.local", "include:config/secrets.yaml"]
    assert "every worktree" in (events[0].parse_problem or "")


def test_an_ordinary_configuration_file_is_read_whole(tmp_path: Path) -> None:
    """Most of these are one line, and there is nothing further to read out of them."""
    path = write(tmp_path / "active_config", "staging\n")
    event = parse(
        path, "claude_code.anthropic_active_config", "/home/alice/.config/anthropic/active_config"
    )[0]
    assert event.raw["content"] == "staging\n"
    assert event.payload["text"] == "staging\n"
    assert "read whole" in (event.parse_problem or "")


def test_a_file_that_is_not_text_is_recorded_rather_than_shown_as_noise(
    tmp_path: Path,
) -> None:
    path = tmp_path / "user_settings"
    path.write_bytes(b"\x00\x01\x02binary\x00" * 40)
    events = parse(path, "cline.data_dir_root", "/home/alice/.cline/data/user_settings")
    assert len(events) == 1
    assert events[0].raw["sha256"]


def test_the_reader_claims_what_somebody_decided_it_should() -> None:
    """Held against the catalogue in both directions, so a text configuration added there
    fails until it is either read or left out on purpose."""
    from agentforensics.catalog import load_catalogue

    catalogue = load_catalogue(Path(__file__).resolve().parents[2] / "catalog")
    assert {a.id for a in catalogue.artifacts} >= SOURCES
    for artifact_id in SOURCES:
        assert catalogue.artifact(artifact_id).parser == "text_config", artifact_id
