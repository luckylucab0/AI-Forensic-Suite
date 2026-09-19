"""Tests for the git index reader, against indexes git itself wrote.

The index one agent keeps beside a checkpoint is a listing of somebody's working copy with
a size, a mode and a clock on every line, untracked files included. There is no library
here to read one, so the fixtures are written by git and read back: a reader that agrees
with the files git produces is a reader that agrees with git, and a fixture built from the
specification would only prove the specification was read the same way twice.

git is not always installed, so these skip without it. The format-level cases at the end do
not, because they are about what the reader does with a file that is not an index.
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from agentforensics.parsers import ParseContext, for_artifact
from agentforensics.parsers.git_index import GitIndexError, looks_like_index, read

ARTIFACT = "cline.checkpoint_scratch"
KEY = "a" * 32

_ENV = {
    "GIT_AUTHOR_NAME": "alice",
    "GIT_AUTHOR_EMAIL": "alice@example.org",
    "GIT_COMMITTER_NAME": "alice",
    "GIT_COMMITTER_EMAIL": "alice@example.org",
}

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(root), *args],
        env={**os.environ, **_ENV},
        capture_output=True,
        text=True,
        check=True,
    )


def workspace(root: Path, version: int = 2) -> bytes:
    """A working copy with the shapes that matter, and its index as git wrote it."""
    root.mkdir(parents=True, exist_ok=True)
    _git(root, "init", "-q", "-b", "main")
    _git(root, "config", "index.version", str(version))
    (root / "settings.json").write_text('{"a": 1}\n', encoding="utf-8", newline="")
    (root / "src").mkdir(exist_ok=True)
    # A shared prefix, which is the one thing version four stores differently.
    (root / "src" / "app.py").write_text("x = 1\n", encoding="utf-8", newline="")
    (root / "src" / "application.py").write_text("y = 2\n", encoding="utf-8", newline="")
    deploy = root / "deploy.sh"
    deploy.write_text("#!/bin/sh\n", encoding="utf-8", newline="")
    deploy.chmod(0o755)
    _git(root, "add", "-A")
    return (root / ".git" / "index").read_bytes()


@needs_git
@pytest.mark.parametrize("version", [2, 4])
def test_every_path_comes_back_with_its_size_mode_and_clock(tmp_path: Path, version: int) -> None:
    """The listing is the evidence: what was in the working copy, how big it was, and when
    the filesystem last changed it."""
    raw = workspace(tmp_path / f"v{version}", version)
    entries = {entry.path: entry for entry in read(raw)}
    assert set(entries) == {
        "deploy.sh",
        "settings.json",
        "src/app.py",
        "src/application.py",
    }
    assert entries["settings.json"].size == len('{"a": 1}\n')
    assert entries["settings.json"].mode == 0o100644
    assert entries["settings.json"].mtime > 0
    assert entries["settings.json"].object_id


@needs_git
@pytest.mark.parametrize("version", [2, 4])
def test_an_executable_is_told_apart_from_an_ordinary_file(tmp_path: Path, version: int) -> None:
    """git stores a regular file as one of two modes and nothing else, and which one it is
    is the difference between a note and something that runs. The mode sat on the device
    number's place in the first version of this reader, and every file came out with a mode
    that looks plausible until somebody prints it in octal."""
    raw = workspace(tmp_path / f"exec{version}", version)
    entries = {entry.path: entry for entry in read(raw)}
    assert entries["deploy.sh"].executable
    assert entries["deploy.sh"].mode == 0o100755
    assert not entries["settings.json"].executable


@needs_git
def test_version_four_paths_are_rebuilt_from_the_one_before(tmp_path: Path) -> None:
    """Version four stores a path as what to strip from the previous one plus the rest, so
    an entry cannot be read on its own and a reader that tried would return prefixes."""
    raw = workspace(tmp_path / "v4only", 4)
    assert struct.unpack(">I", raw[4:8])[0] == 4
    assert sorted(entry.path for entry in read(raw)) == [
        "deploy.sh",
        "settings.json",
        "src/app.py",
        "src/application.py",
    ]


@needs_git
def test_the_reading_stops_where_it_is_told_to(tmp_path: Path) -> None:
    raw = workspace(tmp_path / "limit")
    assert len(list(read(raw, limit=2))) == 2


def test_a_file_that_is_not_an_index_is_refused_rather_than_guessed() -> None:
    assert not looks_like_index(b"ref: refs/heads/main\n")
    with pytest.raises(GitIndexError, match="signature"):
        list(read(b"ref: refs/heads/main\n"))


def test_an_index_version_this_reader_does_not_know_says_so() -> None:
    """Rather than reading it as the nearest version it does know, which would produce a
    listing of plausible-looking wrong paths."""
    with pytest.raises(GitIndexError, match="version 9"):
        list(read(b"DIRC" + struct.pack(">II", 9, 1) + b"\x00" * 64))


def test_an_index_that_stops_early_says_which_entry_it_stopped_on() -> None:
    """A truncated scratch file is what a session killed mid-checkpoint leaves."""
    with pytest.raises(GitIndexError, match="runs off the end"):
        list(read(b"DIRC" + struct.pack(">II", 2, 3) + b"\x00" * 16))


# ----------------------------------------------- the parser over a scratch directory


def parse(path: Path, name: str) -> list:
    parser = for_artifact(ARTIFACT)
    assert parser is not None
    return list(
        parser.parse(
            ParseContext(
                bundle_uuid="b1",
                original_path=f"/home/alice/.cline/data/checkpoint-scratch/{KEY}/{name}",
                local_path=path,
                sha256="aa",
                artifact_id=ARTIFACT,
                agent="cline",
                user="alice",
            )
        )
    )


@needs_git
def test_the_scratch_index_reaches_a_case_as_a_listing_with_times(tmp_path: Path) -> None:
    """The agent keeps this file out of the system temporary directory on purpose, and its
    own source says why: it enumerates workspace paths."""
    raw = workspace(tmp_path / "scratch")
    index = tmp_path / "index"
    index.write_bytes(raw)
    events = parse(index, "index")
    assert {event.raw["path"] for event in events} == {
        "deploy.sh",
        "settings.json",
        "src/app.py",
        "src/application.py",
    }
    assert all(event.kind == "file.snapshot" for event in events)
    assert all(event.ts_utc is not None for event in events)
    assert all("stat cache" in (event.ts_source or "") for event in events)


def test_the_path_list_beside_it_is_read_line_by_line(tmp_path: Path) -> None:
    path = tmp_path / "pathspec"
    path.write_text("settings.json\nsrc/app.py\n", encoding="utf-8", newline="")
    events = parse(path, "pathspec")
    assert [event.raw["path"] for event in events] == ["settings.json", "src/app.py"]


def test_a_file_named_index_that_is_not_one_falls_back_to_being_recorded(
    tmp_path: Path,
) -> None:
    """Every repository has a file called index and not all of them are indexes, so the
    name alone cannot decide."""
    path = tmp_path / "index"
    path.write_text("not an index\n", encoding="utf-8", newline="")
    events = parse(path, "index")
    assert events[0].kind == "config.snapshot"
