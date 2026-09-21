"""No reader may answer a file it cannot read with silence.

This is the failure the project's second rule is about. An analyst who opens a case and
finds no events from an agent concludes the agent was not used, and there is no way to
tell that conclusion apart from the truth unless the case says which of the two happened.
A reader that is handed a file whose content is not the format it expects, and returns
nothing, produces exactly that.

So: every reader in the suite, handed a file of content it cannot read, at a path its own
catalogue entry claims, has to produce something. Two do not, and they are named below
with the reason and with what the case shows instead. The table is the point of the file.
Without it a third reader can be written the same way and nothing would say so.

The file it is handed is not empty. An empty file is a different answer and silence is the
right one for it: there was nothing in it, the artifact row says it was collected, and the
count of events beside that row is zero because zero is true. What is asked here is what
happens to a file that holds something this reader cannot make sense of, which is what a
truncated store, a file somebody replaced, or a catalogue entry pointing one directory too
high all look like from inside a parser.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from agentforensics.catalog import load_catalogue
from agentforensics.ingest import ingest
from agentforensics.model import Case
from agentforensics.parsers import ParseContext, for_artifact

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tests" / "fixtures"))

# Two shapes of unreadable, because a reader can fall over one and not the other: bytes
# that are not text at all, and text that is perfectly readable and is not this format.
UNREADABLE = {
    "bytes that are not text": bytes(range(256)) * 8,
    "text that is not this format": ("the quick brown fox\n" * 40).encode("utf-8"),
}

# The readers that answer with nothing, why, and what the case holds instead. Both are
# line readers for formats whose records are announced by a prefix, and both were written
# to skip a line that announces nothing rather than to report it. The reason each gives is
# that the file's own bytes are in the collection either way, which is true, and which is
# also true of every other reader here, all of which still say something. Kept as a
# declaration rather than changed, because changing what a reader emits changes what is in
# a case and that is the owner's call, and the entry below says what an analyst has in the
# meantime: the artifact row names the reader that ran and puts zero beside it, which is
# not the same as an agent with no artifacts at all.
SILENT = {
    "aider.input_history": (
        "prompt_toolkit writes an entry as a blank line, a hash and a timestamp, then one "
        "plus-prefixed line per line of the prompt. A file with no plus-prefixed line has "
        "no entry in it, and this reader ends without yielding one"
    ),
    "crosscutting.shell_fish_history": (
        "fish announces a record with '- cmd:' and this reader skips everything before the "
        "first one, which it documents as what a rotated or partially copied file begins "
        "with. A file with no such line is all before-the-first-record"
    ),
}


# Read once at import. There is one case per reader and per shape, and loading the
# catalogue inside each of them turned a second of work into several minutes.
CATALOGUE = load_catalogue(REPO_ROOT / "catalog")


# Characters a filesystem will not hold in a name. The list is Windows', because it is
# the strict one and these files have to be creatable on every runner: a catalogue
# spelling holds a colon in a drive letter, a star in a glob and angle brackets around
# every placeholder, and a test that wrote those names verbatim would fail there and
# nowhere else, which is where every silent defect in this project has been found.
_NOT_IN_A_NAME = ':<>"|?*\\'


def _leaf(spelling: str) -> str:
    """The filename part of a catalogue spelling, in a form a filesystem will hold.

    The name matters rather than the path: several readers dispatch on it, so a file
    called something else would take a branch a collection never takes. What has to
    survive is the extension and the distinctive part of the stem, which is why the
    substitution is per character and not a fresh name.
    """
    for separator in ("/", "\\"):
        spelling = spelling.rstrip(separator)
        spelling = spelling.rsplit(separator, 1)[-1]
    for character in _NOT_IN_A_NAME:
        spelling = spelling.replace(character, "-")
    return spelling.strip(". ") or "file"


def _leaves() -> dict[str, str]:
    """One such name per artifact that has a reader."""
    return {
        artifact.id: _leaf(artifact.paths[0] if artifact.paths else "file")
        for artifact in CATALOGUE.artifacts
        if for_artifact(artifact.id) is not None
    }


LEAVES = _leaves()
ARTIFACTS = sorted(LEAVES)


@pytest.mark.parametrize("artifact_id", ARTIFACTS)
@pytest.mark.parametrize("shape", sorted(UNREADABLE))
def test_a_reader_handed_something_it_cannot_read_says_so(
    tmp_path: Path, artifact_id: str, shape: str
) -> None:
    parser = for_artifact(artifact_id)
    assert parser is not None
    local = tmp_path / LEAVES[artifact_id]
    local.write_bytes(UNREADABLE[shape])
    context = ParseContext(
        bundle_uuid="b1",
        original_path="/home/alice/" + local.name,
        local_path=local,
        sha256="aa",
        artifact_id=artifact_id,
        agent=artifact_id.split(".", 1)[0],
        user="alice",
    )

    events = list(parser.parse(context))
    if artifact_id in SILENT:
        assert not events, (
            f"{artifact_id} now says something about a file it cannot read, which is the "
            "behaviour this file is about. Take it out of SILENT rather than leaving a "
            "declaration that is no longer true"
        )
        return
    assert events, (
        f"{parser.name} read {artifact_id} from a file of {shape} and produced no event. "
        "An analyst reading a case with no events from an agent concludes the agent was "
        "not used. Either say what the file was, or add an entry to SILENT saying why "
        "nothing is the honest answer here"
    )


def test_the_silent_table_names_nothing_that_is_not_a_catalogue_entry() -> None:
    """A stale entry would excuse a reader that no longer exists, and hide a new one."""
    assert set(SILENT) <= set(ARTIFACTS), sorted(set(SILENT) - set(ARTIFACTS))


def test_a_case_still_shows_the_file_a_silent_reader_read(tmp_path: Path) -> None:
    """What an analyst has for the two above, and why they are a declaration here rather
    than a defect fixed on the spot.

    The file is in the case: an artifact row with its hash, and the filesystem event this
    suite writes for every collected file, which carries the times it was written and read.
    What is not there is anything about its content. So the case does not claim the file
    was absent, and an analyst who opens the artifact list sees it; an analyst who filters
    the timeline to what people and agents did sees nothing from it, which is the half
    worth being uncomfortable about.
    """
    profile = tmp_path / "alice"
    history = profile / ".local" / "share" / "fish" / "fish_history"
    history.parent.mkdir(parents=True)
    history.write_bytes(UNREADABLE["text that is not this format"])
    # A second directory so the tree is read as a profile rather than as a filesystem root.
    (profile / ".claude").mkdir()

    with Case.open(tmp_path / "case.sqlite") as case:
        ingest(case, profile, CATALOGUE)
        rows = case.query(
            "SELECT parser, parse_status, sha256 FROM artifacts "
            "WHERE original_path LIKE '%fish_history' AND collected = 1"
        )
        kinds = [
            row["kind"]
            for row in case.query(
                "SELECT kind FROM events WHERE original_path LIKE '%fish_history'"
            )
        ]
    assert rows, "the file has to be in the case as a collected artifact"
    assert rows[0]["parser"] == "shell_history"
    assert rows[0]["parse_status"] == "parsed"
    assert rows[0]["sha256"], "and with the hash that lets somebody go back to the bytes"
    # The filesystem event and nothing else: the file existed, and the case says nothing
    # about what was in it.
    assert kinds == ["artifact.fs"], kinds
