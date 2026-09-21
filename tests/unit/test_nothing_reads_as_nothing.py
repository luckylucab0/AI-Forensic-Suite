"""No reader may answer a file it cannot read with silence.

This is the failure the project's second rule is about. An analyst who opens a case and
finds no events from an agent concludes the agent was not used, and there is no way to
tell that conclusion apart from the truth unless the case says which of the two happened.
A reader that is handed a file whose content is not the format it expects, and returns
nothing, produces exactly that.

So: every reader in the suite, handed a file of content it cannot read, at a path its own
catalogue entry claims, has to produce something. Every reader does. The table below, which
names the exceptions, is empty, and it stays in the file because it is what a reader written
the same way as the two that used to be in it has to be added to: an exception here is a
sentence somebody wrote and a case test somebody owes, and that is a harder thing to do than
to fix the reader.

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

# The readers that answer with nothing, and why nothing is the honest answer for that one
# file. Empty, and that is the point of it being here: two line readers were in it, both
# for formats whose records are announced by a prefix, and both were written to skip a line
# that announces nothing rather than to report it. Each gave the same reason, that the
# file's own bytes are in the collection either way, which is true and is also true of
# every other reader in the suite, all of which still say something. Both were changed
# instead: see ADR 0039.
#
# An entry here needs a sentence saying why an analyst is better served by silence than by
# a record saying the file could not be read, and a case test beside the one below showing
# what they do have. Anything less is a reader nobody got round to finishing.
SILENT: dict[str, str] = {}


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


def test_a_case_says_what_was_in_a_file_no_reader_could_read(tmp_path: Path) -> None:
    """What an analyst has for a file whose content is not the format its path claims.

    The whole way through, not only out of the parser: a profile is collected, ingested and
    queried, because the sentence is only worth anything if it survives into the case.

    Three things are there. The artifact row, with the hash that lets somebody go back to
    the bytes. The filesystem event this suite writes for every collected file, carrying
    the times it was written and read. And an unparsed record holding the lines themselves
    with the reason on it, which is the part that used to be missing: an analyst filtering
    the timeline to what people and agents did now sees that this file was read and was not
    a history, instead of seeing nothing and concluding nobody typed at this shell.
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
        events = case.query(
            "SELECT kind, parse_problem, payload, raw FROM events "
            "WHERE original_path LIKE '%fish_history' ORDER BY kind"
        )
    assert rows, "the file has to be in the case as a collected artifact"
    assert rows[0]["parser"] == "shell_history"
    assert rows[0]["parse_status"] == "parsed"
    assert rows[0]["sha256"], "and with the hash that lets somebody go back to the bytes"
    assert [event["kind"] for event in events] == ["artifact.fs", "unparsed.record"]
    unreadable = events[1]
    assert "holds no record of that format" in unreadable["parse_problem"]
    # The content and not a count of lines: an analyst deciding whether this is the wrong
    # path, a rotated file or something else needs to read what was actually in it.
    assert "the quick brown fox" in unreadable["payload"]
    assert "the quick brown fox" in unreadable["raw"]
