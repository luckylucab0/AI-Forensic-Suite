"""Tests for the reading of last resort for a whole JSON document.

The decision this asserts is ADR 0027: a document is split by its structure and never by a
guess at its meaning. So the tests come in two halves. One half shows that the structural
split happens and that a case can reach a conversation nobody has a schema for. The other
half shows the guesses that are refused, which is most of what the module is.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentforensics.catalog import load_catalogue
from agentforensics.parsers import PARSERS, for_artifact
from agentforensics.parsers.base import ParseContext
from agentforensics.parsers.json_generic import DOCUMENTS, SPLIT_LIMIT

CATALOG_DIR = Path(__file__).resolve().parents[2] / "catalog"

# One of the documents with no verified shape, used wherever the test is about the reading
# rather than about which artifact it was. Its own vendor documentation says not to rely on
# the structure, which is the case this module exists for.
ARTIFACT = "lmstudio.conversations"


def write(path: Path, document: object) -> Path:
    path.write_text(json.dumps(document), encoding="utf-8", newline="")
    return path


def parse(path: Path, artifact: str = ARTIFACT, agent: str = "lmstudio") -> list:
    parser = for_artifact(artifact)
    assert parser is not None, artifact
    return list(
        parser.parse(
            ParseContext(
                bundle_uuid="b",
                original_path=f"/home/alice/{path.name}",
                local_path=path,
                sha256="f" * 64,
                artifact_id=artifact,
                agent=agent,
                user="alice",
            )
        )
    )


def read(tmp_path: Path, document: object) -> list:
    return parse(write(tmp_path / "conversation.json", document))


def at(events: list) -> list[str]:
    return [event.provenance.locator for event in events]


# ------------------------------------------------------------------- the split


def test_a_document_that_is_a_list_is_one_event_per_element(tmp_path: Path) -> None:
    """The simple half of the rule, and the one a case most needs.

    A conversation stored as a bare array reached a case as a file name. Now each turn is
    an event with a path back into the file, so a timeline, a rule and a search all reach
    it without anybody having read the vendor's schema.
    """
    events = read(tmp_path, [{"role": "user", "text": "one"}, {"role": "assistant", "text": "two"}])

    assert at(events) == ["$[0]", "$[1]"]
    assert [event.payload["text"] for event in events] == ["one", "two"]


def test_an_object_gives_the_document_and_then_its_top_level_lists(tmp_path: Path) -> None:
    """A document is a record in its own right, because its own fields are evidence: the
    title, the model, the times it carries. The list under it is the conversation, and both
    have to be in the case."""
    events = read(
        tmp_path,
        {
            "name": "an example conversation",
            "createdAt": "2026-09-05T08:00:00Z",
            "messages": [{"text": "one"}, {"text": "two"}],
        },
    )

    assert at(events) == ["$", "$.messages[0]", "$.messages[1]"]
    assert events[0].ts_utc == "2026-09-05T08:00:00.000000Z"


def test_the_split_goes_one_level_and_no_further(tmp_path: Path) -> None:
    """The line between structure and meaning.

    Descending to find the records means deciding which branch holds them, which is the
    guess ADR 0027 refuses. The nested turns are in the case, whole, inside the document
    event: a partial reading rather than a wrong one, and the shape that says this agent
    has earned a parser of its own.
    """
    document = {"data": {"messages": [{"text": "one"}, {"text": "two"}]}}

    events = read(tmp_path, document)

    assert at(events) == ["$"]
    assert events[0].raw == document


def test_a_list_of_loose_values_is_not_split(tmp_path: Path) -> None:
    """A list of objects is a list of things. A list of strings is one setting with several
    values, and an event per string would file a case's evidence beside a list of enabled
    extensions."""
    events = read(tmp_path, {"enabled": ["a", "b", "c"], "turns": [{"text": "one"}]})

    assert at(events) == ["$", "$.turns[0]"]


def test_a_list_too_long_to_split_stays_one_record_and_says_so(tmp_path: Path) -> None:
    """The rule ADR 0022 applies to an index store, moved to the data itself.

    Nothing about an array's name says whether it is a conversation or a machine-generated
    index, so the length decides, and the event says what it holds. Nothing is dropped: the
    whole array is in raw.
    """
    document = {"chunks": [{"n": index} for index in range(SPLIT_LIMIT + 1)]}

    events = read(tmp_path, document)

    assert at(events) == ["$", "$.chunks"]
    assert f"{SPLIT_LIMIT + 1} elements" in (events[1].parse_problem or "")
    assert events[1].raw == document["chunks"]


# ------------------------------------------------------------ only what it says


def test_the_fields_are_read_the_way_the_line_reader_reads_them(tmp_path: Path) -> None:
    """The two generic readers share these four readings, by importing them rather than
    repeating them. A document and a line that carried the same fields and came out of the
    two readers differently would be exactly the drift both of them exist to prevent."""
    events = read(
        tmp_path,
        [
            {
                "ts": "2026-09-05T08:00:00Z",
                "sessionId": "s-1",
                "cwd": "/home/alice/src/app",
                "text": "hello",
            }
        ],
    )

    event = events[0]

    assert event.ts_utc == "2026-09-05T08:00:00.000000Z"
    assert event.ts_source == "the field named ts"
    assert event.session_id == "s-1"
    assert event.project_path == "/home/alice/src/app"
    assert event.payload["text"] == "hello"


def test_every_event_says_it_has_not_been_interpreted(tmp_path: Path) -> None:
    """Without it a thin reading looks like a complete one, and a document showing two
    fields reads as a document that held two fields."""
    problem = read(tmp_path, {"a": 1})[0].parse_problem or ""

    assert "no verified shape" in problem
    assert "in raw" in problem


def test_a_document_that_is_not_json_is_reported_rather_than_skipped(tmp_path: Path) -> None:
    """A truncated write or another encoding. "We collected this and could not read it" is
    something an analyst has to see rather than a blank."""
    path = tmp_path / "conversation.json"
    path.write_text('{"unterminated": ', encoding="utf-8")

    events = parse(path)

    assert len(events) == 1
    assert "not valid JSON" in (events[0].parse_problem or "")


def test_a_document_that_is_a_bare_value_is_still_a_record(tmp_path: Path) -> None:
    """A file whose content is `null` is a different answer from a file nobody read."""
    events = read(tmp_path, None)

    assert at(events) == ["$"]
    assert events[0].raw is None


# ----------------------------------------------- the catalogue staying in step


def test_the_parser_claims_every_json_artifact_that_is_not_a_credential_store() -> None:
    """The omission no other test would catch, and the one narrowing that is deliberate.

    A JSON artifact nobody claims is collected, passes ingest as unsupported, and produces
    a case where nothing looks wrong. The credential stores are the exception: their content
    is not copied by default, and putting a token into the payload of a timeline event is
    not what --include-secrets was for. The file and its hash are in the case either way.
    """
    catalogue = load_catalogue(CATALOG_DIR)
    documents = {artifact.id for artifact in catalogue.artifacts if artifact.format == "json"}
    secrets = {
        artifact.id
        for artifact in catalogue.artifacts
        if artifact.format == "json" and artifact.sensitivity == "secret"
    }

    assert secrets, "the fixture of this rule: there are credential stores in JSON"
    assert documents - secrets == DOCUMENTS


@pytest.mark.parametrize("artifact_id", sorted(DOCUMENTS))
def test_every_claimed_document_is_read_by_something(artifact_id: str) -> None:
    """Either by this reader or by a parser with a verified shape placed ahead of it. The
    set does not shrink when one is taken over, so the drift test above keeps working."""
    parser = for_artifact(artifact_id)
    assert parser is not None
    if parser.name != "json_generic":
        generic = next(p for p in PARSERS if p.name == "json_generic")
        assert generic.handles(artifact_id), (
            f"{artifact_id} was taken over by {parser.name} and dropped out of the generic "
            "reader's set, so adding a document to the catalogue would stop failing here"
        )


def test_a_credential_store_is_left_to_its_own_artifact_event() -> None:
    """The other direction of the same narrowing: no reader claims one, so nothing puts its
    values into the event stream."""
    catalogue = load_catalogue(CATALOG_DIR)
    secrets = [
        artifact
        for artifact in catalogue.artifacts
        if artifact.format == "json" and artifact.sensitivity == "secret"
    ]

    for artifact in secrets:
        parser = for_artifact(artifact.id)
        assert parser is None or parser.name != "json_generic", artifact.id
