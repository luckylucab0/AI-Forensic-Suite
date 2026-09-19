"""Tests for the generic YAML reader.

The floor under every YAML configuration in the catalogue: a file nobody has written a
parser for still reaches a case as records somebody can read, filed as a configuration
where the catalogue says it is one, so a rule about a setting can find it.

Most of what follows is about the three ways YAML differs from the format this reading was
first written for, because each of them is a way to lose a record quietly: several
documents in one file, a key that is not text, and a loader that raises part way through.
"""

from __future__ import annotations

from pathlib import Path

from agentforensics.catalog import load_catalogue
from agentforensics.model import UNINTERPRETED_MARK
from agentforensics.parsers import PARSERS, for_artifact
from agentforensics.parsers.base import ParseContext
from agentforensics.parsers.yaml_generic import CONFIGURATIONS, DOCUMENTS

CATALOG_DIR = Path(__file__).resolve().parents[2] / "catalog"
CONFIG = "goose.permissions"


def parse(path: Path, artifact: str = CONFIG) -> list:
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
                agent="goose",
                user="alice",
            )
        )
    )


def write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def test_a_configuration_reaches_the_case_as_a_configuration(tmp_path: Path) -> None:
    """The point of the whole module: until a file is filed as a configuration, every rule
    about a setting is looking at nothing."""
    events = parse(
        write(
            tmp_path / "permission.yaml",
            "version: 1\npermissions:\n  developer__shell: always_allow\n",
        )
    )
    assert [event.kind for event in events] == ["config.snapshot"]
    assert events[0].raw["permissions"] == {"developer__shell": "always_allow"}
    assert UNINTERPRETED_MARK in (events[0].parse_problem or "")


def test_a_list_of_tables_is_split_one_level_deep(tmp_path: Path) -> None:
    events = parse(
        write(
            tmp_path / "config.yaml",
            "extensions:\n  - name: one\n    enabled: true\n  - name: two\n    enabled: false\n",
        ),
        "goose.config",
    )
    assert [event.provenance.locator for event in events] == [
        "$",
        "$.extensions[0]",
        "$.extensions[1]",
    ]


def test_every_document_in_the_file_is_read_and_says_which_it_is(tmp_path: Path) -> None:
    """A file of several documents is how this format holds a list of profiles, and a
    reader that took the first one would report a machine with one profile on it."""
    events = parse(
        write(
            tmp_path / "profiles.yaml",
            "name: first\n---\nname: second\n---\nname: third\n",
        ),
        "hermes.profiles",
    )
    assert [event.raw["name"] for event in events] == ["first", "second", "third"]
    assert [event.provenance.locator for event in events] == ["$doc[0]", "$doc[1]", "$doc[2]"]


def test_a_key_that_is_not_text_is_kept_and_said_to_be_rendered(tmp_path: Path) -> None:
    """YAML allows it and the case's record format does not. Failing the file would lose
    every setting in it over one key, and rendering it silently would show an analyst a key
    the file does not contain."""
    events = parse(write(tmp_path / "config.yaml", "retries:\n  1: first\n  2: second\n"))
    assert events[0].raw["retries"] == {"1": "first", "2": "second"}
    assert "not text" in (events[0].parse_problem or "")


def test_a_file_that_will_not_load_says_why_and_produces_an_event(tmp_path: Path) -> None:
    """The one answer this suite must never give is nothing at all."""
    events = parse(write(tmp_path / "config.yaml", "a: [1, 2\nb: {\n"))
    assert [event.kind for event in events] == ["unparsed.record"]
    assert "not valid YAML" in (events[0].parse_problem or "")


def test_a_tag_the_loader_does_not_know_is_reported_rather_than_run(tmp_path: Path) -> None:
    """The safe loader refuses a tag that would construct a Python object, which is the
    right answer for evidence: the file is reported as unread and nothing is executed."""
    events = parse(
        write(tmp_path / "config.yaml", "value: !!python/object/apply:os.system ['id']\n")
    )
    assert [event.kind for event in events] == ["unparsed.record"]
    assert "not valid YAML" in (events[0].parse_problem or "")


def test_an_empty_file_is_a_fact_rather_than_a_silence(tmp_path: Path) -> None:
    events = parse(write(tmp_path / "config.yaml", "# nothing but a comment\n"))
    assert len(events) == 1
    assert "empty" in (events[0].parse_problem or "")


# ----------------------------------------------- the catalogue staying in step


def test_the_parser_claims_every_yaml_artifact_that_is_not_a_credential_store() -> None:
    """A YAML artifact nobody claims is collected, passes ingest as unsupported, and
    produces a case where nothing looks wrong. The credential stores are the exception, for
    the reason the JSON reader gives: their content is not copied by default and a token in
    the payload of a timeline event is not what --include-secrets was for."""
    catalogue = load_catalogue(CATALOG_DIR)
    documents = {a.id for a in catalogue.artifacts if a.format == "yaml"}
    secrets = {
        a.id for a in catalogue.artifacts if a.format == "yaml" and a.sensitivity == "secret"
    }
    assert secrets, "the fixture of this rule: there are credential stores in YAML"
    assert documents - secrets == DOCUMENTS


def test_every_claimed_document_is_read_by_something() -> None:
    """Either by this reader or by a parser with a verified shape placed ahead of it. The
    set does not shrink when one is taken over, so the drift test above keeps working."""
    for artifact_id in sorted(DOCUMENTS):
        parser = for_artifact(artifact_id)
        assert parser is not None, artifact_id
        if parser.name != "yaml_generic":
            generic = next(p for p in PARSERS if p.name == "yaml_generic")
            assert generic.handles(artifact_id), artifact_id


def test_the_configurations_are_what_the_catalogue_calls_configurations() -> None:
    """The kind is the one thing about these documents that rests on something checked, so
    it has to keep resting on the catalogue rather than on this file."""
    catalogue = load_catalogue(CATALOG_DIR)
    expected = {
        a.id
        for a in catalogue.artifacts
        if a.id in DOCUMENTS and a.category in ("config", "mcp_config", "permissions")
    }
    assert expected == CONFIGURATIONS
