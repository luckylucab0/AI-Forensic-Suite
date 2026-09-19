"""Tests for the generic TOML reader.

The floor under one agent family's configuration, its MCP servers and its permissions, all
of which are written in this format and none of which reached a case as anything readable
before. The questions here are the same as for the other whole-document readers: is a
configuration filed as one, is a list of tables split, and does a file that will not load
still produce an event that says so.
"""

from __future__ import annotations

from pathlib import Path

from agentforensics.catalog import load_catalogue
from agentforensics.model import UNINTERPRETED_MARK
from agentforensics.parsers import PARSERS, for_artifact
from agentforensics.parsers.base import ParseContext
from agentforensics.parsers.toml_generic import CONFIGURATIONS, DOCUMENTS, NOT_READ

CATALOG_DIR = Path(__file__).resolve().parents[2] / "catalog"
CONFIG = "codex.config"


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
                agent="codex",
                user="alice",
            )
        )
    )


def write(path: Path, text: str) -> Path:
    # newline="" for the reason the other readers' tests give: the suite can simulate
    # Windows text-mode writes, and a document is read from the bytes on disk.
    path.write_text(text, encoding="utf-8", newline="")
    return path


def test_a_configuration_reaches_the_case_as_a_configuration(tmp_path: Path) -> None:
    events = parse(
        write(
            tmp_path / "config.toml",
            'model = "o4"\napproval_policy = "never"\n[sandbox_workspace_write]\nnetwork_access = true\n',
        )
    )
    assert [event.kind for event in events] == ["config.snapshot"]
    assert events[0].raw["approval_policy"] == "never"
    assert events[0].raw["sandbox_workspace_write"] == {"network_access": True}
    assert UNINTERPRETED_MARK in (events[0].parse_problem or "")


def test_an_array_of_tables_is_split_one_level_deep(tmp_path: Path) -> None:
    """Which is where this format puts a list of servers or a list of rules, so the split
    that costs nothing in the other formats buys the most here."""
    events = parse(
        write(
            tmp_path / "config.toml",
            '[[servers]]\nname = "one"\ncommand = "uvx"\n\n[[servers]]\nname = "two"\ncommand = "npx"\n',
        )
    )
    assert [event.provenance.locator for event in events] == ["$", "$.servers[0]", "$.servers[1]"]
    assert events[1].raw["command"] == "uvx"


def test_a_date_survives_into_the_record(tmp_path: Path) -> None:
    """The loader returns a real date object and the case renders a value no JSON encoder
    knows as its text, which is stable. Losing the field would be the alternative."""
    events = parse(write(tmp_path / "config.toml", "last_seen = 2026-09-07\n"))
    assert str(events[0].raw["last_seen"]) == "2026-09-07"
    assert "2026-09-07" in events[0].raw_json()


def test_a_file_that_will_not_load_says_why_and_produces_an_event(tmp_path: Path) -> None:
    events = parse(write(tmp_path / "config.toml", "model = \nbroken\n"))
    assert [event.kind for event in events] == ["unparsed.record"]
    assert "could not be read as TOML" in (events[0].parse_problem or "")


def test_an_empty_file_is_a_fact_rather_than_a_silence(tmp_path: Path) -> None:
    events = parse(write(tmp_path / "config.toml", "# nothing here\n"))
    assert len(events) == 1
    assert "empty" in (events[0].parse_problem or "")


# ----------------------------------------------- the catalogue staying in step


def test_the_parser_claims_every_toml_artifact_it_has_not_declined() -> None:
    """One is declined on purpose, and the declining is in the code with its reason rather
    than in a gap nobody would notice."""
    catalogue = load_catalogue(CATALOG_DIR)
    documents = {a.id for a in catalogue.artifacts if a.format == "toml"}
    assert documents >= NOT_READ, "a declined artifact that left the catalogue"
    assert documents - NOT_READ == DOCUMENTS


def test_every_claimed_document_is_read_by_something() -> None:
    for artifact_id in sorted(DOCUMENTS):
        parser = for_artifact(artifact_id)
        assert parser is not None, artifact_id
        if parser.name != "toml_generic":
            generic = next(p for p in PARSERS if p.name == "toml_generic")
            assert generic.handles(artifact_id), artifact_id


def test_the_configurations_are_what_the_catalogue_calls_configurations() -> None:
    catalogue = load_catalogue(CATALOG_DIR)
    expected = {
        a.id
        for a in catalogue.artifacts
        if a.id in DOCUMENTS and a.category in ("config", "mcp_config", "permissions")
    }
    assert expected == CONFIGURATIONS
