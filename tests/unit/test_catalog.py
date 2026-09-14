"""Tests for the artifact catalogue and its loader.

Most of these assert invariants on the real committed catalogue rather than on a fixture.
That is deliberate: the catalogue is data, and the failures worth catching are wrong data,
not a broken parser. A path that is plausible but unsourced, or a transcript marked in a
way that stops the collector copying it, is the kind of defect that produces a confident
wrong answer in an investigation, and no amount of unit testing the loader would find it.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from agentforensics.catalog import (
    COLLECT_PRIORITY_ORDER,
    Catalogue,
    CatalogueError,
    load_catalogue,
    load_file,
    resolve_text,
)

CATALOG_DIR = Path(__file__).resolve().parents[2] / "catalog"


@pytest.fixture(scope="module")
def catalogue() -> Catalogue:
    return load_catalogue(CATALOG_DIR)


def test_catalogue_loads_and_is_not_empty(catalogue: Catalogue) -> None:
    assert len(catalogue) >= 1
    assert len(catalogue.artifacts) >= 50


def test_every_id_belongs_to_its_agent(catalogue: Catalogue) -> None:
    for agent in catalogue:
        for artifact in agent.artifacts:
            assert artifact.agent == agent.agent


def test_ids_are_unique_across_agents(catalogue: Catalogue) -> None:
    ids = [a.id for a in catalogue.artifacts]
    assert len(ids) == len(set(ids)), "an id is stored in findings, so it must be unique"


def test_verified_entries_cite_a_fetchable_source(catalogue: Catalogue) -> None:
    """The honesty rule, restated as a test.

    A verified entry that rests on a blog post or on somebody's memory causes an empty
    collection that nobody questions, which is worse than an entry openly marked
    unverified.
    """
    for artifact in catalogue.artifacts:
        if artifact.is_verified:
            assert artifact.source_kind in ("official", "source_code"), artifact.id
            assert artifact.source.startswith("http"), artifact.id


def test_unverified_entries_are_still_collectable(catalogue: Catalogue) -> None:
    """Unverified does not mean excluded. It means flagged."""
    for artifact in catalogue.artifacts:
        if not artifact.is_verified:
            assert artifact.paths, artifact.id


def test_only_credential_stores_withhold_their_content(catalogue: Catalogue) -> None:
    """sensitivity is operational, and getting it wrong empties the bundle.

    'secret' stops the collector copying the bytes. It belongs to credential material
    only. A transcript is deeply personal and still has to be copied, because it is the
    evidence the whole suite exists to collect.
    """
    key_pattern = re.compile(r"id_ed25519|id_rsa|private[_-]?key|\.pem\b", re.I)
    for artifact in catalogue.artifacts:
        if artifact.sensitivity == "secret":
            holds_keys = key_pattern.search(" ".join(artifact.paths)) is not None
            assert artifact.category == "credentials" or holds_keys, (
                f"{artifact.id} withholds its content but is not credential material"
            )


def test_no_transcript_or_history_is_withheld(catalogue: Catalogue) -> None:
    """The specific regression this rule exists to prevent."""
    for artifact in catalogue.artifacts:
        if artifact.category in ("transcript", "prompt_history", "file_snapshot"):
            assert artifact.content_collected_by_default, artifact.id


def test_credentials_are_always_withheld(catalogue: Catalogue) -> None:
    for artifact in catalogue.artifacts:
        if artifact.category == "credentials":
            assert artifact.sensitivity == "secret", artifact.id
            assert not artifact.content_collected_by_default


def test_collection_order_is_deterministic_and_priority_first(catalogue: Catalogue) -> None:
    """Two runs must queue the same work in the same order.

    A collection interrupted halfway is only comparable to another if the order was
    stable, and the most volatile artifacts have to be at the front or the priority field
    buys nothing.
    """
    first = catalogue.for_os("linux")
    assert first == catalogue.for_os("linux")
    ranks = [COLLECT_PRIORITY_ORDER.index(a.collect_priority) for a in first]
    assert ranks == sorted(ranks)


def test_every_artifact_declares_at_least_one_os(catalogue: Catalogue) -> None:
    for artifact in catalogue.artifacts:
        assert artifact.os
        assert set(artifact.os) <= {"macos", "windows", "linux"}


def test_windows_paths_are_present_for_profile_anchored_windows_artifacts(
    catalogue: Catalogue,
) -> None:
    """A profile-anchored Windows artifact whose paths are all POSIX cannot be collected.

    Either a placeholder the collector expands (~, %APPDATA%, %LOCALAPPDATA%,
    %USERPROFILE%, %PROGRAMFILES%, %PROGRAMDATA%) or an explicit drive path has to appear.

    Project, repository and plugin paths are exempt, because they are relative to a working
    copy whose location the collector discovers rather than to anything platform-specific.
    """
    for artifact in catalogue.artifacts:
        if "windows" not in artifact.os or artifact.needs_project_roots:
            continue
        joined = " ".join(artifact.paths)
        assert re.search(r"%[A-Z]+%|^~|\s~|[A-Z]:\\|\\", joined), artifact.id


def test_project_anchored_artifacts_are_labelled(catalogue: Catalogue) -> None:
    """A path written relative to a working copy must say so.

    If it does not, the collector expands it against the user profile, finds nothing, and
    the project instruction files, which are exactly where injected instructions live,
    are silently absent from the bundle.
    """
    for artifact in catalogue.artifacts:
        looks_relative = any(
            p.startswith(("<project>", "<repo-root>", "<plugin-root>", "<marketplace-root>"))
            for p in artifact.paths
        )
        assert looks_relative == artifact.needs_project_roots, artifact.id


def test_legacy_paths_are_marked_not_silently_dropped(catalogue: Catalogue) -> None:
    """A legacy path must still be collected, and must never read as live state."""
    legacy = [a for a in catalogue.artifacts if a.legacy]
    for artifact in legacy:
        assert artifact.paths
        text, _ = resolve_text(artifact.volatility)
        notes, _ = resolve_text(artifact.notes)
        assert text or notes, f"{artifact.id} is legacy but says nothing about why"


def test_lookup_helpers(catalogue: Catalogue) -> None:
    agent = next(iter(catalogue))
    assert catalogue.agent(agent.agent) is agent
    some = agent.artifacts[0]
    assert catalogue.artifact(some.id) is some
    with pytest.raises(KeyError):
        catalogue.agent("no_such_agent")
    with pytest.raises(KeyError):
        catalogue.artifact("no_such.artifact")


def test_priority_groups_cover_everything(catalogue: Catalogue) -> None:
    groups = catalogue.by_priority("macos")
    assert set(groups) == set(COLLECT_PRIORITY_ORDER)
    total = sum(len(v) for v in groups.values())
    assert total == len(catalogue.for_os("macos"))


def test_resolve_text_reports_a_missing_translation() -> None:
    assert resolve_text("plain") == ("plain", True)
    assert resolve_text("plain", "de") == ("plain", False)
    assert resolve_text({"en": "a", "de": "b"}, "de") == ("b", True)
    assert resolve_text({"en": "a"}, "de") == ("a", False)
    assert resolve_text(None) == ("", True)


# --------------------------------------------------------------------- loader rejections


def write_catalogue(tmp_path: Path, body: str) -> Path:
    (tmp_path / "schema").mkdir(exist_ok=True)
    (tmp_path / "schema" / "catalog.schema.json").write_text(
        (CATALOG_DIR / "schema" / "catalog.schema.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    path = tmp_path / "test_agent.yaml"
    path.write_text(body, encoding="utf-8")
    return path


MINIMAL = """
agent: test_agent
title: Test Agent
artifacts:
  - id: test_agent.thing
    category: log
    os: [linux]
    paths: ["~/.test/thing.log"]
    format: text
    sensitivity: normal
    status: unverified
    source: observed on linux
    source_kind: observed
"""


def test_minimal_catalogue_is_accepted(tmp_path: Path) -> None:
    agent = load_file(write_catalogue(tmp_path, MINIMAL))
    assert agent.artifacts[0].collect_priority == "normal"
    assert agent.artifacts[0].legacy is False
    assert agent.artifacts[0].parser is None


def test_verified_on_a_community_source_is_rejected(tmp_path: Path) -> None:
    body = MINIMAL.replace("status: unverified", "status: verified").replace(
        "source_kind: observed", "source_kind: community"
    )
    with pytest.raises(CatalogueError, match="schema"):
        load_file(write_catalogue(tmp_path, body))


def test_credentials_must_be_secret(tmp_path: Path) -> None:
    body = MINIMAL.replace("category: log", "category: credentials")
    with pytest.raises(CatalogueError, match="schema"):
        load_file(write_catalogue(tmp_path, body))


def test_id_prefix_must_match_the_agent(tmp_path: Path) -> None:
    body = MINIMAL.replace("id: test_agent.thing", "id: other_agent.thing")
    with pytest.raises(CatalogueError, match="must start with the agent key"):
        load_file(write_catalogue(tmp_path, body))


def test_duplicate_ids_are_rejected(tmp_path: Path) -> None:
    body = MINIMAL + MINIMAL.split("artifacts:")[1]
    with pytest.raises(CatalogueError, match="duplicate artifact ids"):
        load_file(write_catalogue(tmp_path, body))


def test_unknown_field_is_rejected(tmp_path: Path) -> None:
    """A typo in a field name must fail loudly rather than being ignored.

    Silently dropping an unknown key is how a collect_priority typo turns into an artifact
    quietly collected last.
    """
    body = MINIMAL + "    collect_priorty: first\n"
    with pytest.raises(CatalogueError, match="schema"):
        load_file(write_catalogue(tmp_path, body))


def test_broken_yaml_is_reported_with_the_file(tmp_path: Path) -> None:
    with pytest.raises(CatalogueError, match="not valid YAML"):
        load_file(write_catalogue(tmp_path, "agent: [unclosed\n"))


def test_missing_file_is_reported(tmp_path: Path) -> None:
    with pytest.raises(CatalogueError, match="cannot read"):
        load_file(tmp_path / "absent.yaml", CATALOG_DIR / "schema" / "catalog.schema.json")


def test_empty_directory_is_an_error(tmp_path: Path) -> None:
    (tmp_path / "schema").mkdir()
    with pytest.raises(CatalogueError, match="no catalogue files"):
        load_catalogue(tmp_path)
