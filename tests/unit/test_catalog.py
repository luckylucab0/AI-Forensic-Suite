"""Tests for the artifact catalogue and its loader.

Most of these assert invariants on the real committed catalogue rather than on a fixture.
That is deliberate: the catalogue is data, and the failures worth catching are wrong data,
not a broken parser. A path that is plausible but unsourced, or a transcript marked in a
way that stops the collector copying it, is the kind of defect that produces a confident
wrong answer in an investigation, and no amount of unit testing the loader would find it.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
from pathlib import Path
from typing import Any

import pytest

from agentforensics.catalog import (
    COLLECT_PRIORITY_ORDER,
    Catalogue,
    CatalogueError,
    load_catalogue,
    load_file,
    resolve_text,
)
from agentforensics.ingest.match import _pattern_regexes
from agentforensics.parsers import PARSERS, for_artifact

CATALOG_DIR = Path(__file__).resolve().parents[2] / "catalog"


def normalise_path(path: str) -> str:
    """One spelling for a path, so two artifacts claiming the same file compare equal.

    Separators, the profile placeholders and variable segments all vary between entries
    for the same file, and a comparison that missed that would let the conflict this
    module tests for slip through.
    """
    text = path.lower().replace("\\", "/")
    # The two Windows application-data variables are real subdirectories of the profile, so
    # folding them into the profile itself would make %APPDATA%/Claude and ~/Claude compare
    # equal and report a conflict between two directories that are not the same place.
    text = re.sub(r"^%appdata%", "~/appdata/roaming", text)
    text = re.sub(r"^%localappdata%", "~/appdata/local", text)
    # A relocation variable stands in for the profile only when a path follows it. A
    # pattern that is nothing but a variable, which is how a fully relocated file is
    # written, would otherwise collapse to the profile itself and collide with every other
    # such pattern in the catalogue.
    text = re.sub(r"^(%userprofile%|\$[a-z_]+|~)(?=/)", "~", text)
    # The first segment says which root the path hangs off, and a project, a plugin and a
    # marketplace are three different roots. Only the variable segments deeper in the path
    # are interchangeable.
    head, sep, tail = text.partition("/")
    return head + sep + re.sub(r"<[^>]+>", "*", tail).rstrip("/")


@pytest.fixture(scope="module")
def catalogue() -> Catalogue:
    return load_catalogue(CATALOG_DIR)


def _load_collector() -> Any:
    """Import collect.py by path: it is a single standalone file, not a package module."""
    path = Path(__file__).resolve().parent.parent.parent / "collector" / "collect.py"
    spec = importlib.util.spec_from_file_location("collect_under_test", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def is_bare_variable(path: str) -> bool:
    """Whether a path is a relocation variable and nothing else.

    Such a path is whatever the operator pointed the variable at, so it has no platform
    spelling to check and no default location to compare against. One agent records its
    whole protocol trace this way, which means the trace is invisible to any collection
    that only walks known directories.
    """
    return bool(re.fullmatch(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?", path))


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
            # The generated reference renders the source as a Markdown link, and a space
            # or a bracket inside the URL breaks it silently, leaving the analyst with a
            # citation they cannot follow. Qualifiers such as a file name and a commit
            # belong in notes.
            assert not re.search(r"[\s()<>\[\]]", artifact.source), artifact.id


def test_verified_entries_rest_on_their_own_vendor(catalogue: Catalogue) -> None:
    """The other half of the honesty rule: whose page is it.

    A third party who reverse-engineered a path writes it down with exactly the same
    confidence as the vendor does, and nothing in the path itself tells an analyst which
    of the two they are reading. Community research belongs in the catalogue, it just
    belongs there as source_kind: community with status: unverified, which the analyzer
    surfaces so an empty result reads as inconclusive. Each agent file lists the prefixes
    that count as first party in vendor_sources.
    """
    overclaimed = [
        (artifact.id, artifact.source)
        for agent in catalogue
        for artifact in agent.artifacts
        if artifact.is_verified and not agent.is_vendor_source(artifact.source)
    ]
    assert not overclaimed, (
        "verified entries whose source is not first party. Either re-source them to the "
        f"vendor or set status: unverified with source_kind: community: {overclaimed}"
    )


def test_a_vendor_repository_is_not_a_vendor_statement(catalogue: Catalogue) -> None:
    """An issue in the vendor's own repository is written by whoever opened it.

    Found by a research pass that cited one: the URL sits under the vendor's organization,
    so the prefix check above accepts it, while the text is a member of the public
    describing what they saw on their machine. That is community research and often good
    research, but it is not the vendor stating where its product writes, and the
    difference is the whole point of the verified mark.
    """
    borrowed = [
        (artifact.id, artifact.source)
        for artifact in catalogue.artifacts
        if artifact.is_verified
        and any(part in artifact.source for part in ("/issues/", "/discussions/", "/pull/"))
    ]
    assert not borrowed, (
        "these verified entries cite a thread rather than the vendor's own documentation "
        f"or code: {borrowed}"
    )


def test_every_agent_declares_who_its_vendor_is(catalogue: Catalogue) -> None:
    """Without the list the check above silently passes for a whole agent."""
    for agent in catalogue:
        assert agent.vendor_sources, agent.agent


def test_an_unsourced_path_is_one_of_the_artifacts_own_paths(catalogue: Catalogue) -> None:
    """A typo here would silently mark nothing, which is the failure mode of the field."""
    for artifact in catalogue.artifacts:
        stray = sorted(set(artifact.unsourced_paths) - set(artifact.paths))
        assert not stray, f"{artifact.id}: unsourced_paths not in paths: {stray}"


def test_an_unverified_artifact_does_not_also_list_unsourced_paths(
    catalogue: Catalogue,
) -> None:
    """Every path of an unverified artifact is unsourced already.

    Listing a few would read as if the others were confirmed, which is the opposite of
    what the status says.
    """
    for artifact in catalogue.artifacts:
        if not artifact.is_verified:
            assert not artifact.unsourced_paths, artifact.id


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


def test_no_path_is_claimed_as_both_secret_and_evidence(catalogue: Catalogue) -> None:
    """One file, one decision about whether its bytes are copied.

    When two artifacts claim the same path with different sensitivity, the collector's
    behaviour depends on which one it happens to reach first. That is not hypothetical: a
    JetBrains directory glob marked normal matches the c.kdbx password database that the
    catalogue marks secret, and VS Code's state.vscdb was filed as credential material
    although it holds every stored conversation.

    Both shapes are now expressible without a conflict. A container that holds credential
    material stays evidence and lists what is inside it in contains_credentials. A genuine
    credential store is its own artifact and claims no path that evidence also claims.
    """
    claims: dict[str, list[str]] = {}
    sensitivities: dict[str, set[str]] = {}
    for artifact in catalogue.artifacts:
        for path in artifact.paths:
            key = normalise_path(path)
            claims.setdefault(key, []).append(artifact.id)
            sensitivities.setdefault(key, set()).add(artifact.sensitivity)
    conflicts = {path: claims[path] for path, kinds in sensitivities.items() if len(kinds) > 1}
    assert not conflicts, f"paths claimed as both secret and evidence: {conflicts}"


def test_a_container_of_credentials_is_still_collected(catalogue: Catalogue) -> None:
    """contains_credentials names what to redact, it does not withhold the file.

    Several agents keep conversations and tokens in one container. Withholding it to
    protect the tokens throws away the transcripts an investigation exists to read, so the
    file is collected and the names tell an exporter what to strip on the way out.
    """
    holders = [a for a in catalogue.artifacts if a.holds_credentials_inside]
    assert holders, "the catalogue should describe at least one such container"
    for artifact in holders:
        assert artifact.sensitivity == "normal", artifact.id
        assert artifact.content_collected_by_default, artifact.id
        assert artifact.category != "credentials", artifact.id


def test_a_relocation_variable_in_a_path_is_declared(catalogue: Catalogue) -> None:
    """A variable the agent does not read is a pattern that resolves to nothing, forever.

    Found in the real catalogue: four of one editor's five install-evidence paths were
    rooted at a data directory variable the editor never reads, because its only override
    is a function call inside the process. The variable is unset on every host, so the
    collector skipped all four patterns on every platform without reporting an error.

    Declaring an agent-specific variable in env_overrides is what makes somebody check it
    exists and write down what it moves. The shell and base directory variables below are
    the operating system's, not an agent's, and the collector resolves them itself.
    """
    system_variables = {
        "HOME",
        "HISTFILE",
        "ZDOTDIR",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
    }
    undeclared: dict[str, list[str]] = {}
    for agent in catalogue:
        declared = {override.name for override in agent.env_overrides} | system_variables
        for artifact in agent.artifacts:
            for path in artifact.paths:
                for name in re.findall(r"\$\{?([A-Z][A-Z0-9_]*)", path):
                    if name not in declared:
                        undeclared.setdefault(f"{name} in {artifact.id}", []).append(path)
    assert not undeclared, (
        "these paths are rooted at a variable the agent's env_overrides does not declare, "
        f"so nobody has checked the agent reads it: {sorted(undeclared)}"
    )


def test_no_path_lost_a_leading_dot(catalogue: Catalogue) -> None:
    """A dot-directory spelled without its dot collects nothing and says nothing failed.

    Found in the real catalogue: 38 project-anchored paths in the cross-cutting file had
    lost the dot in front of the first segment, so the instruction-file entries pointed at
    <project>/github/ and <project>/clinerules/ rather than the directories that exist.
    The collector would have found nothing under any of them and reported no error, and an
    analyst would have read that as no injected instruction file present.

    The check compares against the catalogue itself: a first segment that appears with a
    dot somewhere must never appear without one, since no project convention uses both
    spellings for the same directory.
    """
    roots = ("<project>/", "<repo_root>/", "~/", "%USERPROFILE%/")
    first_segments: dict[str, set[str]] = {}
    for artifact in catalogue.artifacts:
        for path in artifact.paths:
            text = path.replace("\\", "/")
            for root in roots:
                if text.startswith(root):
                    segment = text[len(root) :].split("/")[0]
                    first_segments.setdefault(segment, set()).add(artifact.id)
    dotless = {
        segment: sorted(ids)
        for segment, ids in first_segments.items()
        if not segment.startswith(".") and ("." + segment) in first_segments
    }
    assert not dotless, (
        "these first path segments appear both with and without a leading dot, so one "
        f"spelling is wrong and collects nothing: {dotless}"
    )


def test_paths_are_paths_and_not_prose(catalogue: Catalogue) -> None:
    """A path with an explanation appended to it matches nothing, silently.

    This arrived repeatedly from research, in shapes like
    "…/state.vscdb  (same ItemTable keys)" and "macOS Keychain: generic-password …".
    Neither exists on disk, so the artifact is never collected and nobody is told. The
    schema rejects these now; this is the same rule stated where a reader will see it.
    """
    for artifact in catalogue.artifacts:
        for path in artifact.paths:
            assert "(" not in path and ")" not in path, f"{artifact.id}: {path!r}"
            assert "  " not in path, f"{artifact.id}: {path!r}"
            assert ": " not in path, f"{artifact.id}: {path!r}"


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
        if "windows" not in artifact.os or artifact.needs_project_roots or artifact.is_registry:
            continue
        if all(is_bare_variable(p) for p in artifact.paths):
            continue
        joined = " ".join(artifact.paths)
        # <vscode-user> is a real placeholder, not a wildcard: the collector expands it to
        # the per-OS user directory of VS Code and of every fork that inherits its storage
        # layout, which is where a dozen agentic extensions keep their conversations.
        if "<vscode-user>" in joined:
            continue
        assert re.search(r"%[A-Z]+%|^~|\s~|[A-Z]:\\|\\", joined), artifact.id


def test_posix_paths_are_present_for_profile_anchored_posix_artifacts(
    catalogue: Catalogue,
) -> None:
    """The mirror of the Windows check, and the same failure in the other direction.

    An artifact that claims macOS or Linux but whose paths are all Windows placeholders
    resolves to nothing on those hosts. The collector passes such a pattern through
    unexpanded, it matches no file, and the bundle is clean: the agent looks unused on
    every Mac and Linux endpoint in the fleet.
    """
    for artifact in catalogue.artifacts:
        posix = {"macos", "linux"} & set(artifact.os)
        if not posix or artifact.needs_project_roots or artifact.is_registry:
            continue
        if all(is_bare_variable(p) for p in artifact.paths):
            continue
        joined = " ".join(artifact.paths)
        if "<vscode-user>" in joined:
            continue
        # ~ for the profile, $XDG_* for the freedesktop directories, or an absolute path.
        assert re.search(r"(^|\s)~|\$XDG_[A-Z_]+|(^|\s)/", joined), artifact.id


def test_every_artifact_resolves_to_at_least_one_pattern_per_declared_os(
    catalogue: Catalogue, monkeypatch
) -> None:
    """Run the collector's own expansion, rather than trusting a regex about it.

    The two checks above look at the catalogue text. This one imports the collector and
    asks it what it would actually search, which is the only thing that decides whether an
    artifact can be found. A placeholder nobody taught the collector about expands to a
    bare wildcard or to nothing, and either way the evidence is missing with no error.
    """
    collect = _load_collector()
    # This test is about the platform spellings, so it asks what the collector would search
    # for a profile whose environment it can speak for. The homes below belong to nobody on
    # the machine running the test, and a relocation variable is refused for a profile that
    # is not the process's own: that guard is right and has its own test, and leaving it in
    # here would make every $VAR pattern look like a refusal about the catalogue.
    monkeypatch.setattr(collect, "environment_applies_to", lambda home, root: not root)
    homes = {"linux": "/home/alice", "macos": "/Users/alice", "windows": "C:/Users/alice"}
    for agent in collect.EMBEDDED_CATALOGUE["agents"]:
        for entry in agent["artifacts"]:
            if entry.get("root") == "registry":
                # A registry key is not a filesystem path, so the file pass cannot resolve
                # one and this test is not about it. Four of these entries are read by the
                # registry pass instead (ADR 0033) and the rest are declined by name, which
                # the tests below hold. The comment that used to stand here said collect.ps1
                # read all of them, and it was wrong in the direction that hides a gap.
                continue
            if all(is_bare_variable(p) for p in entry["paths"]):
                # An artifact that exists only where a variable points has no default
                # location, so resolving to nothing when the variable is unset is the
                # right answer rather than a hole. It is in the catalogue so that an
                # analyst knows to read the variable off the endpoint: one agent records
                # its entire protocol trace this way, at a path no directory walk finds.
                continue
            for target_os in entry["os"]:
                home = homes[target_os]
                resolved = []
                for pattern in entry["paths"]:
                    concrete = pattern
                    if entry.get("root") in ("project", "repo_root", "plugin"):
                        # The collector's own substitution, not a copy of it. A copy kept
                        # passing while the real one crashed: re.sub interprets backslash
                        # escapes in its replacement, and a Windows project root is full of
                        # them.
                        anchor = (
                            "C:\\Users\\alice\\src\\app" if target_os == "windows" else "/src/app"
                        )
                        concrete = collect.substitute_anchor(pattern, anchor)
                    resolved.extend(collect.expand_paths(concrete, home, target_os, None))
                assert resolved, f"{entry['id']} resolves to nothing on {target_os}"
    assert not collect.PATTERN_REFUSALS, (
        f"the collector refused to search a catalogue pattern: {collect.PATTERN_REFUSALS}"
    )


def test_a_windows_project_root_can_be_substituted_into_a_pattern() -> None:
    """The replacement is literal text, not a regular expression replacement.

    re.sub interprets backslash escapes in its replacement string, and a project root on
    Windows is "C:\\Users\\alice\\src\\app": \\U is not a valid escape, so re.sub raised
    and the collection died the moment any project root was discovered. It died before
    writing the manifest, on the platform most endpoints run, while the Linux and macOS
    jobs stayed green.
    """
    collect = _load_collector()
    cases = [
        ("<project>/.claude/CLAUDE.md", "C:\\Users\\alice\\src\\app"),
        ("<repo-root>/AGENTS.md", "C:\\a\\U\\b"),
        ("<project>/.cursorrules", "C:\\x\\name with $1 and backref"),
        ("<project>/x", "/src/app"),
    ]
    for pattern, anchor in cases:
        result = collect.substitute_anchor(pattern, anchor)
        assert result.startswith(anchor.rstrip("/\\")), (pattern, anchor, result)
        assert "<" not in result, result

    # A pattern with no placeholder is returned untouched.
    assert collect.substitute_anchor("~/.claude/x", "/src/app") == "~/.claude/x"


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


def test_the_parser_field_says_what_actually_reads_the_artifact() -> None:
    """The field is a claim about the analyzer, so it has to be the analyzer's answer.

    It sat at null for every one of the 460 entries while six parsers were reading 46 of
    them, which is the quiet kind of wrong this catalogue must not carry: the field is
    documented as naming what turns the artifact into events, `afx catalog` counts it, and
    a reader consulting it would have concluded that nothing in the suite reads anything.
    Asserted in both directions, so a parser added without touching the catalogue fails
    here and so does a field naming a parser that does not claim the entry.
    """
    catalogue = load_catalogue(CATALOG_DIR)

    wrong = []
    for artifact in catalogue.artifacts:
        reader = next((parser for parser in PARSERS if parser.handles(artifact.id)), None)
        expected = reader.name if reader else None
        if artifact.parser != expected:
            wrong.append(
                f"{artifact.id}: catalogue says {artifact.parser!r}, {expected!r} reads it"
            )

    assert not wrong, wrong


# ------------------------------------------- the rule that picks a file's primary claimant


def test_the_two_specificity_rules_agree_on_every_catalogue_path() -> None:
    """The collector and the analyzer rank claimants by one rule implemented twice.

    They have to agree on every path in the catalogue, because the winner decides which
    entry a file is reported under and that decides whether a parser is found for it. The
    two disagreeing cost one agent's whole chat transcript, in a bundle where the winning
    entry had no parser behind it. See ADR 0025.

    Asserted over the catalogue rather than over a handful of examples, so a new path shape
    that the two read differently fails here rather than in a case.
    """
    from agentforensics.ingest.match import _root_rank

    collect = _load_collector()
    catalogue = load_catalogue(CATALOG_DIR)
    checked = 0
    for artifact in catalogue.artifacts:
        for path in artifact.paths:
            assert collect.root_rank(path) == _root_rank(path), path
            checked += 1
    assert checked > 1000, "the whole catalogue, not a sample"


def test_a_pattern_that_names_a_file_beats_one_that_names_its_directory() -> None:
    """The defect the rule replaced.

    The primary claimant used to be the artifact with the fewest path patterns, which is
    the wrong way round: an entry holding one broad glob over a directory has fewer
    patterns than an entry whose pattern names the file. A chat transcript was therefore
    reported under the home tree that contains it, with category config.
    """
    collect = _load_collector()
    tree = collect.pattern_specificity("~/.gemini/")
    chats = collect.pattern_specificity("~/.gemini/tmp/<hash>/chats/*.jsonl")
    assert chats > tree, "the pattern that names the file is the more specific claim"


def test_a_placeholder_root_loses_to_a_root_that_can_be_named() -> None:
    """Literal characters alone cannot tell these apart, and they are not the same claim.

    `~/.claude/CLAUDE.md` and `<project>/.claude/CLAUDE.md` both spell sixteen literal
    characters. The first names one directory; the second matches any directory on the
    disk. Ranking them equal left the tie to the artifact id, so the user's own instruction
    file came out at project scope.
    """
    collect = _load_collector()
    user = collect.pattern_specificity("~/.claude/CLAUDE.md")
    project = collect.pattern_specificity("<project>/.claude/CLAUDE.md")
    assert user[0] == project[0], "the same literal length, which is the whole problem"
    assert user > project


def test_a_plugin_root_loses_to_a_working_copy_root() -> None:
    """Both are substituted with the recorded working copies, and they are not the same.

    A pattern written for a plugin root and matched at a working copy root was matched
    somewhere it was not written for. Without this, a project's own MCP server
    configuration was reported as a plugin manifest: `<project>/.mcp.json` and
    `<plugin-root>/.mcp.json` spell the same nine characters and only the root separates
    them.
    """
    collect = _load_collector()
    assert collect.pattern_specificity("<project>/.mcp.json") > collect.pattern_specificity(
        "<plugin-root>/.mcp.json"
    )


# --------------------------------------- what the Windows target does with a variable


def test_no_relocation_variable_is_dropped_without_a_word_on_a_windows_target(
    catalogue: Catalogue,
) -> None:
    """The defect this test exists for was silent, narrow and in the worst place.

    The Windows branch dropped every pattern beginning with a variable, under a comment
    calling them freedesktop variables. Most are, and dropping those is right: the entry
    carries a Windows sibling and it is being searched. But twelve of them are the agents'
    own relocation variables, which are the same variable on Windows as on POSIX, and 43
    catalogue paths were rooted at one, among them a credential store and two session
    databases. The default location was still found through the entry's `~` sibling, so a
    relocated tree was the only thing missing and nothing in the manifest said so.

    Asserted over the catalogue rather than over examples, so a variable somebody adds
    tomorrow is covered without anybody remembering this.
    """
    collect = _load_collector()
    home, root = "/mnt/img/Users/alice", "/mnt/img"
    silent: list[str] = []
    for agent in catalogue:
        for artifact in agent.artifacts:
            if "windows" not in artifact.os:
                continue
            for path in artifact.paths:
                if not path.startswith("$"):
                    continue
                if collect.variable_name(path) in collect._POSIX_ONLY_VARIABLES:
                    continue
                collect.PATTERN_REFUSALS.clear()
                resolved = collect.expand_paths(path, home, "windows", root)
                if not resolved and not collect.PATTERN_REFUSALS:
                    silent.append(f"{artifact.id}: {path}")
    collect.PATTERN_REFUSALS.clear()
    assert not silent, (
        "these patterns are rooted at an agent's own relocation variable and a Windows "
        f"collection would search nothing for them and report nothing: {sorted(silent)}"
    )


def test_a_freedesktop_variable_on_a_windows_target_is_not_a_refusal() -> None:
    """The other half of the same rule, and the reason it is a set and not a guess.

    A pattern rooted at XDG_DATA_HOME is another platform's spelling of an artifact whose
    entry carries a Windows sibling, so it does not apply here and reporting it would fill
    the manifest's refusal list with the cross-platform case. That list is meant to be read.
    """
    collect = _load_collector()
    collect.PATTERN_REFUSALS.clear()
    resolved = collect.expand_paths(
        "$XDG_DATA_HOME/zed/db/0-stable/db.sqlite", "/mnt/img/Users/alice", "windows", "/mnt/img"
    )
    assert resolved == []
    assert not collect.PATTERN_REFUSALS
    collect.PATTERN_REFUSALS.clear()


def test_a_relocated_tree_is_found_on_a_live_windows_host(monkeypatch) -> None:
    """With no image root there is an environment to read, and it is the endpoint's.

    A trailing separator is part of the case: a Windows value can end in a backslash, and
    joining that onto a tail that starts with one produced a path no glob would match.
    """
    collect = _load_collector()
    # The process's own profile, because the environment is only read for that one.
    monkeypatch.setattr(collect.os.path, "expanduser", lambda _: "C:/Users/alice")
    monkeypatch.setenv("HERMES_HOME", "D:\\agents\\hermes\\")
    collect.PATTERN_REFUSALS.clear()
    resolved = collect.expand_paths("$HERMES_HOME/state.db", "C:/Users/alice", "windows", None)
    assert resolved == ["D:/agents/hermes/state.db"]
    assert not collect.PATTERN_REFUSALS

    monkeypatch.delenv("HERMES_HOME")
    resolved = collect.expand_paths("$HERMES_HOME/state.db", "C:/Users/alice", "windows", None)
    assert resolved == [], "unset means the entry's default sibling covers it"
    assert not collect.PATTERN_REFUSALS, "and unset is not a refusal"
    collect.PATTERN_REFUSALS.clear()


def test_a_percent_variable_with_a_digit_is_recognised_as_a_windows_spelling() -> None:
    """Latent until a catalogue entry uses one, and wrong in the reportable direction.

    The test for another platform's spelling was `^%[A-Za-z_]+%`, which does not match
    %PROGRAMFILES(X86)%. On a POSIX target that pattern fell through to the end of the
    function and was refused as not absolute, so the refusal list, which an analyst reads
    as holes in the evidence, would have carried an entry that is not a hole at all.
    """
    collect = _load_collector()
    collect.PATTERN_REFUSALS.clear()
    assert (
        collect.expand_paths("%PROGRAMFILES(X86)%\\Agent\\x.json", "/home/alice", "linux", None)
        == []
    )
    assert not collect.PATTERN_REFUSALS
    collect.PATTERN_REFUSALS.clear()


# ---------------------------------- a Windows placeholder the endpoint has moved


def test_a_redirected_placeholder_is_searched_as_well_as_its_default(monkeypatch, tmp_path) -> None:
    """Folder redirection is ordinary in a managed fleet, and the default then finds nothing.

    %APPDATA% can be a network share and %TEMP% can be moved. 134 catalogue paths are
    rooted at one of these placeholders, so a collection on such a host found none of them
    and reported nothing wrong. Both locations are searched rather than one replacing the
    other, because the default can still hold what was written before the redirection.
    """
    collect = _load_collector()
    # as_posix, because that is what the collector passes: str(Path) is backslashed on
    # Windows, and an expectation built from it asserts the platform rather than the code.
    home = (tmp_path / "profile").as_posix()
    monkeypatch.setattr(collect.os.path, "expanduser", lambda _: home)
    monkeypatch.setenv("APPDATA", "D:\\redirected\\Roaming")
    collect.PATTERN_REFUSALS.clear()

    resolved = collect.expand_paths("%APPDATA%\\Block\\goose\\sessions.db", home, "windows", None)

    assert resolved == [
        f"{home}/AppData/Roaming/Block/goose/sessions.db",
        "D:/redirected/Roaming/Block/goose/sessions.db",
    ]
    assert not collect.PATTERN_REFUSALS
    collect.PATTERN_REFUSALS.clear()


def test_another_user_s_profile_is_not_given_this_process_s_variables(
    monkeypatch, tmp_path
) -> None:
    """The guard that keeps the redirection read from becoming a mis-attribution.

    A collector run as an administrator walks every profile on the host, and the process
    environment belongs to whoever ran it. Applying this user's %APPDATA% to another user's
    profile would search one person's directory and file it under another's name.
    """
    collect = _load_collector()
    monkeypatch.setattr(collect.os.path, "expanduser", lambda _: (tmp_path / "mine").as_posix())
    monkeypatch.setenv("APPDATA", "D:\\redirected\\Roaming")
    collect.PATTERN_REFUSALS.clear()

    resolved = collect.expand_paths(
        "%APPDATA%\\Block\\goose\\sessions.db", "C:/Users/bob", "windows", None
    )

    assert resolved == ["C:/Users/bob/AppData/Roaming/Block/goose/sessions.db"]
    collect.PATTERN_REFUSALS.clear()


def test_a_mounted_image_is_never_asked_about_this_machine_s_variables(
    monkeypatch, tmp_path
) -> None:
    """The analyst workstation's environment says nothing about the endpoint in the image."""
    collect = _load_collector()
    home = (tmp_path / "img" / "Users" / "alice").as_posix()
    monkeypatch.setattr(collect.os.path, "expanduser", lambda _: home)
    monkeypatch.setenv("APPDATA", "D:\\redirected\\Roaming")
    collect.PATTERN_REFUSALS.clear()

    resolved = collect.expand_paths(
        "%APPDATA%\\Block\\goose\\sessions.db",
        home,
        "windows",
        (tmp_path / "img").as_posix(),
    )

    assert resolved == [f"{home}/AppData/Roaming/Block/goose/sessions.db"]
    collect.PATTERN_REFUSALS.clear()


def test_a_live_run_on_a_windows_host_targets_windows() -> None:
    """platform.system() returns "Windows" and it was not in the map, so the default fell
    through to the linux target: a live run searched POSIX paths, skipped every %APPDATA%
    one as another platform's spelling, and reported a collection that looked clean."""
    collect = _load_collector()
    assert collect.target_os_for("Windows", None) == "windows"
    assert collect.target_os_for("Darwin", None) == "macos"
    assert collect.target_os_for("Linux", None) == "linux"
    # An unknown platform still has to resolve to something, and POSIX is the safe guess
    # for this collector: it is the one whose paths it can actually expand.
    assert collect.target_os_for("FreeBSD", None) == "linux"
    # A named target wins, because a mounted image is collected from a workstation whose
    # own platform says nothing about the image.
    assert collect.target_os_for("Linux", "windows") == "windows"


def test_a_pattern_is_built_with_one_separator_whatever_machine_expands_it(
    monkeypatch,
) -> None:
    """os.path.join uses the separator of the machine running the collector, and every
    consumer of these patterns splits on "/".

    An analyst workstation running Windows produced `/mnt/img\\Windows/Prefetch/*.pf` for a
    machine-wide pattern under --root. iter_matches then looked for a single segment named
    `mnt/img\\Windows`, found nothing, and reported nothing: collecting a mounted image from
    a Windows workstation, the wildcarded execution evidence, Amcache and Prefetch, matched
    nothing at all. The no-wildcard branch normalises and converts back, so only the
    wildcarded patterns were affected, which is most of the machine-wide ones.

    ntpath is substituted rather than the test being skipped off Windows, because a defect
    that only one platform's CI can see is one that waits for the next release to be found.
    """
    import ntpath

    collect = _load_collector()
    monkeypatch.setattr(collect.os, "path", ntpath)
    collect.PATTERN_REFUSALS.clear()

    resolved = collect.expand_paths(
        "%SystemRoot%\\Prefetch\\*.pf", "/mnt/img/Users/alice", "windows", "/mnt/img"
    )

    assert resolved == ["/mnt/img/Windows/Prefetch/*.pf"]
    assert all("\\" not in pattern for pattern in resolved)
    collect.PATTERN_REFUSALS.clear()


def test_a_discovered_profile_home_never_carries_a_backslash(monkeypatch, tmp_path) -> None:
    """The home is the prefix of every pattern for that profile, and it was built with
    os.path.join.

    On a Windows workstation collecting a mounted image that produced
    `/mnt/img\\Users\\alice`. The Windows target normalises separators afterwards and would
    have survived it. A POSIX target does not, and a POSIX target is how a Windows
    workstation collects a macOS or a Linux image.

    Windows' tolerance of both separators is simulated rather than the test being skipped,
    for the reason the test above gives: a defect only one CI platform can see waits for a
    release.
    """
    import ntpath

    collect = _load_collector()
    (tmp_path / "Users" / "alice").mkdir(parents=True)
    (tmp_path / "home" / "bob").mkdir(parents=True)
    real_isdir, real_listdir, real_islink = os.path.isdir, os.listdir, os.path.islink
    monkeypatch.setattr(collect.os.path, "join", ntpath.join)
    monkeypatch.setattr(collect.os.path, "isdir", lambda p: real_isdir(p.replace("\\", "/")))
    monkeypatch.setattr(collect.os.path, "islink", lambda p: real_islink(p.replace("\\", "/")))
    monkeypatch.setattr(collect.os, "listdir", lambda p: real_listdir(p.replace("\\", "/")))

    found = collect.discover_users(str(tmp_path), False, [])

    assert found, "the simulation has to reach the profiles, or it asserts nothing"
    assert [user["name"] for user in found] == ["alice", "bob"]
    for user in found:
        assert "\\" not in user["home"], user


def test_a_backslashed_home_or_root_does_not_double_the_profile(monkeypatch) -> None:
    """The function used to rely on its caller having normalised these two.

    The collector's own entry point does, so this never showed up there. Any other caller,
    including a test that built a path with str(Path) on Windows, got a home and a root full
    of backslashes, and then the re-anchoring's startswith test failed for a separator
    reason rather than a path reason: the pattern was anchored under the root a second time
    and the profile home appeared twice in it. A pattern like that matches nothing, which is
    this project's one unacceptable outcome, so the normalisation is at the top of the
    function now instead of in the caller's hands.
    """
    import ntpath

    collect = _load_collector()
    monkeypatch.setattr(collect.os, "path", ntpath)
    collect.PATTERN_REFUSALS.clear()

    resolved = collect.expand_paths(
        "%APPDATA%\\Block\\goose\\sessions.db",
        "C:\\image\\Users\\alice",
        "windows",
        "C:\\image",
    )

    assert resolved == ["C:/image/Users/alice/AppData/Roaming/Block/goose/sessions.db"]
    assert not collect.PATTERN_REFUSALS
    collect.PATTERN_REFUSALS.clear()


# ------------------------------------------------- --all-users, and where profiles live


def test_the_profile_parent_is_the_one_the_platform_uses(monkeypatch) -> None:
    """Measured on a Windows host rather than assumed, and the measurement was the point.

    "/Users" is not a path to the profiles on Windows. ntpath.isabs("/Users") is False and
    ntpath.abspath("/Users") resolves it against the working directory's drive, which on
    the runner was D: while the system was on C:. So --all-users looked for D:/Users and
    returned no profiles at all: it collected nothing and reported nothing, which is worse
    than a flag that is not there.
    """
    collect = _load_collector()

    monkeypatch.setattr(collect.os, "name", "posix")
    assert collect.live_profile_parents() == ["/Users", "/home"]

    monkeypatch.setattr(collect.os, "name", "nt")
    monkeypatch.setenv("SYSTEMDRIVE", "C:")
    assert collect.live_profile_parents() == ["C:/Users"]
    # A host whose system is not on C:, which is the case the measurement happened to show
    # is possible: the runner's working directory was on D:.
    monkeypatch.setenv("SYSTEMDRIVE", "E:")
    assert collect.live_profile_parents() == ["E:/Users"]
    monkeypatch.delenv("SYSTEMDRIVE")
    assert collect.live_profile_parents() == ["C:/Users"], "a default, not an empty answer"


def test_a_windows_pseudo_profile_is_not_a_user(tmp_path) -> None:
    """Names under a Windows Users directory that are not users.

    "All Users" and "Default User" are junctions, into ProgramData and into the default
    profile, so walking them collects another tree under a user name nobody has. Keyed on
    the parent being named Users rather than on the running platform, so an image of a
    Windows host collected from a POSIX workstation is treated the same way.
    """
    collect = _load_collector()
    users = tmp_path / "Users"
    for name in ("alice", "Public", "Default", "All Users", "defaultuser0", "Bob"):
        (users / name).mkdir(parents=True)

    found = collect._profiles_under(str(users), skip_pseudo=True)
    assert [user["name"] for user in found] == ["Bob", "alice"]

    # And without the flag nothing is filtered, because on POSIX a user may legitimately be
    # called any of those.
    assert len(collect._profiles_under(str(users), skip_pseudo=False)) == 6


def test_a_run_that_found_no_profile_says_so(tmp_path, capsys) -> None:
    """An empty bundle has to say why it is empty.

    Without this a --all-users run on a platform whose profile parent the collector had
    wrong was indistinguishable from a host with no user data on it, which is the one
    answer this tool must never give by accident. It is how the Windows case stayed
    unnoticed: zero profiles, zero files, zero errors.
    """
    collect = _load_collector()
    out = tmp_path / "bundle"
    empty = tmp_path / "empty-image"
    empty.mkdir()

    # An image root with no profile parent in it at all falls back to treating the root as
    # one profile, so --user is the way to reach the empty case deliberately.
    code = collect.main(
        ["--out", str(out), "--root", str(empty), "--os", "windows", "--user", "nobody"]
    )
    printed = capsys.readouterr()
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))

    reasons = [error["error"] for error in manifest["errors"]]
    assert "no_profiles_found" in reasons
    assert "no user profile was found" in printed.err
    assert code in (collect.EXIT_ERRORS, collect.EXIT_NOTHING_FOUND)


@pytest.mark.skipif(os.name != "nt", reason="the answer is only true on a Windows host")
def test_all_users_finds_the_profiles_on_a_live_windows_host() -> None:
    """The assertion the measurement earned, on the host that can answer it.

    Before the fix this returned an empty list on the Windows runner. It runs nowhere else,
    which is the point: the behaviour under test is the platform's.
    """
    collect = _load_collector()
    found = collect.discover_users(None, True, [])

    assert found, "a live Windows host has at least the profile this process runs as"
    for user in found:
        assert re.match(r"^[A-Za-z]:/", user["home"]), user
        assert "\\" not in user["home"], user
        assert user["name"].lower() not in collect._PSEUDO_PROFILES


# ------------------------------ a pattern's anchor, which is not the entry's root


def test_a_profile_path_in_a_project_rooted_entry_is_searched_with_no_working_copy(
    tmp_path,
) -> None:
    """Anchoring is a property of the pattern. Deciding it by the entry cost 191 paths.

    Sixty catalogue entries are one logical thing at two scopes: the working copy's own
    file and the profile or system wide one the same agent reads beside it. The collector
    substituted every pattern of such an entry with the discovered working copies and
    skipped the entry whole when there were none, so a host where no repository was found
    collected none of the global and machine wide instruction files either: a user's own
    CLAUDE.md, the hooks file of one editor, the managed settings under /etc and
    %PROGRAMDATA%. The bundle said nothing about it, which is the shape this project treats
    as worse than an error.

    The tree here deliberately holds no working copy at all.
    """
    collect = _load_collector()
    home = tmp_path / "image" / "home" / "alice"
    (home / ".claude").mkdir(parents=True)
    (home / ".claude" / "CLAUDE.md").write_text("Never push to main.\n", encoding="utf-8")
    out = tmp_path / "bundle"

    code = collect.main(["--out", str(out), "--root", str(tmp_path / "image"), "--os", "linux"])
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))

    assert code in (collect.EXIT_OK, collect.EXIT_ERRORS)
    assert not manifest["project_roots"], "the point of the tree is that it has none"
    collected = [entry["original_path"] for entry in manifest["files"] if entry.get("collected")]
    assert any(path.endswith("/.claude/CLAUDE.md") for path in collected), (
        "the user's own instruction file was not collected from a profile with no "
        f"repository in it: {collected}"
    )
    # And the other half of the same entries is reported rather than dropped, because a
    # bundle with no project tier in it has to say that nothing was searched for one.
    refusals = {refusal["reason"] for refusal in manifest["refused_patterns"]}
    assert "no_project_root" in refusals, sorted(refusals)


# ------------------------- the fixes that had reached only one of the two collectors


def test_a_named_user_is_looked_up_where_the_platform_keeps_profiles(monkeypatch) -> None:
    """The sibling branch of the one that was fixed, which kept the hardcoded POSIX pair.

    --all-users and --user answer the same question about the same host, and only one of
    them was taught where Windows keeps profiles. `--user alice` there looked under a
    directory that does not hold profiles and found nobody, with nothing said.

    Windows is simulated rather than the test being skipped off it, and the first version
    of this test is the reason that is worth insisting on: it compared the joined path with
    a forward-slash literal, which is a statement about the separator of the machine
    running the test rather than about the branch under test. It passed here and failed on
    the one runner nobody watches. ntpath.join reproduces the join Windows would do, and
    the tolerant isdir reproduces Windows accepting either separator.
    """
    import ntpath

    collect = _load_collector()
    asked: list[str] = []

    def parents() -> list[str]:
        asked.append("called")
        return ["Z:/Users"]

    monkeypatch.setattr(collect, "live_profile_parents", parents)
    monkeypatch.setattr(collect.os.path, "join", ntpath.join)
    monkeypatch.setattr(
        collect.os.path, "isdir", lambda path: path.replace("\\", "/") == "Z:/Users/alice"
    )

    found = collect.discover_users(None, False, ["alice"])

    assert asked, "the named branch has to ask the same question --all-users asks"
    # And the home leaves the function in the collector's one separator convention, because
    # it is the prefix of every pattern built for that profile and every consumer of those
    # splits on a forward slash.
    assert found == [{"name": "alice", "home": "Z:/Users/alice"}]


def test_a_symlinked_profile_is_recorded_rather_than_dropped(tmp_path) -> None:
    """Skipping it is right. Skipping it silently is not, and that was a regression.

    Where a linked profile points is not known to be inside the tree being collected: on a
    live host it can leave the profile directory, and in an image it can carry the original
    machine's absolute path and land on the analyst's own disk. The image branch never
    checked for links until it was routed through the shared helper, so a relocated home in
    an image went from collected to absent with nothing said.
    """
    collect = _load_collector()
    (tmp_path / "Users" / "alice").mkdir(parents=True)
    (tmp_path / "elsewhere" / "bob").mkdir(parents=True)
    (tmp_path / "Users" / "bob").symlink_to(tmp_path / "elsewhere" / "bob")
    collect.PATTERN_REFUSALS.clear()

    found = collect.discover_users(str(tmp_path), False, [])

    assert [user["name"] for user in found] == ["alice"]
    reasons = [record["reason"] for record in collect.PATTERN_REFUSALS]
    assert reasons == ["profile_is_a_symlink"]
    assert collect.PATTERN_REFUSALS[0]["pattern"].endswith("/Users/bob")
    collect.PATTERN_REFUSALS.clear()


def test_this_process_s_variables_are_not_another_user_s(monkeypatch, tmp_path) -> None:
    """A collector walking every profile on a live host has one environment, its own.

    Applying this user's CLAUDE_CONFIG_DIR to somebody else's profile searches this user's
    directory and files what it finds under that user's name. A wrong answer under
    somebody's name is worse than no answer, so it is refused and reported instead. The
    guard existed for the Windows placeholders and not for the variables.
    """
    collect = _load_collector()
    mine = (tmp_path / "mine").as_posix()
    monkeypatch.setattr(collect.os.path, "expanduser", lambda _: mine)
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", "/mine/claude")
    monkeypatch.setenv("XDG_DATA_HOME", "/mine/share")
    collect.PATTERN_REFUSALS.clear()

    assert collect.expand_paths("$CLAUDE_CONFIG_DIR/.credentials.json", mine, "linux", None) == [
        "/mine/claude/.credentials.json"
    ]
    assert not collect.PATTERN_REFUSALS

    theirs = collect.expand_paths(
        "$CLAUDE_CONFIG_DIR/.credentials.json", "/home/bob", "linux", None
    )
    assert theirs == []
    assert [record["reason"] for record in collect.PATTERN_REFUSALS] == [
        "environment_unreadable_other_user"
    ]

    # And a base-directory variable falls back to that user's own default rather than to
    # this one's, because the default is where the agent looks when it is unset.
    collect.PATTERN_REFUSALS.clear()
    assert collect.expand_paths("$XDG_DATA_HOME/zed/db", "/home/bob", "linux", None) == [
        "/home/bob/.local/share/zed/db"
    ]
    collect.PATTERN_REFUSALS.clear()


def test_a_short_registry_hive_name_is_not_a_directory(tmp_path) -> None:
    """The catalogue spells a registry key both ways and only one was recognised.

    With HKEY_ alone, `HKCU\\Software\\...` fell through to the end of expand_paths: under
    --root it was re-anchored and globbed, so a registry key was searched as a directory
    under the image root and would have been collected as a file if one had been there.
    """
    collect = _load_collector()
    collect.PATTERN_REFUSALS.clear()
    for pattern in ("HKCU\\Software\\Example", "HKLM\\SOFTWARE\\Example", "HKU\\.DEFAULT\\X"):
        assert collect.expand_paths(pattern, "/mnt/img/home/alice", "linux", "/mnt/img") == []
    assert not collect.PATTERN_REFUSALS
    collect.PATTERN_REFUSALS.clear()


def test_the_manifest_does_not_claim_a_windows_run_was_unelevated(monkeypatch) -> None:
    """The custody record's own field, which was a POSIX-only test.

    hasattr(os, "geteuid") is False on Windows, so the manifest said this run was not
    elevated on every Windows collection whether it was or not. What the collection could
    see is exactly what that field is for.
    """
    collect = _load_collector()
    monkeypatch.delattr(collect.os, "geteuid", raising=False)
    monkeypatch.setattr(collect, "running_elevated", lambda: None)
    source = (Path(__file__).resolve().parents[2] / "collector" / "collect.py").read_text(
        encoding="utf-8"
    )
    assert '"elevated": running_elevated(),' in source
    assert '"elevated": hasattr(os, "geteuid")' not in source


def test_a_windows_roaming_path_is_also_searched_where_the_package_puts_it(
    catalogue: Catalogue,
) -> None:
    """The store install writes somewhere else, and the entry has to look there too.

    A Microsoft Store package redirects a program's writes into its own container, so a
    file the vendor documents at %APPDATA%\\<product>\\x is at
    %LOCALAPPDATA%\\Packages\\<family>\\LocalCache\\Roaming\\<product>\\x on such a host.
    The two can both exist with different contents, and the catalogue's own note for this
    product says the copy the application actually reads is the virtualized one while the
    %APPDATA% copy may be dead.

    This was true of three of twenty entries and false of the rest, which is the worst
    shape for it: the paths looked complete, a store install returned nothing for the audit
    log, the session files and the memory, and nothing said the collection had looked in
    one place out of two. The mapping is the package virtualization itself rather than a
    guess, so it holds for every path under that root.
    """
    missing = []
    for agent in catalogue.agents:
        containers = {
            path.split("\\LocalCache\\", 1)[0] + "\\LocalCache\\Roaming\\"
            for artifact in agent.artifacts
            for path in artifact.paths
            if "\\LocalCache\\Roaming\\" in path
        }
        if not containers:
            continue
        for artifact in agent.artifacts:
            for path in artifact.paths:
                if not path.startswith("%APPDATA%\\"):
                    continue
                tail = path[len("%APPDATA%\\") :]
                if not any(container + tail in artifact.paths for container in containers):
                    missing.append(f"{artifact.id}: {path}")
    assert not missing, (
        "these entries search the roaming path and not the one a packaged install "
        "redirects it to, so a store install reads as an agent that left nothing: "
        f"{missing}"
    )


# --------------------------------------- the write-ahead log beside a database


def test_every_database_has_its_write_ahead_log_claimed() -> None:
    """A database collected without its write-ahead log reads short and says nothing.

    SQLite reports no error: the store opens, every table is there, and the conversation
    stops before its newest messages. That is the one failure in this pipeline that looks
    exactly like success, and it was the state of sixty-two database paths across
    twenty-three entries until their siblings were written into the catalogue.

    The set has to stay empty. A database entering the catalogue without its `-wal` and
    `-shm` fails here, which is the only thing standing between a new entry and a
    collection that reads a conversation short.

    The answer comes from the catalogue's own query, which is what the ingest asks at run
    time, so the two can never disagree about which stores are affected.
    """
    without = load_catalogue(CATALOG_DIR).databases_without_a_claimed_log()
    assert not without, (
        "these databases would be collected without the log holding their newest "
        "transactions, and nothing downstream can tell that the reading is short: "
        f"{ {name: list(paths) for name, paths in sorted(without.items())} }"
    )


# ------------------------------------------------------------- the registry keys


def test_a_registry_key_is_declined_by_name_rather_than_as_a_broken_pattern() -> None:
    """The file pass cannot search a key, and the manifest has to say which it is.

    A key used to fall through to the end of the expander, fail the absolute-path test and
    be refused as `not_absolute`. That reads as a malformed catalogue entry. It is not one:
    it is a whole class the file pass cannot reach, and two of the six entries in that
    class are the managed policy saying what an agent was allowed to do. The difference
    between the two readings is the difference between "no policy was in force" and "nobody
    looked", which is the question a collection exists to answer.

    Those four are read by the registry pass now and never reach the expander, so what this
    holds is the answer for the two the collectors decline. The expander itself still has
    to give it, because it is what a key reaches when nothing else claims it.
    """
    collect = _load_collector()
    collect.PATTERN_REFUSALS.clear()
    for key in (
        r"HKLM\SOFTWARE\Policies\ClaudeCode",
        r"HKEY_CURRENT_USER\Environment",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    ):
        assert collect.expand_paths(key, "C:/Users/alice", "windows", None) == []
    reasons = {refusal["reason"] for refusal in collect.PATTERN_REFUSALS}
    collect.PATTERN_REFUSALS.clear()
    assert reasons == {"registry_key"}


def test_a_registry_key_on_a_posix_target_is_not_a_refusal() -> None:
    """There it is another platform's spelling of the same artifact, like a %APPDATA% path.

    The entry carries no POSIX sibling for it because there is none, and reporting it would
    fill the refusal list on every Linux collection with keys that could never have
    applied. That list is meant to be read.
    """
    collect = _load_collector()
    collect.PATTERN_REFUSALS.clear()
    assert (
        collect.expand_paths(r"HKLM\SOFTWARE\Policies\ClaudeCode", "/home/alice", "linux", None)
        == []
    )
    assert not collect.PATTERN_REFUSALS


def test_every_catalogued_registry_key_is_declined_the_same_way() -> None:
    """Over the catalogue rather than over examples, so a key added tomorrow is covered."""
    collect = _load_collector()
    catalogue = load_catalogue(CATALOG_DIR)
    collect.PATTERN_REFUSALS.clear()
    keys = 0
    for artifact in catalogue.artifacts:
        if artifact.root != "registry":
            continue
        for path in artifact.paths:
            assert collect.expand_paths(path, "C:/Users/alice", "windows", None) == [], path
            keys += 1
    reasons = {refusal["reason"] for refusal in collect.PATTERN_REFUSALS}
    refused = len(collect.PATTERN_REFUSALS)
    collect.PATTERN_REFUSALS.clear()
    assert keys > 15, "the catalogue's registry keys, not a sample"
    assert refused == keys and reasons == {"registry_key"}


def test_a_registry_entry_holds_registry_keys_and_nothing_else() -> None:
    """A filesystem path under a registry root is collected and then claimed by nothing.

    The analyzer's path matcher skips an artifact whose root is registry, because a key is
    not a path it could ever match. That skip is per entry, not per path, so a filesystem
    path listed alongside the keys disappears from the analyzer entirely: the collector
    takes the file, the bundle carries it, and the case reports it as a path no catalogue
    entry claims. Two entries were in that state, and between them they hid eight paths,
    among them the machine-wide policy file that says what an agent was allowed to do for
    every user on the host. Both also declared os: windows, so their macOS and Linux
    locations were never collected either.
    """
    catalogue = load_catalogue(CATALOG_DIR)
    mixed = {}
    for artifact in catalogue.artifacts:
        if artifact.root != "registry":
            continue
        paths = [path for path in artifact.paths if not path.upper().startswith("HK")]
        if paths:
            mixed[artifact.id] = paths
    assert not mixed, (
        "these entries declare a registry root and list filesystem paths, so the analyzer "
        f"skips the entry whole and nothing claims the files: {mixed}"
    )


def test_an_entry_whose_paths_are_registry_keys_says_so_in_its_root() -> None:
    """The other direction, so a key cannot arrive in an entry the matcher will try to
    match against a filesystem path and quietly never hit."""
    catalogue = load_catalogue(CATALOG_DIR)
    misfiled = {}
    for artifact in catalogue.artifacts:
        if artifact.root == "registry":
            continue
        keys = [path for path in artifact.paths if path.upper().startswith("HK")]
        if keys:
            misfiled[artifact.id] = keys
    assert not misfiled, (
        "these entries list a registry key under a filesystem root, so the collector "
        f"would search for it as a path: {misfiled}"
    )


# ------------------------------- the file that says which project a workspace store is


def test_every_per_workspace_store_claims_the_file_that_names_its_folder() -> None:
    """Without it the store's directory name cannot be reversed, and nothing says so.

    A per-workspace store sits in a directory whose name is not a digest of the folder
    path: measurement showed that fifty combinations of normalisation and algorithm fail to
    reproduce one, and the same folder yields the same name in two different products. The
    editor writes the answer beside the store in a `workspace.json`, and the parser reads it
    to put the project on every row of that store (ADR 0038).

    The gap this holds shut was real and it was silent. One product's entry claimed that
    file for macOS alone, so on Windows and on Linux it was never collected, the store
    arrived with nothing that could attribute its rows, and the collection reported success.
    So: any entry that claims a state store under a per-workspace directory has to claim the
    neighbour for every spelling of it, per operating system prefix.
    """
    catalogue = load_catalogue(CATALOG_DIR)
    missing: dict[str, list[str]] = {}
    for artifact in catalogue.artifacts:
        for path in artifact.paths:
            normalised = path.replace("\\", "/")
            if "workspaceStorage/" not in normalised or not normalised.endswith("state.vscdb"):
                continue
            directory = normalised.rsplit("/", 1)[0]
            wanted = f"{directory}/workspace.json"
            claimed = {other.replace("\\", "/") for other in artifact.paths}
            if wanted not in claimed:
                missing.setdefault(artifact.id, []).append(path)

    assert not missing, (
        "these per-workspace stores would be collected without the file that says which "
        "folder they belong to, so every row of them arrives unattributed and nothing in "
        f"the case says why: {missing}"
    )


def test_no_path_has_a_doubled_separator() -> None:
    """A doubled separator survives into a collection rule and matches nothing there.

    It reads as a typo and is not one, because the two halves of this suite disagree about
    it. The matcher and both collectors normalise a path before using it, so a doubled
    separator costs nothing there and a catalogue entry carrying one looks fine in every
    test that reads the catalogue. One of the generated exporters does not normalise: it
    writes the path into its query as it stands, and a glob with an empty segment in it
    matches no file on any endpoint.

    That is how three of one agent's workflow artifacts came to be uncollectable by one of
    the five exporters while being collectable by the other four, for as long as nobody
    read the generated file. The cause was a YAML string written with escaped backslashes
    where its neighbours use plain ones.
    """
    catalogue = load_catalogue(CATALOG_DIR)
    doubled = {
        artifact.id: [path for path in artifact.paths if "//" in path or "\\\\" in path]
        for artifact in catalogue.artifacts
    }
    found = {name: paths for name, paths in doubled.items() if paths}
    assert not found, (
        "these paths carry a doubled separator, which the matcher and the collectors "
        "normalise away and at least one exporter does not, so the entry is collectable "
        f"by some of this suite and by none of the rest: {found}"
    )


# Paths two entries both claim, where the two are read by different readers. The winner is
# decided by the matcher, so the reader a path gets is not the one its own entry names, and
# four catalogue defects of exactly this shape were found and fixed in one pass: a settings
# file read as prose because an instruction entry claimed it and was the more literal claim,
# a server directory read the same way, an editor-wide extension index attributed to one
# vendor, and a settings file inside an entry about state stores.
#
# These four are not that. Each is a path two entries can legitimately want, and in each the
# reader that wins is the right one or costs nothing. They are written down so that a fifth
# has to be argued for rather than appearing.
SHARED_WITH_DIFFERENT_READERS = {
    "~/.bashrc": "the shell profile. One entry wants the relocation variables out of it and "
    "the other wants everything a profile says about an agent; the second wins and its "
    "reader finds the variables too, which is why the relocation rule fires on this file in "
    "the synthetic profile",
    "~/.zshrc": "the same file under the other shell",
    "~/.claude/feedback/drafts": "one entry claims the directory and has no reader, the "
    "other claims what is in it and reads it as the JSON it is. The directory claim wins "
    "the attribution and the ingest then hands the file to the claimant that can read it",
    "~/.local/bin": "two installers put their shims in the same directory, which is a fact "
    "about the directory rather than a defect in either entry",
}


def test_a_path_two_entries_read_differently_is_one_somebody_argued_for() -> None:
    """Which reader a file gets is decided by the matcher, not by the entry that declares it.

    So an entry can name a reader, have its path won by a different entry, and be read by
    something else entirely, with every test that reads the catalogue passing: the parser
    field test asks what reads an id, and this is about what reads a path.

    That gap cost four entries at once. The most expensive was a settings file holding the
    permissions, the server list and the model endpoint, claimed by an instruction entry
    that was the more literal claim, so it reached a case as prose and as no configuration
    snapshot, and the rules that read a configuration could not fire on it.
    """
    catalogue = load_catalogue(CATALOG_DIR)
    claims: dict[str, set[str]] = {}
    for artifact in catalogue.artifacts:
        for path in artifact.paths:
            claims.setdefault(path.replace("\\", "/").rstrip("/").lower(), set()).add(artifact.id)

    contested = {}
    for path, ids in claims.items():
        if len(ids) < 2:
            continue
        readers = {getattr(for_artifact(name), "name", None) for name in ids}
        if len(readers) > 1:
            contested[path] = (sorted(ids), sorted(str(r) for r in readers))

    assert set(contested) == set(SHARED_WITH_DIFFERENT_READERS), (
        "a path claimed by two entries that read it differently gets whichever reader the "
        "matcher hands it, which is not necessarily the one its own entry names: "
        f"{ {k: v for k, v in contested.items() if k not in SHARED_WITH_DIFFERENT_READERS} }"
    )
    for path, reason in SHARED_WITH_DIFFERENT_READERS.items():
        assert reason.strip(), f"{path} is declared with no reason given"


# Artifacts no reading of a directory tree can attribute, with why. Both are properties of
# the artifact rather than defects, and both cost something an analyst should be told: in a
# bundle the collector wrote the attribution into the manifest, and in a tree or a mounted
# image the file is collected and reported as claimed by nothing.
UNMATCHABLE = {
    "goose.recipes": "any file of one extension in the working copy, which is what the "
    "product means and is unusable without knowing where the working copies are. The "
    "collector knows, out of the agent's own state; the matcher does not, and refuses it "
    "rather than claiming every file of that extension on the disk",
    "kiro.acp_wire_record": "a path that is a variable and nothing else, so there is no "
    "part of it to match on. The product writes the file only where somebody names it",
}


def test_an_artifact_a_tree_can_never_attribute_is_one_somebody_argued_for() -> None:
    """Two readings of the same collection do not agree about these, and that is the point.

    A native bundle carries an attribution per file, written by the collector, which knew
    where the working copies were and what the environment held. A directory tree or a
    mounted image carries neither, so the matcher is all there is, and an entry it can never
    act on is an entry that exists for one of the two readings.

    Both of these are defensible and both are surprising, which is why they are written down
    here and said in the entries themselves. A third would need the same.
    """
    catalogue = load_catalogue(CATALOG_DIR)
    unmatchable = {
        artifact.id
        for artifact in catalogue.artifacts
        if artifact.root != "registry"
        and not any(_pattern_regexes(path) for path in artifact.paths)
    }
    assert unmatchable == set(UNMATCHABLE), (
        "an entry no reading of a directory tree can attribute is one an analyst meets as a "
        "file claimed by nothing, so it has to be argued for rather than appear: "
        f"{sorted(unmatchable - set(UNMATCHABLE))}"
    )
    for name, reason in UNMATCHABLE.items():
        assert reason.strip(), f"{name} is declared with no reason given"
