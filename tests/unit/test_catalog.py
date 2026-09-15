"""Tests for the artifact catalogue and its loader.

Most of these assert invariants on the real committed catalogue rather than on a fixture.
That is deliberate: the catalogue is data, and the failures worth catching are wrong data,
not a broken parser. A path that is plausible but unsourced, or a transcript marked in a
way that stops the collector copying it, is the kind of defect that produces a confident
wrong answer in an investigation, and no amount of unit testing the loader would find it.
"""

from __future__ import annotations

import importlib.util
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

CATALOG_DIR = Path(__file__).resolve().parents[2] / "catalog"


def normalise_path(path: str) -> str:
    """One spelling for a path, so two artifacts claiming the same file compare equal.

    Separators, the profile placeholders and variable segments all vary between entries
    for the same file, and a comparison that missed that would let the conflict this
    module tests for slip through.
    """
    text = path.lower().replace("\\", "/")
    text = re.sub(r"^(%userprofile%|%appdata%|%localappdata%|\$[a-z_]+|~)", "~", text)
    return re.sub(r"<[^>]+>", "*", text).rstrip("/")


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
        joined = " ".join(artifact.paths)
        if "<vscode-user>" in joined:
            continue
        # ~ for the profile, $XDG_* for the freedesktop directories, or an absolute path.
        assert re.search(r"(^|\s)~|\$XDG_[A-Z_]+|(^|\s)/", joined), artifact.id


def test_every_artifact_resolves_to_at_least_one_pattern_per_declared_os(
    catalogue: Catalogue,
) -> None:
    """Run the collector's own expansion, rather than trusting a regex about it.

    The two checks above look at the catalogue text. This one imports the collector and
    asks it what it would actually search, which is the only thing that decides whether an
    artifact can be found. A placeholder nobody taught the collector about expands to a
    bare wildcard or to nothing, and either way the evidence is missing with no error.
    """
    collect = _load_collector()
    homes = {"linux": "/home/alice", "macos": "/Users/alice", "windows": "C:/Users/alice"}
    for agent in collect.EMBEDDED_CATALOGUE["agents"]:
        for entry in agent["artifacts"]:
            if entry.get("root") == "registry":
                # A registry key is not a filesystem path. collect.ps1 reads these; the
                # POSIX collector has nothing to expand and correctly resolves nothing.
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
