"""Tests for the collection-rule exporters.

The interesting failure here is not a crash. It is a generated rule that is syntactically
fine, runs without error and searches the wrong place, or silently searches nothing. Most
of what follows asserts the property that guards against that: every catalogue artifact is
either covered by a target or listed in that target's header with a reason, and never
neither.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml

from agentforensics.catalog import Catalogue, load_catalogue
from agentforensics.exporters import FORMATS, render
from agentforensics.exporters.common import bare_variable, iter_paths

REPO_ROOT = Path(__file__).resolve().parents[2]
CATALOG_DIR = REPO_ROOT / "catalog"
GENERATED = REPO_ROOT / "exporters" / "generated"


@pytest.fixture(scope="module")
def catalogue() -> Catalogue:
    return load_catalogue(CATALOG_DIR)


@pytest.fixture(scope="module")
def rendered(catalogue: Catalogue) -> list:
    return render(catalogue)


def test_every_format_produces_at_least_one_file(catalogue: Catalogue) -> None:
    for name, renderer in sorted(FORMATS.items()):
        out = renderer(catalogue)
        assert out, name
        for item in out:
            assert item.text.endswith("\n"), f"{name}: {item.path} does not end in a newline"
            assert item.path.startswith(f"{name}/"), f"{name}: {item.path} is in the wrong folder"


def test_rendering_twice_produces_identical_bytes(catalogue: Catalogue) -> None:
    """Determinism is not a nicety here: the committed copy is compared byte for byte.

    A dict iteration order or an unsorted set anywhere in an exporter would make the
    staleness check fail at random, which would teach everyone to ignore it.
    """
    first = {item.path: item.text for item in render(catalogue)}
    second = {item.path: item.text for item in render(catalogue)}
    assert first == second


def test_every_artifact_is_covered_or_declared(catalogue: Catalogue, rendered: list) -> None:
    """The rule this package exists for.

    An exporter may leave an artifact out. It may not leave it out silently: a target with
    a narrower path language than the catalogue has to say so, or the rule reports a clean
    host for a reason nobody can see.
    """
    for name in sorted(FORMATS):
        files = [item for item in rendered if item.path.startswith(f"{name}/")]
        mentioned: set[str] = set()
        for item in files:
            mentioned.update(re.findall(r"\b([a-z][a-z0-9_]*\.[a-z][a-z0-9_]*)\b", item.text))
            mentioned.update(skip.artifact_id for skip in item.skipped)
        # A target that only runs on one platform declares that once, as a count, rather
        # than naming every artifact of the other two. The files say so; see _scope_note.
        windows_only = name in ("kape", "mde")
        missing = sorted(
            artifact.id
            for artifact in catalogue.artifacts
            if artifact.id not in mentioned and not (windows_only and "windows" not in artifact.os)
        )
        if windows_only:
            joined = " ".join(item.text for item in files)
            assert "Windows only" in joined, f"{name} does not state its platform scope"
        assert not missing, (
            f"{name} neither covers nor declares these artifacts, so a rule built from it "
            f"is quietly narrower than the catalogue: {missing[:12]}"
        )


def test_every_skip_has_a_reason(rendered: list) -> None:
    for item in rendered:
        for skip in item.skipped:
            assert skip.artifact_id, item.path
            assert len(skip.reason) > 20, f"{item.path}: {skip.artifact_id} has a stub reason"


def test_every_file_says_an_empty_result_is_not_a_clean_host(rendered: list) -> None:
    """The one sentence that must survive every future edit to these templates.

    Somebody will run one of these rules, get nothing, and write "no agent activity" in a
    report. The file itself has to argue with them.
    """
    for item in rendered:
        assert "does not mean the host is clean" in item.text.replace("\n", " ").replace(
            "  ", " "
        ) or "not mean the host is clean" in item.text.replace("\n", " "), item.path


def test_velociraptor_artifacts_are_valid_yaml(rendered: list) -> None:
    for item in rendered:
        if not item.path.startswith("velociraptor/"):
            continue
        document = yaml.safe_load(item.text)
        assert document["name"].startswith("Custom."), item.path
        assert document["type"] == "CLIENT", item.path
        assert document["sources"], item.path
        for source in document["sources"]:
            assert "query" in source, item.path


def test_velociraptor_globs_match_their_platform(rendered: list) -> None:
    """A Windows glob in the macOS source runs and matches nothing.

    This is the shape of mistake that makes a collection rule look like it worked. The
    catalogue keeps every platform's spelling of a path in one artifact, so an exporter
    that picks wrongly produces exactly this.
    """
    collect = next(item for item in rendered if item.path.endswith(".Collect.yaml"))
    document = yaml.safe_load(collect.text)
    for source in document["sources"]:
        rows = re.findall(r"^[a-z_]+,[a-z_.]+,(.*)$", source["query"], re.M)
        assert rows, source["name"]
        for glob in rows:
            if source["name"] == "windows":
                assert glob.startswith("C:/"), f"{source['name']}: {glob}"
            else:
                assert glob.startswith("/"), f"{source['name']}: {glob}"


def test_osquery_pack_is_valid_json_and_scoped_per_platform(rendered: list) -> None:
    item = next(i for i in rendered if i.path == "osquery/agentforensics.conf")
    pack = json.loads(item.text)
    assert pack["queries"], "the pack has no queries"
    for name, query in sorted(pack["queries"].items()):
        assert query["platform"] in ("windows", "darwin", "linux"), name
        assert query["query"].startswith("SELECT "), name
        assert query["query"].endswith(";"), name
        if query["platform"] == "windows":
            assert "C:\\\\Users" in query["query"] or "C:\\Users" in query["query"], name
        else:
            assert "path LIKE '/" in query["query"], name


def test_kape_targets_have_a_path_and_a_mask(rendered: list) -> None:
    for item in rendered:
        if not item.path.startswith("kape/") or item.path.endswith("AIAgents.tkape"):
            continue
        document = yaml.safe_load(item.text)
        assert document["Targets"], item.path
        for target in document["Targets"]:
            assert target["Path"].startswith(("C:\\", "c:\\")), f"{item.path}: {target['Path']}"
            assert target["FileMask"], f"{item.path}: {target['Name']} has no file mask"


def test_kape_ids_are_stable(catalogue: Catalogue) -> None:
    """Examiners keep target files under version control, so a random id per run would
    make every regeneration a diff nobody can review."""
    first = {i.path: yaml.safe_load(i.text)["Id"] for i in FORMATS["kape"](catalogue)}
    second = {i.path: yaml.safe_load(i.text)["Id"] for i in FORMATS["kape"](catalogue)}
    assert first == second
    assert len(set(first.values())) == len(first), "two target files share an id"


def test_kql_declares_its_retention_limit(rendered: list) -> None:
    """Advanced Hunting answers a narrower question than the others and has to say so."""
    for item in rendered:
        if item.path.startswith("kql/"):
            assert "retention" in item.text, item.path


def test_kql_process_names_are_names(rendered: list) -> None:
    """A query matching a process called %APPDATA% or Packages is worse than no query.

    The first version of the name extraction took the last segment of any install-evidence
    path and produced exactly those, which would have returned noise while looking
    authoritative. Only an executable extension or a bin directory counts now.
    """
    item = next(i for i in rendered if i.path == "kql/agent-process-events.kql")
    block = re.search(r"let AgentBinaries[^[]*\[\n(.*?)\n\];", item.text, re.S)
    assert block, "the process query has no binary table"
    names = re.findall(r'^    "[a-z_]+", "(.*)",$', block.group(1), re.M)
    assert names, "the binary table is empty"
    for name in names:
        assert not re.search(r"[%<>*]", name), f"not a process name: {name}"
        assert name not in ("local", "bin", "Packages"), f"a directory, not a binary: {name}"
    # A one or two character name is kept when it is the vendor's real binary, but the file
    # has to warn about it, because such a match across an estate is not actionable alone.
    for name in names:
        if len(name) <= 2:
            assert "short enough to collide" in item.text, name


def test_the_committed_output_is_current(rendered: list) -> None:
    """The check CI runs, as a test, so a contributor sees it before pushing."""
    stale = []
    for item in rendered:
        target = GENERATED / item.path
        if not target.exists() or target.read_text(encoding="utf-8") != item.text:
            stale.append(item.path)
    expected = {item.path for item in rendered}
    # as_posix, because a generated path is spelled with forward slashes and
    # str(relative_to(...)) uses the platform separator. On Windows every committed file
    # therefore compared unequal to itself and the whole set came back as orphaned.
    orphans = sorted(
        p.relative_to(GENERATED).as_posix()
        for p in GENERATED.rglob("*")
        if p.is_file() and p.relative_to(GENERATED).as_posix() not in expected
    )
    assert not stale and not orphans, (
        "run scripts/gen_collection_rules.py and commit the result. "
        f"stale={stale} no-longer-generated={orphans}"
    )


def test_a_bare_variable_path_is_recognised() -> None:
    assert bare_variable("$KIRO_ACP_RECORD_PATH")
    assert bare_variable("${QWEN_HOME}")
    assert not bare_variable("$XDG_DATA_HOME/opencode/log/")
    assert not bare_variable("~/.claude/projects/")


def test_posix_only_paths_do_not_reach_a_windows_target(catalogue: Catalogue) -> None:
    """A path under a macOS application support directory is not a Windows path.

    The collector expands ~ on Windows too, which makes most tilde paths worth searching
    there. The ones anchored at a POSIX-only directory are not, and a rule padded with them
    looks like it covers more than it does.
    """
    for artifact in catalogue.artifacts:
        if "windows" not in artifact.os:
            continue
        for path in iter_paths(artifact, "windows"):
            lowered = path.lower()
            assert "library/application support" not in lowered, f"{artifact.id}: {path}"
            assert not lowered.startswith("~/.config/"), f"{artifact.id}: {path}"


def test_no_generated_rule_claims_something_else_collects_the_registry(
    catalogue: Catalogue,
) -> None:
    """Six catalogue entries are registry keys and nothing in this suite reads one.

    Each exporter used to explain that in its own words, and each of the three sentences
    sent the reader somewhere: that this Velociraptor artifact reads the key through a
    separate source, which it does not and never did; that it is a KAPE registry target;
    that osquery has a registry table. The last two are true about the tool and were read
    as true about the generated file, which ships no such target and no such query.

    Two of those six entries are the managed policy that says what an agent was allowed to
    do, and on Windows that policy can exist in the registry alone, with no file anywhere.
    A reader who believed any of the three sentences would conclude that no policy was in
    force when the truth is that nobody looked, which is the confusion this project exists
    to prevent. So the rules say it plainly, and this holds them to it.
    """
    rendered = "\n".join(one.text for one in render(catalogue)).lower()
    for claim in (
        "reads through a separate source",
        "which is a kape registry target rather than",
        "which osquery reads through its own registry table",
    ):
        assert claim not in rendered, f"a generated rule still says: {claim}"
    assert "nothing in this suite reads the registry" in rendered


def test_every_registry_entry_is_named_as_uncovered_somewhere(catalogue: Catalogue) -> None:
    """Named rather than merely absent, because an entry nobody mentions reads as an entry
    nobody needed."""
    rendered = "\n".join(one.text for one in render(catalogue))
    keys = [artifact.id for artifact in catalogue.artifacts if artifact.root == "registry"]
    assert len(keys) >= 6
    missing = [key for key in keys if key not in rendered]
    assert not missing, missing
