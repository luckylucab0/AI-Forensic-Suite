"""The Windows application-data roots, from the catalogue pattern to an event in a case.

134 catalogue paths hang off %APPDATA% and %LOCALAPPDATA%, and until this module no test
followed one of them all the way through. The expansion of the two variables was unit
tested, which is a different thing: between an expanded pattern and an event sit the glob,
the claim order, the bundle path mapping for a path with a drive letter in it, and a parser
reading a file that arrived by a Windows path. Four links, none of them exercised together.

That matters more here than it would elsewhere because every Windows defect this project
has had was silent. A collection that finds nothing looks exactly like a host where the
agent was never installed, and the analyst reading the case concludes the second. So the
tree these tests run against is a Windows profile with agent data at the locations the
catalogue declares for Windows, and the assertions are about what comes out the far end.

The tree deliberately holds the same bytes as the POSIX fixture wherever an agent appears
in both, so the last test here can compare the two readings and attribute any difference to
the path rather than to the content.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from agentforensics.catalog import Catalogue, load_catalogue
from agentforensics.ingest import ingest
from agentforensics.ingest.match import Matcher
from agentforensics.model import Case

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tests" / "fixtures"))

from generate import (  # noqa: E402
    WINDOWS_ARTIFACTS,
    build_home,
    build_windows_home,
)


def _load_collector() -> Any:
    """The collector as a module. It is a single file outside the package on purpose."""
    spec = importlib.util.spec_from_file_location(
        "collect_under_test", REPO_ROOT / "collector" / "collect.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def catalogue() -> Catalogue:
    return load_catalogue(REPO_ROOT / "catalog")


@pytest.fixture(scope="module")
def windows_image(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A mounted Windows image holding one profile, as --root expects to find it."""
    root = tmp_path_factory.mktemp("windows-image")
    build_windows_home(root / "Users" / "alice")
    return root


@pytest.fixture(scope="module")
def windows_bundle(windows_image: Path, tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("windows-bundles") / "case-windows"
    collect = _load_collector()
    code = collect.main(["--out", str(out), "--root", str(windows_image), "--os", "windows"])
    assert code == collect.EXIT_OK, f"the collection failed with {code}"
    return out


@pytest.fixture(scope="module")
def windows_manifest(windows_bundle: Path) -> dict[str, Any]:
    return json.loads((windows_bundle / "manifest.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def windows_case(
    windows_bundle: Path, catalogue: Catalogue, tmp_path_factory: pytest.TempPathFactory
) -> list[dict[str, Any]]:
    """Every event the analyzer made of the Windows bundle, as plain dictionaries."""
    path = tmp_path_factory.mktemp("windows-case") / "case.sqlite"
    with Case.open(path) as case:
        report = ingest(case, windows_bundle, catalogue)
        assert report.unclaimed_paths == [], (
            "a collected file that no catalogue entry claims is a file the case cannot "
            f"attribute to an agent: {report.unclaimed_paths}"
        )
        return [dict(row) for row in case.query("SELECT * FROM events ORDER BY event_id")]


# ------------------------------------------------------------------- the collection


def test_the_fixture_writes_only_files_the_catalogue_claims(
    windows_image: Path, catalogue: Catalogue
) -> None:
    """Every file in the tree is reached by a Windows pattern, and by the declared entry.

    Without this the fixture could drift into decoration: a file nothing claims proves
    nothing about the catalogue, and a file claimed by a different entry than intended
    would make the tests below pass while testing something else.

    The path is spelled the way a live host would report it rather than as it sits in the
    image, because that is the string the matcher sees in a real case.
    """
    matcher = Matcher(catalogue)
    profile = windows_image / "Users" / "alice"
    for path in sorted(windows_image.rglob("*")):
        if not path.is_file():
            continue
        on_endpoint = "C:/Users/alice/" + path.relative_to(profile).as_posix()
        best = matcher.best(on_endpoint)
        assert best is not None, f"nothing in the catalogue claims {on_endpoint}"
        assert best.artifact.id in WINDOWS_ARTIFACTS, (
            f"{on_endpoint} is claimed by {best.artifact.id}, which the fixture does not "
            "declare. Either the claim order changed or the fixture grew a file nobody "
            "named."
        )


def test_the_collection_reaches_every_declared_application_data_artifact(
    windows_manifest: dict[str, Any],
) -> None:
    """The check the 134 paths never had: they collect.

    An artifact missing here is the silent failure this tool exists to avoid. It does not
    raise, it does not warn, and the bundle it produces verifies; the only symptom is a
    case in which that agent was never used.
    """
    found = {entry["artifact_id"] for entry in windows_manifest["files"]}
    missing = set(WINDOWS_ARTIFACTS) - found
    assert not missing, (
        f"{sorted(missing)} is in the fixture and not in the bundle, so the Windows "
        "pattern for it collected nothing"
    )


def test_a_path_under_the_roaming_data_keeps_its_windows_spelling(
    windows_manifest: dict[str, Any],
) -> None:
    """original_path is the endpoint's own spelling, which is what a path map is read by.

    A collection of an image reports the path inside the image, so what is checked here is
    that the application-data segments survive the round trip rather than being folded into
    a profile-relative name that no analyst could match against a host.
    """
    paths = [entry["original_path"] for entry in windows_manifest["files"]]
    assert any("AppData/Roaming/Block/goose/config" in path for path in paths)
    assert any("AppData/Local/Zed/threads/threads.db" in path for path in paths)


def test_a_credential_under_the_roaming_data_is_recorded_and_not_copied(
    windows_manifest: dict[str, Any], windows_bundle: Path
) -> None:
    """The withholding rule, on a Windows path rather than only on a POSIX one.

    The rule is about the catalogue's sensitivity field and not about the platform, which
    is exactly why it is worth asserting here: a defect in the Windows branch of the path
    handling could copy the bytes of a credential file while the POSIX tests stayed green.
    """
    entry = next(e for e in windows_manifest["files"] if e["artifact_id"] == "goose.secrets")
    assert entry["collected"] is False
    assert entry["reason"] == "secret_policy"
    assert entry["sha256"], "the hash is still recorded: the file existed and that is evidence"
    assert not list((windows_bundle / "files").rglob("secrets.yaml"))


def test_a_directory_claim_does_not_take_the_file_from_its_own_entry(
    windows_manifest: dict[str, Any],
) -> None:
    """%APPDATA%\\ itself is a catalogue entry, and it must not win over a specific one.

    The broad entry exists so that an agent nobody catalogued still leaves a trace, which
    means it claims every file in the tree. If it won the claim order, every Windows file
    would be attributed to it, no parser would read any of them, and the case would hold a
    heap of unattributed files instead of a conversation.
    """
    task = next(
        e for e in windows_manifest["files"] if e["original_path"].endswith("ui_messages.json")
    )
    assert task["artifact_id"] == "kilo_code.extension_id_legacy_tree"
    assert "crosscutting.windows_appdata_program_dirs" in task["artifact_ids"], (
        "the broad claim is still reported, because a second claim on a path is evidence "
        "about what else would have collected it"
    )


# ---------------------------------------------------------------------- the reading


def test_the_analyzer_reads_what_the_windows_collection_returned(
    windows_case: list[dict[str, Any]],
) -> None:
    """The far end of the chain: turns in a case, from files found by Windows patterns."""
    kinds = {(row["agent"], row["kind"]) for row in windows_case}
    assert ("kilo_code", "user.prompt") in kinds
    assert ("kilo_code", "command.exec") in kinds
    assert ("zed", "user.prompt") in kinds


def test_a_compressed_store_under_the_local_data_root_is_read_rather_than_recorded(
    windows_case: list[dict[str, Any]],
) -> None:
    """The one store in the fixture whose content is invisible to every other tool.

    Zed keeps each thread as a zstd frame in a BLOB column, so a reader that stopped at the
    column would leave a case saying the agent held some opaque blobs, which reads as an
    agent that was installed and never used. The text has to come out.
    """
    texts = [
        json.loads(row["payload"]).get("text")
        for row in windows_case
        if row["agent"] == "zed" and row["kind"] in ("user.prompt", "assistant.text")
    ]
    assert "why is the pipeline red" in texts
    assert "the lockfile is stale" in texts


def test_the_editors_state_store_is_read_by_the_key_it_is_stored_under(
    windows_case: list[dict[str, Any]],
) -> None:
    """The one file five catalogue entries across three products are, read where it lives.

    A key/value store is searched by its key, so the key has to be a field of the event and
    not something inside raw. This is the end-to-end half of that: the store is found by a
    Windows application-data pattern, collected, matched to its entry, and read by the
    parser that has the vendor's schema.
    """
    keys = [
        json.loads(row["payload"]).get("key")
        for row in windows_case
        if row["artifact_id"] == "vscode.state_vscdb" and row["kind"] == "config.snapshot"
    ]
    assert "extensionIdentifiers/enabled" in keys
    assert "aiService.prompts" in keys


def test_the_electron_key_value_store_gives_up_its_records(
    windows_case: list[dict[str, Any]],
) -> None:
    """The store an Electron agent's window keeps its state in, read key by key.

    Its files are a browser engine's own format, so before the reader for it a collection
    of this directory reached a case as four file names and nothing else. Two things are
    asserted: that the records are there, and that the one in the write-ahead log is among
    them. The log is where a running application's newest writes sit until a compaction
    folds them into a table, so a reader that took only the tables would return a store's
    whole history except the part of it that happened last.
    """
    texts = [
        json.loads(row["payload"]).get("text", "")
        for row in windows_case
        if row["artifact_id"] == "claude_desktop.renderer_state"
    ]
    # The folder the user pointed the agent at, which the vendor's description of this
    # store as UI state understates, written the way this store writes a string: behind an
    # encoding tag, in sixteen bit units.
    assert any("recentFolders" in text for text in texts)
    assert any("lastProject" in text and "C:/Users/alice/src/app" in text for text in texts)


def test_a_file_with_no_parser_is_carried_rather_than_dropped(
    windows_case: list[dict[str, Any]],
) -> None:
    """Three of the six artifacts have no parser, and a case must still say they were there.

    A shell history is the evidence that a CLI agent was invoked at all. Recording the file
    and no event for it is honest; leaving it out of the case is the failure this project
    calls never hiding a record.
    """
    paths = [row["original_path"] for row in windows_case if row["kind"] == "artifact.fs"]
    assert any("ConsoleHost_history.txt" in (path or "") for path in paths)
    assert any("config.yaml" in (path or "") for path in paths)


# ------------------------------------------------------------------ the differential


# The two catalogue entries that hold the same task, one per location. One extension id per
# entry is how the catalogue records these, and one parser reads all of them, so the entry
# and the agent differ between the trees while the content does not.
_TASK_ENTRIES = {"cline.vscode_task_transcripts", "kilo_code.extension_id_legacy_tree"}


def _comparable(rows: list[dict[str, Any]]) -> list[tuple[str, str]]:
    """The task's events as (kind, payload), with everything path-derived left out.

    The agent id, the artifact id, the provenance and the event id all encode where the
    file was, and here the whole point is that the file was in two different places. What
    must not differ is the reading. artifact.fs is the filesystem record of the file
    itself, which is nothing but where it was.
    """
    out = []
    for row in rows:
        if row["artifact_id"] not in _TASK_ENTRIES or row["kind"] == "artifact.fs":
            continue
        out.append((row["kind"], row["payload"]))
    return sorted(out)


def test_the_same_task_reads_the_same_from_both_shapes(
    windows_case: list[dict[str, Any]], catalogue: Catalogue, tmp_path: Path
) -> None:
    """One task, the same bytes, at the POSIX location and at the Windows one.

    This is the differential the two collectors already have, moved one stage later: two
    readings of one content, where only the path differs. A parser that derived anything
    from the shape of the path would show up here as a difference in the events, and
    nowhere else, because each reading on its own is self-consistent.

    The catalogue entry differs between the trees (one editor extension id per entry, one
    parser for all of them) and the agent with it, so the agent is not compared. Everything
    a reader of the case would quote is.
    """
    posix_home = tmp_path / "home"
    build_home(posix_home, with_edge_cases=False)
    out = tmp_path / "posix-bundle"
    collect = _load_collector()
    assert collect.main(["--out", str(out), "--root", str(posix_home), "--os", "linux"]) in (
        collect.EXIT_OK,
        collect.EXIT_ERRORS,
    )
    with Case.open(tmp_path / "posix-case.sqlite") as case:
        ingest(case, out, catalogue)
        posix_rows = [dict(row) for row in case.query("SELECT * FROM events")]

    posix = _comparable(posix_rows)
    windows = _comparable(windows_case)
    assert posix, "the POSIX fixture's task produced no events, so there is nothing to compare"
    assert windows == posix, (
        "the same task read differently depending on where it was found.\n"
        f"only windows={[e for e in windows if e not in posix]}\n"
        f"only posix={[e for e in posix if e not in windows]}"
    )


def test_the_fixture_declares_why_each_artifact_is_in_it() -> None:
    """The fixture names its own coverage, so a gap is a sentence rather than an absence.

    Eleven artifacts, ten of them under the two application-data roots out of the
    eighty-four the catalogue has there, and one under the profile's Documents folder as
    OneDrive's Known Folder Move leaves it. The number is not the point and raising it is
    not automatically an improvement: what this pins is that the chain works for every
    shape in the fixture, and that somebody said out loud which shapes those are.
    """
    assert set(WINDOWS_ARTIFACTS) == {
        "claude_code.mcp_logs",
        "claude_desktop.renderer_state",
        "crosscutting.instructions_clinerules",
        "crosscutting.shell_psreadline_history",
        "cursor.workspace_state_vscdb",
        "goose.config",
        "goose.secrets",
        "kilo_code.extension_id_legacy_tree",
        "vscode.state_vscdb",
        "windsurf.ide_workspace_state_vscdb",
        "zed.threads_db",
    }
    for artifact, reason in WINDOWS_ARTIFACTS.items():
        assert reason.strip(), f"{artifact} is in the fixture with no reason given"


def test_the_subprocess_route_agrees_with_the_in_process_one(
    windows_image: Path, windows_manifest: dict[str, Any], tmp_path: Path
) -> None:
    """The collector is a script before it is a module, and that is how it is deployed.

    Importing it gives the tests above a fast path; what gets pushed through live-response
    tooling is the file, run by an interpreter that is not this one. The two have differed
    before, over a global set at import time, so the file is run once here as itself.
    """
    out = tmp_path / "subprocess-bundle"
    result = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "collector" / "collect.py"),
            "--out",
            str(out),
            "--root",
            str(windows_image),
            "--os",
            "windows",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert {e["original_path"] for e in manifest["files"]} == {
        e["original_path"] for e in windows_manifest["files"]
    }
