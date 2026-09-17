"""Tests for the ingest adapters and the catalogue path matcher.

The matcher is where a wrong answer is cheapest to produce and most expensive to notice: it
decides which catalogue entry claims a file, and therefore which parser reads it and which
agent a finding is attributed to. Most of what follows is about the two ways it can be
wrong, claiming a file it should not and failing to claim one it should, with the
false-claim cases first because those are the ones that look like success.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from agentforensics.catalog import Catalogue, load_catalogue
from agentforensics.ingest import detect, ingest
from agentforensics.ingest.match import Matcher
from agentforensics.ingest.tree import CollectedTree, _is_profile_root
from agentforensics.model import Case

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def catalogue() -> Catalogue:
    return load_catalogue(REPO_ROOT / "catalog")


@pytest.fixture(scope="module")
def matcher(catalogue: Catalogue) -> Matcher:
    return Matcher(catalogue)


def ids(matcher: Matcher, path: str) -> list[str]:
    return [match.artifact.id for match in matcher.matches(path)]


def test_a_transcript_is_attributed_to_its_agent(matcher: Matcher) -> None:
    best = matcher.best("/home/alice/.claude/projects/-home-alice-src-app/9f2e.jsonl")
    assert best is not None
    assert best.artifact.id == "claude_code.transcripts"


def test_a_more_specific_claim_wins(matcher: Matcher) -> None:
    """A file is claimed by its own entry, not by the directory entry above it.

    Both claims are real and both are reported; which one the file is attributed to decides
    which parser reads it, so the specific one has to come first.
    """
    path = (
        "C:/Users/alice/AppData/Roaming/Code/User/globalStorage/"
        "saoudrizwan.claude-dev/tasks/42/ui_messages.json"
    )
    found = ids(matcher, path)
    assert found[0] == "cline.vscode_task_transcripts"
    assert "vscode.user_data_roots" in found, "the directory-level claim is still reported"


def test_a_relocated_tree_does_not_claim_every_file(matcher: Matcher) -> None:
    """The regression this check exists for.

    A pattern rooted at a relocation variable can only be matched at any location, and the
    first version of that turned `$VAR/**/*.jsonl` into a claim on every line-delimited
    transcript on the disk. Four agents were credited with each other's transcripts, which
    is a wrong answer that looks exactly like a right one.
    """
    found = ids(matcher, "/home/alice/.claude/projects/-src-app/9f2e.jsonl")
    assert found == ["claude_code.transcripts"], found


def test_an_unrelated_file_is_claimed_by_nothing(matcher: Matcher) -> None:
    assert ids(matcher, "/home/alice/src/app/README.md") == []
    assert ids(matcher, "/home/alice/holiday-photos/beach.jpg") == []


def test_a_windows_machine_wide_path_is_matched(matcher: Matcher) -> None:
    """Written with a drive letter in the catalogue, which produced no pattern at all
    until this was noticed: every machine-wide Windows entry matched nothing in a tree."""
    found = ids(matcher, "C:/ProgramData/Claude/Logs/coworkd/user-1.log")
    assert "claude_desktop.coworkd_service_log" in found


def test_a_drive_other_than_c_still_matches(matcher: Matcher) -> None:
    """An endpoint whose system volume is not C: is still that endpoint."""
    assert ids(matcher, "D:/ProgramData/Claude/Logs/coworkd/user-1.log")


def test_a_trailing_double_wildcard_matches_files_not_just_directories(
    matcher: Matcher,
) -> None:
    """`cli-checkouts/<id>/**` means the repository and its contents.

    Written as an intermediate wildcard it matched the directory and none of the files in
    it, which is the entire content of the artifact.
    """
    found = ids(matcher, "/home/alice/.aws/amazonq/cli-checkouts/conv-1/refs/heads/main")
    assert "amazonq.cli_checkpoints" in found


def test_a_project_instruction_file_is_matched(matcher: Matcher) -> None:
    """Project-anchored patterns are the injected-instruction evidence.

    Their location comes from the agent's own state file, which a tree does not have, so
    they are matched at any depth. Leaving them out meant an ingest attributed a
    developer's agent configuration and none of the files that told the agent what to do.
    """
    found = ids(matcher, "/home/alice/src/app/.claude/rules/style.md")
    assert found, "a project rule file should be claimed by something"
    assert any(entry.startswith(("claude_code.", "crosscutting.")) for entry in found)


def test_a_profile_relative_path_is_matched(matcher: Matcher) -> None:
    """An exported profile is one of the four sources, and its paths have no profile above."""
    assert "claude_code.transcripts" in ids(matcher, "~/.claude/projects/-src-app/9f2e.jsonl")


def test_a_literal_dot_in_a_pattern_is_not_a_wildcard(matcher: Matcher) -> None:
    """Escaping matters: an unescaped dot in one agent's filename would start claiming
    another agent's files whose names differ by one character."""
    assert "claude_code.global_config" in ids(matcher, "/home/alice/.claude.json")
    assert "claude_code.global_config" not in ids(matcher, "/home/alice/.claudeXjson")


def test_matching_is_stable(matcher: Matcher) -> None:
    path = "/home/alice/.claude/projects/-src-app/9f2e.jsonl"
    assert matcher.matches(path) == matcher.matches(path)


# ------------------------------------------------------------------ the adapters


def write_tree(root: Path) -> None:
    """A minimal profile: one transcript, one config, one file nothing claims."""
    (root / ".claude" / "projects" / "-src-app").mkdir(parents=True)
    (root / ".claude" / "projects" / "-src-app" / "s1.jsonl").write_text(
        '{"type":"user","message":{"role":"user","content":"hi"}}\n', encoding="utf-8"
    )
    (root / ".claude.json").write_text('{"projects":{}}', encoding="utf-8")
    (root / ".config").mkdir()
    (root / "notes.txt").write_text("not evidence", encoding="utf-8")


def test_a_profile_root_is_recognised(tmp_path: Path) -> None:
    profile = tmp_path / "alice"
    profile.mkdir()
    write_tree(profile)
    assert _is_profile_root(profile)

    filesystem = tmp_path / "image"
    (filesystem / "home" / "alice").mkdir(parents=True)
    (filesystem / "etc").mkdir()
    assert not _is_profile_root(filesystem)


def test_a_profile_rooted_tree_keeps_its_paths_relative(
    tmp_path: Path, catalogue: Catalogue
) -> None:
    """Presenting a profile's contents as absolute would assert a filesystem root that is
    not there, and then nothing would match."""
    profile = tmp_path / "alice"
    profile.mkdir()
    write_tree(profile)
    tree = CollectedTree(profile, Matcher(catalogue))
    paths = {entry.original_path for entry in tree.entries()}
    assert "~/.claude.json" in paths
    assert any(p.startswith("~/.claude/projects/") for p in paths)


def test_a_tree_ingest_attributes_what_it_can_and_reports_the_rest(
    tmp_path: Path, catalogue: Catalogue
) -> None:
    profile = tmp_path / "alice"
    profile.mkdir()
    write_tree(profile)
    with Case.open(tmp_path / "case.sqlite") as case:
        report = ingest(case, profile, catalogue)
    assert report.attributed_by_path >= 2
    assert "~/notes.txt" in report.unclaimed_paths, (
        "a file nothing claims is a lead and has to be named, not counted away"
    )
    assert report.attributed_by_collector == 0, "a tree has no collector to attribute to"


def test_a_tree_ingest_records_that_it_had_no_manifest(
    tmp_path: Path, catalogue: Catalogue
) -> None:
    """Every attribution from a tree is an inference, and the case has to say so."""
    profile = tmp_path / "alice"
    profile.mkdir()
    write_tree(profile)
    with Case.open(tmp_path / "case.sqlite") as case:
        ingest(case, profile, catalogue)
        kinds = {row["kind"] for row in case.query("SELECT kind FROM collection_gaps")}
    assert "no_manifest" in kinds
    assert "profile_root" in kinds


def test_a_native_bundle_is_preferred_over_a_tree_reading(
    tmp_path: Path, catalogue: Catalogue
) -> None:
    """A manifest is the only record of what the endpoint knew.

    Reading a native bundle as a plain tree would replace the collector's own attribution,
    hashes and timestamps with guesses made afterwards.
    """
    bundle = tmp_path / "bundle"
    (bundle / "files" / "home" / "alice" / ".claude").mkdir(parents=True)
    target = bundle / "files" / "home" / "alice" / ".claude" / "settings.json"
    target.write_text("{}", encoding="utf-8")
    (bundle / "manifest.json").write_text(
        json.dumps(
            {
                "format_version": 1,
                "collection": {"uuid": "u-9", "os": "linux", "hostname": "vm"},
                "tool": {"name": "collect.py", "version": "0"},
                "files": [
                    {
                        "original_path": "/home/alice/.claude/settings.json",
                        "bundle_path": "files/home/alice/.claude/settings.json",
                        "sha256": "deadbeef",
                        "size": 2,
                        "agent": "claude_code",
                        "artifact_id": "claude_code.user_settings",
                        "category": "config",
                        "status": "verified",
                        "collected": True,
                        "user": "alice",
                        "mtime_utc": "2026-09-07T00:00:00.000000Z",
                    }
                ],
                "refused_patterns": [{"pattern": "$CLAUDE_CONFIG_DIR/*", "reason": "unset"}],
            }
        ),
        encoding="utf-8",
    )
    assert detect(bundle) == "native"
    with Case.open(tmp_path / "case.sqlite") as case:
        report = ingest(case, bundle, catalogue)
        row = case.query("SELECT sha256, status FROM artifacts")[0]
        bundle_row = case.query("SELECT manifest_sha256 FROM bundles")[0]
    assert report.attributed_by_collector == 1
    assert report.attributed_by_path == 0
    assert row["sha256"] == "deadbeef", "the manifest's hash, not one recomputed here"
    assert report.gaps >= 1, "a refused glob is a hole in the evidence and belongs in the case"
    # The manifest cannot state its own hash, so it has to be computed from the bytes in
    # hand. Without this the column was always null and a case could not be checked against
    # the bundle it came from: the custody records commit to exactly this value.
    expected = hashlib.sha256((bundle / "manifest.json").read_bytes()).hexdigest()
    assert bundle_row["manifest_sha256"] == expected


def test_an_artifact_row_exists_even_when_nothing_was_collected(
    tmp_path: Path, catalogue: Catalogue
) -> None:
    """The difference between no events from an agent and nothing collected from it.

    Those are opposite conclusions, and a case that only recorded the files it parsed could
    not tell them apart.
    """
    bundle = tmp_path / "bundle"
    (bundle / "files").mkdir(parents=True)
    (bundle / "manifest.json").write_text(
        json.dumps(
            {
                "format_version": 1,
                "collection": {"uuid": "u-8"},
                "files": [
                    {
                        "original_path": "/home/alice/.claude/.credentials.json",
                        "sha256": "aa",
                        "collected": False,
                        "reason": "credential store: metadata and hash only",
                        "agent": "claude_code",
                        "artifact_id": "claude_code.credentials",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    with Case.open(tmp_path / "case.sqlite") as case:
        ingest(case, bundle, catalogue)
        row = case.query("SELECT collected, reason, parse_status FROM artifacts")[0]
    assert row["collected"] == 0
    assert "credential" in row["reason"]
    assert row["parse_status"] == "skipped"


def test_a_filesystem_event_exists_for_every_collected_file(
    tmp_path: Path, catalogue: Catalogue
) -> None:
    """Some artifacts carry no internal timestamps at all.

    For those the only temporal evidence is when the file was written, so without this kind
    the instruction files and the configuration snapshots would be missing from every
    timeline and an analyst would read a gap where there was evidence.
    """
    profile = tmp_path / "alice"
    profile.mkdir()
    write_tree(profile)
    with Case.open(tmp_path / "case.sqlite") as case:
        ingest(case, profile, catalogue)
        rows = case.query(
            "SELECT count(*) AS n FROM events WHERE kind = 'artifact.fs' AND ts_utc IS NOT NULL"
        )
    assert rows[0]["n"] >= 3


def test_re_ingesting_a_tree_does_not_double_the_case(tmp_path: Path, catalogue: Catalogue) -> None:
    """Which is why a tree's bundle id is derived from its path, not generated."""
    profile = tmp_path / "alice"
    profile.mkdir()
    write_tree(profile)
    with Case.open(tmp_path / "case.sqlite") as case:
        first = ingest(case, profile, catalogue)
        before = case.counts()["events"]
        second = ingest(case, profile, catalogue)
        after = case.counts()["events"]
    assert first.bundle_uuid == second.bundle_uuid
    assert before == after
