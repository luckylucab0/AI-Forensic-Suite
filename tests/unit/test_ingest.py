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

from agentforensics.bundle import BundleError
from agentforensics.catalog import Catalogue, load_catalogue
from agentforensics.ingest import detect, ingest
from agentforensics.ingest.ingest import IngestReport
from agentforensics.ingest.match import Matcher
from agentforensics.ingest.native import NativeBundle
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


def test_a_claim_anchored_at_a_known_root_beats_one_that_could_be_anywhere(
    matcher: Matcher,
) -> None:
    """Two claims with the same literal length are not equally specific.

    A placeholder contributes no literal characters, so `~/.claude/CLAUDE.md` and
    `<project>/.claude/CLAUDE.md` both count sixteen. The first names one directory; the
    second compiles to a claim that matches at any depth anywhere on the disk. The tie was
    broken by artifact id, so the user's own instruction file came out as the project entry,
    and scope is exactly what an analyst reads off the instruction surface: a rule that
    applied to every project looked like one that applied to one.
    """
    assert ids(matcher, "~/.claude/CLAUDE.md")[0] == "claude_code.user_claude_md"
    assert ids(matcher, "~/.claude/settings.json")[0] == "claude_code.user_settings"
    # Both entries still claim it, because both do. Only the order changed.
    assert "claude_code.project_claude_md" in ids(matcher, "~/.claude/CLAUDE.md")


def test_a_project_file_still_goes_to_the_project_entry(matcher: Matcher) -> None:
    """The other direction of the same rule, so the fix cannot be a blanket preference for
    the user profile: a file that is genuinely inside a working copy belongs to the project
    entry, which is the only claimant that matches it at all."""
    assert ids(matcher, "~/src/app/CLAUDE.md")[0] == "claude_code.project_claude_md"
    assert ids(matcher, "~/src/app/.claude/CLAUDE.md")[0] == "claude_code.project_claude_md"
    assert (
        ids(matcher, "~/src/app/.claude/settings.local.json")[0]
        == "claude_code.project_settings_local"
    )


def test_a_relocated_tree_does_not_claim_every_file(matcher: Matcher) -> None:
    """The regression this check exists for.

    A pattern rooted at a relocation variable can only be matched at any location, and the
    first version of that turned `$VAR/**/*.jsonl` into a claim on every line-delimited
    transcript on the disk. Four agents were credited with each other's transcripts, which
    is a wrong answer that looks exactly like a right one.
    """
    found = ids(matcher, "/home/alice/.claude/projects/-src-app/9f2e.jsonl")
    assert found == ["claude_code.transcripts"], found


def test_a_project_pattern_that_is_only_an_extension_claims_nothing(matcher: Matcher) -> None:
    """One catalogue entry says a recipe is any yaml file in the working copy, which is
    true and is not something this module can act on.

    The collector knows where the working copies are, out of the agent's own state, so
    collecting that pattern there collects one repository's yaml files. This module has no
    state file and matches below any directory, so the same pattern would hand every yaml
    file on the disk to one agent: a build configuration, a deployment manifest, another
    agent's own settings. A length floor used to let it through at exactly five characters.

    Unattributed is the honest answer and the file is still carried forward. A
    mis-attributed file is an error nobody sees; an unattributed one is a question somebody
    answers.
    """
    for path in (
        "/home/alice/src/app/docker-compose.yaml",
        "/home/alice/src/other/.github/workflows/ci.yaml",
    ):
        assert "goose.recipes" not in ids(matcher, path), path


def test_a_project_file_named_in_full_is_claimed_however_short_its_name(
    matcher: Matcher,
) -> None:
    """The other half of the same defect, and the more expensive one.

    A project's environment file is four literal characters, so the length floor refused
    it, and in most repositories it is the credential store. It was collected and
    attributed to nothing, which reads in a case as a file no catalogue entry claims: a
    lead somebody has to chase rather than the answer the catalogue already had.
    """
    found = ids(matcher, "/home/alice/src/app/.env")
    assert "aider.dotenv" in found or "qwen_code.env_files" in found, found


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


def test_the_recorded_working_copies_reach_the_parsers(
    tmp_path: Path, catalogue: Catalogue
) -> None:
    """Both collectors write an object per working copy, {path, source}, so the manifest
    says which agent's state revealed it.

    Reading that object as a string produced its repr, which matches no path, so every
    project instruction file was scoped as the user's own configuration. The wrong answer
    was silent and it reverses the finding an investigation cares about: whether a cloned
    repository instructed the agent or the user did.
    """
    bundle = tmp_path / "bundle"
    project = bundle / "files" / "home" / "alice" / "work" / "repo"
    project.mkdir(parents=True)
    (project / "CLAUDE.md").write_text("# Project rules\n\nrun make\n", encoding="utf-8")
    (bundle / "manifest.json").write_text(
        json.dumps(
            {
                "format_version": 1,
                "collection": {"uuid": "u-10", "os": "linux", "hostname": "vm"},
                "tool": {"name": "collect.py", "version": "0"},
                "project_roots": [
                    {"path": "/home/alice/work/repo", "source": "claude_code.global_config"}
                ],
                "files": [
                    {
                        "original_path": "/home/alice/work/repo/CLAUDE.md",
                        "bundle_path": "files/home/alice/work/repo/CLAUDE.md",
                        "sha256": "aa",
                        "size": 30,
                        "agent": "claude_code",
                        "artifact_id": "claude_code.project_claude_md",
                        "category": "project_instructions",
                        "status": "verified",
                        "collected": True,
                        "user": "alice",
                        "mtime_utc": "2026-09-07T00:00:00.000000Z",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with Case.open(tmp_path / "case.sqlite") as case:
        ingest(case, bundle, catalogue)
        scopes = [
            row["scope"] for row in case.query("SELECT scope FROM facet_instructions ORDER BY path")
        ]

    assert scopes == ["project"]


# ----------------------------------------- the attribution is a hint, not a verdict


def _bundle_with(tmp_path: Path, entry: dict, content: str, relative: str) -> Path:
    """A one-file native bundle carrying the manifest entry the caller wants tested."""
    bundle = tmp_path / "bundle"
    target = bundle / "files" / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    (bundle / "manifest.json").write_text(
        json.dumps(
            {
                "format_version": 1,
                "collection": {"uuid": "u-1", "os": "linux", "hostname": "vm"},
                "tool": {"name": "collect.py", "version": "0"},
                "files": [{**entry, "bundle_path": f"files/{relative}", "collected": True}],
            }
        ),
        encoding="utf-8",
    )
    return bundle


def test_a_file_attributed_to_an_entry_with_no_parser_is_still_read(
    tmp_path: Path, catalogue: Catalogue
) -> None:
    """The defect this was written for, and it cost a whole transcript.

    A file can be claimed by a directory-level catalogue entry and a file-level one. The
    collector attributes it to the entry with the fewest path patterns, which is a proxy for
    specificity rather than the thing itself: one broad glob over a directory beats a
    pattern that names the file. So a Gemini CLI chat transcript arrived attributed to the
    tree that contains it, that entry has no parser, and the transcript sat in the case as
    an inventory row with its content never read. Measured on the synthetic profile before
    this: 37 parsed events reading the tree directly, 0 of those 37 from the same files via
    a bundle.
    """
    bundle = _bundle_with(
        tmp_path,
        {
            "original_path": "~/.gemini/tmp/7f3a9c2e1b8d4f60/chats/session-1.jsonl",
            "sha256": "aa",
            "size": 1,
            "agent": "gemini_cli",
            "artifact_id": "gemini_cli.home_tree",
            "artifact_ids": ["gemini_cli.chats", "gemini_cli.home_tree"],
            "category": "config",
            "status": "verified",
            "user": "alice",
        },
        '{"type":"user","content":"check the lockfile"}\n',
        "home/alice/.gemini/tmp/7f3a9c2e1b8d4f60/chats/session-1.jsonl",
    )
    with Case.open(tmp_path / "case.sqlite") as case:
        report = ingest(case, bundle, catalogue)
        parsed = case.query("SELECT artifact_id, kind FROM events WHERE kind != 'artifact.fs'")
        gap_kinds = [row["kind"] for row in case.query("SELECT kind FROM collection_gaps")]
        artifact = case.query("SELECT artifact_id FROM artifacts")[0]

    assert parsed, "the content has to be read rather than left as an inventory row"
    assert {row["artifact_id"] for row in parsed} == {"gemini_cli.chats"}, (
        "the events name the entry whose parser read them"
    )
    assert len(report.reattributed) == 1
    assert "read as gemini_cli.chats" in report.reattributed[0]
    assert "attribution_disagreement" in gap_kinds, (
        "durable in the case, not only in a report printed once"
    )
    assert artifact["artifact_id"] == "gemini_cli.home_tree", (
        "the manifest's own attribution is left alone, so the two can be compared"
    )


def test_an_attribution_that_has_a_parser_is_never_second_guessed(
    tmp_path: Path, catalogue: Catalogue
) -> None:
    """A source that attributed a file well has to be taken at its word.

    The fallback exists for the case where the alternative is leaving content unread. Using
    it whenever another claimant looked more specific would overrule the one record of what
    the endpoint knew, which is the whole reason a native bundle beats a tree reading.
    """
    bundle = _bundle_with(
        tmp_path,
        {
            "original_path": "~/.claude/CLAUDE.md",
            "sha256": "aa",
            "size": 1,
            "agent": "claude_code",
            "artifact_id": "claude_code.user_claude_md",
            "artifact_ids": [
                "claude_code.user_claude_md",
                "crosscutting.instructions_claude_md",
            ],
            "category": "instructions",
            "status": "verified",
            "user": "alice",
        },
        "# house rules\n",
        "home/alice/.claude/CLAUDE.md",
    )
    with Case.open(tmp_path / "case.sqlite") as case:
        report = ingest(case, bundle, catalogue)
        parsed = case.query("SELECT DISTINCT artifact_id FROM events WHERE kind != 'artifact.fs'")

    assert not report.reattributed
    assert [row["artifact_id"] for row in parsed] == ["claude_code.user_claude_md"]


def test_the_other_claimants_are_tried_in_a_stable_order(
    catalogue: Catalogue, matcher: Matcher
) -> None:
    """Which claimant is tried first has to be decided the same way every time.

    With a matcher the order is its specificity ranking, the same rule the tree adapter
    attributes by, so the two readings of one catalogue agree about which claim is more
    precise. Without one, or for a path no pattern recognises, it is the ids in sorted
    order: that decides nothing, but it decides it reproducibly, and a case whose contents
    depend on dictionary order is not evidence.
    """
    from agentforensics.ingest.ingest import _other_claimants
    from agentforensics.ingest.source import SourceEntry

    entry = SourceEntry(
        original_path="~/.gemini/tmp/7f3a9c2e1b8d4f60/chats/session-1.jsonl",
        local_path=None,
        artifact_id="gemini_cli.home_tree",
        also_claimed_by=("gemini_cli.home_tree", "gemini_cli.chats"),
    )
    assert _other_claimants(entry, matcher) == ["gemini_cli.chats"], (
        "the attributed entry is never among the alternatives"
    )
    assert _other_claimants(entry, None) == ["gemini_cli.chats"]

    # A path from a bundle taken with --root carries the analyst workstation's absolute
    # path, which matches no catalogue pattern. The matcher then ranks nothing and the
    # sorted order has to carry the decision.
    off_tree = SourceEntry(
        original_path="/mnt/image/home/alice/.gemini/tmp/x/chats/session-1.jsonl",
        local_path=None,
        artifact_id="gemini_cli.home_tree",
        also_claimed_by=("gemini_cli.chats", "gemini_cli.home_tree", "aider.tags_cache"),
    )
    assert _other_claimants(off_tree, matcher) == ["aider.tags_cache", "gemini_cli.chats"]


# A catalogue of one entry that names a database and not the files SQLite keeps beside it.
# The committed catalogue no longer has such an entry, and a test that asserted against it
# would have gone quiet the moment that was fixed while still passing.
_DATABASE_ONLY = """
agent: test_agent
title: Test Agent
artifacts:
  - id: test_agent.store
    category: transcript
    os: [linux]
    paths: ["~/.test/sessions.db"]
    format: sqlite
    sensitivity: normal
    status: unverified
    source: observed on linux
    source_kind: observed
"""


def _catalogue_of(tmp_path: Path, body: str) -> Catalogue:
    directory = tmp_path / "catalog"
    (directory / "schema").mkdir(parents=True)
    (directory / "schema" / "catalog.schema.json").write_text(
        (REPO_ROOT / "catalog" / "schema" / "catalog.schema.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (directory / "test_agent.yaml").write_text(body, encoding="utf-8")
    return load_catalogue(directory)


def _wal_database(path: Path) -> None:
    import sqlite3

    path.parent.mkdir(parents=True, exist_ok=True)
    # A second dot-directory, because that is what makes the tree adapter read this root as
    # one user's home rather than as a filesystem root. Without it the paths come back
    # unanchored, nothing in the catalogue claims them, and the test would pass or fail for
    # a reason that has nothing to do with write-ahead logs.
    (path.parent.parent / ".config").mkdir(exist_ok=True)
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("CREATE TABLE session (id TEXT)")
    connection.commit()
    # Closed, so the log is folded in and deleted, which is the state a dead-box collection
    # finds. The point is not that a log is missing here but that the entry never asks for
    # one, so no collection of it could carry a log whatever the endpoint held.
    connection.close()


def test_a_database_that_arrived_without_its_log_is_a_gap_in_the_case(tmp_path: Path) -> None:
    """The reading that looks complete and is not, recorded where the case keeps them.

    A gap rather than an event, because it is a statement about what the collection carried
    and not about a record in a file. The store opens, its tables are all there, and SQLite
    reports nothing at all about the transactions that stayed behind in a log nobody was
    asked to take, so the case has to say it instead.
    """
    home = tmp_path / "home" / "alice"
    _wal_database(home / ".test" / "sessions.db")

    with Case.open(tmp_path / "case.db") as case:
        report = ingest(case, home, _catalogue_of(tmp_path, _DATABASE_ONLY))
        kinds = {row["kind"] for row in case.query("SELECT kind FROM collection_gaps")}

    assert report.databases_without_their_log == ["~/.test/sessions.db"]
    assert "sqlite_write_ahead_log_not_collected" in kinds


def test_a_store_whose_log_the_catalogue_does_ask_for_is_not_flagged(tmp_path: Path) -> None:
    """Otherwise the gap would fire for almost every database in almost every collection.

    A cleanly closed application leaves no log at all, and most databases in a dead-box
    collection are in that state. Warning about each of them would train an analyst to
    scroll past the one collection where the log really was left behind.
    """
    home = tmp_path / "home" / "alice"
    _wal_database(home / ".test" / "sessions.db")
    body = _DATABASE_ONLY.replace(
        'paths: ["~/.test/sessions.db"]',
        'paths: ["~/.test/sessions.db", "~/.test/sessions.db-shm", "~/.test/sessions.db-wal"]',
    )

    with Case.open(tmp_path / "case.db") as case:
        report = ingest(case, home, _catalogue_of(tmp_path, body))

    assert report.databases_without_their_log == []


def test_the_committed_catalogue_leaves_no_database_without_its_log(catalogue: Catalogue) -> None:
    """The same check the catalogue tests make, asserted from the ingest's side.

    This is the one that matters for a real collection: it is the ingest that asks the
    question, and an entry that lost its sidecars would make every store it claims read
    short with nothing but this saying so.
    """
    assert not catalogue.databases_without_a_claimed_log()


@pytest.mark.slow
def test_no_parser_hands_out_two_events_with_one_identity(tmp_path: Path) -> None:
    """A record this suite read, gone from the case, with nothing saying so.

    An event is identified by its provenance and its kind, so two events out of one file
    that share a locator are one row: the insert takes the first and drops the second
    without a word. It is the worst shape of defect this project has, because the reading
    worked and the case is short, and it happened: a reader of a prompt library located
    every event by the prompt id, and a prompt's live version, an earlier version of it and
    the two halves of a recovered one all carry the same id, so three of four events
    disappeared into one row.

    The ingest counts them now, and this holds the count at zero over the whole synthetic
    profile, which is the only place every parser in the suite runs at once.
    """
    import sys

    from agentforensics.catalog import load_catalogue

    root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(root / "tests" / "fixtures"))
    from generate import build_home

    home = tmp_path / "profile"
    build_home(home, with_edge_cases=False)
    with Case.open(tmp_path / "case.db") as case:
        report = ingest(case, home, load_catalogue(root / "catalog"))
    assert report.colliding_events == []


# ---------------------------------------------- what a manifest says went wrong


def _bundle(tmp_path: Path, **extra: object) -> Path:
    """The smallest native bundle, plus whatever a case wants to put in its manifest."""
    bundle = tmp_path / "bundle"
    (bundle / "files").mkdir(parents=True)
    manifest: dict[str, object] = {
        "format_version": 1,
        "collection": {"uuid": "u-1", "os": "linux", "hostname": "vm"},
        "tool": {"name": "collect.py", "version": "0"},
        "files": [],
    }
    manifest.update(extra)
    (bundle / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return bundle


def test_what_the_collector_could_not_read_reaches_the_case(
    tmp_path: Path, catalogue: Catalogue
) -> None:
    """The errors the endpoint reported are holes in the evidence, and they were not read.

    A collection that hit forty permission denials and one locked database produced a
    manifest saying so and a case saying nothing, so the analyst saw an agent with fewer
    files than it had and no reason given. Both shapes are accepted because the field is
    read by anything that can write a bundle, not only by the two collectors here.
    """
    bundle = _bundle(
        tmp_path,
        errors=[
            {"kind": "unreadable", "path": "/home/alice/.claude/state.db", "reason": "locked"},
            "a producer that wrote a bare string",
        ],
    )
    with Case.open(tmp_path / "case.sqlite") as case:
        ingest(case, bundle, catalogue)
        gaps = case.query("SELECT kind, detail, reason FROM collection_gaps")
    kinds = {row["kind"] for row in gaps}
    assert "unreadable" in kinds, kinds
    assert "error" in kinds, kinds
    assert any("state.db" in (row["detail"] or "") for row in gaps)


def test_a_project_root_written_as_a_plain_string_is_still_read(
    tmp_path: Path, catalogue: Catalogue
) -> None:
    """Both collectors write an object per root. Another producer may write a string, and
    an unread project root turns every project file into an unattributed one."""
    bundle = _bundle(tmp_path, project_roots=["/home/alice/work/repo", {"path": "/srv/app"}])

    assert NativeBundle(bundle).project_roots == ["/home/alice/work/repo", "/srv/app"]


def test_a_manifest_that_is_not_json_says_so_rather_than_reading_as_empty(
    tmp_path: Path,
) -> None:
    """A bundle whose manifest is damaged must not open as a bundle with no files in it."""
    bundle = tmp_path / "bundle"
    (bundle / "files").mkdir(parents=True)
    (bundle / "manifest.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(BundleError, match="could not be read"):
        NativeBundle(bundle)


def test_a_json_document_that_is_not_a_manifest_is_refused(tmp_path: Path) -> None:
    """Valid JSON with the wrong shape, which is what a file renamed into place looks
    like. Read as a manifest it would report a collection that found nothing."""
    bundle = tmp_path / "bundle"
    (bundle / "files").mkdir(parents=True)
    (bundle / "manifest.json").write_text('{"hello": "world"}', encoding="utf-8")
    with pytest.raises(BundleError, match="is not a bundle manifest"):
        NativeBundle(bundle)


def test_a_directory_with_no_manifest_is_not_a_native_bundle(tmp_path: Path) -> None:

    (tmp_path / "files").mkdir()
    assert not NativeBundle.looks_like(tmp_path)
    with pytest.raises(BundleError, match=r"has no manifest\.json"):
        NativeBundle(tmp_path)


def test_a_link_whose_target_was_not_collected_is_a_gap_not_a_silence(
    tmp_path: Path, catalogue: Catalogue
) -> None:
    """A tree full of links to files nobody copied is what a partial collection looks like.

    The walk yields the link, because the fact that it was there is evidence, and then
    everything that wants its content fails: the hash, the size and the timestamps. All of
    that used to happen without a word, so the case held an entry with no hash beside
    entries with one and nothing said which of the two states it was in.
    """
    profile = tmp_path / "alice"
    (profile / ".claude").mkdir(parents=True)
    (profile / ".claude" / "settings.json").symlink_to(tmp_path / "never-collected.json")

    with Case.open(tmp_path / "case.sqlite") as case:
        ingest(case, profile, catalogue)
        gaps = case.query("SELECT kind, detail, reason FROM collection_gaps")
    unreadable = [row for row in gaps if row["kind"] == "unreadable_file"]
    assert unreadable, [dict(row) for row in gaps]
    assert "settings.json" in unreadable[0]["detail"]
    assert "could not be read" in (unreadable[0]["reason"] or "")


def test_a_timestamp_a_filesystem_cannot_represent_is_absent_not_1970() -> None:
    """A zeroed or deliberately corrupted inode carries one, and a date this suite cannot
    vouch for must not appear on a timeline as if it could."""
    from agentforensics.ingest.tree import _stamp

    assert _stamp(None) is None
    assert _stamp(1e300) is None
    assert _stamp(0) == "1970-01-01T00:00:00.000000Z", (
        "a real epoch timestamp is a real timestamp and stays one"
    )


# ------------------------------------ the summary an examiner reads after an ingest

# Everything the ingest could not do is in this text and nowhere else, and most of it had
# never been rendered: the synthetic profile produces a clean run, so the sections about
# colliding events, files read under another entry, databases missing their log and the
# trimming of a long list were reached by nothing. An exception or a wrong number in one
# of them would appear at the moment it matters, in front of the person deciding whether
# the case is complete.
#
# One case per section, plus a run with all of them at once, so a section that stops
# rendering is caught whether it fails alone or together with the rest.

SECTIONS: dict[str, tuple[dict[str, object], str]] = {
    "unreadable": ({"unreadable_records": 7}, "7 record(s) nothing could read"),
    "uninterpreted": (
        {"uninterpreted_records": 3},
        "3 record(s) read but in a format nobody has mapped",
    ),
    "colliding": (
        {"colliding_events": ["~/.claude/a.jsonl: two events at line:4"]},
        "1 file(s) produced events sharing an identity",
    ),
    "reattributed": (
        {"reattributed": ["~/.codex/x.jsonl: codex.rollouts -> codex.sessions"]},
        "1 file(s) read under a catalogue entry other than the one",
    ),
    "no_log": (
        {"databases_without_their_log": ["~/.config/agent/state.db"]},
        "1 database(s) journal ahead and arrived without their write-ahead log",
    ),
    "gaps": ({"gaps": 4}, "4 gap(s) in the collection"),
    "unclaimed": (
        {"unclaimed_paths": ["~/.someagent/history.json"]},
        "1 path(s) no catalogue entry claims",
    ),
}


def _report(**fields: object) -> IngestReport:
    return IngestReport(bundle_uuid="b-1", source_kind="native", source_path="/ev/b", **fields)  # type: ignore[arg-type]


@pytest.mark.parametrize("name", sorted(SECTIONS))
def test_each_thing_an_ingest_could_not_do_is_in_its_summary(name: str) -> None:
    fields, expected = SECTIONS[name]
    assert expected in _report(**fields).summary()


def test_a_clean_run_says_none_of_it() -> None:
    """The sections are conditional, so a run with nothing wrong has to read as one.

    A summary that listed every heading with a zero beside it would bury the one that is
    not zero, which is the only reason any of them is there.
    """
    text = _report(artifacts=10, collected=8, events=40).summary()
    for _, expected in SECTIONS.values():
        assert expected not in text
    assert "40 event(s)" in text


# The three sections that list paths rather than counting them, each of which trims.
TRIMMED = ("unclaimed_paths", "reattributed", "databases_without_their_log")


@pytest.mark.parametrize("field_name", TRIMMED)
def test_a_long_list_is_trimmed_and_says_how_much_it_left_out(field_name: str) -> None:
    """Five and a count. A summary that printed nine hundred paths would be scrolled past,
    and one that printed five and stopped would say there were five."""
    paths = [f"~/.agent/{index}.json" for index in range(9)]
    text = _report(**{field_name: paths}).summary()
    assert paths[4] in text
    assert paths[5] not in text
    assert "... and 4 more" in text


def test_the_trimming_table_names_every_section_that_lists_rather_than_counts() -> None:
    """Without this a fourth list could be added and print all nine hundred of whatever it
    holds, with the three above still passing."""
    listing = {
        name
        for name, value in vars(_report()).items()
        # colliding_events is the one list that does not trim this way. It puts its count
        # in the sentence and then joins five onto the same line, so a run with nine
        # hundred of them says nine hundred and shows five, which hides nothing even
        # though it never writes "and more".
        if isinstance(value, list) and name != "colliding_events"
    }
    assert listing == set(TRIMMED), listing


def test_every_optional_section_renders_when_they_all_apply() -> None:
    """Together as well as apart, because they share the list that builds the text and a
    change that dropped one of them would leave the others passing."""
    everything: dict[str, object] = {}
    for fields, _ in SECTIONS.values():
        everything.update(fields)
    text = _report(**everything).summary()
    for _, expected in SECTIONS.values():
        assert expected in text, text


# ------------------------------------- putting an endpoint path back together again

# A collection taken with another tool arrives as a tree with the endpoint's paths buried
# under whatever that tool wraps them in, and this is what digs them back out. Everything
# downstream rests on the answer: the catalogue matches on the path, the user is read out
# of the path, and a rule about a project file asks where the path was. A prefix left on,
# or a drive directory read as a folder, moves every path in the case one level down and
# the catalogue then claims none of them, which looks exactly like a host with no agents.
#
# None of it had ever run. One row per layout, and a guard that the table names every
# container prefix this reader strips.

LAYOUTS: dict[str, tuple[str, str]] = {
    # name: the path inside the tree, the endpoint path it has to come back as
    "this suite's own bundle": (
        "files/C/Users/alice/.claude/settings.json",
        "C:/Users/alice/.claude/settings.json",
    ),
    # Velociraptor writes the drive with its colon percent-encoded, because a colon is not
    # a character a filesystem will hold in a name on every platform.
    "velociraptor offline container": (
        "uploads/C%3A/Users/alice/.claude/settings.json",
        "C:/Users/alice/.claude/settings.json",
    ),
    "collection directory": (
        "collection/D/Users/alice/.claude/settings.json",
        "D:/Users/alice/.claude/settings.json",
    ),
    # KAPE writes the drive letter as the top directory with no container above it.
    "drive directory at the root": (
        "C/Users/alice/.claude/settings.json",
        "C:/Users/alice/.claude/settings.json",
    ),
    "no container and no drive": (
        "Users/alice/.claude/settings.json",
        "/Users/alice/.claude/settings.json",
    ),
}


@pytest.mark.parametrize("layout", sorted(LAYOUTS))
def test_a_container_layout_gives_back_the_path_the_endpoint_had(
    tmp_path: Path, catalogue: Catalogue, layout: str
) -> None:
    inside, expected = LAYOUTS[layout]
    root = tmp_path / "tree"
    local = root / inside
    local.parent.mkdir(parents=True)
    local.write_text("{}", encoding="utf-8")
    assert CollectedTree(root, Matcher(catalogue)).original_path(local) == expected


def test_the_layout_table_names_every_container_this_reader_strips() -> None:
    """A prefix added to the reader and not to the table is one nothing has ever undone."""
    from agentforensics.ingest.tree import _ROOT_PREFIXES

    covered = {inside.split("/")[0].lower() for inside, _ in LAYOUTS.values()}
    assert set(_ROOT_PREFIXES) <= covered, sorted(set(_ROOT_PREFIXES) - covered)


def test_a_profile_rooted_tree_says_so_rather_than_inventing_a_filesystem_root(
    tmp_path: Path, catalogue: Catalogue
) -> None:
    """An exported profile has no drive and no Users above it. Presenting its paths as
    absolute would assert a filesystem root that is not in the collection, so they are
    profile-relative, which is also the spelling the catalogue is written in."""
    root = tmp_path / "alice"
    (root / ".claude").mkdir(parents=True)
    (root / ".codex").mkdir()
    local = root / ".claude" / "settings.json"
    local.write_text("{}", encoding="utf-8")
    assert CollectedTree(root, Matcher(catalogue)).original_path(local) == (
        "~/.claude/settings.json"
    )


def test_a_path_says_which_account_it_belongs_to(tmp_path: Path) -> None:
    """Recovered from the path because a tree has nothing else to say it, and almost every
    question in a case is asked about one user. A path outside a profile gets no guess."""
    from agentforensics.ingest.tree import _user_from_path

    assert _user_from_path("C:/Users/alice/.claude/settings.json") == "alice"
    assert _user_from_path("/home/alice/.codex/config.toml") == "alice"
    assert _user_from_path("/root/.claude/settings.json") == "root"
    assert _user_from_path("/var/root/.claude/settings.json") == "root"
    assert _user_from_path("/opt/agent/state.json") is None


# --------------------------------------------------- which adapter reads which source

# The first decision an ingest makes, and the one every later decision rests on. A
# Velociraptor container read as a plain tree keeps its container directory on every
# path; a KAPE output read as a plain tree keeps the drive letter as a folder; and a
# native bundle read as a tree throws away the only record of what the endpoint knew,
# replacing the collector's own attributions, hashes and timestamps with guesses made
# afterwards. Only two of the four answers had ever been asked for.

SOURCES: dict[str, tuple[tuple[str, ...], str]] = {
    # name: directories to create, the answer detect has to give
    "a bundle from this suite": (("files",), "native"),
    "a velociraptor container": (("uploads", "uploads/C%3A"), "velociraptor"),
    "a kape output tree": (("C", "C/Users"), "kape"),
    "a mounted image or an exported profile": ((".claude", ".codex"), "directory"),
}


@pytest.mark.parametrize("shape", sorted(SOURCES))
def test_a_source_is_named_for_what_it_is(tmp_path: Path, shape: str) -> None:
    directories, expected = SOURCES[shape]
    root = tmp_path / "source"
    for name in directories:
        (root / name).mkdir(parents=True)
    if expected == "native":
        (root / "manifest.json").write_text('{"files": [], "collection": {}}', encoding="utf-8")
    if expected == "velociraptor":
        # The container carries its own metadata beside the uploads directory, and that
        # pair is what tells it apart from any other tree with an uploads folder in it.
        (root / "collection.json").write_text("{}", encoding="utf-8")
    assert detect(root) == expected


def test_a_manifest_wins_over_everything_that_looks_like_a_tree(tmp_path: Path) -> None:
    """A bundle that also has the shape of a container is still a bundle.

    The manifest is the only record of what the endpoint knew, and reading it as a tree
    would replace the collector's attributions, hashes and timestamps with inferences made
    afterwards. The order of the checks is what guarantees that, so it is asserted rather
    than left to whoever edits the function next.
    """
    root = tmp_path / "both"
    (root / "files").mkdir(parents=True)
    (root / "uploads").mkdir()
    (root / "C").mkdir()
    (root / "manifest.json").write_text('{"files": [], "collection": {}}', encoding="utf-8")
    assert detect(root) == "native"


def test_a_path_that_cannot_be_listed_is_a_tree_rather_than_an_error(tmp_path: Path) -> None:
    """A directory of collected files is what a mounted image and an exported profile look
    like, so the fallback has to be the reading that leaves their paths as they were
    found. A path that is not a directory at all takes the same route rather than
    raising, because refusing here would rule out the two sources an analyst most often
    has over a spelling mistake."""
    assert detect(tmp_path / "does-not-exist") == "directory"
    a_file = tmp_path / "a-file"
    a_file.write_text("not a directory", encoding="utf-8")
    assert detect(a_file) == "directory"
