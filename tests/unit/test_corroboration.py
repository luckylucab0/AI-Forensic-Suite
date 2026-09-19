"""Tests for the view that compares an agent's stores against each other.

The question here is the one neither a parser nor a rule can answer. A parser sees one
record; a rule sees one event, or a count of events in a group. A conversation that one
store of an agent remembers and another does not is about a record that is not there, and
it only becomes visible when the two stores are put side by side.

Zed is the case these tests are built on, because it is the clearest: the thread store holds
the conversations and a second store holds their metadata, and the vendor's own migration
history shows threads reaching one and not the other in both directions. The same shape
exists for Codex between the rollout files and the database that projects them, and the
synthetic profile shows it there without anything being staged for it.
"""

from __future__ import annotations

import compression.zstd as zstd
import sqlite3
import sys
import uuid
from pathlib import Path

import pytest

from agentforensics.catalog import load_catalogue
from agentforensics.cli import main
from agentforensics.ingest import ingest
from agentforensics.model import Case
from agentforensics.webui.api import corroboration

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tests" / "fixtures"))

from generate import ZED_SCHEMA, build_home, zed_thread  # noqa: E402

KEPT = "01H0000000000000000001"
ONLY_IN_THE_THREAD_STORE = "01H0000000000000000002"

SIDEBAR_SCHEMA = """CREATE TABLE sidebar_threads(
    thread_id BLOB PRIMARY KEY, session_id TEXT, agent_id TEXT, title TEXT NOT NULL,
    updated_at TEXT NOT NULL, created_at TEXT, folder_paths TEXT, folder_paths_order TEXT,
    archived INTEGER DEFAULT 0, main_worktree_paths TEXT, main_worktree_paths_order TEXT,
    remote_connection TEXT, interacted_at TEXT, title_override TEXT) STRICT"""


def zed_profile(home: Path, *, threads: list[str], sidebar: list[str]) -> Path:
    """A profile with Zed's two stores, each naming the threads it is given.

    The two are written apart on purpose: what is being tested is the case where they
    disagree, and a fixture that could only produce agreement would pass whatever the view
    did.
    """
    build_home(home, with_edge_cases=False)

    store = home / ".local" / "share" / "zed" / "threads" / "threads.db"
    store.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(store)
    try:
        connection.execute(ZED_SCHEMA)
        for thread in threads:
            connection.execute(
                "INSERT INTO threads (id, summary, updated_at, data_type, data, parent_id, "
                "folder_paths, folder_paths_order, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    thread,
                    "fix the build",
                    "2026-09-06T09:30:00Z",
                    "zstd",
                    zstd.compress(zed_thread().encode("utf-8")),
                    None,
                    "/home/alice/src/app",
                    "0",
                    "2026-09-06T09:00:00Z",
                ),
            )
        connection.commit()
    finally:
        connection.close()

    metadata = home / ".local" / "share" / "zed" / "db" / "0-stable" / "db.sqlite"
    metadata.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(metadata)
    try:
        connection.execute(SIDEBAR_SCHEMA)
        for thread in sidebar:
            connection.execute(
                "INSERT INTO sidebar_threads (thread_id, session_id, agent_id, title, "
                "updated_at, created_at, archived) VALUES (?,?,?,?,?,?,?)",
                (
                    uuid.uuid4().bytes,
                    thread,
                    None,
                    "fix the build",
                    "2026-09-06T09:30:00+00:00",
                    "2026-09-06T09:00:00+00:00",
                    0,
                ),
            )
        connection.commit()
    finally:
        connection.close()
    return home


def case_of(home: Path, path: Path) -> Path:
    with Case.open(path) as case, case.transaction():
        ingest(case, home, load_catalogue(REPO_ROOT / "catalog"))
    return path


def view_of(tmp_path: Path, **profile: list[str]) -> dict:
    home = zed_profile(tmp_path / "home", **profile)
    with Case.open(case_of(home, tmp_path / "case.db"), create=False, read_only=True) as case:
        return corroboration(case)


def zed(view: dict) -> dict:
    return next(agent for agent in view["agents"] if agent["agent"] == "zed")


# ---------------------------------------------------------- one store, not the other


def test_a_conversation_only_one_store_remembers_is_named(tmp_path: Path) -> None:
    """The finding this view exists for, and the one nothing else in the suite can make."""
    view = view_of(tmp_path, threads=[KEPT, ONLY_IN_THE_THREAD_STORE], sidebar=[KEPT])

    alone = [
        row
        for row in view["sessions"]
        if row["agent"] == "zed" and row["session_id"] == ONLY_IN_THE_THREAD_STORE
    ]
    assert len(alone) == 1
    assert [entry["artifact_id"] for entry in alone[0]["named_by"]] == ["zed.threads_db"]
    assert [entry["artifact_id"] for entry in alone[0]["silent"]] == ["zed.sidebar_threads"]


def test_the_silent_store_says_how_much_it_does_know(tmp_path: Path) -> None:
    """A store that knows one conversation in forty is not a peer of one that knows all.

    Without the count an analyst has to work that out for themselves, and a list of stores
    that stayed silent reads as forty findings instead of one.
    """
    view = view_of(tmp_path, threads=[KEPT, ONLY_IN_THE_THREAD_STORE], sidebar=[KEPT])

    row = next(row for row in view["sessions"] if row["session_id"] == ONLY_IN_THE_THREAD_STORE)
    assert row["silent"] == [{"artifact_id": "zed.sidebar_threads", "names_sessions": 1}]


def test_a_conversation_both_stores_name_is_not_reported_as_alone(tmp_path: Path) -> None:
    view = view_of(tmp_path, threads=[KEPT, ONLY_IN_THE_THREAD_STORE], sidebar=[KEPT])

    row = next(row for row in view["sessions"] if row["session_id"] == KEPT)
    assert row["silent"] == []
    assert row["stores"] == 2


def test_the_pair_counts_both_directions(tmp_path: Path) -> None:
    """Which way the disagreement runs is the difference between two explanations.

    A thread in the transcript store and not in the index is a conversation the interface
    would not show. One in the index and not in the transcript store is a conversation whose
    content is gone.
    """
    view = view_of(
        tmp_path, threads=[KEPT, ONLY_IN_THE_THREAD_STORE], sidebar=[KEPT, "01H0000000000000000003"]
    )

    pair = zed(view)["pairs"][0]
    assert (pair["left"], pair["right"]) == ("zed.sidebar_threads", "zed.threads_db")
    assert pair["both"] == 1
    assert pair["left_only"] == 1, "the index names a conversation the transcript store lost"
    assert pair["right_only"] == 1, "and the transcript store has one the index never had"
    assert pair["overlap"] == "partial"


def test_two_stores_that_share_nothing_say_it_is_probably_two_id_spaces(
    tmp_path: Path,
) -> None:
    """The reading that would otherwise be catastrophically wrong.

    Told that no conversation at all is in both stores, an analyst would conclude that
    everything had been removed from one of them. By far the likelier explanation is that
    the two stores do not name conversations the same way, and the view says so where the
    number is, not in a manual.
    """
    view = view_of(tmp_path, threads=[KEPT], sidebar=["a-different-id-space-entirely"])

    pair = zed(view)["pairs"][0]
    assert pair["both"] == 0
    assert pair["overlap"] == "none"
    assert "id space" in view["note"]


# --------------------------------------------------------------- what is compared


def test_only_stores_that_name_conversations_are_compared(tmp_path: Path) -> None:
    """A settings file is not a store that forgot a conversation.

    Every artifact in a case would otherwise be silent about every conversation, and the
    view would produce one line per file per session.
    """
    view = view_of(tmp_path, threads=[KEPT], sidebar=[KEPT])

    for agent in view["agents"]:
        for entry in agent["artifacts"]:
            assert entry["sessions"] > 0
    for row in view["sessions"]:
        for entry in row["silent"]:
            assert entry["names_sessions"] > 0


def test_the_synthetic_profile_corroborates_without_anything_staged(tmp_path: Path) -> None:
    """The other half of the answer: agreement is as much a result as disagreement.

    Codex writes a prompt history beside its rollout files and Claude Code keeps a
    transcript that was set aside beside the live one. Both pairs name the same
    conversations in the fixture, which is what a case should look like when nothing is
    missing, and a view that only ever reported trouble would not be able to show it.
    """
    home = tmp_path / "home"
    build_home(home, with_edge_cases=False)
    with Case.open(case_of(home, tmp_path / "case.db"), create=False, read_only=True) as case:
        view = corroboration(case)

    agents = {agent["agent"]: agent for agent in view["agents"]}
    codex = next(pair for pair in agents["codex"]["pairs"])
    assert {codex["left"], codex["right"]} == {"codex.prompt_history", "codex.rollouts"}
    assert codex["overlap"] == "complete"
    assert view["counts"]["in_one_store"] == 0
    assert view["counts"]["corroborated"] >= 2


def test_the_note_says_that_silence_is_a_lead(tmp_path: Path) -> None:
    """The sentence that keeps this view from being read as a list of deletions."""
    view = view_of(tmp_path, threads=[KEPT], sidebar=[KEPT])

    assert "lead and not a finding" in view["note"]
    assert "absent" in view["note"], "a store nobody collected is a different answer"


# ------------------------------------------------------------------- the command


def test_the_command_lists_the_conversation_one_store_forgot(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """What an analyst actually runs, and what they see when they run it."""
    home = zed_profile(tmp_path / "home", threads=[KEPT, ONLY_IN_THE_THREAD_STORE], sidebar=[KEPT])
    path = case_of(home, tmp_path / "case.db")

    assert main(["sessions", "--case", str(path), "--agent", "zed"]) == 0

    out = capsys.readouterr()
    assert ONLY_IN_THE_THREAD_STORE in out.out
    assert "not named by zed.sidebar_threads" in out.out
    assert KEPT not in out.out, "a corroborated conversation is not what this listing is for"
    assert "lead and not a finding" in out.err, "the limits travel with the listing"


def test_the_command_can_list_every_conversation(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home = zed_profile(tmp_path / "home", threads=[KEPT, ONLY_IN_THE_THREAD_STORE], sidebar=[KEPT])
    path = case_of(home, tmp_path / "case.db")

    assert main(["sessions", "--case", str(path), "--agent", "zed", "--all"]) == 0

    out = capsys.readouterr().out
    assert KEPT in out
    assert ONLY_IN_THE_THREAD_STORE in out
