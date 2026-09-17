"""Tests for the event model and the case database.

The properties asserted here are the ones the rest of the analyzer is allowed to assume:
that the same evidence always produces the same event id, that re-ingest is a no-op, that a
record nobody could parse is still an event, and that a timestamp is never invented.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agentforensics.model import (
    EVENT_KINDS,
    BundleRecord,
    Case,
    CaseError,
    Event,
    Provenance,
    unparsed,
)


def provenance(locator: str = "line:1") -> Provenance:
    return Provenance("bundle-1", "/home/alice/.claude/projects/p/s.jsonl", "aa", "x.y", locator)


def event(kind: str = "user.prompt", **overrides: object) -> Event:
    fields: dict[str, object] = {
        "kind": kind,
        "provenance": provenance(),
        "agent": "claude_code",
        "raw": {"role": "user", "text": "hello"},
    }
    fields.update(overrides)
    return Event(**fields)  # type: ignore[arg-type]


@pytest.fixture
def case(tmp_path: Path) -> Case:
    opened = Case.open(tmp_path / "case.sqlite")
    with opened.transaction():
        opened.add_bundle(BundleRecord("bundle-1", "native", "/tmp/b"))
    return opened


def test_an_event_id_is_derived_from_provenance_not_a_counter() -> None:
    """Re-ingest depends on this: the same evidence must produce the same identity."""
    assert event().event_id == event().event_id
    assert event().event_id != event(provenance=provenance("line:2")).event_id


def test_one_record_can_produce_several_events_with_distinct_ids() -> None:
    """A transcript turn that calls a tool is both a turn and a call.

    They share a locator and need separate identities, which is why the kind is in the
    hash. Without it the second event would silently overwrite the first.
    """
    assert event("assistant.text").event_id != event("tool.call").event_id


def test_an_unknown_kind_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown event kind"):
        event("something.invented")


def test_a_timestamp_and_its_precision_travel_together() -> None:
    """The one thing a forensic timeline may not do is imply precision it does not have."""
    with pytest.raises(ValueError, match="not there"):
        event(ts_utc=None, ts_precision="second")
    with pytest.raises(ValueError, match="no precision"):
        event(ts_utc="2026-09-07T00:00:00Z", ts_precision="absent")


def test_every_declared_kind_is_constructible() -> None:
    for kind in EVENT_KINDS:
        assert event(kind).kind == kind


def test_re_ingesting_the_same_events_changes_nothing(case: Case) -> None:
    with case.transaction():
        first = case.add_events([event(), event("tool.call")])
        second = case.add_events([event(), event("tool.call")])
    assert (first, second) == (2, 0)
    assert case.counts()["events"] == 2


def test_an_unparsed_record_is_an_event_and_is_counted(case: Case) -> None:
    """The rule the whole project turns on.

    A line nothing could read has to appear on the timeline and in the counts. A pipeline
    that dropped it would make a broken parser indistinguishable from an agent that was
    never used.
    """
    with case.transaction():
        case.add_events([unparsed(provenance("line:9"), "cline", "{not json", "invalid json")])
    counts = case.counts()
    assert counts["events"] == 1
    assert counts["events_unparsed"] == 1
    row = case.query("SELECT raw, parse_problem FROM events")[0]
    assert "not json" in row["raw"], "the record itself has to be kept, not just the failure"
    assert row["parse_problem"] == "invalid json"


def test_the_original_record_is_always_kept(case: Case) -> None:
    with case.transaction():
        case.add_events([event(raw={"weird": {"nested": [1, 2, {"x": None}]}})])
    assert '"weird"' in case.query("SELECT raw FROM events")[0]["raw"]


def test_a_record_json_cannot_encode_is_still_stored(case: Case) -> None:
    """Losing a record because it held an odd value would be the worst possible trade."""
    with case.transaction():
        case.add_events([event(raw={"when": object()})])
    assert case.counts()["events"] == 1


def test_identity_is_indirected_through_its_own_tables(case: Case) -> None:
    """So that pseudonymizing a case later is two updates, not a rewrite."""
    with case.transaction():
        case.add_events([event(user="alice", host="workstation")])
    row = case.query(
        "SELECT u.name AS user, h.name AS host FROM events e "
        "JOIN users u ON u.user_id = e.user_id JOIN hosts h ON h.host_id = e.host_id"
    )[0]
    assert (row["user"], row["host"]) == ("alice", "workstation")


def test_facets_are_derived_from_the_payload(case: Case) -> None:
    with case.transaction():
        case.add_events(
            [
                event(
                    "command.exec",
                    payload={
                        "commands": [{"command": "FOO=1 npm install", "cwd": "/src"}],
                        "network": [{"host": "example.org", "url": "https://example.org/x"}],
                        "files": [{"path": "/src/a.py", "operation": "write", "bytes": 12}],
                        "mcp": [{"server": "fs", "tool": "read"}],
                        "models": [{"model": "a-model", "input_tokens": 10}],
                        "permissions": [{"mode": "auto", "decision": "allow", "subject": "Bash"}],
                        "instructions": [{"path": "/src/AGENTS.md", "scope": "project"}],
                    },
                )
            ]
        )
    assert case.query("SELECT executable FROM facet_commands")[0]["executable"] == "npm", (
        "a leading VAR=value assignment is not the executable"
    )
    for table in (
        "facet_files",
        "facet_network",
        "facet_mcp",
        "facet_models",
        "facet_permissions",
        "facet_instructions",
    ):
        # A table name from this module's own tuple, not from input.
        rows = case.query(f"SELECT count(*) AS n FROM {table}")  # noqa: S608
        assert rows[0]["n"] == 1, table


def test_a_facet_given_as_a_bare_string_still_lands(case: Case) -> None:
    """Tolerance here costs a coarser row; strictness would cost the rest of the file."""
    with case.transaction():
        case.add_events([event("file.write", payload={"files": "/src/a.py"})])
    assert case.query("SELECT path FROM facet_files")[0]["path"] == "/src/a.py"


def test_a_case_from_another_schema_version_is_refused(tmp_path: Path) -> None:
    """A partly migrated case would have counts nobody could trust."""
    path = tmp_path / "old.sqlite"
    with Case.open(path) as opened:
        opened.set_meta("schema_version", "999")
    with pytest.raises(CaseError, match="schema version"):
        Case.open(path)


def test_opening_something_that_is_not_a_case_fails_clearly(tmp_path: Path) -> None:
    path = tmp_path / "not-a-case.sqlite"
    path.write_bytes(b"")
    with pytest.raises(CaseError):
        Case.open(path)
