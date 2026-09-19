"""Tests for the VS Code state store parser.

The store is a key/value table, so the tests are mostly about the key: it is the evidence,
and before this parser existed it was in `raw` while the value sat in the searchable field.
The rest is about the two ways a reader of a store like this goes wrong, which are reading a
table it has not verified as though it had, and quietly leaving out the tables it has not.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from agentforensics.parsers import for_artifact
from agentforensics.parsers.base import ParseContext

ARTIFACT = "vscode.state_vscdb"

# The vendor's own CREATE statement, copied from the source the parser cites so a change to
# either shows up here:
# https://raw.githubusercontent.com/microsoft/vscode/main/src/vs/base/parts/storage/node/storage.ts
SCHEMA = "CREATE TABLE IF NOT EXISTS ItemTable (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB)"


def store(
    path: Path, items: list[tuple[str, Any]], *, schema: str = SCHEMA, extra: str = ""
) -> Path:
    connection = sqlite3.connect(path)
    try:
        connection.execute(schema)
        connection.executemany("INSERT INTO ItemTable VALUES (?,?)", items)
        if extra:
            connection.executescript(extra)
        connection.commit()
    finally:
        connection.close()
    return path


def parse(path: Path, artifact: str = ARTIFACT, agent: str = "vscode") -> list:
    parser = for_artifact(artifact)
    assert parser is not None, artifact
    return list(
        parser.parse(
            ParseContext(
                bundle_uuid="b",
                original_path="C:/Users/alice/AppData/Roaming/Code/User/globalStorage/state.vscdb",
                local_path=path,
                sha256="f" * 64,
                artifact_id=artifact,
                agent=agent,
                user="alice",
            )
        )
    )


def rows(events: list) -> list:
    return [event for event in events if event.provenance.locator != "schema"]


# ------------------------------------------------------------------------ the key


def test_the_key_is_a_field_and_not_only_inside_raw(tmp_path: Path) -> None:
    """The one thing this parser exists for.

    The generic reader put the value in the searchable text and left the key in raw, which
    in a store whose structure is that the key names the thing is the wrong way round. An
    analyst asking what an extension left behind searches for the extension's key.
    """
    path = store(tmp_path / "state.vscdb", [("anysphere.cursor-always/enabled", '"yes"')])
    events = rows(parse(path))

    assert [event.payload["key"] for event in events] == ["anysphere.cursor-always/enabled"]
    assert events[0].kind == "config.snapshot"


def test_a_json_value_is_carried_parsed_and_whole(tmp_path: Path) -> None:
    """Both, because they answer different questions.

    The text is what a keyword search over the case matches. The parsed value is what a rule
    or a person can walk. Carrying only one of them means either the search misses the row
    or the structure has to be parsed again by whoever reads it.
    """
    value = json.dumps([{"id": "saoudrizwan.claude-dev", "uuid": "0000"}])
    path = store(tmp_path / "state.vscdb", [("extensionIdentifiers/enabled", value)])
    event = rows(parse(path))[0]

    assert event.payload["text"] == value
    assert event.payload["value"] == [{"id": "saoudrizwan.claude-dev", "uuid": "0000"}]
    assert event.parse_problem is None


def test_a_value_that_is_not_json_is_a_value_and_not_a_problem(tmp_path: Path) -> None:
    """The storage layer stores strings. JSON is a convention the extensions follow.

    A parser that treated a bare string as damaged would mark ordinary rows as defects, and
    a case in which half the rows carry a parse problem is one nobody reads the problems in.
    """
    path = store(tmp_path / "state.vscdb", [("colorThemeId", "Default Dark Modern")])
    event = rows(parse(path))[0]

    assert event.payload["text"] == "Default Dark Modern"
    assert "value" not in event.payload
    assert event.parse_problem is None


def test_a_value_the_reader_could_not_decode_is_described_rather_than_dropped(
    tmp_path: Path,
) -> None:
    """A BLOB that is not text still happened, and the row still names its key."""
    path = store(tmp_path / "state.vscdb", [("secret", bytes([0xFF, 0xFE, 0x00]))])
    event = rows(parse(path))[0]

    assert event.payload["key"] == "secret"
    assert "not carried into the case" in event.payload["text"]
    assert "value" not in event.payload, "a description of bytes is not a parsed value"
    assert "not text the reader could decode" in (event.parse_problem or "")
    assert event.raw is not None, "and the description itself is in raw"


# ----------------------------------------------------------------------- the time


def test_no_row_carries_a_timestamp_and_the_store_says_why_once(tmp_path: Path) -> None:
    """The table has no time column, and the file's mtime is not the row's time.

    Dating every row of a state store to the moment the file was last written would put
    three thousand fabricated moments on a timeline. The absence is in ts_precision, where
    a consumer can act on it, and the sentence is on the store's own event rather than on
    every row: a parse problem on all of them would say the reading went wrong when it did
    not.
    """
    path = store(
        tmp_path / "state.vscdb", [("a", "1"), ("b", "2")], extra="PRAGMA user_version = 1;"
    )
    events = parse(path)

    assert all(event.ts_utc is None for event in events)
    assert all(event.ts_precision == "absent" for event in events)
    assert all(event.parse_problem is None for event in rows(events))
    schema = next(event for event in events if event.provenance.locator == "schema")
    assert "keeps no time of its own" in schema.payload["text"]


# --------------------------------------------------------------- the other tables


def test_a_table_this_parser_has_not_read_still_comes_back(tmp_path: Path) -> None:
    """Cursor keeps its conversations in a second table in the same file.

    This parser has read the vendor's schema for ItemTable and nothing else, so the other
    table goes through the uninterpreted reader with the note that says so. Leaving it out
    would make a case state that a store holding conversations held only settings.
    """
    path = store(
        tmp_path / "state.vscdb",
        [("colorThemeId", "Default Dark Modern")],
        extra=(
            "CREATE TABLE cursorDiskKV (key TEXT PRIMARY KEY, value BLOB);"
            "INSERT INTO cursorDiskKV VALUES ('bubbleId:1', '{\"text\":\"why is the build red\"}');"
        ),
    )
    events = rows(parse(path, "cursor.global_state_vscdb", "cursor"))

    other = [event for event in events if event.kind == "unparsed.record"]
    assert len(other) == 1
    assert "cursorDiskKV" in (other[0].provenance.locator or "")
    assert "no verified schema" in (other[0].parse_problem or "")
    assert "why is the build red" in other[0].payload["text"]


def test_an_item_table_that_is_not_the_vendors_is_not_read_as_though_it_were(
    tmp_path: Path,
) -> None:
    """A table with the right name and the wrong columns is a different table.

    Reading it as the vendor's would put a key and a value in the case that the row does not
    have. It falls through to the uninterpreted reader instead, which is the same answer the
    store had before anybody verified a schema for it.
    """
    path = store(
        tmp_path / "state.vscdb",
        [("a", "1")],
        schema="CREATE TABLE ItemTable (name TEXT, payload BLOB)",
    )
    events = rows(parse(path))

    assert [event.kind for event in events] == ["unparsed.record"]
    assert "no verified schema" in (events[0].parse_problem or "")
    assert all("key" not in event.payload for event in events)


# ------------------------------------------------------------- the store as a whole


def test_an_empty_store_still_says_what_it_is(tmp_path: Path) -> None:
    """An empty state store and an uncollected one are opposite answers.

    The editor creates the table on connect, so an ItemTable with no rows is a profile the
    editor opened and wrote nothing into. Returning nothing at all for it would read as no
    store having been collected.
    """
    path = store(tmp_path / "state.vscdb", [])
    events = parse(path)

    assert len(events) == 1
    assert events[0].payload["tables"] == ["ItemTable"]
    assert "1 table(s)" in events[0].payload["text"]


def test_a_file_that_is_not_a_database_is_reported_rather_than_skipped(tmp_path: Path) -> None:
    """These files are rewritten while the editor runs, so a mid-write copy is ordinary.

    Collected and unreadable is a finding: it tells an analyst to go back for the -wal
    sibling or for a second copy, and a silent nothing tells them the agent left nothing.
    """
    path = tmp_path / "state.vscdb"
    path.write_bytes(b"not a database at all")
    events = parse(path)

    assert len(events) == 1
    assert events[0].parse_problem


@pytest.mark.parametrize(
    "artifact",
    [
        "vscode.state_vscdb",
        "cursor.global_state_vscdb",
        "cursor.workspace_state_vscdb",
        "windsurf.ide_global_state_vscdb",
        "windsurf.ide_workspace_state_vscdb",
    ],
)
def test_every_product_that_keeps_this_file_is_read_by_this_parser(artifact: str) -> None:
    """One file, one schema, five catalogue entries under three product names.

    The catalogue is the source of truth for which entry a parser claims, and a separate
    test asserts the parser field matches in both directions. This one is about the other
    half: a fork renaming the product must not quietly take its store back to being unread.
    """
    parser = for_artifact(artifact)
    assert parser is not None
    assert parser.name == "vscode_state"
