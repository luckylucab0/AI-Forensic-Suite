"""Tests for the reader over the registry keys a Windows collection carried.

The collector writes a key as one JSON document and this reads it back, so these tests are
about the contract between the two halves. They can run anywhere, which is the point of
having the contract be a document: the collector needs Windows and this does not.

What they are mostly about is the difference between three answers a policy key can give.
The key holds a policy, the key exists and is empty, or the key is not there at all. Only
the first two produce a document, the third is a manifest entry with nothing behind it, and
a case that ran them together would say no policy was in force on a host where nobody
looked.
"""

from __future__ import annotations

import json
from pathlib import Path

from agentforensics.parsers import ParseContext, for_artifact
from agentforensics.parsers.registry import EMPTY_KEY

ARTIFACT = "claude_code.managed_settings_registry"
KEY = "HKLM\\SOFTWARE\\Policies\\ClaudeCode"


def write(path: Path, document: dict) -> Path:
    path.write_text(json.dumps(document), encoding="utf-8", newline="")
    return path


def parse(path: Path, artifact_id: str = ARTIFACT, key: str = KEY) -> list:
    parser = for_artifact(artifact_id)
    assert parser is not None, artifact_id
    return list(
        parser.parse(
            ParseContext(
                bundle_uuid="b1",
                original_path=key,
                local_path=path,
                sha256="aa",
                artifact_id=artifact_id,
                agent=artifact_id.split(".")[0],
                user="alice",
            )
        )
    )


def document(values: list, key: str = KEY, **extra) -> dict:
    return {
        "format_version": 1,
        "key": key,
        "last_write_utc": "2026-09-14T09:02:11.000000Z",
        "values": values,
        "subkeys": [],
        **extra,
    }


def test_a_value_becomes_an_event_with_the_keys_time(tmp_path: Path) -> None:
    path = write(
        tmp_path / "k.json", document([{"name": "Enabled", "type": "REG_DWORD", "data": 1}])
    )
    event = parse(path)[0]
    assert event.kind == "config.snapshot"
    assert event.raw["value_name"] == "Enabled"
    assert event.raw["data"] == 1
    assert event.ts_utc == "2026-09-14T09:02:11.000000Z"
    assert event.ts_source == "the registry key's last-write time"


def test_the_time_says_it_belongs_to_the_key(tmp_path: Path) -> None:
    """The registry keeps no time per value, so every value of one key shares it.
    Attributing it to one value would date a setting that may be years older."""
    path = write(
        tmp_path / "k.json",
        document(
            [
                {"name": "A", "type": "REG_SZ", "data": "one"},
                {"name": "B", "type": "REG_SZ", "data": "two"},
            ]
        ),
    )
    events = parse(path)
    assert {event.ts_utc for event in events} == {"2026-09-14T09:02:11.000000Z"}
    assert all(
        "the key's and is the same on every value" in (e.parse_problem or "") for e in events
    )


def test_a_key_that_exists_and_is_empty_says_the_policy_was_not_set(tmp_path: Path) -> None:
    """The answer that matters most and is easiest to lose. A key with nothing in it is
    not a key that is missing, and neither is a host nobody looked at."""
    path = write(tmp_path / "k.json", document([]))
    events = parse(path)
    assert len(events) == 1
    assert events[0].raw["key"] == KEY
    assert EMPTY_KEY in (events[0].parse_problem or "")


def test_the_hive_is_a_field_because_it_says_who_could_have_written_it(tmp_path: Path) -> None:
    """The same policy under the machine hive needs administrative rights and under the
    user's own does not, so a policy present only in the user's hive is one a
    non-administrator could have put there."""
    machine = write(tmp_path / "m.json", document([{"name": "A", "type": "REG_SZ", "data": "x"}]))
    user = write(
        tmp_path / "u.json",
        document(
            [{"name": "A", "type": "REG_SZ", "data": "x"}],
            key="HKCU\\SOFTWARE\\Policies\\ClaudeCode",
        ),
    )
    assert parse(machine)[0].raw["hive"] == "machine"
    assert parse(user, key="HKCU\\SOFTWARE\\Policies\\ClaudeCode")[0].raw["hive"] == "user"


def test_a_settings_document_inside_a_value_is_parsed(tmp_path: Path) -> None:
    """One product keeps its whole managed settings as JSON in a string value, and its own
    documentation says to read it. Parsed here, so the rules about a permission, an
    endpoint or a hook see a managed policy the way they see a settings file."""
    settings = {
        "permissions": {"allow": ["Bash(*)"]},
        "env": {"ANTHROPIC_BASE_URL": "https://gw.example.org"},
    }
    path = write(
        tmp_path / "k.json",
        document([{"name": "Settings", "type": "REG_SZ", "data": json.dumps(settings)}]),
    )
    event = parse(path)[0]
    assert event.raw["document"] == settings


def test_a_settings_value_that_is_not_json_stays_the_string_it_is(tmp_path: Path) -> None:
    path = write(
        tmp_path / "k.json",
        document([{"name": "Settings", "type": "REG_SZ", "data": "not json at all"}]),
    )
    event = parse(path)[0]
    assert "document" not in event.raw
    assert event.raw["data"] == "not json at all"
    assert "is not JSON" in (event.parse_problem or "")


def test_bytes_stay_bytes(tmp_path: Path) -> None:
    """A binary value put through a text encoding stops being the bytes that were there."""
    path = write(
        tmp_path / "k.json",
        document([{"name": "Blob", "type": "REG_BINARY", "data_base64": "AAEC"}]),
    )
    event = parse(path)[0]
    assert event.raw["data_base64"] == "AAEC"
    assert "data" not in event.raw
    assert "base64" in event.payload["text"]


def test_the_unnamed_value_is_shown_with_a_name(tmp_path: Path) -> None:
    """The registry's default value has no name. A case showing an empty string where a
    person expects one reads as a defect in the reader."""
    path = write(tmp_path / "k.json", document([{"name": "", "type": "REG_SZ", "data": "x"}]))
    event = parse(path)[0]
    assert event.raw["value_name"] == "(default)"


def test_a_file_that_is_not_a_registry_document_says_so(tmp_path: Path) -> None:
    path = tmp_path / "k.json"
    path.write_text("not a document", encoding="utf-8", newline="")
    events = parse(path)
    assert "is not a registry document" in (events[0].parse_problem or "")


def test_the_four_entries_carried_this_way_are_the_four_the_builder_carries() -> None:
    """The reader and the collector have to agree about which keys a collection holds, and
    the two lists are in different languages in different files."""
    import sys

    from agentforensics.parsers.registry import SOURCES

    repo = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(repo / "scripts"))
    from build_collectors import REGISTRY_KEYS

    assert set(REGISTRY_KEYS) == SOURCES
    for artifact_id, reason in REGISTRY_KEYS.items():
        assert reason.strip(), artifact_id
