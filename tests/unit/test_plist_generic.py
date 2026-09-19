"""Tests for the property list reader.

Two of the three files this reader claims are managed preferences: policy pushed onto a Mac
by device management, written outside the user's profile, overriding what the user's own
settings say. So the failure to guard against is a policy file that a case cannot read and
does not mention, because an analyst then answers a question about what was allowed from
the user's own file, which is the file the policy overrode.
"""

from __future__ import annotations

import plistlib
from pathlib import Path

from agentforensics.catalog import load_catalogue
from agentforensics.parsers import for_artifact
from agentforensics.parsers.base import ParseContext
from agentforensics.parsers.plist_generic import DOCUMENTS

CATALOG_DIR = Path(__file__).resolve().parents[2] / "catalog"
POLICY = "claude_code.managed_settings_macos_profile"


def parse(path: Path, artifact: str = POLICY) -> list:
    parser = for_artifact(artifact)
    assert parser is not None, artifact
    return list(
        parser.parse(
            ParseContext(
                bundle_uuid="b",
                original_path=f"/Library/Managed Preferences/{path.name}",
                local_path=path,
                sha256="f" * 64,
                artifact_id=artifact,
                agent="claude_code",
                user=None,
            )
        )
    )


def write(path: Path, value: object, binary: bool = True) -> Path:
    with path.open("wb") as handle:
        plistlib.dump(value, handle, fmt=plistlib.FMT_BINARY if binary else plistlib.FMT_XML)
    return path


def test_a_managed_policy_reaches_the_case_as_a_configuration(tmp_path: Path) -> None:
    events = parse(
        write(tmp_path / "policy.plist", {"permissions": {"defaultMode": "bypassPermissions"}})
    )
    assert [event.kind for event in events] == ["config.snapshot"]
    assert events[0].raw["permissions"]["defaultMode"] == "bypassPermissions"


def test_the_binary_form_and_the_text_form_are_both_read(tmp_path: Path) -> None:
    """A managed preferences file is usually the binary one, so a reader that handled only
    the text form would report the policy as unreadable on exactly the machines that have a
    policy."""
    binary = parse(write(tmp_path / "binary.plist", {"apiKeyHelper": "/usr/local/bin/key"}))
    text = parse(write(tmp_path / "text.plist", {"apiKeyHelper": "/usr/local/bin/key"}, False))
    assert binary[0].raw == text[0].raw == {"apiKeyHelper": "/usr/local/bin/key"}


def test_a_list_of_tables_is_split_one_level_deep(tmp_path: Path) -> None:
    events = parse(
        write(
            tmp_path / "policy.plist",
            {"servers": [{"name": "one"}, {"name": "two"}], "version": 1},
        )
    )
    assert [event.provenance.locator for event in events] == ["$", "$.servers[0]", "$.servers[1]"]


def test_raw_data_is_kept_as_text_and_the_record_says_so(tmp_path: Path) -> None:
    """The alternative is an ingest that fails on the file, and a policy file that fails to
    ingest is a policy nobody sees."""
    events = parse(write(tmp_path / "policy.plist", {"token": b"\x01\x02\x03"}))
    assert events[0].raw["token"] == "AQID"
    assert "raw data value" in (events[0].parse_problem or "")


def test_a_file_that_is_not_a_property_list_says_so(tmp_path: Path) -> None:
    path = tmp_path / "policy.plist"
    path.write_bytes(b"this is not a property list\n")
    events = parse(path)
    assert [event.kind for event in events] == ["unparsed.record"]
    assert "could not be read as a property list" in (events[0].parse_problem or "")


def test_the_reader_claims_every_property_list_in_the_catalogue() -> None:
    catalogue = load_catalogue(CATALOG_DIR)
    assert {a.id for a in catalogue.artifacts if a.format == "plist"} == DOCUMENTS
