"""Normalizing a collection into one vendor-neutral log.

These run against the synthetic fixture tree rather than against hand-written events,
because the property worth proving is about a whole collection: every record that the
collection carried appears in the log, in a stable order, and every line of the log
satisfies the schema that the other producers validate against.
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

from agentforensics.catalog import Catalogue, load_catalogue
from agentforensics.model import Case
from agentforensics.unified import NormalizeReport, normalize, validator, write_log

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tests" / "fixtures"))

from generate import build_home  # noqa: E402


@pytest.fixture(scope="module")
def catalogue() -> Catalogue:
    return load_catalogue(REPO_ROOT / "catalog")


@pytest.fixture(scope="module")
def tree(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """One synthetic profile, built once: it is the same input for every test here."""
    home = tmp_path_factory.mktemp("profile")
    build_home(home)
    return home


@pytest.fixture(scope="module")
def log(tree: Path, catalogue: Catalogue) -> list[dict]:
    handle = io.StringIO()
    write_log(tree, catalogue, handle)
    return [json.loads(line) for line in handle.getvalue().splitlines()]


def test_every_line_satisfies_the_schema(log: list[dict]) -> None:
    """The one test that keeps this producer and a Velociraptor query interchangeable: both
    are held to the same file, so a change to one cannot quietly diverge from the other."""
    check = validator()
    for index, record in enumerate(log, start=1):
        try:
            check(record)
        except Exception as exc:  # the validator raises its own exception type
            pytest.fail(f"line {index} ({record.get('kind')}) does not validate: {exc}")


def test_every_record_names_its_agent(log: list[dict]) -> None:
    """Required by the format. An event that cannot be attributed is worth less than no
    event, because it is counted all the same."""
    assert all(record["agent"] for record in log)


def test_every_record_carries_its_origin_on_the_endpoint(log: list[dict]) -> None:
    for record in log:
        assert record["provenance"]["original_path"]
        assert record["provenance"]["locator"]


def test_the_three_agents_with_parsers_are_all_in_the_log(log: list[dict]) -> None:
    agents = {record["agent"] for record in log}
    assert {"claude_code", "codex", "copilot"} <= agents


def test_the_conversation_kinds_are_all_present(log: list[dict]) -> None:
    """The events the format exists to carry. A log with tool calls and no prompts, or the
    other way round, would mean a normalizer that reads half of a transcript."""
    kinds = {record["kind"] for record in log}
    for kind in (
        "session.start",
        "user.prompt",
        "assistant.text",
        "tool.call",
        "tool.result",
        "command.exec",
        "file.read",
        "permission.change",
        "artifact.fs",
    ):
        assert kind in kinds, kind


def test_a_tool_call_keeps_its_input(log: list[dict]) -> None:
    calls = [r for r in log if r["kind"] == "tool.call" and r["payload"].get("input")]
    assert calls, "a tool call with no arguments recorded anywhere would be a lossy mapping"


def test_a_command_keeps_its_command_line(log: list[dict]) -> None:
    commands = [r for r in log if r["kind"] == "command.exec"]
    assert commands
    for record in commands:
        assert record["payload"]["commands"][0]["command"]


def test_every_file_a_parser_claims_says_what_was_done_to_it(log: list[dict]) -> None:
    """The facet's field is `operation` and it has to be one of the five the format allows.

    The case database reads exactly that key and stores `unknown` when it is missing, so a
    parser that spelled it anything else would file every file it found as a file nobody
    knows what happened to, and a search for what an agent wrote would not find them. That
    is silent: the events are there, the counts look right, and the answer is wrong. It
    happened once, which is why this is a test.
    """
    allowed = {"read", "write", "delete", "snapshot", "unknown"}
    files = [
        (record["provenance"], entry)
        for record in log
        for entry in (record["payload"].get("files") or [])
    ]
    assert files, "the fixture has file facets, or this test is asserting nothing"
    for provenance, entry in files:
        assert entry.get("operation") in allowed, (provenance, entry)


def test_a_working_directory_reaches_the_log(log: list[dict]) -> None:
    assert any(record["project_path"] for record in log)


def test_records_no_parser_could_read_are_in_the_log(log: list[dict]) -> None:
    """The non-negotiable, carried into this format: a record that is quietly dropped reads
    as a record that never existed.

    The one record allowed to be empty in `raw` is a file that was read and was empty, and
    it has to say so: an empty object with nothing else on the event reads as a parser that
    came back with nothing, and those are opposite answers.
    """
    unreadable = [r for r in log if r["kind"] == "unparsed.record"]
    assert unreadable
    for record in unreadable:
        assert record["parse_problem"]
        if record["raw"] in (None, "", {}, []):
            assert "read and holds an empty" in record["parse_problem"], record["provenance"]


def test_a_file_with_no_parser_still_appears_once(log: list[dict], tree: Path) -> None:
    """As an artifact.fs record. It says the file was there and when it was written, which
    is the difference between no evidence and evidence nobody has read yet."""
    paths = {r["provenance"]["original_path"] for r in log if r["kind"] == "artifact.fs"}
    assert any(path.endswith("settings.json") for path in paths)


def test_the_order_is_stable_across_runs(tree: Path, catalogue: Catalogue) -> None:
    """Same input, same output. A log gets hashed and compared, and an order that depended
    on a dict iteration would break that silently."""
    first, _ = normalize(tree, catalogue)
    second, _ = normalize(tree, catalogue)
    assert [e.event_id for e in first] == [e.event_id for e in second]


def test_undated_records_sort_first_rather_than_being_dropped(
    tree: Path, catalogue: Catalogue
) -> None:
    """Their position is unknown, not early. Sorting them into a leading block is what says
    so: everything after the first dated record is in time order, everything before is not
    claimed to be."""
    events, _ = normalize(tree, catalogue)
    dated = [index for index, event in enumerate(events) if event.ts_utc is not None]
    undated = [index for index, event in enumerate(events) if event.ts_utc is None]
    assert undated, "the fixture has records with no timestamp"
    assert max(undated) < min(dated)


def test_the_report_names_what_it_could_not_read(tree: Path, catalogue: Catalogue) -> None:
    """The numbers that qualify the log travel with it. A log of ten thousand events from a
    collection that also held forty unreadable files is a different piece of evidence from
    one that read cleanly.

    """
    _, report = normalize(tree, catalogue)
    text = report.summary()
    assert report.unparsed_records > 0
    assert "nothing could read" in text
    assert report.files_unsupported > 0
    assert "have no parser" in text
    assert report.unclaimed_paths
    assert "no catalogue entry claims" in text


def test_a_record_read_out_of_an_unmapped_format_is_not_called_unreadable() -> None:
    """The two populations under `unparsed.record` are opposite answers, so the summary
    gives two numbers.

    A record nothing could read is a defect in the evidence, worth opening before the rest
    of the log is quoted. A record read out of a format nobody has mapped is intact evidence
    with no reading yet, and one store can hold a hundred thousand of them. Added up under
    the word unreadable, the one line that matters disappears into the rows that do not, and
    the total is wrong about almost all of what it counts.
    """
    report = NormalizeReport(
        bundle_uuid="b",
        source_kind="directory",
        source_path="/tmp/x",
        unparsed_records=5,
        unreadable_records=1,
        uninterpreted_records=4,
    )

    text = report.summary()

    assert "1 record(s) nothing could read" in text
    assert "4 record(s) read but in a format nobody has mapped" in text


def test_the_log_and_a_case_hold_the_same_events(
    tree: Path, catalogue: Catalogue, tmp_path: Path
) -> None:
    """The reason the two paths share their adapters and parsers. If the short path and the
    case path disagreed about what an agent's log says, there would be no way to tell which
    one was right."""
    from agentforensics.ingest import ingest

    case_path = tmp_path / "case.sqlite"
    with Case.open(case_path) as case:
        ingest(case, tree, catalogue)
        in_case = {row["event_id"] for row in case.query("SELECT event_id FROM events")}

    events, _ = normalize(tree, catalogue)
    assert {event.event_id for event in events} == in_case
