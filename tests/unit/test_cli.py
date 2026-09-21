"""Tests for the command line entry point.

Exit codes are part of this tool's interface, because it is driven from scripts and from
live-response sessions where the only signal is the exit code.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from agentforensics import __version__
from agentforensics.cli import (
    EXIT_ERROR,
    EXIT_NOTHING_FOUND,
    EXIT_OK,
    build_parser,
    main,
)
from agentforensics.model import (
    UNINTERPRETED_MARK,
    BundleRecord,
    Case,
    Event,
    Provenance,
)
from agentforensics.webui import api


def test_version_is_reported(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_no_command_prints_help_and_fails(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == EXIT_ERROR
    assert "usage:" in capsys.readouterr().err


def test_help_names_the_planned_commands(capsys: pytest.CaptureFixture[str]) -> None:
    """The help text describes the tool being built, not only the part that exists, so a
    user is not left guessing whether a capability is missing or merely undocumented."""
    with pytest.raises(SystemExit):
        build_parser().parse_args(["--help"])
    out = capsys.readouterr().out
    for command in ("verify", "ingest", "timeline", "scan", "serve"):
        assert command in out


def test_the_help_does_not_advertise_a_gap_that_is_filled(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The planned list is a promise, so it has to empty as the promises are kept: a gap
    advertised after it was filled sends a user looking for another tool."""
    with pytest.raises(SystemExit):
        build_parser().parse_args(["--help"])
    out = capsys.readouterr().out
    assert "not implemented yet" not in out
    assert "export" in out


def test_authorization_is_mentioned_in_the_help(capsys: pytest.CaptureFixture[str]) -> None:
    """This tool reads other people's prompts and files. The first thing a user sees
    should say that using it requires authorization."""
    with pytest.raises(SystemExit):
        build_parser().parse_args(["--help"])
    assert "authorization" in capsys.readouterr().out.lower()


# ---------------------------------------------------------------- the case summary


def _case_with_unread(path: Path) -> Path:
    """A case holding one record nobody could read and two nobody has mapped."""
    with Case.open(path) as case, case.transaction():
        case.add_bundle(BundleRecord("bundle-1", "native", "/tmp/b"))
        case.add_events(
            [
                Event(
                    kind="unparsed.record",
                    provenance=Provenance(
                        "bundle-1", "/home/alice/a.log", "aa", "agent.debug_logs", f"line:{n}"
                    ),
                    agent="claude_code",
                    raw={"line": n},
                    parse_problem=f"read but {UNINTERPRETED_MARK}",
                )
                for n in (1, 2)
            ]
            + [
                Event(
                    kind="unparsed.record",
                    provenance=Provenance(
                        "bundle-1", "/home/alice/b.jsonl", "bb", "agent.transcripts", "line:1"
                    ),
                    agent="claude_code",
                    raw={"line": 1},
                    parse_problem="the line could not be read",
                )
            ]
        )
    return path


def test_the_case_summary_says_where_the_unread_records_are(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The counts say how many; an analyst's next question is which files, because one
    debug log and every transcript on the machine give the same number."""
    case_path = _case_with_unread(tmp_path / "case.sqlite")
    assert main(["case", "--case", str(case_path)]) == EXIT_OK

    err = capsys.readouterr().err
    assert "record(s) nothing could read" in err
    assert "agent.debug_logs" in err
    assert "agent.transcripts" in err


def test_the_json_summary_carries_the_same_breakdown(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    case_path = _case_with_unread(tmp_path / "case.sqlite")
    assert main(["case", "--case", str(case_path), "--json"]) == EXIT_OK

    out = json.loads(capsys.readouterr().out)
    rows = {row["artifact_id"]: row for row in out["unread"]["artifacts"]}
    assert rows["agent.debug_logs"]["uninterpreted"] == 2
    assert rows["agent.transcripts"]["unreadable"] == 1
    assert out["unread"]["total"] == 2


# ------------------------------------------------- the keys an examiner supplies


def test_a_key_is_taken_from_the_command_line() -> None:
    from agentforensics.cli import _keys

    assert _keys(["windsurf=aabbcc"]) == {"windsurf": "aabbcc"}


def test_a_key_may_come_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """So that a key does not sit in a shell history, which this suite reads for a living."""
    from agentforensics.cli import _keys

    monkeypatch.setenv("AFX_KEY_WINDSURF", "ddeeff")
    assert _keys(None) == {"windsurf": "ddeeff"}


def test_the_command_line_wins_over_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    from agentforensics.cli import _keys

    monkeypatch.setenv("AFX_KEY_WINDSURF", "from-the-environment")
    assert _keys(["windsurf=from-the-command-line"]) == {"windsurf": "from-the-command-line"}


def test_a_malformed_key_argument_is_refused_rather_than_ignored() -> None:
    """A key that silently did not apply produces a case saying the store could not be
    opened, which is the same output as a wrong key and a different fact."""
    from agentforensics.cli import _keys

    with pytest.raises(ValueError):
        _keys(["windsurf"])
    with pytest.raises(ValueError):
        _keys(["=aabbcc"])


def test_ingest_refuses_to_run_with_a_malformed_key(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "tree"
    (source / "home").mkdir(parents=True)
    assert (
        main(
            [
                "ingest",
                str(source),
                "--case",
                str(tmp_path / "case.sqlite"),
                "--key",
                "windsurf",
            ]
        )
        == EXIT_ERROR
    )
    assert "--key expects AGENT=KEY" in capsys.readouterr().err


# ----------------------------------------------------- the export of a whole case


def _case_with_a_conversation(path: Path, turns: int = 5) -> Path:
    """A case holding one conversation: one prompt and one tool call per turn."""
    with Case.open(path) as case, case.transaction():
        case.add_bundle(BundleRecord("bundle-1", "native", "/tmp/b"))
        events: list[Event] = []
        for turn in range(1, turns + 1):
            stamp = f"2026-01-01T00:00:{turn:02d}.000000Z"
            provenance = Provenance(
                "bundle-1",
                "/home/alice/session.jsonl",
                "aa",
                "agent.transcripts",
                f"line:{turn}",
            )
            events.append(
                Event(
                    kind="user.prompt",
                    provenance=provenance,
                    agent="claude_code",
                    raw={"line": turn},
                    ts_utc=stamp,
                    ts_precision="exact",
                    ts_source="timestamp",
                    actor="user",
                    session_id="s-1",
                    project_path="/home/alice/project",
                    payload={"text": f"turn {turn}"},
                )
            )
            events.append(
                Event(
                    kind="tool.call",
                    provenance=provenance,
                    agent="claude_code",
                    raw={"line": turn},
                    ts_utc=stamp,
                    ts_precision="exact",
                    ts_source="timestamp",
                    actor="assistant",
                    session_id="s-1",
                    project_path="/home/alice/project",
                    payload={"tool": "Bash", "summary": f"ls {turn}"},
                )
            )
        case.add_events(events)
    return path


def _rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def test_an_export_writes_every_view_and_the_events(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """One command, one directory, and a file per view an analyst attaches to a report."""
    case_path = _case_with_a_conversation(tmp_path / "case.sqlite")
    out = tmp_path / "export"
    assert main(["export", "--case", str(case_path), "--out", str(out)]) == EXIT_OK

    written = sorted(path.name for path in out.iterdir())
    assert written == [
        "afx-artifacts.csv",
        "afx-conversations.csv",
        "afx-events.jsonl",
        "afx-findings.csv",
        "afx-instructions.csv",
        "afx-timeline.csv",
        "afx-tools.csv",
    ]
    # The viewer's own event shape, which is what makes an export openable in the
    # standalone viewer with nothing behind the page.
    records = [
        json.loads(line)
        for line in (out / "afx-events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert len(records) == 10
    for record in records:
        assert record["v"], "a record with no format version is not a unified log record"
        assert record["event_id"]
        assert record["provenance"]["original_path"] == "/home/alice/session.jsonl"

    # The numbers that qualify the case travel with the files, because the files are read
    # away from the case.
    assert "record(s) nothing could read" in capsys.readouterr().err


def test_an_exported_file_is_the_bytes_the_api_serves(tmp_path: Path) -> None:
    """A file attached to a report and the table on screen must not be able to describe one
    case differently, so neither of them may have a renderer of its own."""
    case_path = _case_with_a_conversation(tmp_path / "case.sqlite")
    out = tmp_path / "export"
    assert main(["export", "--case", str(case_path), "--out", str(out)]) == EXIT_OK

    with Case.open(case_path, create=False, read_only=True) as case:
        for name in api.EXPORTS:
            served = api.export_csv(case, name).encode("utf-8")
            assert (out / f"afx-{name}.csv").read_bytes() == served, name
        log = "".join(api.log_lines(case)).encode("utf-8")
    assert (out / "afx-events.jsonl").read_bytes() == log


def test_an_export_holds_the_whole_view_and_not_one_page(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Paged projections, written whole.

    The page size is cut to two records here rather than a case being built with twenty
    thousand events in it: what has to be pinned is that the writer keeps asking until the
    projection says there is no next page, and a view that quietly held the first page
    would be a document making a claim about a case that nobody could reproduce.
    """
    monkeypatch.setattr(api, "MAX_PAGE", 2)
    case_path = _case_with_a_conversation(tmp_path / "case.sqlite")
    out = tmp_path / "export"
    assert main(["export", "--case", str(case_path), "--out", str(out)]) == EXIT_OK

    lines = (out / "afx-events.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 10, "the event log stopped at a page boundary"
    assert len(_rows(out / "afx-tools.csv")) == 5, "the tool view stopped at a page boundary"
    assert len(_rows(out / "afx-timeline.csv")) == 10


def test_a_view_with_nothing_in_it_is_still_written(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An absent file reads as a view nobody exported, which is a different fact from a view
    with nothing in it. In a forensic tool that difference is the whole point."""
    case_path = tmp_path / "empty.sqlite"
    with Case.open(case_path):
        pass
    out = tmp_path / "export"
    # Nothing found rather than success: a case holding nothing is a valid result, and a
    # script has to be able to tell it from a crash.
    assert main(["export", "--case", str(case_path), "--out", str(out)]) == EXIT_NOTHING_FOUND

    for name in api.EXPORTS:
        target = out / f"afx-{name}.csv"
        header = target.read_text(encoding="utf-8").splitlines()
        assert header, f"{name} was written as no bytes at all"
        assert "," in header[0], f"{name} was written without the columns it has"
        assert _rows(target) == []
    assert (out / "afx-events.jsonl").read_text(encoding="utf-8") == ""
    assert "held no rows" in capsys.readouterr().err


def test_a_view_that_is_not_a_view_is_refused_and_the_views_are_named(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A misspelled view that wrote no file would leave an analyst holding an export they
    believe is complete, so it is a usage error and nothing is written at all."""
    case_path = _case_with_a_conversation(tmp_path / "case.sqlite")
    out = tmp_path / "export"
    assert (
        main(["export", "--case", str(case_path), "--out", str(out), "--view", "passwords"])
        == EXIT_ERROR
    )
    err = capsys.readouterr().err
    assert "no view named passwords" in err
    for name in (*api.EXPORTS, "events"):
        assert name in err
    assert not out.exists(), "a refused export left a directory behind"


def test_one_view_can_be_asked_for_on_its_own(tmp_path: Path) -> None:
    case_path = _case_with_a_conversation(tmp_path / "case.sqlite")
    out = tmp_path / "export"
    assert (
        main(["export", "--case", str(case_path), "--out", str(out), "--view", "timeline"])
        == EXIT_OK
    )
    assert sorted(path.name for path in out.iterdir()) == ["afx-timeline.csv"]


def test_the_export_report_says_where_the_files_are(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The machine-readable form, for the script that has to find the files afterwards."""
    case_path = _case_with_a_conversation(tmp_path / "case.sqlite")
    out = tmp_path / "export"
    assert main(["export", "--case", str(case_path), "--out", str(out), "--json"]) == EXIT_OK

    report = json.loads(capsys.readouterr().out)
    files = {entry["view"]: entry for entry in report["files"]}
    assert set(files) == {*api.EXPORTS, "events"}
    for view, entry in files.items():
        assert Path(entry["path"]).exists(), view
        assert entry["bytes"] > 0, view
    assert files["events"]["rows"] == 10
    assert files["tools"]["rows"] == 5


def test_a_case_that_is_not_there_is_an_error_rather_than_an_empty_export(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "export"
    assert (
        main(["export", "--case", str(tmp_path / "absent.sqlite"), "--out", str(out)]) == EXIT_ERROR
    )
    assert capsys.readouterr().err.startswith("export:")
    assert not out.exists()
