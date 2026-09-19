"""Tests for the command line entry point.

Exit codes are part of this tool's interface, because it is driven from scripts and from
live-response sessions where the only signal is the exit code.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentforensics import __version__
from agentforensics.cli import EXIT_ERROR, EXIT_OK, build_parser, main
from agentforensics.model import (
    UNINTERPRETED_MARK,
    BundleRecord,
    Case,
    Event,
    Provenance,
)


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
