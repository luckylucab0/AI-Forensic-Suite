"""Tests for the command line entry point.

Exit codes are part of this tool's interface, because it is driven from scripts and from
live-response sessions where the only signal is the exit code.
"""

from __future__ import annotations

import pytest

from agentforensics import __version__
from agentforensics.cli import EXIT_ERROR, build_parser, main


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
