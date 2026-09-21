"""Every subcommand, run the way an examiner runs it, against a real collection.

The entry point is the whole of this tool's interface. Everything under it has tests of
its own, and those call a function with the arguments it wants; the command line is the
layer that decides what those arguments are, and it is the layer nobody notices is broken
until somebody types the command. Four of the eleven subcommands appeared nowhere in the
command line tests at all.

What that layer can get wrong is not exotic. An option renamed on one side, a default that
stopped matching, an import that only happens when a subcommand runs: each of them leaves
every other test green and the command unusable, and the place it shows up is a live
response session where the only signal is an exit code.

So this walks the chain in the order an examiner does, over the synthetic profile, and then
asks every remaining subcommand for its help so that a parser nobody exercises still has to
be well formed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from agentforensics.cli import EXIT_FINDING, EXIT_OK, build_parser, main

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tests" / "fixtures"))

from generate import build_home  # noqa: E402

COMMANDS = (
    "verify",
    "catalog",
    "export-collection",
    "ingest",
    "normalize",
    "case",
    "instructions",
    "sessions",
    "scan",
    "serve",
    "timeline",
    "export",
)


def test_every_subcommand_has_a_parser_that_builds(capsys: pytest.CaptureFixture[str]) -> None:
    """A subcommand whose parser is malformed fails when it is asked for, not at import.

    Cheap and worth having on its own: it is the one check that covers the subcommands no
    test drives end to end, and it fails on a duplicated option or a default that no longer
    matches its type.
    """
    parser = build_parser()
    for command in COMMANDS:
        with pytest.raises(SystemExit) as exc:
            parser.parse_args([command, "--help"])
        assert exc.value.code == 0, command
        out = capsys.readouterr().out
        assert "usage:" in out, command


@pytest.fixture(scope="module")
def collection(tmp_path_factory: pytest.TempPathFactory) -> Path:
    home = tmp_path_factory.mktemp("cli-profile") / "home"
    build_home(home, with_edge_cases=False)
    return home


@pytest.mark.slow
def test_the_chain_an_examiner_runs(
    collection: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Read a collection, then ask the case every question the tool can answer.

    One test rather than eight, because the order is the point: each command here depends on
    what the one before it wrote, which is exactly the coupling that a test calling each
    function on its own cannot see.
    """
    case = tmp_path / "case.db"

    # Not zero, and that is the interface rather than a failure: this command exits with
    # the finding code when the source carried files no catalogue entry claims, which the
    # synthetic profile does on purpose, and a script that treated it as an error would
    # stop on the most ordinary result there is.
    assert main(["ingest", str(collection), "--case", str(case)]) in (EXIT_OK, EXIT_FINDING)
    assert case.exists()
    capsys.readouterr()

    assert main(["case", "--case", str(case), "--json"]) == EXIT_OK
    summary = json.loads(capsys.readouterr().out)
    assert summary["counts"]["events"] > 0, summary
    assert summary["agents"], "the case names no agent, so the ingest above did nothing"

    for command in ("instructions", "sessions", "scan"):
        # scan exits with the finding code when a rule fired, which over this profile it
        # does, so both are the command working.
        assert main([command, "--case", str(case)]) in (EXIT_OK, EXIT_FINDING), command
        assert capsys.readouterr().out.strip(), f"{command} printed nothing at all"

    exported = tmp_path / "timeline.csv"
    assert main(["timeline", "--case", str(case), "--out", str(exported)]) == EXIT_OK
    assert exported.stat().st_size > 0
    capsys.readouterr()

    # And the whole case written out at once, which is the last thing an examiner does
    # with it: the files that leave with the report.
    bundle_out = tmp_path / "export"
    assert main(["export", "--case", str(case), "--out", str(bundle_out)]) == EXIT_OK
    written = sorted(path.name for path in bundle_out.iterdir())
    assert "afx-events.jsonl" in written, written
    assert "afx-timeline.csv" in written, written
    for name in written:
        assert (bundle_out / name).stat().st_size > 0, name
    capsys.readouterr()


@pytest.mark.slow
def test_the_commands_that_need_no_case(collection: Path, tmp_path: Path) -> None:
    """The three that read the catalogue or a collection directly.

    They are in no other command line test, and each writes or prints something an examiner
    then works from, so "it ran" is not the assertion: what it produced has to exist.
    """
    assert main(["catalog"]) == EXIT_OK

    out = tmp_path / "rules"
    # The finding code again, for the same kind of reason: a format that cannot express
    # part of the catalogue says so through the exit code, because a rule with gaps is
    # still useful and whoever generated it has to know it has them.
    assert main(["export-collection", "--out", str(out)]) in (EXIT_OK, EXIT_FINDING)
    written = sorted(path.name for path in out.rglob("*") if path.is_file())
    assert written, "export-collection wrote no files"

    log = tmp_path / "agents.jsonl"
    assert main(["normalize", str(collection), "--out", str(log)]) in (EXIT_OK, EXIT_FINDING)
    lines = log.read_text(encoding="utf-8").splitlines()
    assert lines, "normalize produced an empty log"
    for line in lines[:20]:
        json.loads(line)
