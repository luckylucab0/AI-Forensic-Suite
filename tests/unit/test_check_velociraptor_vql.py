"""Tests for the VQL engine check, which is the one check that needs a program we ship none of.

There is a limit to what can be asserted without a Velociraptor binary, and it is worth
being precise about it. What is pinned here is the command line and the guard rails: the
invocation this script builds, the fact that it does nothing rather than something wrong
when no engine is given, and that the sandbox rewrite it depends on actually moves every
profile root out of the way. Whether Velociraptor accepts that command line is a question
only CI can answer, and the job that does so is where it is answered.

The command line is worth a test rather than only a comment because getting a flag wrong
here does not fail loudly: `velociraptor query` without `--from_files` would treat the file
name as the query text and return a single row of nothing, which reads exactly like a clean
run over a machine that never had an agent on it.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "check_velociraptor_vql.py"


def load():
    spec = importlib.util.spec_from_file_location("check_vql_under_test", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def script():
    return load()


def test_the_velociraptor_command_line_is_the_verified_one(script) -> None:
    """Read out of the vendor's own command definition. Each flag earns its place:
    --from_files or the file name becomes the query, jsonl or the output is not one object
    per row, --output or it goes to stdout mixed with the engine's own logging, and
    --nocolor before the command or escape codes reach the parser."""
    command = script.velociraptor_command(Path("/opt/vr"), Path("/tmp/q.vql"), Path("/tmp/o.jsonl"))

    assert command == [
        "/opt/vr",
        "--nocolor",
        "query",
        "--from_files",
        "--format",
        "jsonl",
        "--output",
        "/tmp/o.jsonl",
        "/tmp/q.vql",
    ]
    # The application flag goes before the subcommand, which is how kingpin parses it.
    assert command.index("--nocolor") < command.index("query")


def test_without_an_engine_it_does_nothing_and_says_so(script) -> None:
    """So it can sit in CI unconditionally. Exiting non-zero would make the absence of a
    binary look like a failing check, and exiting quietly would make it look like a passing
    one."""
    result = subprocess.run(
        [sys.executable, str(SCRIPT)], capture_output=True, text=True, check=False
    )

    assert result.returncode == 0
    assert "not checked here is engine behaviour" in result.stdout


def test_two_engines_at_once_is_refused(script) -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--runner", "/bin/true", "--velociraptor", "/bin/true"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 2
    assert "not both" in result.stderr


def test_a_missing_engine_is_an_error_and_not_a_skip(script) -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--velociraptor", "/nonexistent/velociraptor"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 2
    assert "no such runner" in result.stderr


# Where an absolute path can begin inside the generated query: the delimiters that surround
# a glob in a CSV data block, a VQL string, a regex anchor or an argument. Used to find the
# start of the path a given occurrence sits in, which is the only way to judge it: the
# profile roots overlap, and /root/ inside an already-moved /var/root/ is fine while /root/
# on its own is a glob pointing at the machine this runs on.
PATH_START = "'\",;= ^[(\n\t"


def path_start(text: str, index: int) -> int:
    position = index
    while position > 0 and text[position - 1] not in PATH_START:
        position -= 1
    return position


def test_every_profile_glob_is_moved_under_the_sandbox(script) -> None:
    """The sandbox is the part of this script that matters.

    A collection artifact's whole job is to go and find agent data wherever it lives, so a
    run with one glob left alone would read the machine it runs on, and this project's
    second rule is that real agent data never reaches a test or a log. The rewrite is
    therefore asserted rather than trusted, over the whole query text: the globs live in a
    CSV data block without quotes around them, so checking only the quoted literals would
    check the regexes and nothing else.
    """
    import yaml

    document = yaml.safe_load(script.ARTIFACT.read_text(encoding="utf-8"))
    sandbox = Path("/tmp/afx-sandbox")
    prefix = str(sandbox)

    for os_name in sorted(script.PROFILE_PLACEMENTS):
        query = script.sandbox_query(document, os_name, sandbox)

        # One: the prefix is a prefix. An occurrence in the middle of a path means a
        # rewrite matched inside its own output, which is the bug this script's own comment
        # records: /var/root/ was moved, then /root/ matched inside the result and left a
        # path that is still under the sandbox and points at nothing. Under the sandbox and
        # wrong is the harder failure to see, because the safety check still passes.
        for found in re.finditer(re.escape(prefix), query):
            assert path_start(query, found.start()) == found.start(), (
                f"{os_name}: the sandbox appears inside a path rather than at its start, "
                f"near {query[max(0, found.start() - 40) : found.start() + 40]!r}"
            )

        # Two: every profile root is under it. Judged from the start of the path the
        # occurrence sits in, because the roots overlap.
        for root in script.PROFILE_ROOTS:
            for found in re.finditer(re.escape(root), query):
                begins = path_start(query, found.start())
                assert query[begins:].startswith(prefix), (
                    f"{os_name}: the glob "
                    f"{query[begins : found.end() + 30]!r} starts at the profile root "
                    f"{root!r} and not under the sandbox, so it would read the machine "
                    "this runs on"
                )


def test_the_sandbox_rewrite_would_notice_a_new_profile_root(script) -> None:
    """A root added to the exporter and not to this script is the silent version of the
    same failure, so the script refuses to run rather than rewriting nothing."""
    document = {
        "parameters": [],
        "sources": [{"name": "linux", "query": "SELECT * FROM glob(globs='/opt/nothing/*')"}],
    }

    with pytest.raises(SystemExit, match="none of the known profile roots"):
        script.sandbox_query(document, "linux", Path("/tmp/afx-sandbox"))


def test_the_artifact_the_script_reads_is_the_committed_one(script) -> None:
    """A path that drifted would make this check read something nobody ships."""
    assert script.ARTIFACT.is_file()
    assert script.ARTIFACT.is_relative_to(REPO / "exporters" / "generated")
