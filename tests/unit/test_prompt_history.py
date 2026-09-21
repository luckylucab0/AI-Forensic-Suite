"""Tests for the prompt history parser.

These files are the line editor's recall file, which is why they matter: they are
append-only, they sit outside the transcript store, and they outlive a swept or deleted
conversation. A prompt in one of them with no session anywhere in the case is a lead of its
own.

Three libraries write the three files and none of the formats is the others, so most of
what follows is about reading each one the way its own writer wrote it. Every sample here
is written the way the library's own code writes it, from the sources the parser cites.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from agentforensics.parsers import for_artifact
from agentforensics.parsers.base import ParseContext

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tests" / "fixtures"))

from generate import build_home  # noqa: E402

AIDER = "aider.input_history"
AMAZONQ = "amazonq.cli_prompt_history"
OLLAMA = "ollama.cli_prompt_history"


def parse(path: Path, artifact: str, agent: str = "aider", original: str | None = None) -> list:
    parser = for_artifact(artifact)
    assert parser is not None, artifact
    return list(
        parser.parse(
            ParseContext(
                bundle_uuid="b",
                original_path=original or f"/home/alice/{path.name}",
                local_path=path,
                sha256="f" * 64,
                artifact_id=artifact,
                agent=agent,
                user="alice",
            )
        )
    )


def write(path: Path, text: str) -> Path:
    # newline="" so the bytes are what the test says they are on every platform: these
    # formats are line oriented and a translated newline would change what is being read.
    path.write_text(text, encoding="utf-8", newline="")
    return path


# ------------------------------------------------------------------ prompt_toolkit


def test_a_multi_line_prompt_comes_back_whole(tmp_path: Path) -> None:
    """The reason this format exists, and the thing a naive reader loses.

    prompt_toolkit writes one `+` line per line of the entry, so a prompt somebody typed
    over four lines is four lines in the file. Read as one entry per line it would become
    four prompts, each of them a fragment, and a fragment reads in a report as what
    somebody asked.
    """
    path = write(
        tmp_path / ".aider.input.history",
        "\n# 2026-09-05 08:00:00.123456\n+fix this:\n+  line two\n+  line three\n",
    )

    events = parse(path, AIDER)

    assert len(events) == 1
    assert events[0].payload["text"] == "fix this:\n  line two\n  line three"
    assert events[0].kind == "prompt.history"
    assert events[0].actor == "user"


def test_the_headers_time_is_read_as_utc_and_the_event_says_so(tmp_path: Path) -> None:
    """The library writes datetime.now(), which is the endpoint's local time with no zone.

    This suite reads a naive timestamp as UTC and says so on the event, because the
    alternatives are to drop the record or to apply the analyst's own workstation zone,
    which would shift every prompt in the case by an unknown amount.
    """
    path = write(
        tmp_path / ".aider.input.history", "\n# 2026-09-05 08:00:00.123456\n+add the linter\n"
    )

    event = parse(path, AIDER)[0]

    assert event.ts_utc == "2026-09-05T08:00:00.123456Z"
    assert event.ts_precision == "exact"
    assert "no timezone" in (event.parse_problem or "")


def test_a_prompt_whose_header_is_missing_is_still_a_prompt(tmp_path: Path) -> None:
    """A file can begin part way through: a rotation, a partial copy, a truncated write.

    Dropping the entry because its header is gone would lose the record over its metadata,
    which is the trade this project never makes.
    """
    path = write(tmp_path / ".aider.input.history", "+what did the last change break\n")

    event = parse(path, AIDER)[0]

    assert event.payload["text"] == "what did the last change break"
    assert event.ts_utc is None
    assert event.ts_precision == "absent"


def test_two_entries_separated_by_a_blank_line_do_not_merge(tmp_path: Path) -> None:
    """A blank line ends an entry, which is the library's own rule.

    The shared line reader drops blank lines, because for line-delimited JSON a blank line
    is not a record. Here it is a separator, so this parser reads the file itself. Merged,
    two prompts would become one prompt nobody typed.
    """
    path = write(tmp_path / ".aider.input.history", "+first prompt\n\n+second prompt\n")

    events = parse(path, AIDER)

    assert [event.payload["text"] for event in events] == ["first prompt", "second prompt"]


def test_a_slash_command_carries_the_token_as_typed(tmp_path: Path) -> None:
    """What the line says, not what the command did.

    The slash commands are how somebody adds a file to the context or runs a shell command
    from the prompt, so they are worth finding. What ran is a question for the agent's own
    records; this field is the first token exactly as it was typed.
    """
    path = write(tmp_path / ".aider.input.history", "+/run pytest -x\n")

    event = parse(path, AIDER)[0]

    assert event.payload["typed_command"] == "/run"
    assert event.payload["text"] == "/run pytest -x"


def test_a_history_inside_a_repository_names_the_repository(tmp_path: Path) -> None:
    """The vendor joins the file name to the git root, so the directory is the project.

    It is the only project attribution these prompts have, and it is worth having: a
    prompt history in a working copy says which working copy somebody was typing in.
    """
    path = write(tmp_path / ".aider.input.history", "+what broke\n")

    event = parse(path, AIDER, original="/home/alice/src/app/.aider.input.history")[0]

    assert event.project_path == "/home/alice/src/app"


def test_a_history_in_a_profile_claims_no_project(tmp_path: Path) -> None:
    """The other side of the same rule. A history in a profile says nothing about which
    project a prompt belonged to, and filling it in from the file's own directory would
    attribute every prompt to the agent's configuration directory."""
    path = write(tmp_path / "history", "summarise this file\n")

    event = parse(path, OLLAMA, agent="ollama")[0]

    assert event.project_path is None


def test_a_file_with_no_entry_in_it_says_so(tmp_path: Path) -> None:
    """The failure this reader used to have, and the reason ADR 0039 exists.

    A file at this path whose content is not this format produced nothing at all: no event,
    and so no row in a timeline. An analyst filtering a case to what people typed saw an
    aider with no prompts, which is what an aider nobody used also looks like. Now the
    lines are in the case as a record nothing could read, with the reason on it.
    """
    path = write(tmp_path / ".aider.input.history", "the quick brown fox\njumps over\n")

    events = parse(path, AIDER)

    assert len(events) == 1
    assert events[0].kind == "unparsed.record"
    assert "holds no record of that format" in (events[0].parse_problem or "")
    # The content, not a count of lines: whether this is the wrong path, a file somebody
    # replaced or something else is a question only the lines themselves answer.
    assert events[0].payload["text"] == "the quick brown fox\njumps over"
    assert events[0].provenance.locator == "line:1"


def test_a_file_of_headers_with_no_prompt_under_them_says_so(tmp_path: Path) -> None:
    """Every line is a shape this format writes and there is still no prompt in it.

    It is the one file that reaches the end of this reader with nothing to report line by
    line, so it is the case the last statement in the reader is there for. A truncated copy
    that caught the stamps and none of the content looks like this.
    """
    path = write(tmp_path / ".aider.input.history", "\n# 2026-09-05 08:00:00.123456\n\n")

    events = parse(path, AIDER)

    assert [event.kind for event in events] == ["unparsed.record"]
    assert "holds no record of that format" in (events[0].parse_problem or "")


def test_a_stray_line_between_two_prompts_is_reported_and_keeps_both(tmp_path: Path) -> None:
    """A line the library that owns this file does not write, in a file that parses.

    Both prompts still come out, in order, and the lines in between are a record of their
    own rather than something that only closed the entry above them. The three events read
    downwards through the file, because a case ordered by locator is how somebody checks a
    finding against the bytes.
    """
    path = write(
        tmp_path / ".aider.input.history",
        "# 2026-09-05 08:00:00.123456\n"
        "+first prompt\n"
        "\x00 something else wrote this\n"
        "# 2026-09-05 09:00:00.123456\n"
        "+second prompt\n",
    )

    events = parse(path, AIDER)

    assert [event.kind for event in events] == [
        "prompt.history",
        "unparsed.record",
        "prompt.history",
    ]
    assert [event.provenance.locator for event in events] == ["line:2", "line:3", "line:5"]
    assert events[1].payload["text"] == "\x00 something else wrote this"
    assert "neither an entry nor the header of one" in (events[1].parse_problem or "")
    assert events[2].payload["text"] == "second prompt"


def test_a_history_of_blank_lines_is_still_silence(tmp_path: Path) -> None:
    """The one file silence is the true answer for, next to an empty one.

    Nothing was in it, the artifact row says it was collected, and a record claiming
    unreadable content would be a claim about bytes that are not there.
    """
    assert parse(write(tmp_path / ".aider.input.history", "\n\n\n"), AIDER) == []


# ---------------------------------------------------------------------- rustyline


def test_the_version_header_is_not_a_prompt(tmp_path: Path) -> None:
    """`#V2` is how rustyline says the entries below it are escaped.

    Read as content it becomes the oldest prompt in the case, which is a prompt nobody
    typed sitting at the top of a listing an analyst reads first.
    """
    path = write(tmp_path / ".cli_bash_history", "#V2\nwhy is the build red\n")

    events = parse(path, AMAZONQ, agent="amazonq")

    assert [event.payload["text"] for event in events] == ["why is the build red"]
    assert events[0].provenance.locator == "line:2", "and the line number is the file's own"


def test_an_escaped_entry_comes_back_as_the_text_that_was_typed(tmp_path: Path) -> None:
    """In a v2 file a line feed is written as backslash-n and a backslash as two.

    Left escaped, a multi-line prompt reads as one line with visible escapes, and a
    keyword search for a phrase that spans the break does not match it.
    """
    path = write(
        tmp_path / ".cli_bash_history",
        "#V2\nwrite a script that does:\\nstep one\\nstep two\npath C:\\\\Users\\\\alice\n",
    )

    events = parse(path, AMAZONQ, agent="amazonq")

    assert events[0].payload["text"] == "write a script that does:\nstep one\nstep two"
    assert events[1].payload["text"] == "path C:\\Users\\alice"
    assert all(event.parse_problem is None for event in events)


def test_a_file_without_the_header_is_not_unescaped(tmp_path: Path) -> None:
    """The older format escapes nothing, so unescaping it would corrupt what it holds.

    A prompt containing a literal backslash-n is ordinary in a shell context, and turning
    it into a line break would put a prompt in the case that nobody typed. The first line
    of such a file is an entry rather than a header.
    """
    path = write(
        tmp_path / ".cli_bash_history", "first prompt\nsecond prompt with a literal \\n in it\n"
    )

    events = parse(path, AMAZONQ, agent="amazonq")

    assert [event.payload["text"] for event in events] == [
        "first prompt",
        "second prompt with a literal \\n in it",
    ]


def test_an_escape_the_writer_does_not_produce_is_kept_as_it_is(tmp_path: Path) -> None:
    """What the vendor's own reader does with a line it cannot unescape.

    A backslash before anything other than n or a backslash means the line was written by
    something else or was edited. Keeping it exactly as it is on disk, and saying so, is
    the reading: a repaired line would hide that it was ever odd.
    """
    path = write(tmp_path / ".cli_bash_history", "#V2\nsomething \\q strange\n")

    event = parse(path, AMAZONQ, agent="amazonq")[0]

    assert event.payload["text"] == "something \\q strange"
    assert "kept exactly as it is on disk" in (event.parse_problem or "")


# -------------------------------------------------------------------------- plain


def test_one_line_is_one_prompt_and_there_are_no_times(tmp_path: Path) -> None:
    """ollama's readline writes the line and nothing else.

    No timestamp anywhere in the file, so every event says absent rather than being dated
    from the file's own mtime, which would give a hundred prompts one moment they did not
    happen at.
    """
    path = write(tmp_path / "history", "summarise this file\nwhat models do i have\n")

    events = parse(path, OLLAMA, agent="ollama")

    assert [event.payload["text"] for event in events] == [
        "summarise this file",
        "what models do i have",
    ]
    assert all(event.ts_utc is None and event.ts_precision == "absent" for event in events)


def test_an_empty_file_produces_nothing_rather_than_failing(tmp_path: Path) -> None:
    """An agent that was installed and never used leaves this file empty."""
    path = write(tmp_path / "history", "")

    assert parse(path, OLLAMA, agent="ollama") == []


def test_a_line_that_did_not_decode_says_so_on_its_own_event(tmp_path: Path) -> None:
    """A prompt read with replacement characters is not the prompt that was typed.

    The file is still read, because the lines around it are fine, and the one that is not
    exact carries that on the event rather than in a log nobody keeps.
    """
    path = tmp_path / "history"
    path.write_bytes(b"fine prompt\nbroken \xff\xfe prompt\n")

    events = parse(path, OLLAMA, agent="ollama")

    assert len(events) == 2
    assert events[0].parse_problem is None
    assert "did not decode" in (events[1].parse_problem or "")


@pytest.mark.parametrize("artifact", [AIDER, AMAZONQ, OLLAMA])
def test_every_history_in_the_table_has_this_parser(artifact: str) -> None:
    """The catalogue says which parser reads an entry and a separate test asserts the two
    agree. This one is the other direction: a file added to the table above without a
    catalogue entry, or an entry renamed, fails here."""
    parser = for_artifact(artifact)
    assert parser is not None
    assert parser.name == "prompt_history"


def test_the_collector_finds_all_three_in_a_profile(tmp_path: Path) -> None:
    """The end of the chain, and one trap that only a real collection can catch.

    Amazon Q's chat prompt history is a dotfile inside a dotdirectory. A collector whose
    globs do not reach hidden files inside `~/.aws/amazonq` misses it and says nothing,
    which is how the best answer to what somebody actually asked goes absent from a case
    that otherwise looks complete. The catalogue entry warns about it; this asserts it.
    """
    spec = importlib.util.spec_from_file_location(
        "collect_ph", REPO_ROOT / "collector" / "collect.py"
    )
    assert spec is not None and spec.loader is not None
    collect = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(collect)

    home = tmp_path / "home"
    build_home(home, with_edge_cases=False)
    out = tmp_path / "bundle"
    collect.main(["--out", str(out), "--root", str(home), "--os", "linux"])
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))

    found = {entry["artifact_id"] for entry in manifest["files"]}
    assert AIDER in found
    assert AMAZONQ in found, "a dotfile inside a dotdirectory is still evidence"
    assert OLLAMA in found
