"""Tests for the shell history parser.

The shell's history is where an agent's start line is: the flag that switched the approvals
off, the variable that moved a configuration directory, the credential handed to a tool as
an option. Four files carry it, in four formats, and the failure this file guards against
is the quiet one in every case: a reader that produces events which look right and lose a
command, a time or a continuation line on the way.

Every sample here is written the way the shell itself writes the file, from the formats the
catalogue entries record against their sources.
"""

from __future__ import annotations

from pathlib import Path

from agentforensics.parsers import for_artifact
from agentforensics.parsers.base import ParseContext
from agentforensics.parsers.shell_history import DEDUPLICATED, NO_TIME

AGENT_RECALL = "gemini_cli.shell_history"
BASH = "crosscutting.shell_bash_history"
FISH = "crosscutting.shell_fish_history"
PSREADLINE = "crosscutting.shell_psreadline_history"
ZSH = "crosscutting.shell_zsh_history"


def parse(path: Path, artifact: str) -> list:
    parser = for_artifact(artifact)
    assert parser is not None, artifact
    return list(
        parser.parse(
            ParseContext(
                bundle_uuid="b",
                original_path=f"/home/alice/{path.name}",
                local_path=path,
                sha256="f" * 64,
                artifact_id=artifact,
                agent="crosscutting",
                user="alice",
            )
        )
    )


def write(path: Path, text: str) -> Path:
    # newline="" so the file holds the bytes the test says it holds: these formats are line
    # oriented, and a newline translated on the way in would be a different file.
    path.write_text(text, encoding="utf-8", newline="")
    return path


def commands(events: list) -> list[str]:
    return [event.payload["commands"][0]["command"] for event in events]


# ------------------------------------------------------------------------------ zsh


def test_the_extended_entry_gives_up_its_time_and_its_command(tmp_path: Path) -> None:
    events = parse(
        write(
            tmp_path / ".zsh_history",
            ": 1788912000:0;claude --dangerously-skip-permissions\n"
            ": 1788912060:12;codex exec 'fix the build'\n",
        ),
        ZSH,
    )
    assert commands(events) == [
        "claude --dangerously-skip-permissions",
        "codex exec 'fix the build'",
    ]
    assert [event.ts_utc for event in events] == [
        "2026-09-09T00:00:00.000000Z",
        "2026-09-09T00:01:00.000000Z",
    ]
    assert events[1].payload["commands"][0]["duration_s"] == 12
    assert events[0].payload["commands"][0]["executable"] == "claude"


def test_a_plain_entry_in_the_same_file_is_still_a_command(tmp_path: Path) -> None:
    """EXTENDED_HISTORY can be switched on part way through a profile's life, so one file
    holds both shapes. Reading only the extended one would drop every command from before
    the option was set, which is exactly the older evidence an investigation wants."""
    events = parse(
        write(
            tmp_path / ".zsh_history",
            "cd ~/src/app\n: 1788912000:0;claude --dangerously-skip-permissions\n",
        ),
        ZSH,
    )
    assert commands(events) == ["cd ~/src/app", "claude --dangerously-skip-permissions"]
    assert events[0].ts_utc is None
    assert events[0].parse_problem == NO_TIME


def test_a_command_that_begins_with_a_colon_is_not_read_as_a_header(tmp_path: Path) -> None:
    """`: > file` is the shortest way to truncate a file and it is a real line in a real
    history. Treating the leading colon as the extended header would turn an anti-forensic
    command into an entry with no command in it."""
    events = parse(write(tmp_path / ".zsh_history", ": > ~/.claude/history.jsonl\n"), ZSH)
    assert commands(events) == [": > ~/.claude/history.jsonl"]


def test_a_continued_command_comes_back_as_one_command(tmp_path: Path) -> None:
    """zsh ends a line with a backslash when the command carries on. Read line by line, a
    pipeline somebody wrote over three lines becomes three commands, two of which are
    fragments that read in a report as things that ran."""
    events = parse(
        write(
            tmp_path / ".zsh_history",
            ": 1788912000:0;curl -fsSL https://example.org/install.sh \\\n| sh\n"
            ": 1788912100:0;echo done\n",
        ),
        ZSH,
    )
    assert commands(events) == [
        "curl -fsSL https://example.org/install.sh \n| sh",
        "echo done",
    ]


# ----------------------------------------------------------------------------- bash


def test_the_timestamp_line_dates_the_command_behind_it(tmp_path: Path) -> None:
    events = parse(
        write(
            tmp_path / ".bash_history",
            "#1788912000\nclaude --dangerously-skip-permissions\n",
        ),
        BASH,
    )
    assert commands(events) == ["claude --dangerously-skip-permissions"]
    assert events[0].ts_utc == "2026-09-09T00:00:00.000000Z"


def test_a_time_belongs_to_one_command_and_not_to_the_rest_of_the_file(tmp_path: Path) -> None:
    """HISTTIMEFORMAT can be set for one session and unset for the next, so a file holds
    dated and undated entries together. Carrying the last stamp forward would date a year
    of commands to one minute, and a timeline is read as fact."""
    events = parse(
        write(tmp_path / ".bash_history", "#1788912000\nnpm install\ncodex exec\n"),
        BASH,
    )
    assert [event.ts_utc for event in events] == ["2026-09-09T00:00:00.000000Z", None]
    assert events[1].parse_problem == NO_TIME


def test_a_comment_that_is_not_a_timestamp_is_a_command(tmp_path: Path) -> None:
    """bash has no escaping at all, so a line beginning with a hash is only a stamp when
    the rest of it is digits. Anything else is what somebody typed, comment or not."""
    events = parse(write(tmp_path / ".bash_history", "# deploy the thing\nls\n"), BASH)
    assert commands(events) == ["# deploy the thing", "ls"]


# ----------------------------------------------------------------------------- fish


def test_the_record_gives_up_its_command_its_times_and_its_paths(tmp_path: Path) -> None:
    events = parse(
        write(
            tmp_path / "fish_history",
            "- cmd: aider --yes src/app/main.py\n"
            "  when: 1788912000\n"
            "  added_when: 1788911000\n"
            "  paths:\n"
            "    - src/app/main.py\n"
            "- cmd: git status\n"
            "  when: 1788912100\n",
        ),
        FISH,
    )
    assert commands(events) == ["aider --yes src/app/main.py", "git status"]
    assert events[0].payload["commands"][0]["fish_paths"] == ["src/app/main.py"]
    assert events[0].raw["added_when"] == 1788911000
    assert events[0].ts_utc == "2026-09-09T00:00:00.000000Z"


def test_the_two_escapes_are_undone_in_one_pass(tmp_path: Path) -> None:
    """fish replaces a newline with \\n and a backslash with \\\\. Undoing them one after
    the other turns a literal backslash followed by an n into a line feed, which splits a
    command that was never multi-line."""
    events = parse(
        write(
            tmp_path / "fish_history",
            "- cmd: printf 'a\\\\nb'\n  when: 1788912000\n",
        ),
        FISH,
    )
    assert commands(events) == ["printf 'a\\nb'"]


def test_a_file_with_no_record_in_it_says_so(tmp_path: Path) -> None:
    """The failure this reader used to have, and the reason ADR 0039 exists.

    fish announces every entry with `- cmd:`, and this reader skipped everything in front
    of the first one. A file at this path with no such line was all before-the-first-record,
    so the reader ran to the end of it and produced nothing: a shell with no commands in the
    case, which is what a shell nobody typed into also looks like.
    """
    events = parse(write(tmp_path / "fish_history", "the quick brown fox\njumps over\n"), FISH)

    assert len(events) == 1
    assert events[0].kind == "unparsed.record"
    assert "holds no record of that format" in (events[0].parse_problem or "")
    assert events[0].payload["text"] == "the quick brown fox\njumps over"
    assert events[0].provenance.locator == "line:1"


def test_a_file_that_begins_part_way_through_a_record_reports_the_remains(
    tmp_path: Path,
) -> None:
    """What a rotated history, a partial copy or an edited file leaves at the top.

    The fields are there and the command they belong to is not, which is a different
    finding from a file that is not a fish history at all: something was run and this file
    no longer says what. Both readings need the lines, so they are in the event, and the
    records below them are read as usual.
    """
    events = parse(
        write(
            tmp_path / "fish_history",
            "  when: 1788911000\n"
            "  paths:\n"
            "    - src/app/main.py\n"
            "- cmd: git status\n"
            "  when: 1788912100\n",
        ),
        FISH,
    )

    assert [event.kind for event in events] == ["unparsed.record", "command.exec"]
    assert events[0].provenance.locator == "line:1"
    assert "in front of the first '- cmd:' line" in (events[0].parse_problem or "")
    assert events[0].raw["lines"] == ["  when: 1788911000", "  paths:", "    - src/app/main.py"]
    assert commands(events[1:]) == ["git status"]


def test_a_history_of_blank_lines_is_still_silence(tmp_path: Path) -> None:
    """The one file silence is the true answer for, next to an empty one.

    Nothing was in it, the artifact row says it was collected, and a record claiming
    unreadable content would be a claim about bytes that are not there.
    """
    assert parse(write(tmp_path / "fish_history", "\n\n"), FISH) == []
    assert parse(write(tmp_path / "fish_history", ""), FISH) == []


def test_a_fragment_that_did_not_decode_says_so_once(tmp_path: Path) -> None:
    """The decode note belongs on the record, not once per line of it.

    Every line of a file that is not text carries the same note, and a sentence repeated
    forty times is a sentence nobody reads to the end of.
    """
    path = tmp_path / "fish_history"
    path.write_bytes(b"\xff\xfe one\n\xff\xfe two\n")

    events = parse(path, FISH)

    assert len(events) == 1
    problem = events[0].parse_problem or ""
    assert problem.count("did not decode") == 1
    assert "holds no record of that format" in problem


# ----------------------------------------------------------------------- psreadline


def test_every_entry_says_the_format_carries_no_time(tmp_path: Path) -> None:
    """This file cannot be timelined from its own content, and an undated event with no
    reason on it reads as a parser that lost the timestamp rather than as a format that
    never had one."""
    events = parse(
        write(tmp_path / "ConsoleHost_history.txt", "Get-ChildItem\nclaude --help\n"),
        PSREADLINE,
    )
    assert commands(events) == ["Get-ChildItem", "claude --help"]
    assert [event.parse_problem for event in events] == [NO_TIME, NO_TIME]


def test_the_backtick_continues_the_entry(tmp_path: Path) -> None:
    events = parse(
        write(
            tmp_path / "ConsoleHost_history.txt",
            "Invoke-WebRequest -Uri https://example.org/a.ps1 `\n  -OutFile a.ps1\n",
        ),
        PSREADLINE,
    )
    assert commands(events) == [
        "Invoke-WebRequest -Uri https://example.org/a.ps1 \n  -OutFile a.ps1"
    ]


# ------------------------------------------------------------------------ provenance


def test_every_event_points_at_the_line_it_came_from(tmp_path: Path) -> None:
    """A finding on a history file has to be checkable against the file, and the line is
    the only locator these formats have."""
    events = parse(
        write(tmp_path / ".bash_history", "ls\n#1788912000\ncodex exec\n"),
        BASH,
    )
    assert [event.provenance.locator for event in events] == ["line:1", "line:3"]


def test_a_line_that_did_not_decode_is_kept_and_said_to_be_inexact(tmp_path: Path) -> None:
    """A history file is bytes from whatever encoding the terminal had. Failing the read
    would lose every command in the file over one of them, and reading it silently would
    put a command in the case that differs from the one on disk."""
    path = tmp_path / ".bash_history"
    path.write_bytes(b"echo \xff\xfe\nls\n")
    events = parse(path, BASH)
    assert len(events) == 2
    assert "did not decode" in (events[0].parse_problem or "")


# --------------------------------------------------------------- the agent's own


def test_the_agents_own_history_is_one_command_per_line(tmp_path: Path) -> None:
    events = parse(
        write(tmp_path / "shell_history", "npm test\ngit status\n"),
        AGENT_RECALL,
    )
    assert commands(events) == ["npm test", "git status"]


def test_a_continued_command_is_rejoined_the_way_the_product_rejoins_it(tmp_path: Path) -> None:
    """With a space, not a line break. The vendor's own reader replaces the trailing
    backslash with a space, so a line break here would show a command the agent never
    assembled."""
    events = parse(
        write(tmp_path / "shell_history", "grep -r needle \\\n  src/\n"),
        AGENT_RECALL,
    )
    # The spacing is the vendor's arithmetic rather than a choice made here: the
    # trailing backslash is dropped, a space is put in its place, and the next line
    # follows with its own indentation intact.
    assert commands(events) == ["grep -r needle    src/"]


def test_an_even_number_of_backslashes_ends_the_command(tmp_path: Path) -> None:
    """Two trailing backslashes are an escaped backslash, not a continuation, which is what
    the product counts for. Getting it wrong glues two commands into one."""
    events = parse(
        write(tmp_path / "shell_history", "printf 'a\\\\'\nls\n"),
        AGENT_RECALL,
    )
    assert commands(events) == ["printf 'a\\\\'", "ls"]


def test_every_entry_says_the_file_holds_no_repeats(tmp_path: Path) -> None:
    """The absence this explains reads as evidence otherwise: a command that appears once
    may have run a hundred times, and one that is missing may have left the ring."""
    events = parse(write(tmp_path / "shell_history", "npm test\n"), AGENT_RECALL)
    assert DEDUPLICATED in (events[0].parse_problem or "")
    assert NO_TIME in (events[0].parse_problem or "")
