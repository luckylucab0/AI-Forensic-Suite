"""Tests for the reader over the shell environment one agent copies before it runs.

The file is a generated shell script, so the tests are about the line that the shell's own
grammar makes unambiguous and the line that it does not. A reader that read more than the
script states would be writing a shell; one that read less would leave the environment a
command ran in out of the case, which is where the variable that turned the prompts off is.
"""

from __future__ import annotations

from pathlib import Path

from agentforensics.model import is_uninterpreted
from agentforensics.parsers import ParseContext, for_artifact
from agentforensics.parsers.shell_snapshot import SURVIVED

ARTIFACT = "claude_code.shell_snapshots"


def parse(path: Path) -> list:
    parser = for_artifact(ARTIFACT)
    assert parser is not None
    return list(
        parser.parse(
            ParseContext(
                bundle_uuid="b1",
                original_path=f"/home/alice/.claude/shell-snapshots/{path.name}",
                local_path=path,
                sha256="aa",
                artifact_id=ARTIFACT,
                agent="claude_code",
                user="alice",
            )
        )
    )


def write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8", newline="")
    return path


def settings(events: list) -> dict[str, str | None]:
    return {
        event.payload["key"]: event.raw["value"]
        for event in events
        if event.kind == "config.snapshot" and "key" in (event.payload or {})
    }


def test_an_exported_variable_is_a_setting_with_its_name_searchable(tmp_path: Path) -> None:
    """A variable exported here was in force when the agent ran, which is a stronger
    statement than the same line in a history file."""
    path = write(
        tmp_path / "snapshot-1.sh",
        "export CLAUDE_CODE_SKIP_PROMPT_HISTORY=1\nexport PATH=/usr/bin:/bin\n",
    )
    found = settings(parse(path))
    assert found["export:CLAUDE_CODE_SKIP_PROMPT_HISTORY"] == "1"
    assert found["export:PATH"] == "/usr/bin:/bin"


def test_an_export_with_no_value_is_its_own_record(tmp_path: Path) -> None:
    """`export NAME` exports whatever an earlier line set, which is a different fact from
    exporting the empty string and has to stay distinguishable from it."""
    path = write(tmp_path / "snapshot-2.sh", 'export ALREADY_SET\nexport EMPTY=""\n')
    found = settings(parse(path))
    assert found["export:ALREADY_SET"] is None
    assert found["export:EMPTY"] == ""


def test_an_alias_keeps_its_name_even_when_the_shell_would_not_allow_it_as_a_variable(
    tmp_path: Path,
) -> None:
    path = write(tmp_path / "snapshot-3.sh", "alias ll='ls -la'\nalias g.='git status'\n")
    found = settings(parse(path))
    assert found["alias:ll"] == "ls -la"
    assert found["alias:g."] == "git status"


def test_a_function_comes_back_whole(tmp_path: Path) -> None:
    """What a wrapper does is invisible in the command a transcript records: the transcript
    shows the wrapper's name. Summarising the body would put the reader back where they
    started."""
    path = write(
        tmp_path / "snapshot-4.sh",
        'deploy () {\n  curl -H "Authorization: Bearer $TOKEN" https://example.org/deploy\n}\n',
    )
    found = settings(parse(path))
    body = found["function:deploy"]
    assert body is not None
    assert "Authorization: Bearer" in body
    assert "https://example.org/deploy" in body


def test_a_function_in_the_other_spelling_is_read_too(tmp_path: Path) -> None:
    path = write(tmp_path / "snapshot-5.sh", "function helper() {\n  true\n}\n")
    assert "function:helper" in settings(parse(path))


def test_a_function_that_never_closes_is_returned_and_said_to_be_unclosed(
    tmp_path: Path,
) -> None:
    """A snapshot is written as a session starts, so a truncated one is what a session
    killed mid-write leaves. What there is of the function is evidence."""
    path = write(tmp_path / "snapshot-6.sh", "wrapper () {\n  export TOKEN=secret-not-real\n")
    events = parse(path)
    found = settings(events)
    assert "export TOKEN=secret-not-real" in (found["function:wrapper"] or "")
    problems = [e.parse_problem or "" for e in events if e.kind == "config.snapshot"]
    assert any("no closing brace" in p for p in problems)


def test_a_line_that_is_none_of_the_three_is_kept_and_says_nobody_read_it(
    tmp_path: Path,
) -> None:
    """It is a shell script. A reader that decided what an arbitrary line means would be
    writing a shell, and a reader that dropped it would hide a record."""
    path = write(tmp_path / "snapshot-7.sh", "unalias -a\nshopt -s expand_aliases\n")
    events = [e for e in parse(path) if e.kind == "unparsed.record"]
    assert [e.raw["line"] for e in events] == ["unalias -a", "shopt -s expand_aliases"]
    assert all(is_uninterpreted(e) for e in events)


def test_the_file_being_there_at_all_is_an_event(tmp_path: Path) -> None:
    """The vendor states a snapshot is removed on a clean exit and that the directory
    survives the product's own purge command, so its presence is a fact about the session
    rather than about its contents."""
    path = write(tmp_path / "snapshot-8.sh", "export A=1\n")
    events = parse(path)
    assert events[0].payload["text"] == SURVIVED
    assert events[0].kind == "config.snapshot"


def test_a_file_that_is_not_text_is_recorded_rather_than_shown_as_noise(
    tmp_path: Path,
) -> None:
    path = tmp_path / "snapshot-9.sh"
    path.write_bytes(b"\x00\x01\x02binary\x00" * 40)
    events = parse(path)
    assert len(events) == 1
    assert "not the shell script" in (events[0].parse_problem or "")
