"""Tests for aider's chat log.

The file is markdown that one writer appends to, so every test here is built the way that
writer writes: a banner per run, `#### ` per line of a prompt, plain markdown for an answer,
and one blockquote for everything else the tool says.

The last of those is the point of several of these tests. Four different callers produce a
blockquote line and the file keeps nothing that tells them apart, so an approval and a
status notice look identical. What must not happen is that this parser decides which is
which and a case ends up holding approvals nobody gave.
"""

from __future__ import annotations

from pathlib import Path

from agentforensics.parsers import for_artifact
from agentforensics.parsers.base import ParseContext

ARTIFACT = "aider.chat_history"
PROJECT = "/home/alice/src/app"


def log(path: Path, text: str) -> Path:
    # newline="" so the file holds the bytes this test says it does: the format is line
    # oriented and a translated newline would change what is being read.
    path.write_text(text, encoding="utf-8", newline="")
    return path


def parse(path: Path, original: str | None = None) -> list:
    parser = for_artifact(ARTIFACT)
    assert parser is not None
    return list(
        parser.parse(
            ParseContext(
                bundle_uuid="b",
                original_path=original or f"{PROJECT}/.aider.chat.history.md",
                local_path=path,
                sha256="f" * 64,
                artifact_id=ARTIFACT,
                agent="aider",
                user="alice",
            )
        )
    )


# ------------------------------------------------------------------------ the turns


def test_a_prompt_typed_over_several_lines_comes_back_whole(tmp_path: Path) -> None:
    """The writer prefixes every line of a prompt and ends all but the last with two
    spaces, which is markdown for a line break rather than part of what was typed.

    Read one event per line, a prompt becomes a handful of fragments, and a fragment reads
    in a report as the whole of what somebody asked.
    """
    path = log(
        tmp_path / "chat.md",
        "\n#### remove the debug logging from:  \n#### src/app/index.js  \n#### src/app/util.js\n",
    )

    events = parse(path)

    assert len(events) == 1
    assert events[0].kind == "user.prompt"
    assert events[0].payload["text"] == (
        "remove the debug logging from:\nsrc/app/index.js\nsrc/app/util.js"
    )


def test_an_answer_keeps_the_code_the_model_emitted(tmp_path: Path) -> None:
    """This is the reason the file is worth collecting at all.

    An answer is written as plain markdown with no prefix, so the code blocks are in the
    file exactly as the model produced them. A reader that stripped the fences or the
    blank lines inside them would leave a case holding code that does not compile and
    cannot be compared against what is in the repository.
    """
    path = log(
        tmp_path / "chat.md",
        "\n#### fix it\n\nHere is the change.\n\n```python\nif x:\n\n    pass\n```\n\n",
    )

    events = parse(path)

    assert [event.kind for event in events] == ["user.prompt", "assistant.text"]
    assert events[1].payload["text"] == "Here is the change.\n\n```python\nif x:\n\n    pass\n```"


def test_an_empty_prompt_says_it_was_empty(tmp_path: Path) -> None:
    """The writer puts `<blank>` in the file when somebody pressed enter on nothing.

    Carried as text it reads as a prompt whose content was the word blank in angle
    brackets, which is a sentence nobody typed.
    """
    path = log(tmp_path / "chat.md", "\n#### <blank>\n")

    event = parse(path)[0]

    assert event.payload["text"] is None
    assert event.payload["empty"] is True


# ----------------------------------------------------------------------- the notices


def test_an_approval_is_carried_and_not_read_as_an_approval(tmp_path: Path) -> None:
    """The limit this parser refuses to guess past.

    `confirm_ask` writes the question and the letter somebody answered, and `tool_output`
    writes a status line. Both come out as one blockquote line and the file keeps nothing
    that tells them apart. Mapping the first to a permission decision on the shape of its
    text would put approvals in a case that nobody can show were given.
    """
    path = log(
        tmp_path / "chat.md",
        "> Add src/app/index.js to the chat? y  \n> Applied edit to src/app/index.js  \n",
    )

    events = parse(path)

    assert [event.kind for event in events] == ["unparsed.record", "unparsed.record"]
    assert events[0].payload["text"] == "Add src/app/index.js to the chat? y"
    assert events[1].payload["text"] == "Applied edit to src/app/index.js"
    assert all("nothing to tell them apart" in (event.parse_problem or "") for event in events)


def test_a_notice_between_two_prompts_does_not_join_them(tmp_path: Path) -> None:
    """Anything that is not a prompt line ends the prompt, which is the writer's own rule."""
    path = log(tmp_path / "chat.md", "\n#### first\n> a notice  \n\n#### second\n")

    kinds = [(event.kind, event.payload.get("text")) for event in parse(path)]

    assert kinds == [
        ("user.prompt", "first"),
        ("unparsed.record", "a notice"),
        ("user.prompt", "second"),
    ]


# ------------------------------------------------------------------------ the times


def test_each_run_starts_at_the_time_its_banner_says(tmp_path: Path) -> None:
    """A run writes the banner when its IO is built, so each one is the start of a run.

    The time is datetime.now() with no zone on it, read as UTC with the note this suite
    puts on every naive timestamp.
    """
    path = log(
        tmp_path / "chat.md",
        "\n# aider chat started at 2026-09-05 08:00:00\n\n#### one\n"
        "\n# aider chat started at 2026-09-05 09:30:00\n\n#### two\n",
    )

    starts = [event for event in parse(path) if event.kind == "session.start"]

    assert [event.ts_utc for event in starts] == [
        "2026-09-05T08:00:00.000000Z",
        "2026-09-05T09:30:00.000000Z",
    ]
    assert all("no timezone" in (event.parse_problem or "") for event in starts)


def test_no_turn_is_dated_from_the_run_it_belongs_to(tmp_path: Path) -> None:
    """The file has one time per run and none per turn.

    Dating every turn to the banner would put a day of work at one instant, and a timeline
    built from it would show a conversation that happened in a second.
    """
    path = log(
        tmp_path / "chat.md",
        "\n# aider chat started at 2026-09-05 08:00:00\n\n#### one\n\nan answer\n",
    )

    turns = [event for event in parse(path) if event.kind != "session.start"]

    assert turns
    assert all(event.ts_utc is None and event.ts_precision == "absent" for event in turns)


# ---------------------------------------------------------------------- the project


def test_every_event_names_the_working_copy_the_file_sits_in(tmp_path: Path) -> None:
    """The vendor joins this file name to the repository root.

    So the directory holding it is the working copy the conversation was about, and that
    is the only project attribution the file carries. It matters more here than elsewhere:
    this transcript lives in the repository, which is how it ends up committed by accident
    and recoverable from git objects long after a profile has been wiped.
    """
    path = log(tmp_path / "chat.md", "\n#### what broke\n\nthe lockfile\n> a notice  \n")

    events = parse(path)

    assert events
    assert all(event.project_path == PROJECT for event in events)
