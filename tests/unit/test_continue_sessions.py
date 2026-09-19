"""Tests for Continue's session store.

This store is unusual twice over, and both are asserted here.

It has no clock. Not on a session, not on a turn. The only time in it is `dateCreated` in
the index, and it is a number in a string. So most of these tests are about a gap that is
reported as a gap rather than filled in from the one time that does exist.

And it records three things a transcript usually does not: the status a tool call was left
in, the files and URLs that were put in front of the model, and the rule files the product
says applied to a turn. The last of those is the instruction surface answered per turn
rather than per endpoint, which nothing else in this catalogue can do.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentforensics.parsers import for_artifact
from agentforensics.parsers.base import ParseContext

REPO_ROOT = Path(__file__).resolve().parents[2]
import sys  # noqa: E402

sys.path.insert(0, str(REPO_ROOT / "tests" / "fixtures"))

from generate import (  # noqa: E402
    CONTINUE_HIDDEN,
    CONTINUE_SESSION,
    continue_index,
    continue_session,
)

ARTIFACT = "continue.sessions"
STORE = "/home/alice/.continue/sessions"


def parse(path: Path) -> list:
    parser = for_artifact(ARTIFACT)
    assert parser is not None
    return list(
        parser.parse(
            ParseContext(
                bundle_uuid="b",
                original_path=f"{STORE}/{path.name}",
                local_path=path,
                sha256="f" * 64,
                artifact_id=ARTIFACT,
                agent="continue",
                user="alice",
            )
        )
    )


def write(path: Path, value: object) -> Path:
    text = value if isinstance(value, str) else json.dumps(value)
    path.write_text(text, encoding="utf-8", newline="")
    return path


def session(tmp_path: Path, document: object | None = None) -> list:
    body = continue_session() if document is None else document
    return parse(write(tmp_path / f"{CONTINUE_SESSION}.json", body))


def index(tmp_path: Path, document: object | None = None) -> list:
    body = continue_index() if document is None else document
    return parse(write(tmp_path / "sessions.json", body))


def one(events: list, kind: str) -> object:
    return next(event for event in events if event.kind == kind)


# --------------------------------------------------------------------- the clock


def test_nothing_in_a_session_file_is_dated(tmp_path: Path) -> None:
    """Because nothing in it carries a date. The vendor's own type has no timestamp on the
    session or on a message, and dating the turns from the index would put a whole
    conversation at the moment it was first saved."""
    events = [event for event in session(tmp_path) if event.kind != "assistant.thinking"]

    assert events
    assert all(event.ts_utc is None for event in events)
    for event in events:
        # The statement travels as a parse problem on an ordinary turn and in the payload on
        # an instruction, because the instruction surface counts a file with a parse problem
        # as one that was not fully read, and these were read completely.
        said = (event.parse_problem or "") + (event.payload.get("timing_note") or "")
        assert "no timestamp" in said, event.kind


def test_the_one_clock_in_a_session_is_the_reasoning_block(tmp_path: Path) -> None:
    """`startAt` is epoch milliseconds and it is the only time the vendor's type puts inside
    a session file. It dates the thinking and nothing else."""
    thinking = one(session(tmp_path), "assistant.thinking")

    assert thinking.ts_utc == "2026-09-07T09:15:01.000000Z"
    assert "startAt" in (thinking.ts_source or "")


def test_the_index_time_is_read_as_the_epoch_it_is(tmp_path: Path) -> None:
    """`String(Date.now())`, so a number in a string. Read as a date it is unparseable and
    the session loses the only time anybody has for it."""
    starts = [event for event in index(tmp_path) if event.kind == "session.start"]

    assert [event.ts_utc for event in starts] == [
        "2026-09-07T09:15:00.000000Z",
        "2026-07-25T17:20:00.000000Z",
    ]
    assert "first saved" in (starts[0].ts_source or "")


# --------------------------------------------------------------------- the index


def test_a_session_the_product_hides_is_in_the_case(tmp_path: Path) -> None:
    """The vendor's own reader filters out every entry that names its session under
    `session_id`, calling it the old format. That conversation is in the store and not in
    the list the product shows, which is exactly the kind of thing a case exists to surface.
    """
    hidden = next(
        event
        for event in index(tmp_path)
        if event.payload.get("hidden_from_the_session_list") is True
    )

    assert hidden.session_id == CONTINUE_HIDDEN
    assert "old format" in (hidden.parse_problem or "")
    assert "not in the product's list" in (hidden.parse_problem or "")


def test_the_message_count_says_what_it_counts(tmp_path: Path) -> None:
    """It counts assistant messages, not turns. An analyst comparing it against the length
    of a history finds a mismatch that is not evidence of anything, so the event says so
    rather than leaving the number to be read as a total."""
    first = index(tmp_path)[0]

    assert first.payload["assistant_messages"] == 1
    assert "not the number of turns" in first.payload["count_meaning"]


def test_an_index_that_is_not_a_list_is_reported(tmp_path: Path) -> None:
    """The vendor's reader accepts nothing else, so a case has to see that this file is in a
    shape the product itself would not read."""
    events = index(tmp_path, {"sessions": []})

    assert events[0].kind == "unparsed.record"
    assert "not a list" in (events[0].parse_problem or "")


# ------------------------------------------------------------------ the history


def test_the_roles_become_the_turns_they_are(tmp_path: Path) -> None:
    events = session(tmp_path)
    kinds = [event.kind for event in events]

    assert "user.prompt" in kinds
    assert "assistant.text" in kinds
    assert "assistant.thinking" in kinds
    assert one(events, "tool.result").payload["tool_use_id"] == "call-1"


def test_a_role_the_union_does_not_name_is_carried_whole(tmp_path: Path) -> None:
    """The vendor's ChatMessage union can grow. A new role read as an old one would put a
    turn in a case under the wrong actor, which is wrong and silent."""
    events = session(
        tmp_path,
        json.dumps(
            {
                "sessionId": CONTINUE_SESSION,
                "history": [{"message": {"role": "example_future_role", "content": "x"}}],
            }
        ),
    )

    unknown = one(events, "unparsed.record")

    assert "example_future_role" in (unknown.parse_problem or "")
    assert unknown.raw["message"]["content"] == "x"


def test_a_canceled_tool_call_is_not_read_as_a_refusal(tmp_path: Path) -> None:
    """The limit this parser refuses to guess past.

    The vendor's own note says a canceled call is canceled by the user or by the system, and
    the file does not say which. Mapping it to a permission decision would put a refusal
    somebody made into a case on the strength of a word that does not mean that.
    """
    call = one(session(tmp_path), "tool.call")

    assert call.payload["status"] == "canceled"
    assert "by the user or by the system" in call.payload["status_meaning"]
    assert call.payload["is_error"] is False
    assert not [event for event in session(tmp_path) if event.kind == "permission.decision"]


def test_a_tool_call_keeps_both_the_arguments_and_the_parse(tmp_path: Path) -> None:
    """The string the model produced and the vendor's own parse of it. The first is the
    evidence when a call did something the second does not explain."""
    call = one(session(tmp_path), "tool.call")

    assert call.payload["input"] == {"path": "/home/alice/src/app/index.js"}
    assert "index.js" in (call.payload["arguments"] or "")


# ----------------------------------------------- what this store has and others do not


def test_the_files_and_urls_put_in_front_of_the_model_are_events(tmp_path: Path) -> None:
    """A context item is not a tool call, and the event says so. It is still the answer to
    the question an analyst asks of every agent: which files, which destinations."""
    events = session(tmp_path)

    read = one(events, "file.read")
    request = one(events, "network.request")

    assert read.payload["files"] == [
        {"path": "/home/alice/src/app/index.js", "operation": "read", "from_context": True}
    ]
    assert request.payload["network"] == [
        {"url": "https://example.org/style-guide", "host": "example.org"}
    ]
    assert read.payload["from_context"] is True


def test_the_rules_that_applied_to_a_turn_are_the_instruction_surface(tmp_path: Path) -> None:
    """Per turn rather than per endpoint, which nothing else in this catalogue can answer.

    The path is where the rule came from, the source is the vendor's own word for how it
    was produced, and both are what an analyst needs to decide whether a turn was shaped by
    something somebody planted.
    """
    rules = [
        event
        for event in session(tmp_path)
        if event.kind == "instruction.source" and event.payload.get("rule_source")
    ]

    assert len(rules) == 1
    assert rules[0].payload["instructions"][0]["path"] == "/home/alice/src/app/.continuerules"
    assert rules[0].payload["rule_source"] == ".continuerules"
    assert rules[0].payload["always_apply"] is True


def test_a_rule_with_no_source_file_says_nothing_says_where_it_came_from(tmp_path: Path) -> None:
    """A rule the product built in has no file on the endpoint. Filling the path in from the
    session file would claim the rule was planted there."""
    events = session(
        tmp_path,
        json.dumps(
            {
                "sessionId": CONTINUE_SESSION,
                "history": [
                    {
                        "message": {"role": "user", "content": "hi"},
                        "appliedRules": [{"name": "default", "source": "default-agent"}],
                    }
                ],
            }
        ),
    )

    rule = next(event for event in events if event.payload.get("rule_source") == "default-agent")

    assert rule.payload["instructions"] == []
    assert rule.payload["scope"] == "unknown"
    assert "names no source file" in (rule.parse_problem or "")


def test_the_system_message_is_the_prompt_this_session_ran_under(tmp_path: Path) -> None:
    """It is in the file, so it is on the endpoint, so it is evidence, and the path says
    which file holds it rather than claiming to be a base prompt the vendor compiles in."""
    prompt = next(
        event
        for event in session(tmp_path)
        if event.kind == "instruction.source" and not event.payload.get("rule_source")
    )

    assert prompt.payload["scope"] == "session"
    assert prompt.payload["instructions"][0]["path"].endswith("#$.history[0]")


def test_the_mode_says_whether_a_person_was_driving(tmp_path: Path) -> None:
    """chat, agent, plan or background. The one field in this store that distinguishes a
    conversation from a run nobody was watching."""
    header = one(session(tmp_path), "config.snapshot")

    assert header.payload["mode"] == "agent"
    assert header.payload["models"][0]["model"] == "example-model-6"


# --------------------------------------------------------------------- the store


@pytest.mark.parametrize("name", ["sessions.json", f"{CONTINUE_SESSION}.json"])
def test_both_files_of_the_store_are_read_by_this_parser(tmp_path: Path, name: str) -> None:
    """One catalogue entry claims the index and every session file, so the dispatch is the
    file name. Reversed, an index would be read as a conversation and produce nothing."""
    body = continue_index() if name == "sessions.json" else continue_session()
    events = parse(write(tmp_path / name, body))

    assert events
    expected = "session.start" if name == "sessions.json" else "config.snapshot"
    assert events[0].kind == expected


def test_the_session_id_comes_from_the_file_name(tmp_path: Path) -> None:
    """Which is where the vendor's own loader takes it from, so a partial write that left a
    stale id in the document does not rename the conversation."""
    events = session(
        tmp_path, json.dumps({"sessionId": "some-other-id", "history": [], "title": "t"})
    )

    assert events[0].session_id == CONTINUE_SESSION
