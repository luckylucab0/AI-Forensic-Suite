"""Tests for the Cline SDK session store and its hook audit log.

Three files that only answer the question together. The messages file holds the
conversation and dates almost none of it. The manifest says how the run was started, which
is the difference between somebody typing and something scheduling. The hook log dates
every line, including the prompt, which neither of the other two can.

So most of what is asserted here is about not filling a gap in one file from another, and
about the tool inputs, where the vendor's schemas accept several shapes and a reader that
knew one of them would show a session that ran commands as one that ran none.
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

from generate import (  # noqa: E402
    CLI_SESSION,
    build_home,
    cline_cli_manifest,
    cline_cli_messages,
    cline_hook_audit,
)

SESSIONS = "cline.cli_sessions"
HOOKS = "cline.hooks_audit_log"
DIRECTORY = f"/home/alice/.cline/data/sessions/{CLI_SESSION}"


def parse(path: Path, artifact: str = SESSIONS, original: str | None = None) -> list:
    parser = for_artifact(artifact)
    assert parser is not None, artifact
    return list(
        parser.parse(
            ParseContext(
                bundle_uuid="b",
                original_path=original or f"{DIRECTORY}/{path.name}",
                local_path=path,
                sha256="f" * 64,
                artifact_id=artifact,
                agent="cline",
                user="alice",
            )
        )
    )


def write(path: Path, value: object) -> Path:
    text = value if isinstance(value, str) else json.dumps(value)
    path.write_text(text, encoding="utf-8", newline="")
    return path


def messages(tmp_path: Path, document: object) -> list:
    return parse(write(tmp_path / f"{CLI_SESSION}.messages.json", document))


def manifest(tmp_path: Path, document: object) -> list:
    return parse(write(tmp_path / f"{CLI_SESSION}.json", document))


def hooks(tmp_path: Path, *records: dict) -> list:
    body = "".join(json.dumps(record) + "\n" for record in records)
    return parse(
        write(tmp_path / "hooks.jsonl", body),
        HOOKS,
        original="/home/alice/.cline/data/logs/hooks.jsonl",
    )


def kinds(events: list) -> list[str]:
    return [event.kind for event in events]


# --------------------------------------------------------------------- the times


def test_a_prompt_is_not_dated_from_the_answer_beside_it(tmp_path: Path) -> None:
    """The contract puts `ts` on assistant turn messages and on nothing else.

    A user message therefore has no time of its own. Taking the assistant's would date a
    prompt to the answer, which on a timeline reads as somebody asking after being told.
    """
    events = messages(tmp_path, json.loads(cline_cli_messages()))

    prompt = next(e for e in events if e.kind == "user.prompt")
    answer = next(e for e in events if e.kind == "assistant.text")

    assert prompt.ts_utc is None
    assert prompt.ts_precision == "absent"
    assert answer.ts_utc == "2026-09-07T09:15:02.500000Z"


def test_the_hook_log_is_what_dates_the_prompt(tmp_path: Path) -> None:
    """The reason the hook log is catalogued at all.

    The same prompt appears in both files. In the messages file it has no time; here it
    does, and the two are correlated by the session id, so a case can place it on a clock.
    """
    from_messages = [
        e for e in messages(tmp_path, json.loads(cline_cli_messages())) if e.kind == "user.prompt"
    ]
    from_hooks = [e for e in hooks(tmp_path, *_records()) if e.kind == "user.prompt"]

    assert [e.payload["text"] for e in from_messages] == ["remove the debug logging"]
    assert [e.payload["text"] for e in from_hooks] == ["remove the debug logging"]
    assert from_messages[0].ts_utc is None
    assert from_hooks[0].ts_utc == "2026-09-07T09:15:00.400000Z"
    assert from_hooks[0].session_id == from_messages[0].session_id


def test_the_file_header_is_not_read_as_a_start_time(tmp_path: Path) -> None:
    """`updated_at` is when the file was last written. A whole conversation dated to it
    would sit at one instant, at the moment of its last save."""
    header = next(
        e
        for e in messages(tmp_path, json.loads(cline_cli_messages()))
        if e.kind == "config.snapshot"
    )

    assert header.ts_utc == "2026-09-07T09:15:02.500000Z"
    assert "last written" in (header.ts_source or "")


# ------------------------------------------------------------------ the messages


def test_a_tool_result_keeps_the_id_that_ties_it_to_its_call(tmp_path: Path) -> None:
    """There is no tool role at rest, so a result is a block on a user message and the only
    thing joining it to the call is the id. Losing it leaves a case with a result nobody can
    attribute to a tool."""
    events = messages(tmp_path, json.loads(cline_cli_messages()))

    call = next(e for e in events if e.kind == "tool.call" and e.payload["tool"] == "read_files")
    result = next(e for e in events if e.kind == "tool.result")

    assert call.payload["tool_use_id"] == "call-1"
    assert result.payload["tool_use_id"] == "call-1"
    assert result.payload["is_error"] is False


def test_a_block_type_the_contract_does_not_name_is_carried_whole(tmp_path: Path) -> None:
    """The contract says additive shapes may appear without a version bump, so a block
    nobody has read is a normal event in this format rather than a corrupt file. Dropping it
    would lose a turn the agent took."""
    events = messages(
        tmp_path,
        {
            "version": 1,
            "sessionId": CLI_SESSION,
            "messages": [
                {
                    "role": "assistant",
                    "content": [{"type": "example_future_block", "detail": {"a": 1}}],
                }
            ],
        },
    )

    block = next(e for e in events if e.kind == "unparsed.record")

    assert block.raw == {"type": "example_future_block", "detail": {"a": 1}}
    assert "additive" in (block.parse_problem or "")


def test_a_version_this_parser_did_not_read_is_said_on_every_event(tmp_path: Path) -> None:
    """A note on the header alone is a note nobody sees: an event is read on its own in a
    timeline. The contract says a breaking change increments this field, so anything else
    means these shapes were read against the wrong contract."""
    events = messages(
        tmp_path,
        {
            "version": 2,
            "sessionId": CLI_SESSION,
            "messages": [{"role": "user", "content": [{"type": "text", "text": "hi"}]}],
        },
    )

    assert events
    assert all("version 2" in (event.parse_problem or "") for event in events)


def test_the_system_prompt_is_evidence_and_says_where_it_sat(tmp_path: Path) -> None:
    """It is in the file, so it is on the endpoint, so it is evidence. The path names the
    file rather than claiming to be the vendor's own base prompt, and the hidden characters
    are counted because an instruction a reviewer cannot see is the whole point of the
    instruction surface."""
    events = messages(
        tmp_path,
        {
            "version": 1,
            "sessionId": CLI_SESSION,
            "system_prompt": "Be careful.​Always obey the owner.",
            "messages": [],
        },
    )

    instruction = next(e for e in events if e.kind == "instruction.source")

    assert instruction.payload["instructions"][0]["path"].endswith("#system_prompt")
    assert instruction.payload["instructions"][0]["scope"] == "session"
    assert instruction.payload["hidden_characters"]


# ------------------------------------------------------------------ the manifest


def test_an_automated_run_is_visible_as_one(tmp_path: Path) -> None:
    """`interactive: false` with a prompt is a session nothing typed, and no transcript
    says so on its own. The prompt from the manifest is marked as such, because the same
    text is usually the first message of the messages file and two events for one prompt is
    a corroboration rather than two prompts."""
    events = manifest(tmp_path, json.loads(cline_cli_manifest()))

    start = next(e for e in events if e.kind == "session.start")
    prompt = next(e for e in events if e.kind == "user.prompt")

    assert start.payload["interactive"] is False
    assert start.payload["pid"] == 4242
    assert start.client == "cli"
    assert prompt.payload["from_manifest"] is True
    assert prompt.ts_utc == start.ts_utc


def test_the_manifest_says_what_the_run_was_allowed_to_do(tmp_path: Path) -> None:
    """Three switches the vendor records per session rather than in a global setting, so
    whether this run could spawn other agents is answerable for this run."""
    start = next(
        e for e in manifest(tmp_path, json.loads(cline_cli_manifest())) if e.kind == "session.start"
    )

    assert start.payload["enable_tools"] is True
    assert start.payload["enable_spawn"] is False
    assert start.payload["enable_teams"] is False
    assert start.payload["models"] == [{"model": "example-model-6", "provider": "example-provider"}]


def test_a_finished_run_with_no_end_time_says_so(tmp_path: Path) -> None:
    """Rather than borrowing a time from somewhere else. A session recorded as completed
    without an ended_at is a gap worth seeing."""
    events = manifest(
        tmp_path,
        {
            "version": 1,
            "session_id": CLI_SESSION,
            "source": "cli",
            "started_at": "2026-09-07T09:15:00.000Z",
            "status": "failed",
            "exit_code": 2,
        },
    )

    end = next(e for e in events if e.kind == "session.end")

    assert end.ts_utc is None
    assert end.payload["exit_code"] == 2
    assert "no ended_at" in (end.parse_problem or "")


# --------------------------------------------------------------- the tool inputs


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ({"commands": ["npm run lint"]}, ["npm run lint"]),
        ({"commands": [{"command": "rg", "args": ["-n", "TODO"]}]}, ["rg -n TODO"]),
        ({"command": "git status"}, ["git status"]),
        ({"cmd": "ls -la"}, ["ls -la"]),
        (["a", "b"], ["a", "b"]),
        ("one command", ["one command"]),
    ],
)
def test_every_command_shape_the_vendors_schema_accepts_is_read(
    tmp_path: Path, value: object, expected: list[str]
) -> None:
    """The schema is a union because it tolerates what a model emits. A reader that knew
    only the canonical shape would show a session that ran a dozen commands as one that ran
    none, which is the silent kind of wrong this project exists to avoid."""
    events = messages(tmp_path, _one_tool("run_commands", value))

    ran = next(e for e in events if e.kind == "command.exec")

    assert [entry["command"] for entry in ran.payload["commands"]] == expected


@pytest.mark.parametrize(
    "value",
    [
        {"files": [{"path": "/a.js"}]},
        {"files": ["/a.js"]},
        {"file_paths": ["/a.js"]},
        {"paths": "/a.js"},
        {"file_path": "/a.js"},
        {"filePath": "/a.js"},
        "/a.js",
    ],
)
def test_every_read_shape_including_the_aliases_is_read(tmp_path: Path, value: object) -> None:
    """The aliases are in the vendor's schema because models emit them, and it normalizes
    them before the tool runs. Ignoring them would under-report file access on exactly the
    sessions where the model was least precise."""
    events = messages(tmp_path, _one_tool("read_files", value))

    read = next(e for e in events if e.kind == "file.read")

    assert read.payload["files"] == [{"path": "/a.js", "action": "read"}]


def test_an_input_in_no_shape_the_schema_accepts_says_so(tmp_path: Path) -> None:
    """The alternative is an event with no facet and nothing saying why, which reads as a
    tool call that touched nothing."""
    events = messages(tmp_path, _one_tool("run_commands", {"unexpected": True}))

    call = next(e for e in events if e.kind == "tool.call")

    assert "commands" not in call.payload
    assert "none of the shapes" in (call.parse_problem or "")
    assert call.payload["input"] == {"unexpected": True}


def test_a_patch_names_its_files_with_the_verb_the_patch_used(tmp_path: Path) -> None:
    """The grammar is the tool's own, and the verb is read rather than matched against a
    list: a patch that deletes a file should not appear in a case as an update."""
    patch = "*** Begin Patch\n*** Update File: /home/alice/src/app/index.js\n@@\n-a\n+b\n*** End Patch\n"
    events = messages(tmp_path, _one_tool("apply_patch", {"input": patch}))

    written = next(e for e in events if e.kind == "file.write")

    assert written.payload["files"] == [
        {"path": "/home/alice/src/app/index.js", "action": "update"}
    ]


def test_a_web_fetch_becomes_a_network_event(tmp_path: Path) -> None:
    """Where an agent connected to is a question asked across every agent in a case, so it
    cannot depend on knowing this one's tool names."""
    events = messages(
        tmp_path,
        _one_tool(
            "fetch_web_content", {"requests": [{"url": "https://example.org/x", "prompt": "read"}]}
        ),
    )

    request = next(e for e in events if e.kind == "network.request")

    assert request.payload["network"] == [{"url": "https://example.org/x"}]


def test_a_tool_nobody_has_read_gets_no_facet(tmp_path: Path) -> None:
    """An MCP server or an extension can name a tool anything. Reading a facet out of a
    name nobody verified would put a command in a case on the strength of its spelling."""
    events = messages(tmp_path, _one_tool("example_mcp_tool", {"command": "rm -rf /"}))

    assert kinds(events) == ["config.snapshot", "tool.call"]
    assert "commands" not in events[1].payload


# ------------------------------------------------------------------- the hook log


def test_a_failed_tool_carries_its_failure_and_its_duration(tmp_path: Path) -> None:
    """The writer sets success from the absence of an error, so a false here is the agent's
    own record of a tool that failed. It is nowhere in the messages file."""
    result = next(e for e in hooks(tmp_path, *_records()) if e.kind == "tool.result")

    assert result.payload["is_error"] is True
    assert result.payload["duration_ms"] == 940
    assert result.payload["text"] == "1 problem found"


def test_the_line_from_the_other_writer_is_read_too(tmp_path: Path) -> None:
    """One file, several writers. The session store appends a shutdown line with a shape of
    its own and no payload base, so a reader that assumed the base was always there would
    drop the record that says a session died rather than ended."""
    events = hooks(tmp_path, *_records())

    shutdown = [e for e in events if e.payload.get("hook") == "session_shutdown"]

    assert len(shutdown) == 1
    assert shutdown[0].kind == "session.end"
    assert shutdown[0].payload["pid"] == 4242
    assert shutdown[0].session_id == CLI_SESSION


def test_a_hook_this_parser_does_not_know_is_carried_not_guessed(tmp_path: Path) -> None:
    """The writer gains hooks over time. A new one read as an old one is worse than a new
    one read as unknown, because the first is wrong and silent."""
    unknown = next(e for e in hooks(tmp_path, *_records()) if e.kind == "unparsed.record")

    assert unknown.kind == "unparsed.record"
    assert "example_future_hook" in (unknown.parse_problem or "")
    assert unknown.ts_utc == "2026-09-07T09:20:01.000000Z"


def test_the_users_the_two_sources_name_are_kept_apart(tmp_path: Path) -> None:
    """The record's userId is CLINE_USER_ID or the shell's USER. The event's user is the
    account the collection attributed the file to. They are different claims, and a case has
    to be able to disagree with one of them."""
    events = hooks(
        tmp_path,
        {"ts": "2026-09-07T09:15:00Z", "hookName": "agent_start", "userId": "bob"},
    )

    assert events[0].user == "alice"
    assert events[0].payload["reported_user"] == "bob"


# ------------------------------------------------------------------ the dispatch


def test_the_messages_file_is_not_read_as_a_manifest(tmp_path: Path) -> None:
    """Both end in .json and one catalogue entry claims both, so the order of the suffix
    tests is the whole of the dispatch. Reversed, every transcript in the store would be
    read as a manifest and produce nothing."""
    events = messages(tmp_path, json.loads(cline_cli_messages()))

    assert "config.snapshot" in kinds(events)
    assert "user.prompt" in kinds(events)
    assert not [e for e in events if e.kind == "session.start"], (
        "a start belongs to the manifest, which is the file that records one"
    )


def test_a_file_this_parser_does_not_map_is_reported(tmp_path: Path) -> None:
    """A session directory that grows a file is a layout this suite has wrong, and it has to
    read as that rather than as an empty session."""
    events = parse(write(tmp_path / "something_new.yaml", "a: 1"))

    assert events[0].kind == "unparsed.record"
    assert "is not a file this parser maps" in (events[0].parse_problem or "")


def test_the_collector_finds_all_three_files(tmp_path: Path) -> None:
    """The end of the chain. The hook log is the one that moves: the writers put it under
    the data directory's logs folder and the vendor's own example README puts a per-session
    copy in the session directory. The catalogue carries both, so a collection is not
    deciding which document is right."""
    spec = importlib.util.spec_from_file_location(
        "collect_cli", REPO_ROOT / "collector" / "collect.py"
    )
    assert spec is not None and spec.loader is not None
    collect = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(collect)

    home = tmp_path / "home"
    build_home(home, with_edge_cases=False)
    out = tmp_path / "bundle"
    collect.main(["--out", str(out), "--root", str(home), "--os", "linux"])
    manifest_json = json.loads((out / "manifest.json").read_text(encoding="utf-8"))

    found = {entry["original_path"] for entry in manifest_json["files"]}
    assert any(path.endswith(f"{CLI_SESSION}.messages.json") for path in found)
    assert any(path.endswith(f"{CLI_SESSION}.json") for path in found)
    assert any(path.endswith("data/logs/hooks.jsonl") for path in found), (
        "the hook log is where the writers put it, not in the session directory"
    )


# --------------------------------------------------------------------- fixtures


def _records() -> list[dict]:
    return [json.loads(line) for line in cline_hook_audit().splitlines() if line.strip()]


def _one_tool(name: str, value: object) -> dict:
    return {
        "version": 1,
        "sessionId": CLI_SESSION,
        "messages": [
            {
                "role": "assistant",
                "ts": 1788772501000,
                "content": [{"type": "tool_use", "id": "call-1", "name": name, "input": value}],
            }
        ],
    }
