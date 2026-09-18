"""Windows behaviour, exercised on whatever platform the suite happens to run on.

Three Windows-only defects reached CI in three consecutive commits, and every one of them
was silent: a directory name built with a drive colon that no Windows filesystem can hold,
a path compared with the platform separator against forward-slash keys, and a fixture
written in text mode so its bytes differed per platform. Each was found by the one runner
nobody watches while the other five stayed green, which is the worst place to find anything.

So this module feeds Windows-shaped input to the code on purpose. It runs everywhere and it
fails everywhere, which is the point: a defect of this class should cost a local test run
rather than a red CI job eight minutes later.

Two corpora, and only the second one is about the tests themselves.

**Path shapes.** Backslashes, a drive letter, a UNC share, and the mixed spelling a Windows
tool produces when it writes a forward-slash path into a record. Every function that reads
an endpoint path and derives an answer from it gets all four, because the answers decide
which session a turn belongs to and whether an instruction came from a repository or from
the user's own profile.

**Line endings.** This one is not about test hygiene at all, it is about the product. An
agent running on Windows writes CRLF, so a transcript collected from a Windows endpoint
arrives with CRLF, and a parser that reads one record fewer there would lose evidence on
the platform this suite most needs to work on. Every parser therefore has to produce the
same events from the same content written both ways.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from agentforensics.parsers import for_artifact
from agentforensics.parsers.base import ParseContext
from agentforensics.parsers.cline import _task_id
from agentforensics.parsers.instructions import scope_of

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tests" / "fixtures"))

from generate import (  # noqa: E402
    cline_api_history,
    cline_ui_messages,
    codex_rollout,
    copilot_events,
    gemini_session,
    pi_session,
    qwen_transcript,
    transcript,
)

SESSION = "4f8c1e2a-0000-4000-8000-000000000001"


# --------------------------------------------------------------- path shapes


# One working copy, spelled the four ways a path for it can reach the analyzer. The
# collector writes the profile's own spelling into the manifest, and a record inside a
# transcript can carry a different one, so both have to resolve to the same answer.
WINDOWS_PROJECT = [
    pytest.param(
        "C:\\Users\\alice\\work\\repo\\CLAUDE.md",
        ("C:\\Users\\alice\\work\\repo",),
        id="backslashes on both sides",
    ),
    pytest.param(
        "C:\\Users\\alice\\work\\repo\\CLAUDE.md",
        ("C:/Users/alice/work/repo",),
        id="a root a tool wrote with forward slashes",
    ),
    pytest.param(
        "C:/Users/alice/work/repo/CLAUDE.md",
        ("C:\\Users\\alice\\work\\repo",),
        id="a path a tool wrote with forward slashes",
    ),
    pytest.param(
        "\\\\fileserver\\share\\work\\repo\\CLAUDE.md",
        ("\\\\fileserver\\share\\work\\repo",),
        id="a UNC share, which has no drive letter at all",
    ),
    pytest.param(
        "C:\\Users\\Alice\\Work\\Repo\\CLAUDE.md",
        ("c:\\users\\alice\\work\\repo",),
        id="a case difference, which Windows does not have",
    ),
]


@pytest.mark.parametrize(("path", "roots"), WINDOWS_PROJECT)
def test_a_windows_project_file_is_project_scoped(path: str, roots: tuple[str, ...]) -> None:
    """Whether the instruction came from the repository or from the profile is usually the
    whole finding, and on Windows the two are the same string with different separators."""
    assert scope_of(path, roots)[0] == "project"


def test_a_windows_profile_file_is_not_mistaken_for_a_project_one() -> None:
    assert scope_of("C:\\Users\\alice\\.claude\\CLAUDE.md", ("C:\\Users\\alice\\work\\repo",)) == (
        "user",
        None,
    )


def test_a_windows_machine_wide_path_is_managed() -> None:
    """An administrator's policy file, which applies to every user on the endpoint."""
    for path in (
        "C:\\Program Files\\ClaudeCode\\CLAUDE.md",
        "C:\\ProgramData\\ClaudeCode\\CLAUDE.md",
        "C:/Program Files/ClaudeCode/CLAUDE.md",
    ):
        assert scope_of(path, ("C:\\Users\\alice\\work\\repo",))[0] == "managed", path


def test_a_windows_local_override_is_told_apart_from_the_repositorys_file() -> None:
    roots = ("C:\\Users\\alice\\work\\repo",)
    assert scope_of("C:\\Users\\alice\\work\\repo\\CLAUDE.local.md", roots)[0] == "local"


def test_a_windows_sibling_directory_is_not_inside_the_working_copy() -> None:
    """`...\\repo-notes` is not inside `...\\repo`, and a prefix comparison that forgot the
    separator would put every neighbouring directory into the project."""
    scope, _ = scope_of(
        "C:\\Users\\alice\\work\\repo-notes\\CLAUDE.md", ("C:\\Users\\alice\\work\\repo",)
    )
    assert scope == "user"


def test_a_task_id_comes_out_of_a_windows_path() -> None:
    """The task directory is the only session identifier these files have, so a path the
    parser cannot read means a conversation that scatters across sessions."""
    assert (
        _task_id("C:\\Users\\alice\\AppData\\Roaming\\Code\\tasks\\1737000000000\\ui_messages.json")
        == "1737000000000"
    )
    assert _task_id("/home/alice/.config/Code/tasks/1737000000000/ui_messages.json") == (
        "1737000000000"
    )


def test_a_copilot_session_id_comes_out_of_a_windows_path(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    path.write_text(copilot_events(SESSION, "C:\\Users\\alice\\work\\repo"), newline="")
    events = parse_with(
        path,
        "copilot.session_event_log",
        "copilot",
        f"C:\\Users\\alice\\.copilot\\history-session-state\\{SESSION}\\events.jsonl",
    )
    assert {event.session_id for event in events} == {SESSION}


# -------------------------------------------------------------- line endings


def parse_with(
    path: Path, artifact_id: str, agent: str, original: str, roots: tuple[str, ...] = ()
) -> list:
    parser = for_artifact(artifact_id)
    assert parser is not None, artifact_id
    return list(
        parser.parse(
            ParseContext(
                bundle_uuid="b1",
                original_path=original,
                local_path=path,
                sha256="aa",
                artifact_id=artifact_id,
                agent=agent,
                user="alice",
                project_roots=roots,
            )
        )
    )


# Every parser, with content from the synthetic fixture generator rather than a happy-path
# record invented here: the generator's files carry the awkward cases on purpose, which is
# exactly what a line ending rewrite is most likely to break.
CRLF_CASES = [
    pytest.param(
        transcript(SESSION, "/home/alice/src/app"),
        "session.jsonl",
        "claude_code.transcripts",
        "claude_code",
        id="claude code transcript",
    ),
    pytest.param(
        codex_rollout(SESSION, "/home/alice/src/app"),
        "rollout-2026-09-06T09-00-00-s1.jsonl",
        "codex.rollouts",
        "codex",
        id="codex rollout",
    ),
    pytest.param(
        copilot_events(SESSION, "/home/alice/src/app"),
        "events.jsonl",
        "copilot.session_event_log",
        "copilot",
        id="copilot event log",
    ),
    pytest.param(
        gemini_session(SESSION, "abc123"),
        "chat.json",
        "gemini_cli.chats",
        "gemini_cli",
        id="gemini chat",
    ),
    pytest.param(
        qwen_transcript(SESSION, "/home/alice/src/app"),
        "transcript.json",
        "qwen_code.conversation_transcript",
        "qwen_code",
        id="qwen transcript",
    ),
    pytest.param(
        pi_session(SESSION, "/home/alice/src/app"),
        "session.jsonl",
        "pi.sessions",
        "pi",
        id="pi session",
    ),
    pytest.param(
        cline_api_history(),
        "api_conversation_history.json",
        "cline.data_tasks",
        "cline",
        id="cline api history",
    ),
    pytest.param(
        cline_ui_messages(),
        "ui_messages.json",
        "cline.data_tasks",
        "cline",
        id="cline ui messages",
    ),
    pytest.param(
        "# House rules\n\nAlways run the tests.\n",
        "CLAUDE.md",
        "claude_code.project_claude_md",
        "claude_code",
        id="an instruction file",
    ),
]


@pytest.mark.parametrize(("content", "name", "artifact_id", "agent"), CRLF_CASES)
def test_a_file_written_with_windows_line_endings_reads_the_same(
    tmp_path: Path, content: str, name: str, artifact_id: str, agent: str
) -> None:
    """An agent on Windows writes CRLF, so this is what a collection from a Windows endpoint
    actually contains. One record fewer here is evidence lost on the platform this suite
    most needs to work on, and it would be invisible: a short transcript looks like a short
    conversation."""
    unix = tmp_path / "unix" / name
    windows = tmp_path / "windows" / name
    for target, text in ((unix, content), (windows, content.replace("\n", "\r\n"))):
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(text.encode("utf-8"))

    original = "/home/alice/tasks/1737000000000/" + name
    left = parse_with(unix, artifact_id, agent, original)
    right = parse_with(windows, artifact_id, agent, original)

    assert [event.kind for event in left] == [event.kind for event in right]
    assert [event.provenance.locator for event in left] == [
        event.provenance.locator for event in right
    ]
    assert [event.ts_utc for event in left] == [event.ts_utc for event in right]
    assert [event.session_id for event in left] == [event.session_id for event in right]
    unreadable = sum(1 for event in right if event.kind == "unparsed.record")
    assert unreadable == sum(1 for event in left if event.kind == "unparsed.record")


@pytest.mark.parametrize(("content", "name", "artifact_id", "agent"), CRLF_CASES)
def test_the_text_a_windows_file_carried_reaches_the_case(
    tmp_path: Path, content: str, name: str, artifact_id: str, agent: str
) -> None:
    """The same text, modulo the carriage returns the file really contains.

    Not normalised away by the parsers on purpose: what a case holds is what was on the
    disk. The comparison strips them here rather than the parser stripping them there.
    """
    unix = tmp_path / "unix" / name
    windows = tmp_path / "windows" / name
    for target, text in ((unix, content), (windows, content.replace("\n", "\r\n"))):
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(text.encode("utf-8"))

    original = "/home/alice/tasks/1737000000000/" + name
    left = [str(e.payload.get("text", "")) for e in parse_with(unix, artifact_id, agent, original)]
    right = [
        str(e.payload.get("text", "")).replace("\r\n", "\n")
        for e in parse_with(windows, artifact_id, agent, original)
    ]

    assert left == right


def test_a_windows_file_keeps_its_carriage_returns_in_the_case(tmp_path: Path) -> None:
    """The other half of the same property: nothing normalises them away.

    A case says what was on the disk. An instruction file collected from a Windows endpoint
    holds CRLF, so the case has to hold CRLF, and a parser that tidied that up would be
    quietly editing evidence. It also matters for the reading: a byte count and a hash in a
    report have to match the file an examiner opens.
    """
    body = b"# House rules\r\n\r\nAlways run the tests.\r\n"
    path = tmp_path / "CLAUDE.md"
    path.write_bytes(body)

    events = parse_with(
        path,
        "claude_code.project_claude_md",
        "claude_code",
        "C:\\Users\\alice\\work\\repo\\CLAUDE.md",
        ("C:\\Users\\alice\\work\\repo",),
    )

    assert len(events) == 1
    assert events[0].payload["text"] == body.decode()
    # Counted from the bytes on disk rather than from a number typed here, so the count in
    # a report is the file's own and not the test author's arithmetic.
    assert events[0].payload["bytes"] == len(body)
    # And the reading of it is unaffected: the heading is still a heading.
    assert events[0].payload["title"] == "House rules"


def test_the_windows_newline_switch_is_doing_something(
    tmp_path: Path, request: pytest.FixtureRequest
) -> None:
    """The simulation's own test, because a simulation that quietly stopped working is
    false assurance: the suite would go on passing under --windows-newlines while testing
    nothing, and the defect it exists for would reach the Windows runner anyway.

    Passes in both modes. It asserts what each mode is supposed to do, not that one of them
    is in effect.
    """
    translated = tmp_path / "translated.txt"
    translated.write_text("one\ntwo\n", encoding="utf-8")
    # On Windows a text-mode write already translates, which is the behaviour the flag
    # reproduces everywhere else, so CRLF is the right expectation there in both modes.
    # The first version of this test asserted LF whenever the flag was off and therefore
    # failed on the one runner it was written to protect, which is the same platform
    # assumption it exists to catch.
    translating = request.config.getoption("--windows-newlines") or os.name == "nt"
    assert translated.read_bytes() == (b"one\r\ntwo\r\n" if translating else b"one\ntwo\n")

    # A caller that says what it wants gets it, on every platform and in both modes. This
    # is the spelling every fixture that is later compared byte for byte has to use.
    exact = tmp_path / "exact.txt"
    exact.write_text("one\ntwo\n", encoding="utf-8", newline="")
    assert exact.read_bytes() == b"one\ntwo\n"
