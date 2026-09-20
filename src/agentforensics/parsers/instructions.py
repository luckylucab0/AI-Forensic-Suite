"""Read the instruction surface: everything the agent was told to obey, off the disk.

This is the module behind the question the brief puts last and an investigation usually
asks first: was the agent manipulated by instructions somebody planted. Until this module
that question could only be answered from the transcript side, where a rule can spot an
injection arriving in a tool result. The other half, the standing instructions the agent
ran under, was collected and never read: sixty-three catalogue artifacts, skills and
commands and output styles and rules and steering files and hook scripts, produced exactly
one `artifact.fs` event each. The case knew the file names and nothing about what they said,
so a poisoned CLAUDE.md, a skill quietly granting itself every tool, and a rules file with
an instruction hidden in zero-width characters were all invisible.

What it does not do is claim to show a system prompt. For nearly every agent here the
vendor's base prompt is compiled into the binary or arrives from the vendor's server, and it
is not on the endpoint at all. Presenting a reconstruction as "the system prompt" would be
the same defect as an invented catalogue path: an analyst would read a confident answer to a
question the evidence cannot answer. So the events say `instruction.source`, one per file,
and what an analyst gets is the part of the prompt that was on the machine, complete and
attributable, plus the honest statement that the base prompt was not.

Three things in here are worth knowing.

**Scope comes from recorded data, not from a guess.** Whether a CLAUDE.md was the user's own
or came out of a cloned repository is often the whole finding, and both are absolute paths
under the same home directory. The collector records the working copies it found, those
travel in the manifest, and this module matches against them. Where a collection did not
record them, the scope is `unknown` and says why, because "we could not tell" and "it was
the user's own" are different answers.

**A hook script is an instruction too.** It is the one kind the agent executes rather than
reads, which makes it the most direct form of the same thing, and the catalogue files it
under instructions for that reason. It is read as text like the rest, with a flag.

**Invisible characters are counted per file.** A reviewer approving a pull request sees one
thing and the agent reads another, and that gap is the entire technique. A rule pack matches
on the text as well, but the count travels on the event so the overview can show it without
a scan having been run.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import yaml

from agentforensics.model import Event, unparsed
from agentforensics.parsers.base import ParseContext, looks_binary, read_json

# Every catalogue artifact filed under instructions or project_instructions. Written out
# rather than derived at runtime, because a parser is handed an artifact id and not the
# catalogue entry, and because a new instruction surface should be read because somebody
# decided it should be. tests/unit/test_instructions.py compares this against the catalogue,
# so adding an entry there fails CI until it is listed here.
SOURCES = frozenset(
    {
        # Executable TypeScript the agent loads. Its entry says to treat it as
        # capability grant and, potentially, the malicious component itself. The
        # script that fetches code and runs it needs to see it.
        # suffix rule below files it as executable, which is what a rule about a
        # user-supplied code: a modified built-in or a bespoke tool is both a
        "amazonq.cli_todo_lists",
        "amazonq.cli_user_rules",
        "amazonq.project_rules",
        "amazonq.prompt_library",
        "amp.skills",
        "claude_code.agents",
        "claude_code.commands",
        "claude_code.loop_instructions",
        "claude_code.managed_claude_md",
        "claude_code.output_styles",
        "claude_code.plans",
        "claude_code.project_claude_local_md",
        "claude_code.project_claude_md",
        "claude_code.project_rules",
        "claude_code.settings_referenced_executables",
        "claude_code.skills",
        "claude_code.skills_trash",
        "claude_code.synced_skills",
        "claude_code.user_claude_md",
        "claude_code.user_rules",
        "claude_code.workflows",
        "claude_desktop.org_plugins",
        "claude_desktop.scheduled_tasks",
        "claude_desktop.user_plugins",
        "cline.home_config_tree",
        "cline.rules_global",
        "cline.rules_project",
        "copilot.agents_skills_hooks",
        "copilot.instructions",
        "copilot.lsp_config_repo",
        "crosscutting.hook_scripts",
        "crosscutting.instructions_agents_md",
        "crosscutting.instructions_claude_md",
        "crosscutting.instructions_clinerules",
        "crosscutting.instructions_copilot_instructions",
        "crosscutting.instructions_cursor_rules",
        "crosscutting.instructions_gemini_md",
        "crosscutting.instructions_junie_guidelines",
        "crosscutting.instructions_kiro_steering",
        "crosscutting.instructions_windsurf_rules",
        "cursor.commands_and_plans",
        "cursor.project_instructions",
        "cursor.skills",
        "cursor.subagents",
        "factory_droid.skills_and_droids",
        "gemini_cli.agent_definitions",
        "gemini_cli.commands",
        "gemini_cli.project_config",
        "goose.hints",
        "goose.prompts",
        "hermes.skills",
        "hermes.soul",
        "junie.project_dir",
        "kiro.kiroignore",
        "kiro.prompt_library",
        "kiro.skills_powers",
        "kiro.specs",
        "kiro.steering_project",
        "kiro.steering_user",
        "lmstudio.hub_downloads",
        "lmstudio.presets",
        "opencode.agents_commands",
        "pi.extensions",
        "pi.prompts",
        "qwen_code.ignore_files",
        "qwen_code.project_extension_points",
        "qwen_code.project_instructions",
        "qwen_code.user_extension_points",
        "qwen_code.user_instructions",
        "qwen_code.workflow_generated_scripts",
        "roo_code.global_dirs",
        "roo_code.rules",
        "windsurf.global_rules",
        "windsurf.project_instructions",
        "windsurf.system_config",
        "windsurf.workflows_and_skills",
    }
)

# Absolute prefixes that are machine-wide rather than somebody's profile, so a file under
# one of them was placed by an administrator and applies to every user. Taken from the
# catalogue's own spelling of its managed entries rather than invented: these are the roots
# the vendors document for managed policy and system-wide configuration. Compared
# lowercased and with forward slashes, so the user's own ~/Library/Application Support does
# not match, because that path does not begin here.
_MANAGED_PREFIXES = (
    "/etc/",
    "/library/application support/",
    "/library/managed preferences/",
    "/opt/",
    "/usr/",
    "c:/program files",
    "c:/programdata/",
    "c:/windows/",
    "/programdata/",
)

# A file name that marks the personal, usually git-ignored override of a project
# instruction file. The vendors document the convention, and it is the difference between
# "the repository told the agent this" and "this user told the agent this in the
# repository", which are different findings about the same directory.
_LOCAL_MARKER = ".local."

# Extensions of an instruction the agent runs instead of reading. A hook is the most direct
# form of an injected instruction there is, so it is worth a flag on the event.
_EXECUTABLE_SUFFIXES = (
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".psm1",
    ".cmd",
    ".bat",
    ".py",
    ".js",
    ".ts",
)

# Keys that literally hold an instruction inside a JSON document. Short and exact: a preset
# or a settings file is read for the field that carries a prompt, and nothing else in it is
# turned into instruction text, because guessing which key of a settings file is an order to
# the model would produce a confident wrong reading.
_PROMPT_KEYS = (
    "systemPrompt",
    "system_prompt",
    "instructions",
    "prompt",
    "customInstructions",
    "custom_instructions",
)

# Front matter keys through which a skill widens what the agent may do without the user
# being asked. Surfaced on the event because a skill that grants itself a shell is a
# permission change written as a document.
_TOOL_KEYS = ("allowed-tools", "allowedTools", "allowed_tools", "tools", "permissions")

# The characters a human reviewer cannot see and the model reads anyway. Zero-width joiners
# and spaces render as nothing; the bidirectional overrides make stored text display in a
# different order than it is stored in; the Unicode tag block renders as nothing at all and
# is wide enough to smuggle a whole sentence.
_HIDDEN = (
    "\u200b",
    "\u200c",
    "\u200d",
    "\u2060",
    "\ufeff",
    "\u202a",
    "\u202b",
    "\u202c",
    "\u202d",
    "\u202e",
    "\u2066",
    "\u2067",
    "\u2068",
    "\u2069",
    "\u00ad",
)

# How much of one file's text is carried into an event. An instruction file is prose a
# person wrote, so this is generous by design and the limit exists only to stop a generated
# file of several megabytes from filling a case. Reaching it is reported on the event, never
# applied quietly.
MAX_TEXT = 1_000_000

# Said instead of the text, where the file is not text. The file itself is in the bundle
# under this hash, so nothing is lost: what the event refuses to do is show an analyst a
# page of replacement characters that reads as the content of a document.
BINARY_FILE = (
    "this file is not text: most of it did not decode, so it is recorded by size and hash "
    "rather than as content. It is in the bundle at the path in this event's provenance, "
    "and reading it needs a reader for whatever format it actually is"
)


def _digest(raw_bytes: bytes) -> str:
    """The file's own hash, so a binary document is still identifiable in the case."""
    return hashlib.sha256(raw_bytes).hexdigest()


class InstructionsParser:
    """One module for the whole instruction surface, because it is a format and not an agent.

    Every agent here writes the same three shapes: prose in Markdown or plain text, a
    document with YAML front matter, and a JSON settings file with a prompt in one field.
    A module per agent would be twenty copies of one reader, and the copy that was forgotten
    would be the silent gap.
    """

    name = "instructions"

    def handles(self, artifact_id: str | None) -> bool:
        return artifact_id in SOURCES

    def parse(self, context: ParseContext) -> Iterator[Event]:
        yield from read_document(context, kind="instruction.source")


def read_document(
    context: ParseContext, *, kind: str, extra: dict[str, Any] | None = None
) -> Iterator[Event]:
    """One event for one file of agent-facing prose, whatever the case calls that file.

    The reading is the same for an instruction and for a memory the agent wrote itself:
    both are Markdown or plain text, both can carry front matter, both can carry characters
    a reviewer cannot see, and for both the question is what the model was going to read.
    What differs is the kind, and the kind is what keeps them apart in a case: the
    instruction surface view is the answer to what the agent was told to obey, and an
    agent's own notes are not that, however much they steer the next session.
    """
    path = context.local_path
    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:
        yield unparsed(
            context.provenance("file"),
            context.agent,
            {"file": path.name},
            f"this instruction file could not be read: {exc}",
            user=context.user,
            host=context.host,
        )
        return

    text = raw_bytes.decode("utf-8", "replace")
    problems: list[str] = []
    if looks_binary(raw_bytes):
        # Not text at all: an encrypted store, a protocol buffer, a compiled thing that
        # landed in a directory of documents. Carried as bytes rather than as a page of
        # replacement characters, because that page reads as the content of the file and
        # one of the memory stores in this catalogue is exactly this shape.
        yield Event(
            kind=kind,
            provenance=context.provenance("file"),
            agent=context.agent,
            raw={"file": path.name, "bytes": len(raw_bytes), "sha256": _digest(raw_bytes)},
            ts_utc=None,
            ts_precision="absent",
            actor="system",
            user=context.user,
            host=context.host,
            payload={
                "file": path.name,
                "bytes": len(raw_bytes),
                "sha256": _digest(raw_bytes),
                "binary": True,
                **(extra or {}),
            },
            parse_problem=BINARY_FILE,
        )
        return
    if "\ufffd" in text:
        problems.append(
            "the file did not decode as UTF-8 and was read with replacement characters, "
            "so its content is not exact"
        )
    if len(text) > MAX_TEXT:
        problems.append(
            f"the text is longer than the ingest limit of {MAX_TEXT} characters and is "
            "carried truncated. The whole file is in the bundle, at the path in this "
            "event's provenance"
        )
        text = text[:MAX_TEXT]

    scope, scope_note = scope_of(context.original_path, context.project_roots)

    payload: dict[str, Any] = {
        "text": text,
        "scope": scope,
        "file": path.name,
        "bytes": len(raw_bytes),
        "lines": text.count("\n") + 1 if text else 0,
    }
    if scope_note:
        # Beside the scope and not in parse_problem. The file was read completely; what
        # is not known is which tier it applied at. Carrying that as a parse problem
        # made every view say the file had not been fully read, and a tool that reports
        # sound evidence as unreadable teaches an analyst to distrust the one case
        # where it means it.
        payload["scope_problem"] = scope_note

    # A script's `#` lines are comments, not Markdown headings, and the two are
    # syntactically identical. Reading one as a title showed `!/bin/sh` as the name of a
    # hook file, which is the kind of small wrongness that makes an analyst stop
    # trusting a listing.
    executable = path.name.lower().endswith(_EXECUTABLE_SUFFIXES)
    title = None if executable else _title(text)
    if title:
        payload["title"] = title

    front, front_problem = _front_matter(text)
    if front_problem:
        problems.append(front_problem)
    if front:
        payload["front_matter"] = front
        for key in ("name", "description"):
            value = front.get(key)
            if isinstance(value, str) and value.strip():
                payload[f"declared_{key}"] = value.strip()
        tools = _declared_tools(front)
        if tools:
            # A skill that names its own tools has widened what the agent may do, in a
            # document rather than in a settings file, which is why it belongs next to
            # the instruction text and not only in the permissions view.
            payload["declared_tools"] = tools

    if path.name.lower().endswith(".json"):
        document, json_problem = read_json(path)
        if json_problem:
            problems.append(f"the file has a .json name but {json_problem}")
        else:
            payload["document"] = document
            prompt, prompt_key = _prompt_in(document)
            if prompt:
                payload["text"] = prompt
                payload["prompt_field"] = prompt_key
                payload["document_text"] = text

    if executable:
        # Not "probably a hook": the catalogue filed this path under instructions, and a
        # script there is an instruction the agent executes. Flagged rather than
        # interpreted, because what it does is a question for the analyst.
        payload["executable"] = True

    hidden = hidden_characters(text)
    if hidden:
        payload["hidden_characters"] = hidden

    if kind == "instruction.source":
        # The facet the case indexes, and the join the injected-instruction question
        # needs: which instruction files were in force, at which scope. It is not written
        # for an agent's own notes: the instruction surface answers what the agent was
        # told to obey, and a file it wrote to itself is a different question that the
        # kind keeps separate.
        payload["instructions"] = [{"path": context.original_path, "scope": scope}]
    payload.update(extra or {})
    yield Event(
        kind=kind,
        provenance=context.provenance("file"),
        agent=context.agent,
        raw={"file": path.name, "text": text, "front_matter": front or None},
        # No timestamp. The file carries no time of its own, and the artifact.fs event
        # for the same path already carries the filesystem's, attributed to the
        # filesystem. Repeating an mtime here would present it as the instruction's own
        # time, which is exactly what the model forbids.
        ts_utc=None,
        ts_precision="absent",
        # The instruction is part of the environment the agent ran in rather than a turn
        # somebody took. Who wrote the file is a question the file cannot answer, and
        # the answer is in version control or in the filesystem timestamps.
        actor="system",
        user=context.user,
        host=context.host,
        project_path=_project_of(context.original_path, context.project_roots),
        payload=payload,
        parse_problem=" ".join(problems) if problems else None,
    )


def scope_of(original_path: str, project_roots: tuple[str, ...]) -> tuple[str, str | None]:
    """Whose instruction this was: managed, local, project, user, or honestly unknown.

    Returns the scope and a note when something could not be decided. The order matters. A
    machine-wide path is an administrator's file whatever else is true of it; a `.local.`
    name is the documented personal override; after that only the recorded working copies
    can tell a repository's file from the user's own.
    """
    path = original_path.replace("\\", "/").lower()
    if any(path.startswith(prefix) for prefix in _MANAGED_PREFIXES):
        return "managed", None
    if _LOCAL_MARKER in Path(path).name:
        return "local", None
    for root in project_roots:
        normalised = root.replace("\\", "/").lower().rstrip("/")
        if normalised and (path == normalised or path.startswith(normalised + "/")):
            return "project", None
    if not project_roots:
        return "unknown", (
            "the collection recorded no working copies, so this file cannot be told apart "
            "from one inside a project. The scope is unknown rather than assumed"
        )
    return "user", None


def _project_of(original_path: str, project_roots: tuple[str, ...]) -> str | None:
    """The working copy this file sits in, where a recorded one contains it."""
    path = original_path.replace("\\", "/").lower()
    for root in project_roots:
        normalised = root.replace("\\", "/").lower().rstrip("/")
        if normalised and path.startswith(normalised + "/"):
            return root
    return None


# An ATX heading: one to six hashes, then whitespace, then something. The whitespace is the
# part that matters here, because without it a shell script's `#!/bin/sh` was read as the
# heading of a hook file and shown as its title.
_HEADING = re.compile(r"^#{1,6}\s+(\S.*)$")


def _title(text: str) -> str | None:
    """The first Markdown heading, which is what a person calls the file."""
    for line in text.splitlines()[:40]:
        found = _HEADING.match(line.strip())
        if found:
            return found.group(1).strip()
    return None


def _front_matter(text: str) -> tuple[dict[str, Any] | None, str | None]:
    """The YAML block a skill or a rules file opens with, or the reason it did not parse.

    Parsed with safe_load and inside a guard. A malformed block is a finding of its own,
    since the agent would not have loaded the skill either, and it must not cost the file:
    the text is the evidence and it is returned regardless.
    """
    if not text.startswith("---"):
        return None, None
    lines = text.splitlines()
    end = None
    for number, line in enumerate(lines[1:], start=1):
        if line.strip() in ("---", "..."):
            end = number
            break
    if end is None:
        return None, "the file opens a YAML front matter block that is never closed"
    block = "\n".join(lines[1:end])
    try:
        parsed = yaml.safe_load(block)
    except yaml.YAMLError as exc:
        return None, f"the front matter is not valid YAML: {exc}"
    if parsed is None:
        return None, None
    if not isinstance(parsed, dict):
        return (
            None,
            f"the front matter is a YAML {type(parsed).__name__} where a mapping was expected",
        )
    # Rendered through JSON so that a date or a custom tag cannot reach the case as a Python
    # object the serializer would then have to guess at.
    return json.loads(json.dumps(parsed, default=str)), None


def _declared_tools(front: dict[str, Any]) -> list[str]:
    """Tools a document grants itself, from the keys the vendors document for it."""
    out: list[str] = []
    for key in _TOOL_KEYS:
        value = front.get(key)
        if isinstance(value, str) and value.strip():
            out.extend(part.strip() for part in value.split(",") if part.strip())
        elif isinstance(value, list):
            out.extend(str(item).strip() for item in value if str(item).strip())
        elif isinstance(value, dict):
            out.extend(str(name) for name in value)
    # Ordered and de-duplicated, so two reads of one file produce the same event.
    return sorted(set(out))


def _prompt_in(document: Any) -> tuple[str | None, str | None]:
    """An instruction inside a JSON document, only from a key that names one."""
    if not isinstance(document, dict):
        return None, None
    for key in _PROMPT_KEYS:
        value = document.get(key)
        if isinstance(value, str) and value.strip():
            return value, key
        if isinstance(value, list):
            parts = [str(item) for item in value if isinstance(item, (str, int, float))]
            if parts:
                return "\n".join(parts), key
    # One level down, because several of these formats wrap the prompt in a fields or a
    # config object. Deeper than that is searching rather than reading.
    for holder in document.values():
        if isinstance(holder, dict):
            for key in _PROMPT_KEYS:
                value = holder.get(key)
                if isinstance(value, str) and value.strip():
                    return value, key
    return None, None


def hidden_characters(text: str) -> list[dict[str, Any]]:
    """Characters a reviewer cannot see, counted.

    Public because it is about text and not about files: an instruction that reached a model
    from a database column or from a hook is exactly as worth checking as one in a file, and
    a second copy of this list would be a second place to fix.

    The tag block is counted as a range rather than per character: it exists only to carry
    smuggled text, so how many of them there are matters and which ones do not.
    """
    out = []
    for character in _HIDDEN:
        count = text.count(character)
        if count:
            out.append(
                {
                    "codepoint": f"U+{ord(character):04X}",
                    "name": unicodedata.name(character, "unnamed"),
                    "count": count,
                }
            )
    tags = sum(1 for character in text if 0xE0000 <= ord(character) <= 0xE007F)
    if tags:
        out.append(
            {
                "codepoint": "U+E0000..U+E007F",
                "name": "UNICODE TAG CHARACTERS",
                "count": tags,
            }
        )
    return out


__all__ = ["MAX_TEXT", "SOURCES", "InstructionsParser", "hidden_characters", "scope_of"]
