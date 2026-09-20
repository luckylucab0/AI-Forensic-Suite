"""Read the session store and the hook audit log Cline's own SDK writes.

This is a different product on disk from the editor extension `cline` reads. That one keeps
a directory per task under the editor's global storage. This one keeps a directory per
session under the agent's data directory, and the shapes in it are the ones the vendor
versions and documents.

Three files, three questions, and they answer them at different levels of confidence.

**`<sessionId>.messages.json`** is the canonical replay artifact, versioned by a top-level
`version` field, documented as v1. Source, fetched and read:
https://raw.githubusercontent.com/cline/cline/main/sdk/packages/core/docs/messages-contract-v1.md
A message is a role and a list of provider-native content blocks: `text`, `thinking`,
`tool_use` and `tool_result`. There is no tool role at rest, so a tool result is a block on
a user message, and a `tool_result.tool_use_id` matches the `tool_use.id` of the assistant
message that called it. The contract says additive fields may appear without a version
bump, so an unknown block type is carried rather than dropped, and a `version` other than 1
is said out loud on every event of the file instead of being read as if it were 1.

**`<sessionId>.json`** is the session manifest, and for an investigation it is the richest
of the three. Source, fetched and read, as a zod schema:
https://raw.githubusercontent.com/cline/cline/main/sdk/packages/core/src/session/models/session-manifest.ts
It records when the run started and ended, its process id, its exit code and status, which
provider and model it used, the working directory and the workspace root, whether it was
interactive, whether tools, spawning and teams were enabled for it, and the prompt it was
started with. An `interactive: false` run with a `prompt` is an automated one, which is a
question about a session that no transcript answers by itself.

**The hook audit log** is one JSON object per line, appended by the hook writer, the
session manifest store and the team child session manager. Source, fetched and read:
https://raw.githubusercontent.com/cline/cline/main/sdk/packages/core/src/hooks/hook-file-hooks.ts
It matters for one reason above the others: in the messages file a timestamp is present on
assistant turn messages only, so a prompt there cannot be placed on a clock. Every line
here is dated, which makes this the artifact that says when somebody asked for something.

**Tool facets.** The default tool names and their input shapes are a source too:
https://raw.githubusercontent.com/cline/cline/main/sdk/packages/core/src/extensions/tools/schemas.ts
Each of them accepts several shapes, because the schemas are unions written to tolerate
what a model emits, and a reader that handled only the canonical one would show a case with
no commands in it on a session that ran a dozen. The shapes handled here are the ones in
that file, and an input that matches none of them says so on the event rather than
silently producing no facet.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from agentforensics.model import Actor, Event, unparsed
from agentforensics.parsers.base import (
    ParseContext,
    Parser,
    first_word,
    iter_lines,
    normalise_ts,
    read_json,
    text_of,
)
from agentforensics.parsers.instructions import hidden_characters

# The version of the messages file this parser was written against. A file that says
# something else is still read, because the shapes are additive by contract, and every one
# of its events carries the mismatch.
MESSAGES_VERSION = 1

# The vendor's default tool names. Only an exact match produces a facet: a tool the agent
# was given by an MCP server or an extension has a name nobody here has read, and inventing
# a facet for it would put a command or a file access in a case on the strength of its name.
READ_FILES = "read_files"
RUN_COMMANDS = "run_commands"
FETCH_WEB = "fetch_web_content"
APPLY_PATCH = "apply_patch"
EDITOR = "editor"
SKILLS = "skills"

# A line of the canonical patch grammar that names a file, as the tool's own description
# states it ("*** Begin Patch, *** Update File:, @@, and *** End Patch"). The verb is read
# rather than matched against a list, so a patch that adds or deletes a file is reported
# with the word the patch itself used.
_PATCH_FILE = re.compile(r"^\*\*\*\s+(?P<verb>[A-Za-z]+)\s+File:\s*(?P<path>.+?)\s*$")

# What the hook writer calls each event. Mapped by name, and a name that is not on this list
# is carried uninterpreted: the writer gains hooks over time and a new one read as an old
# one would be worse than a new one read as unknown.
HOOKS = {
    "agent_start": "session.start",
    "agent_resume": "session.start",
    "prompt_submit": "user.prompt",
    "tool_call": "tool.call",
    "tool_result": "tool.result",
    "agent_end": "session.end",
    "agent_abort": "session.end",
    "agent_error": "session.end",
    "session_shutdown": "session.end",
}


class ClineCliParser:
    """The SDK's session store: the messages file, the manifest and the hook audit log."""

    name = "cline_cli"

    _SESSIONS = frozenset({"cline.cli_sessions"})
    _HOOKS = frozenset({"cline.hooks_audit_log"})

    def handles(self, artifact_id: str | None) -> bool:
        return artifact_id in self._SESSIONS or artifact_id in self._HOOKS

    def parse(self, context: ParseContext) -> Iterator[Event]:
        """Dispatch on the file's own name, because one catalogue entry claims three files.

        The entry is the session directory, so one artifact id arrives holding the messages
        file, the manifest and, where the vendor's own documentation puts it, a hook log.
        The suffix is the only thing that tells them apart, and `.messages.json` has to be
        tested before `.json` or the manifest reader would be handed a transcript.
        """
        name = context.local_path.name
        if context.artifact_id in self._HOOKS or name.endswith(".hooks.jsonl"):
            yield from self._hooks(context)
        elif name.endswith(".messages.json"):
            yield from self._messages(context)
        elif name.endswith(".json"):
            yield from self._manifest(context)
        else:
            yield unparsed(
                context.provenance("document"),
                context.agent,
                None,
                f"{name!r} is in a session directory and is not a file this parser maps",
                user=context.user,
                host=context.host,
                session_id=_from_name(name),
            )

    # ------------------------------------------------------------ the messages file

    def _messages(self, context: ParseContext) -> Iterator[Event]:
        document, problem, relaxed = read_json(context.local_path)
        problem = problem or relaxed
        if problem is not None or not isinstance(document, dict):
            yield unparsed(
                context.provenance("document"),
                context.agent,
                None,
                problem or "the messages file is not a JSON object",
                user=context.user,
                host=context.host,
                session_id=_from_name(context.local_path.name),
            )
            return

        session = _text(document.get("sessionId")) or _from_name(context.local_path.name)
        version = document.get("version")
        # Said on every event of the file rather than once, because an event is read on its
        # own in a timeline and a note attached to a header nobody scrolled to is not a
        # warning. The contract versions this field and says a breaking change increments
        # it, so anything else means these shapes were read against the wrong contract.
        note = (
            None
            if version == MESSAGES_VERSION
            else f"this file says version {version!r} and these shapes were read against "
            f"the vendor's version {MESSAGES_VERSION} contract, so a field may have moved"
        )
        common: dict[str, Any] = {
            "user": context.user,
            "host": context.host,
            "session_id": session,
            "agent": context.agent,
        }

        yield Event(
            kind="config.snapshot",
            provenance=context.provenance("header"),
            raw={key: value for key, value in document.items() if key != "messages"},
            # updated_at is when this file was last written, which is not when the session
            # began. It is the file's own clock and it is named as such, because a reader
            # who takes it for a start time dates a whole conversation to its last save.
            ts_utc=(when := normalise_ts(document.get("updated_at")))[0],
            ts_precision=when[1],
            ts_source="the file's updated_at, which is when it was last written"
            if when[0]
            else None,
            actor="system",
            payload={
                "text": f"{len(_list(document.get('messages')))} message(s) in this session",
                # lead, subagent or teammate. The vendor derives it from the shape of the
                # session id, and it is how a case tells a run somebody started from a run
                # another run started.
                "role": document.get("agent"),
                "task_type": document.get("taskType"),
                "subagent": _origin(document).get("subagent"),
                "parent_session_id": _origin(document).get("parentThreadId"),
                # How the session came to exist, in the vendor's own words. `mode` is
                # "user" for one a person drove, and `trigger` is set where something else
                # started it.
                "origin_mode": _origin(document).get("mode"),
                "origin_trigger": _origin(document).get("trigger"),
                "origin_source": _origin(document).get("source"),
                "version": version,
            },
            parse_problem=" ".join(filter(None, [when[2], note])) or None,
            **common,
        )

        system_prompt = _text(document.get("system_prompt"))
        if system_prompt:
            hidden = hidden_characters(system_prompt)
            yield Event(
                kind="instruction.source",
                provenance=context.provenance("$.system_prompt"),
                raw={"system_prompt": system_prompt},
                ts_utc=None,
                ts_precision="absent",
                actor="system",
                payload={
                    "text": system_prompt,
                    # The path is the file that holds it, because that is what the evidence
                    # is: this is the prompt as persisted with the session, not a claim
                    # about the vendor's own base prompt, which is not on the endpoint.
                    "instructions": [
                        {
                            "path": f"{context.original_path}#system_prompt",
                            "scope": "session",
                        }
                    ],
                    # The same field the instruction parser sets, so this prompt appears in
                    # the instruction surface beside the files an agent was told to obey
                    # rather than as a row whose tier nobody could settle.
                    "scope": "session",
                    "hidden_characters": hidden,
                },
                parse_problem=note,
                **common,
            )

        for index, message in enumerate(_list(document.get("messages"))):
            yield from self._message(context, common, index, message, note)

    def _message(
        self,
        context: ParseContext,
        common: dict[str, Any],
        index: int,
        message: Any,
        note: str | None,
    ) -> Iterator[Event]:
        locator = f"$.messages[{index}]"
        if not isinstance(message, dict):
            yield unparsed(
                context.provenance(locator),
                context.agent,
                message,
                "a message that is not an object, which the contract does not allow",
                user=context.user,
                host=context.host,
                session_id=common.get("session_id"),
            )
            return

        role = _text(message.get("role"))
        # Epoch milliseconds, and the contract says it is present on assistant turn
        # messages. A user message therefore has no time of its own, and none is taken from
        # the assistant message beside it: that would date a prompt to the answer.
        when, precision, timing = normalise_ts(message.get("ts"))
        model = _mapping(message.get("modelInfo"))
        metrics = _mapping(message.get("metrics"))
        models = (
            [
                {
                    "model": model.get("id"),
                    "provider": model.get("provider"),
                    "family": model.get("family"),
                    "input_tokens": metrics.get("inputTokens"),
                    "output_tokens": metrics.get("outputTokens"),
                    "cache_read_tokens": metrics.get("cacheReadTokens"),
                    "cache_write_tokens": metrics.get("cacheWriteTokens"),
                    "cost": metrics.get("cost"),
                }
            ]
            if model
            else []
        )
        fields: dict[str, Any] = {
            "ts_utc": when,
            "ts_precision": precision,
            "ts_source": "the message's own ts" if when else None,
            **common,
        }
        problem = " ".join(filter(None, [timing, note])) or None

        blocks = _list(message.get("content"))
        if not blocks:
            # The contract says content is always an array and never a string. One that is
            # not is the file disagreeing with its own contract, which is worth seeing.
            yield unparsed(
                context.provenance(locator),
                context.agent,
                message,
                "this message's content is not a list of blocks, which the contract "
                "requires, so nothing in it could be read as a turn",
                ts_utc=when,
                ts_precision=precision,
                user=context.user,
                host=context.host,
                session_id=common.get("session_id"),
            )
            return

        for position, block in enumerate(blocks):
            where = f"{locator}.content[{position}]"
            if not isinstance(block, dict):
                yield unparsed(
                    context.provenance(where),
                    context.agent,
                    block,
                    "a content block that is not an object",
                    ts_utc=when,
                    ts_precision=precision,
                    user=context.user,
                    host=context.host,
                    session_id=common.get("session_id"),
                )
                continue
            yield from self._block(context, where, role, block, message, fields, models, problem)

    def _block(
        self,
        context: ParseContext,
        where: str,
        role: str | None,
        block: dict[str, Any],
        message: dict[str, Any],
        fields: dict[str, Any],
        models: list[dict[str, Any]],
        problem: str | None,
    ) -> Iterator[Event]:
        kind = _text(block.get("type"))
        actor: Actor = "assistant" if role == "assistant" else "user"
        provenance = context.provenance(where)

        if kind == "text":
            yield Event(
                kind="assistant.text" if role == "assistant" else "user.prompt",
                provenance=provenance,
                raw=block,
                actor=actor,
                payload={"text": text_of(block.get("text")), "models": models},
                parse_problem=problem,
                **fields,
            )
            return
        if kind == "thinking":
            yield Event(
                kind="assistant.thinking",
                provenance=provenance,
                raw=block,
                actor="assistant",
                payload={"text": text_of(block.get("thinking")), "models": models},
                parse_problem=problem,
                **fields,
            )
            return
        if kind == "tool_use":
            yield from self._tool_use(context, where, block, fields, problem)
            return
        if kind == "tool_result":
            content = block.get("content")
            yield Event(
                kind="tool.result",
                provenance=provenance,
                raw=block,
                actor="tool",
                payload={
                    "tool_use_id": block.get("tool_use_id"),
                    "output": content,
                    "text": text_of(content),
                    # The contract names is_error as the single canonical error signal and
                    # says it is normalized to a boolean, so a missing one is not an error.
                    "is_error": bool(block.get("is_error")),
                },
                parse_problem=problem,
                **fields,
            )
            return
        yield unparsed(
            provenance,
            context.agent,
            block,
            f"a content block of type {kind!r}, which is not one of the four the contract "
            "names. The contract allows additive shapes, so this is carried whole rather "
            "than dropped",
            ts_utc=fields["ts_utc"],
            ts_precision=fields["ts_precision"],
            user=fields.get("user"),
            host=fields.get("host"),
            session_id=fields.get("session_id"),
            payload={"message_role": role},
        )
        return

    def _tool_use(
        self,
        context: ParseContext,
        where: str,
        block: dict[str, Any],
        fields: dict[str, Any],
        problem: str | None,
    ) -> Iterator[Event]:
        name = _text(block.get("name")) or ""
        value = block.get("input")
        facets, unread = _facets(name, value)
        payload: dict[str, Any] = {
            "tool": name,
            "tool_use_id": block.get("id"),
            "input": value,
            **facets,
        }
        yield Event(
            kind="tool.call",
            provenance=context.provenance(where),
            raw=block,
            actor="assistant",
            payload=payload,
            parse_problem=" ".join(filter(None, [problem, unread])) or None,
            **fields,
        )
        # A command or a fetch is also its own event, so that "what ran on this endpoint"
        # and "where did this agent connect to" are answerable across every agent in a case
        # rather than by knowing this one's tool names.
        for kind, extra in _effects(facets):
            yield Event(
                kind=kind,
                provenance=context.provenance(f"{where}#{kind}"),
                raw=block,
                actor="assistant",
                payload={"tool": name, "tool_use_id": block.get("id"), **extra},
                parse_problem=problem,
                **fields,
            )

    # ---------------------------------------------------------------- the manifest

    def _manifest(self, context: ParseContext) -> Iterator[Event]:
        document, problem, relaxed = read_json(context.local_path)
        problem = problem or relaxed
        if problem is not None or not isinstance(document, dict):
            yield unparsed(
                context.provenance("document"),
                context.agent,
                None,
                problem or "the session manifest is not a JSON object",
                user=context.user,
                host=context.host,
                session_id=_from_name(context.local_path.name),
            )
            return

        session = _text(document.get("session_id")) or _from_name(context.local_path.name)
        project = _text(document.get("cwd")) or _text(document.get("workspace_root"))
        common: dict[str, Any] = {
            "user": context.user,
            "host": context.host,
            "session_id": session,
            "project_path": project,
            "agent": context.agent,
            # The vendor's own word for how the run was driven: cli, desktop, vscode,
            # jetbrains, api, web, enterprise. It is what tells two sessions in one store
            # apart when both belong to the same person.
            "client": _text(document.get("source")),
        }
        started, started_precision, started_note = normalise_ts(document.get("started_at"))
        models = (
            [{"model": document.get("model"), "provider": document.get("provider")}]
            if document.get("model") or document.get("provider")
            else []
        )

        yield Event(
            kind="session.start",
            provenance=context.provenance("$.started_at"),
            raw=document,
            ts_utc=started,
            ts_precision=started_precision,
            ts_source="the manifest's started_at" if started else None,
            actor="system",
            payload={
                "text": f"session {session or 'with no id'} started",
                "models": models,
                "pid": document.get("pid"),
                # False with a prompt present is an automated run, which is a question no
                # transcript answers on its own.
                "interactive": document.get("interactive"),
                "status": document.get("status"),
                "workspace_root": document.get("workspace_root"),
                "team_name": document.get("team_name"),
                # What the run was allowed to do, as three separate switches the vendor
                # records per session rather than in a global setting.
                "enable_tools": document.get("enable_tools"),
                "enable_spawn": document.get("enable_spawn"),
                "enable_teams": document.get("enable_teams"),
                # Where the rest of this session is, as the manifest itself states it. A
                # case whose messages file is missing can say whether it was ever written.
                "messages_path": document.get("messages_path"),
                "compaction_path": document.get("compaction_path"),
                "metadata": document.get("metadata"),
            },
            parse_problem=started_note,
            **common,
        )

        prompt = _text(document.get("prompt"))
        if prompt:
            yield Event(
                kind="user.prompt",
                provenance=context.provenance("$.prompt"),
                raw={"prompt": prompt},
                # Dated to the start of the run, because that is what the manifest records
                # it as: the prompt the session was started with, not one typed later.
                ts_utc=started,
                ts_precision=started_precision,
                ts_source="the manifest's started_at" if started else None,
                actor="user",
                payload={
                    "text": prompt,
                    # Said, because the same text is usually the first message of the
                    # messages file as well, and two events for one prompt is a
                    # corroboration rather than two prompts.
                    "from_manifest": True,
                    "interactive": document.get("interactive"),
                },
                parse_problem=started_note,
                **common,
            )

        ended, ended_precision, ended_note = normalise_ts(document.get("ended_at"))
        status = _text(document.get("status"))
        if ended or status in ("completed", "failed", "cancelled"):
            yield Event(
                kind="session.end",
                provenance=context.provenance("$.ended_at"),
                raw=document,
                ts_utc=ended,
                ts_precision=ended_precision,
                ts_source="the manifest's ended_at" if ended else None,
                actor="system",
                payload={
                    "text": f"session {status or 'with no status'}",
                    "status": status,
                    "exit_code": document.get("exit_code"),
                },
                # A terminal status with no ended_at is a run that was recorded as finished
                # without a time, which is worth seeing rather than filling in.
                parse_problem=ended_note
                or (None if ended else "this run has a terminal status and no ended_at"),
                **common,
            )

    # ------------------------------------------------------------- the hook audit log

    def _hooks(self, context: ParseContext) -> Iterator[Event]:
        for line in iter_lines(context.local_path):
            record = line.value if line.ok else None
            if not isinstance(record, dict):
                yield unparsed(
                    context.provenance(line.locator),
                    context.agent,
                    line.text or None,
                    line.problem or "the line could not be read",
                    user=context.user,
                    host=context.host,
                )
                continue
            yield from self._hook(context, line.locator, record)

    def _hook(self, context: ParseContext, locator: str, record: dict[str, Any]) -> Iterator[Event]:
        hook = _text(record.get("hookName"))
        kind = HOOKS.get(hook or "")
        # `ts` is written by the appender itself and `timestamp` by the payload builder.
        # Both are ISO strings from the same process; ts is preferred because it is the one
        # every writer of this file sets, including the two that write no payload base.
        when, precision, timing = normalise_ts(record.get("ts") or record.get("timestamp"))
        roots = _list(record.get("workspaceRoots"))
        session = _context(record).get("rootSessionId")
        common: dict[str, Any] = {
            "user": context.user,
            "host": context.host,
            "agent": context.agent,
            "ts_utc": when,
            "ts_precision": precision,
            "ts_source": "the line's own ts" if when else None,
            "session_id": _text(record.get("taskId"))
            or _text(session)
            or _text(record.get("sessionId")),
            "project_path": _text(roots[0]) if roots else None,
        }
        if kind is None:
            yield unparsed(
                context.provenance(locator),
                context.agent,
                record,
                f"a hook named {hook!r}, which is not one of the nine this parser reads. "
                "The writer gains hooks over time, so it is carried whole rather than read "
                "as one of the others",
                ts_utc=when,
                ts_precision=precision,
                user=context.user,
                host=context.host,
                session_id=common["session_id"],
                project_path=common["project_path"],
            )
            return

        payload: dict[str, Any] = {
            "hook": hook,
            "version": _text(record.get("clineVersion")) or None,
            # The agent's own idea of who was running it: CLINE_USER_ID, or the shell's
            # USER, or the literal string unknown. Not put in the event's user field, which
            # is the account the collection attributed the file to, because the two are
            # different claims and a case has to be able to disagree with one of them.
            "reported_user": _text(record.get("userId")),
            "subagent": _text(record.get("agent_id")),
            "parent_subagent": _text(record.get("parent_agent_id")),
            "iteration": record.get("iteration"),
        }

        if hook == "prompt_submit":
            prompt = _mapping(record.get("userPromptSubmit"))
            payload["text"] = text_of(prompt.get("prompt"))
            payload["attachments"] = prompt.get("attachments")
        elif hook == "tool_call":
            call = _mapping(record.get("tool_call"))
            name = _text(call.get("name")) or ""
            facets, unread = _facets(name, call.get("input"))
            payload.update(
                {"tool": name, "tool_use_id": call.get("id"), "input": call.get("input"), **facets}
            )
            timing = " ".join(filter(None, [timing, unread])) or None
        elif hook == "tool_result":
            after = _mapping(record.get("postToolUse"))
            result = _mapping(record.get("tool_result"))
            payload.update(
                {
                    "tool": _text(after.get("toolName")) or _text(result.get("name")),
                    "tool_use_id": result.get("id"),
                    "output": after.get("result") if "result" in after else result.get("output"),
                    "text": text_of(after.get("result")),
                    # The writer sets success from the absence of an error, so a false here
                    # is the agent's own record of a tool that failed.
                    "is_error": after.get("success") is False or bool(result.get("error")),
                    "duration_ms": after.get("executionTimeMs") or result.get("durationMs"),
                }
            )
        elif hook in ("agent_end", "agent_abort", "agent_error"):
            turn = _mapping(record.get("turn"))
            error = _mapping(record.get("error"))
            payload.update(
                {
                    "text": text_of(turn.get("outputText")) or _text(record.get("reason")) or None,
                    "status": _text(turn.get("status"))
                    or ("aborted" if hook == "agent_abort" else None),
                    "error": error or None,
                    "is_error": hook == "agent_error",
                }
            )
        elif hook == "session_shutdown":
            payload.update(
                {
                    "text": _text(record.get("reason")),
                    "pid": record.get("pid"),
                    "status": "shutdown",
                }
            )

        yield Event(
            kind=kind,
            provenance=context.provenance(locator),
            raw=record,
            actor=_ACTORS[hook],
            payload=payload,
            parse_problem=timing,
            **common,
        )
        for effect_kind, extra in _effects(payload):
            yield Event(
                kind=effect_kind,
                provenance=context.provenance(f"{locator}#{effect_kind}"),
                raw=record,
                actor="assistant",
                payload={"tool": payload.get("tool"), **extra},
                parse_problem=timing,
                **common,
            )


# Who acted, per hook. Written out rather than derived, because the difference between a
# prompt somebody submitted and a run the agent ended is the whole point of the field.
_ACTORS: dict[str | None, Any] = {
    "agent_start": "system",
    "agent_resume": "system",
    "prompt_submit": "user",
    "tool_call": "assistant",
    "tool_result": "tool",
    "agent_end": "system",
    "agent_abort": "system",
    "agent_error": "system",
    "session_shutdown": "system",
}


def _facets(name: str, value: Any) -> tuple[dict[str, Any], str | None]:
    """The facets one tool call earns, and the reason where an input could not be read.

    Only the vendor's own default tools, by exact name. The input shapes are the unions in
    the vendor's schema file: they are wide because they tolerate what a model emits, and a
    reader that handled only the canonical shape would show a session that ran a dozen
    commands as one that ran none.
    """
    if name == RUN_COMMANDS:
        commands = _commands(value)
        if not commands:
            return {}, (
                "this run_commands input is in none of the shapes the vendor's schema "
                "accepts, so no command was read out of it. The input is in the payload"
            )
        return {"commands": commands}, None
    if name == READ_FILES:
        files = [{"path": path, "operation": "read"} for path in _paths(value)]
        if not files:
            return {}, (
                "this read_files input is in none of the shapes the vendor's schema "
                "accepts, so no path was read out of it. The input is in the payload"
            )
        return {"files": files}, None
    if name == EDITOR:
        path = _text(_mapping(value).get("path"))
        if not path:
            return {}, "this editor input names no path, so no file was read out of it"
        return {"files": [{"path": path, "operation": "write"}]}, None
    if name == APPLY_PATCH:
        body = value if isinstance(value, str) else _text(_mapping(value).get("input"))
        files = _patched(body or "")
        if not files:
            return {}, (
                "this apply_patch input holds no line of the canonical patch grammar that "
                "names a file, so no path was read out of it. The patch is in the payload"
            )
        return {"files": files}, None
    if name == FETCH_WEB:
        urls = [
            {"url": url}
            for request in _list(_mapping(value).get("requests"))
            if (url := _text(_mapping(request).get("url")))
        ]
        if not urls:
            return {}, "this fetch_web_content input names no URL"
        return {"network": urls}, None
    if name == SKILLS:
        skill = _mapping(value)
        return {"skill": _text(skill.get("skill")), "skill_args": _text(skill.get("args"))}, None
    return {}, None


def _effects(payload: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """The events a facet earns in its own right, so a timeline can be asked across agents."""
    out: list[tuple[str, dict[str, Any]]] = []
    if payload.get("commands"):
        out.append(("command.exec", {"commands": payload["commands"]}))
    if payload.get("network"):
        out.append(("network.request", {"network": payload["network"]}))
    for entry in payload.get("files") or []:
        # There is no file.delete kind: a delete is a change to the working copy, and the
        # operation on the facet is what says which change it was.
        kind = "file.read" if entry.get("operation") == "read" else "file.write"
        out.append((kind, {"files": [entry]}))
    return out


def _commands(value: Any) -> list[dict[str, Any]]:
    """Every shape of run_commands input the vendor's union accepts."""
    if isinstance(value, str):
        return [_command(value)]
    if isinstance(value, list):
        return [command for item in value for command in _commands(item)]
    if isinstance(value, dict):
        inner = value.get("commands")
        if inner is not None:
            return _commands(inner)
        # The structured form: an executable and an argv list, which the vendor runs
        # without a shell. Rendered back into one line for the facet, and the argv is in
        # the payload either way, because a case searches commands as text.
        executable = _text(value.get("command")) or _text(value.get("cmd"))
        if not executable:
            return []
        args = [str(arg) for arg in _list(value.get("args"))]
        rendered = " ".join([executable, *args]) if args else executable
        return [{"command": rendered, "executable": first_word(executable), "argv": args or None}]
    return []


def _command(text: str) -> dict[str, Any]:
    return {"command": text, "executable": first_word(text)}


def _paths(value: Any) -> list[str]:
    """Every shape of read_files input the vendor's union accepts, including the aliases.

    The aliases are in the schema because models emit them: `file_path` and `filePath` for
    one entry, `file_paths` and `paths` for the list. The vendor normalizes them before the
    tool runs, so a reader that ignored them would under-report file access on exactly the
    sessions where the model was least precise.
    """
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [path for item in value for path in _paths(item)]
    if isinstance(value, dict):
        for key in ("files", "file_paths", "paths"):
            if key in value:
                return _paths(value[key])
        for key in ("path", "file_path", "filePath"):
            if (path := _text(value.get(key))) is not None:
                return [path]
    return []


# What a patch verb does to a file, in the words the unified format's file facet uses. A
# verb this does not know is `unknown` rather than a guess at write: the grammar can grow
# one, and the patch's own word travels beside it either way.
_PATCH_OPERATIONS = {"add": "write", "update": "write", "delete": "delete"}


def _patched(body: str) -> list[dict[str, Any]]:
    """The files a patch names, with what the patch does to each."""
    out = []
    for line in body.splitlines():
        found = _PATCH_FILE.match(line)
        if found:
            verb = found.group("verb").lower()
            out.append(
                {
                    "path": found.group("path"),
                    "operation": _PATCH_OPERATIONS.get(verb, "unknown"),
                    # The patch's own word, kept beside the operation rather than in place
                    # of it: a grammar that grows a verb should show it rather than be read
                    # as an update, and a case queries the operation.
                    "patch_verb": verb,
                }
            )
    return out


def _origin(document: dict[str, Any]) -> dict[str, Any]:
    return _mapping(document.get("origin"))


def _context(record: dict[str, Any]) -> dict[str, Any]:
    return _mapping(record.get("sessionContext"))


def _from_name(name: str) -> str | None:
    """The session id in a file name, which is how the vendor names all three files."""
    for suffix in (".messages.json", ".hooks.jsonl", ".json"):
        if name.endswith(suffix):
            return name[: -len(suffix)] or None
    return None


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


_: Parser = ClineCliParser()

__all__ = ["HOOKS", "MESSAGES_VERSION", "ClineCliParser"]
