"""Parse Gemini CLI and Qwen Code transcripts.

One module for two agents because Qwen Code is a fork of Gemini CLI, so both write the
Gemini API's own content shape: a message is a list of `parts`, and a part is text, a
thought, a `functionCall` or a `functionResponse`. Two parsers would have had to agree with
each other about that shape forever.

They differ in what wraps it, and each wrapper has one thing a reader has to know.

Gemini CLI writes a session as JSON Lines whose records are told apart by which key they
carry, not by a type field: `$rewindTo` is a rewind, `id` is a message, `$set` is a
metadata update, and `sessionId` with `projectHash` is the conversation header. That is the
service's own discrimination order and this parser uses the same one, because a record that
matched a later test first would be read as the wrong kind.
Source: https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/services/chatRecordingService.ts

A `$rewindTo` record is the forensically interesting one. It says the conversation was
rolled back to an earlier message, so the turns after that point were taken out of the
agent's view while still sitting in the file. An analyst reading the transcript top to
bottom would otherwise see turns the model never saw again, with nothing to say so.

Qwen Code writes one `ChatRecord` per line, with a uuid and parentUuid chain, the working
directory, the CLI version and the git branch on every record, and a `subtype` for the
records that are not a turn. Its prompt history is a different thing again: `logs.json` is
one JSON array rewritten in place on every append, which means a crash mid-write loses the
whole file rather than one line.
Source: https://github.com/QwenLM/qwen-code/blob/main/packages/core/src/services/chatRecordingService.ts
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any
from urllib.parse import urlsplit

from agentforensics.model import Event, unparsed
from agentforensics.parsers.base import (
    Line,
    ParseContext,
    first_word,
    iter_lines,
    normalise_ts,
    read_json,
    text_of,
)

# The tool names both CLIs ship with. Only an exact name produces a facet: a tool nobody
# here recognises still becomes a tool.call with its arguments intact, which costs an
# indexed facet rather than the evidence. Guessing from a name that merely looks like a
# shell tool would put a command in a case that nothing ran.
_COMMAND = ("run_shell_command", "run_terminal_command", "shell")
_FILE_READ = ("read_file", "read_many_files")
_FILE_WRITE = ("write_file", "replace", "edit", "smart_edit")
_NETWORK = ("web_fetch", "google_web_search", "web_search")
_MEMORY = ("save_memory",)

# Keys the same argument is spelled with across versions of these tools, in the order they
# are tried. A tolerant read rather than one spelling, because a renamed argument should
# cost nothing: the whole argument mapping is in the payload either way.
_PATH_KEYS = ("absolute_path", "file_path", "path", "filename")

# A URL inside the prompt of a fetch tool is what the tool fetched. Extracted so that
# "which external hosts did this agent reach" is an indexed query, and only for http and
# https, because those are the ones that leave the machine.
_URL = re.compile(r"https?://[^\s<>\"')\]]+")

# The locator for an event about a whole file rather than a record inside one.
DOCUMENT = "document"


class GeminiParser:
    """Gemini CLI sessions, Qwen Code transcripts, and Qwen Code's prompt history."""

    name = "gemini"

    _GEMINI = frozenset({"gemini_cli.chats"})
    _QWEN = frozenset({"qwen_code.conversation_transcript", "qwen_code.subagent_transcripts"})
    _QWEN_HISTORY = frozenset({"qwen_code.prompt_history_log"})

    def handles(self, artifact_id: str | None) -> bool:
        return (
            artifact_id in self._GEMINI
            or artifact_id in self._QWEN
            or artifact_id in self._QWEN_HISTORY
        )

    def parse(self, context: ParseContext) -> Iterator[Event]:
        if context.artifact_id in self._QWEN_HISTORY:
            yield from self._qwen_history(context)
            return
        if context.artifact_id in self._QWEN:
            yield from self._qwen(context)
            return
        yield from self._gemini(context)

    # ------------------------------------------------------------------ Gemini CLI

    def _gemini(self, context: ParseContext) -> Iterator[Event]:
        """A Gemini CLI session file, one record per line.

        The conversation's identity arrives in the header record and applies to everything
        after it, so it is carried forward rather than looked up per event.
        """
        state: dict[str, Any] = {"session_id": None, "project": None, "kind": None}

        for line in iter_lines(context.local_path):
            if not line.ok:
                yield self._unreadable(context, line)
                continue
            record = line.value

            # The service's own order. A message record also has a timestamp and a
            # metadata record also has an id in some versions, so the tests have to run in
            # the order the writer expects or a record is read as the wrong kind.
            if isinstance(record.get("$rewindTo"), str):
                yield from self._rewind(context, line, record, state)
                continue
            if isinstance(record.get("id"), str):
                yield from self._gemini_message(context, line, record, state)
                continue
            if isinstance(record.get("$set"), dict):
                yield from self._metadata_update(context, line, record, state)
                continue
            if isinstance(record.get("sessionId"), str) and isinstance(
                record.get("projectHash"), str
            ):
                yield from self._gemini_header(context, line, record, state)
                continue
            yield unparsed(
                context.provenance(line.locator),
                context.agent,
                record,
                "a session record carrying none of the keys this format is told apart by "
                "($rewindTo, id, $set, or sessionId with projectHash)",
                user=context.user,
                host=context.host,
                session_id=state["session_id"],
            )

    def _gemini_header(
        self,
        context: ParseContext,
        line: Line,
        record: dict[str, Any],
        state: dict[str, Any],
    ) -> Iterator[Event]:
        state["session_id"] = record.get("sessionId")
        state["project"] = record.get("projectHash")
        state["kind"] = record.get("kind")
        ts, precision, note = normalise_ts(record.get("startTime"))
        directories = record.get("directories")
        yield Event(
            kind="session.start",
            provenance=context.provenance(line.locator),
            agent=context.agent,
            raw=record,
            ts_utc=ts,
            ts_precision=precision,
            ts_source="startTime" if ts else None,
            actor="system",
            user=context.user,
            host=context.host,
            session_id=state["session_id"],
            # The header records a hash of the working directory rather than the directory
            # itself, so it is reported as what it is. Presenting a hash where a path
            # belongs would read as a path nobody could find.
            project_path=None,
            payload={
                "project_hash": state["project"],
                "session_kind": record.get("kind"),
                "directories": list(directories) if isinstance(directories, list) else None,
                "summary": record.get("summary"),
                "last_updated": record.get("lastUpdated"),
                "text": f"session {state['session_id']} began, project hash {state['project']}",
            },
            parse_problem=note,
        )

    def _metadata_update(
        self,
        context: ParseContext,
        line: Line,
        record: dict[str, Any],
        state: dict[str, Any],
    ) -> Iterator[Event]:
        """A `$set` record: the conversation's own metadata was rewritten.

        Recorded as a configuration snapshot, which is the closest existing kind and is
        deliberate rather than convenient: inventing a kind for it would put a name in the
        event model that only one agent uses, and dropping it is not an option, because a
        summary or a scratchpad being rewritten mid-session is a change to what the agent
        was working from.
        """
        changed = record["$set"]
        yield Event(
            kind="config.snapshot",
            provenance=context.provenance(line.locator),
            agent=context.agent,
            raw=record,
            actor="system",
            user=context.user,
            host=context.host,
            session_id=state["session_id"],
            payload={
                "updated": sorted(changed) if isinstance(changed, dict) else None,
                "values": changed,
                "text": "the session's recorded metadata was updated: " + ", ".join(sorted(changed))
                if isinstance(changed, dict)
                else "the session's recorded metadata was updated",
            },
        )

    def _rewind(
        self,
        context: ParseContext,
        line: Line,
        record: dict[str, Any],
        state: dict[str, Any],
    ) -> Iterator[Event]:
        """A rewind: everything after the named message left the agent's view.

        The turns themselves are still in the file, above this record, which is why this
        has to be an event. A reader going top to bottom would otherwise see turns the
        model never saw again and have nothing telling them so.
        """
        target = record["$rewindTo"]
        yield Event(
            kind="session.end",
            provenance=context.provenance(line.locator),
            agent=context.agent,
            raw=record,
            actor="user",
            user=context.user,
            host=context.host,
            session_id=state["session_id"],
            payload={
                "rewind_to": target,
                "text": f"the conversation was rewound to message {target}, so the turns "
                "recorded after it were taken out of the agent's view. They are still in "
                "this file, above this record.",
            },
        )

    def _gemini_message(
        self,
        context: ParseContext,
        line: Line,
        record: dict[str, Any],
        state: dict[str, Any],
    ) -> Iterator[Event]:
        ts, precision, note = normalise_ts(record.get("timestamp"))
        common: dict[str, Any] = {
            "ts_utc": ts,
            "ts_precision": precision,
            "ts_source": "timestamp" if ts else None,
            "user": context.user,
            "host": context.host,
            "session_id": state["session_id"],
        }
        models = [{"model": record["model"]}] if record.get("model") else []
        tokens = record.get("tokens")
        if models and isinstance(tokens, dict):
            models[0].update(
                {
                    "input_tokens": tokens.get("input"),
                    "output_tokens": tokens.get("output"),
                }
            )
        kind = record.get("type")
        parts = _parts(record.get("content"))
        # displayContent is what the user was shown where it differs from what the model
        # was sent. Both are kept: the difference between them is the difference between
        # what happened and what somebody saw happen.
        shown = _parts(record.get("displayContent")) if record.get("displayContent") else None

        if kind == "user":
            yield Event(
                kind="user.prompt",
                provenance=context.provenance(line.locator),
                agent=context.agent,
                raw=record,
                actor="user",
                payload={
                    "text": parts["text"],
                    "displayed_text": shown["text"] if shown else None,
                    "message_id": record.get("id"),
                    "other_parts": parts["other"] or None,
                },
                parse_problem=note,
                **common,
            )
        elif kind == "gemini":
            emitted = False
            for index, thought in enumerate(_thoughts(record.get("thoughts"))):
                emitted = True
                thought_ts, thought_precision, _ = normalise_ts(thought.get("timestamp"))
                yield Event(
                    kind="assistant.thinking",
                    provenance=context.provenance(f"{line.locator}#thought{index}"),
                    agent=context.agent,
                    raw=thought,
                    ts_utc=thought_ts or ts,
                    ts_precision=thought_precision if thought_ts else precision,
                    ts_source=("timestamp" if thought_ts else common["ts_source"]),
                    actor="assistant",
                    user=context.user,
                    host=context.host,
                    session_id=state["session_id"],
                    payload={
                        "text": text_of(thought.get("description") or thought.get("subject")),
                        "subject": thought.get("subject"),
                        "models": models,
                        "message_id": record.get("id"),
                    },
                )
            if parts["thinking"]:
                emitted = True
                yield Event(
                    kind="assistant.thinking",
                    provenance=context.provenance(f"{line.locator}#thinking"),
                    agent=context.agent,
                    raw=record,
                    actor="assistant",
                    payload={
                        "text": parts["thinking"],
                        "models": models,
                        "message_id": record.get("id"),
                    },
                    parse_problem=note,
                    **common,
                )
            if parts["text"] or not (parts["calls"] or emitted):
                emitted = True
                yield Event(
                    kind="assistant.text",
                    provenance=context.provenance(line.locator),
                    agent=context.agent,
                    raw=record,
                    actor="assistant",
                    payload={
                        "text": parts["text"],
                        "displayed_text": shown["text"] if shown else None,
                        "models": models,
                        "message_id": record.get("id"),
                        "other_parts": parts["other"] or None,
                    },
                    parse_problem=note,
                    **common,
                )
            # The parts of the message itself can carry function calls, and the record can
            # carry an enriched toolCalls list as well. Both are mapped: they are the same
            # calls seen at two moments, and the enriched one is the only one that has the
            # result.
            for index, call in enumerate(parts["calls"]):
                yield from self._tool_call(
                    context,
                    line,
                    record,
                    f"part{index}",
                    str(call.get("name") or ""),
                    _mapping(call.get("args")),
                    call.get("id"),
                    models,
                    common,
                )
            for index, call in enumerate(_listed(record.get("toolCalls"))):
                yield from self._tool_call(
                    context,
                    line,
                    record,
                    f"tool{index}",
                    str(call.get("name") or ""),
                    _mapping(call.get("args")),
                    call.get("id"),
                    models,
                    common,
                    status=call.get("status"),
                    description=call.get("description"),
                    result=call.get("result"),
                    result_display=call.get("resultDisplay"),
                    call_ts=call.get("timestamp"),
                )
        else:
            yield unparsed(
                context.provenance(line.locator),
                context.agent,
                record,
                f"message type {kind!r} is not one this parser maps",
                ts_utc=ts,
                ts_precision=precision,
                ts_source=common["ts_source"],
                user=context.user,
                host=context.host,
                session_id=state["session_id"],
            )

    # ---------------------------------------------------------------- Qwen Code

    def _qwen(self, context: ParseContext) -> Iterator[Event]:
        """A Qwen Code transcript, one ChatRecord per line."""
        for line in iter_lines(context.local_path):
            if not line.ok:
                yield self._unreadable(context, line)
                continue
            record = line.value
            ts, precision, note = normalise_ts(record.get("timestamp"))
            common: dict[str, Any] = {
                "ts_utc": ts,
                "ts_precision": precision,
                "ts_source": "timestamp" if ts else None,
                "user": context.user,
                "host": context.host,
                "session_id": record.get("sessionId"),
                "project_path": record.get("cwd"),
                "git_branch": record.get("gitBranch"),
                "client": record.get("version"),
            }
            message = _mapping(record.get("message"))
            parts = _parts(message.get("parts", message.get("content")))
            usage = _mapping(record.get("usageMetadata"))
            models = (
                [
                    {
                        "model": record["model"],
                        "input_tokens": usage.get("promptTokenCount"),
                        "output_tokens": usage.get("candidatesTokenCount"),
                    }
                ]
                if record.get("model")
                else []
            )
            kind = record.get("type")
            subtype = record.get("subtype")

            if subtype == "chat_compression":
                # The same situation Codex's `compacted` record describes: the conversation
                # was rewritten to fit a context window, which is the usual explanation for
                # an apparent gap in a transcript.
                yield Event(
                    kind="session.end",
                    provenance=context.provenance(line.locator),
                    agent=context.agent,
                    raw=record,
                    actor="system",
                    payload={
                        "compaction": True,
                        "text": "the conversation was compressed, so earlier turns were "
                        "rewritten or removed: " + parts["text"],
                        "system_payload": record.get("systemPayload"),
                    },
                    parse_problem=note,
                    **common,
                )
                continue

            if kind == "user":
                yield Event(
                    kind="user.prompt",
                    provenance=context.provenance(line.locator),
                    agent=context.agent,
                    raw=record,
                    actor="user",
                    payload={
                        "text": parts["text"],
                        "message_id": record.get("uuid"),
                        "parent_id": record.get("parentUuid"),
                        # 'real_user' against anything else is the writer's own record of
                        # whether a person typed this, which is exactly the question an
                        # analyst has about a prompt.
                        "provenance_class": record.get("provenance"),
                        "subtype": subtype,
                        "other_parts": parts["other"] or None,
                    },
                    parse_problem=note,
                    **common,
                )
            elif kind == "assistant":
                if parts["thinking"]:
                    yield Event(
                        kind="assistant.thinking",
                        provenance=context.provenance(f"{line.locator}#thinking"),
                        agent=context.agent,
                        raw=record,
                        actor="assistant",
                        payload={
                            "text": parts["thinking"],
                            "models": models,
                            "message_id": record.get("uuid"),
                        },
                        parse_problem=note,
                        **common,
                    )
                if parts["text"] or not parts["calls"]:
                    yield Event(
                        kind="assistant.text",
                        provenance=context.provenance(line.locator),
                        agent=context.agent,
                        raw=record,
                        actor="assistant",
                        payload={
                            "text": parts["text"],
                            "models": models,
                            "message_id": record.get("uuid"),
                            "parent_id": record.get("parentUuid"),
                            "other_parts": parts["other"] or None,
                        },
                        parse_problem=note,
                        **common,
                    )
                for index, call in enumerate(parts["calls"]):
                    yield from self._tool_call(
                        context,
                        line,
                        record,
                        f"tool{index}",
                        str(call.get("name") or ""),
                        _mapping(call.get("args")),
                        call.get("id"),
                        models,
                        common,
                        result=_mapping(record.get("toolCallResult")) or None,
                    )
            elif kind == "tool_result":
                for index, response in enumerate(parts["responses"] or [{}]):
                    yield Event(
                        kind="tool.result",
                        provenance=context.provenance(f"{line.locator}#result{index}"),
                        agent=context.agent,
                        raw=record,
                        actor="tool",
                        payload={
                            "tool": response.get("name"),
                            "tool_use_id": response.get("id"),
                            "output": response.get("response"),
                            "text": parts["text"] or text_of(response.get("response")),
                            "tool_call_result": record.get("toolCallResult"),
                        },
                        parse_problem=note,
                        **common,
                    )
            elif kind == "system":
                yield Event(
                    kind="config.snapshot",
                    provenance=context.provenance(line.locator),
                    agent=context.agent,
                    raw=record,
                    actor="system",
                    payload={
                        "text": parts["text"],
                        "subtype": subtype,
                        "system_payload": record.get("systemPayload"),
                    },
                    parse_problem=note,
                    **common,
                )
            else:
                yield unparsed(
                    context.provenance(line.locator),
                    context.agent,
                    record,
                    f"record type {kind!r} is not one this parser maps",
                    ts_utc=ts,
                    ts_precision=precision,
                    ts_source=common["ts_source"],
                    user=context.user,
                    host=context.host,
                    session_id=record.get("sessionId"),
                )

    def _qwen_history(self, context: ParseContext) -> Iterator[Event]:
        """`logs.json`: one JSON array, rewritten in place on every append.

        Worth knowing while reading it: because the whole array is rewritten rather than
        appended to, a crash during a write loses every prompt in the file rather than the
        last one. An empty or truncated `logs.json` next to a full transcript is that,
        not evidence that nobody typed anything.
        """
        value, problem = read_json(context.local_path)
        if problem is not None:
            yield unparsed(
                context.provenance(DOCUMENT),
                context.agent,
                # The text itself, because a truncated or undecodable prompt history is
                # exactly the thing a reader has to be able to look at. An unparsed record
                # with nothing in raw says only that something went wrong.
                _text_of_file(context),
                f"the prompt history {problem}",
                user=context.user,
                host=context.host,
            )
            return
        if not isinstance(value, list):
            yield unparsed(
                context.provenance(DOCUMENT),
                context.agent,
                value,
                f"the prompt history is a JSON {type(value).__name__}, not the array this "
                "format writes",
                user=context.user,
                host=context.host,
            )
            return
        for index, entry in enumerate(value):
            locator = f"index:{index}"
            if not isinstance(entry, dict):
                yield unparsed(
                    context.provenance(locator),
                    context.agent,
                    entry,
                    f"a prompt history entry is a JSON {type(entry).__name__}, not an object",
                    user=context.user,
                    host=context.host,
                )
                continue
            ts, precision, note = normalise_ts(entry.get("timestamp"))
            yield Event(
                kind="prompt.history",
                provenance=context.provenance(locator),
                agent=context.agent,
                raw=entry,
                ts_utc=ts,
                ts_precision=precision,
                ts_source="timestamp" if ts else None,
                actor="user",
                user=context.user,
                host=context.host,
                session_id=entry.get("sessionId"),
                payload={
                    "text": text_of(entry.get("message")),
                    "message_id": entry.get("messageId"),
                    "sender_type": entry.get("type"),
                },
                parse_problem=note,
            )

    # ------------------------------------------------------------------- shared

    def _tool_call(
        self,
        context: ParseContext,
        line: Line,
        record: dict[str, Any],
        suffix: str,
        name: str,
        arguments: dict[str, Any],
        call_id: Any,
        models: list[dict[str, Any]],
        common: dict[str, Any],
        *,
        status: Any = None,
        description: Any = None,
        result: Any = None,
        result_display: Any = None,
        call_ts: Any = None,
    ) -> Iterator[Event]:
        """One tool call, plus what it did, plus its result where the record has one.

        Three events rather than one where all three are present, because an analyst asks
        three different questions: what did the agent try, what got touched, and what came
        back. Each keeps its own provenance so a finding can cite the one it rests on.
        """
        ts, precision = common["ts_utc"], common["ts_precision"]
        source = common["ts_source"]
        if call_ts is not None:
            own_ts, own_precision, _ = normalise_ts(call_ts)
            if own_ts:
                ts, precision, source = own_ts, own_precision, "timestamp"
        timing = {"ts_utc": ts, "ts_precision": precision, "ts_source": source}
        rest = {key: value for key, value in common.items() if key not in timing}

        yield Event(
            kind="tool.call",
            provenance=context.provenance(f"{line.locator}#{suffix}"),
            agent=context.agent,
            raw=record,
            actor="assistant",
            payload={
                "tool": name,
                "tool_use_id": call_id,
                "input": arguments,
                "status": status,
                "description": description,
                "models": models,
            },
            **timing,
            **rest,
        )

        effect_kind, effect_payload = self._effect(name, arguments)
        if effect_kind:
            yield Event(
                kind=effect_kind,
                provenance=context.provenance(f"{line.locator}#effect-{suffix}"),
                agent=context.agent,
                raw=record,
                actor="assistant",
                payload={"tool": name, "tool_use_id": call_id, **effect_payload},
                **timing,
                **rest,
            )

        if result is not None or result_display is not None:
            yield Event(
                kind="tool.result",
                provenance=context.provenance(f"{line.locator}#result-{suffix}"),
                agent=context.agent,
                raw=record,
                actor="tool",
                payload={
                    "tool": name,
                    "tool_use_id": call_id,
                    "status": status,
                    "output": result,
                    "displayed_output": result_display,
                    "text": text_of(result if result is not None else result_display),
                },
                **timing,
                **rest,
            )

    def _effect(self, name: str, arguments: dict[str, Any]) -> tuple[str | None, dict[str, Any]]:
        """What a named tool did, in facets an analyst can query.

        A tool this does not recognise returns nothing, so the call is still recorded with
        its arguments and only the index is missing. The opposite mistake, guessing from a
        name, would write a command or a file path into a case that nothing produced.
        """
        if name in _COMMAND:
            command = arguments.get("command")
            if not command:
                return None, {}
            return "command.exec", {
                "commands": [
                    {
                        "command": str(command),
                        "executable": first_word(str(command)),
                        "cwd": arguments.get("directory") or arguments.get("cwd"),
                    }
                ],
                "description": arguments.get("description"),
            }
        if name in _FILE_READ:
            paths = _paths(arguments)
            if not paths:
                return None, {}
            return "file.read", {"files": [{"path": path, "operation": "read"} for path in paths]}
        if name in _FILE_WRITE:
            paths = _paths(arguments)
            if not paths:
                return None, {}
            content = arguments.get("content") or arguments.get("new_string")
            return "file.write", {
                "files": [
                    {
                        "path": path,
                        "operation": "write",
                        "bytes": len(str(content).encode("utf-8")) if content else None,
                    }
                    for path in paths
                ]
            }
        if name in _NETWORK:
            destinations = []
            for value in arguments.values():
                for found in _URL.findall(str(value)):
                    destinations.append({"url": found, "host": urlsplit(found).netloc})
            query = arguments.get("query") or arguments.get("prompt")
            if not destinations and not query:
                return None, {}
            return "network.request", {
                "network": destinations or None,
                "query": query,
                "text": str(query) if query else "",
            }
        if name in _MEMORY:
            fact = arguments.get("fact") or arguments.get("memory")
            if not fact:
                return None, {}
            return "memory.write", {"text": str(fact)}
        return None, {}

    def _unreadable(self, context: ParseContext, line: Line) -> Event:
        return unparsed(
            context.provenance(line.locator),
            context.agent,
            line.text or None,
            line.problem or "the line could not be read",
            user=context.user,
            host=context.host,
        )


def _text_of_file(context: ParseContext) -> str:
    try:
        return context.local_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:  # pragma: no cover - read_json already failed on this path
        return f"the file could not be read: {exc}"


def _parts(value: Any) -> dict[str, Any]:
    """A Gemini content value, split into the things a reader asks for separately.

    A `PartListUnion` is a string, one part, or a list of parts, and a part is text, a
    thought (text with `thought` set), a `functionCall` or a `functionResponse`. Anything
    else lands in `other` rather than being dropped: an inline image or a part type added
    in a later version is still evidence that something was in the message.
    """
    out: dict[str, Any] = {
        "text": "",
        "thinking": "",
        "calls": [],
        "responses": [],
        "other": [],
    }
    text: list[str] = []
    thinking: list[str] = []

    for part in _listed(value, allow_scalar=True):
        if isinstance(part, str):
            text.append(part)
            continue
        if not isinstance(part, dict):
            out["other"].append(part)
            continue
        if isinstance(part.get("functionCall"), dict):
            out["calls"].append(part["functionCall"])
            continue
        if isinstance(part.get("functionResponse"), dict):
            out["responses"].append(part["functionResponse"])
            continue
        if "text" in part:
            # `thought: true` on a text part is how the API marks reasoning. Kept apart
            # from the answer, because a plan the model formed and an answer it gave are
            # different claims about what happened.
            (thinking if part.get("thought") else text).append(str(part.get("text") or ""))
            continue
        out["other"].append(part)

    out["text"] = "\n".join(piece for piece in text if piece)
    out["thinking"] = "\n".join(piece for piece in thinking if piece)
    return out


def _thoughts(value: Any) -> list[dict[str, Any]]:
    return [item for item in _listed(value) if isinstance(item, dict)]


def _listed(value: Any, *, allow_scalar: bool = False) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        # A Content object rather than a bare part list: unwrap it so a caller that was
        # handed either gets the same answer.
        parts = value.get("parts")
        if isinstance(parts, list):
            return list(parts)
        return [value]
    return [value] if allow_scalar else []


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _paths(arguments: dict[str, Any]) -> list[str]:
    """Every path an argument mapping names, under any of the spellings these tools use."""
    found: list[str] = []
    for key in _PATH_KEYS:
        value = arguments.get(key)
        if isinstance(value, str) and value:
            found.append(value)
    for key in ("paths", "files", "file_paths"):
        value = arguments.get(key)
        if isinstance(value, list):
            found.extend(str(item) for item in value if item)
    return found


__all__ = ["GeminiParser"]
