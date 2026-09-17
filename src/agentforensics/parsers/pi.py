"""Parse Pi coding agent sessions.

One of the few agents with a written format specification, which is why this parser can be
exact rather than tolerant: the record types, their fields and the tree the entries form
are documented.
Source: https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/session-format.md

Three things about the format a reader has to know.

The first line is the session header and carries the working directory, so everything after
it inherits a `cwd` that is not repeated per record. A `parentSession` on that header means
this session was forked from another one, which matters because the forked-from turns are
not in this file: an analyst seeing a conversation that starts mid-thought is looking at a
fork, not at a truncated collection.

A tool result is a message with its own role rather than a block inside an assistant turn,
and it carries `isError`. That makes "what did the agent try and what came back" readable
without pairing blocks by hand, and it makes a failed tool call visible as a failure.

The entries form a tree through `id` and `parentId`, not a list. A `compaction` or a
`branch_summary` entry means the line above it and the line below it need not be
consecutive turns, so the ids travel into the payload and nothing here assumes the file is
a conversation in order.
"""

from __future__ import annotations

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
    text_of,
)

# Pi's own tool names. Only an exact match produces a facet: a tool this does not know
# still becomes a tool.call with its arguments intact, which costs an index rather than the
# evidence.
_COMMAND = ("bash", "shell", "run")
_FILE_READ = ("read", "read_file")
_FILE_WRITE = ("write", "write_file", "edit", "apply_patch")
_NETWORK = ("fetch", "web_fetch", "web_search")

_PATH_KEYS = ("path", "file_path", "filePath", "absolute_path")


class PiParser:
    """Session files under the agent's session directory."""

    name = "pi"

    _SESSIONS = frozenset({"pi.sessions"})

    def handles(self, artifact_id: str | None) -> bool:
        return artifact_id in self._SESSIONS

    def parse(self, context: ParseContext) -> Iterator[Event]:
        state: dict[str, Any] = {"session_id": None, "cwd": None, "model": None}

        for line in iter_lines(context.local_path):
            if not line.ok:
                yield unparsed(
                    context.provenance(line.locator),
                    context.agent,
                    line.text or None,
                    line.problem or "the line could not be read",
                    user=context.user,
                    host=context.host,
                    session_id=state["session_id"],
                )
                continue
            record = line.value
            ts, precision, note = normalise_ts(record.get("timestamp"))
            entry_type = record.get("type")
            common: dict[str, Any] = {
                "ts_utc": ts,
                "ts_precision": precision,
                "ts_source": "timestamp" if ts else None,
                "user": context.user,
                "host": context.host,
                "session_id": state["session_id"],
                "project_path": state["cwd"],
            }

            if entry_type == "session":
                state["session_id"] = record.get("id")
                state["cwd"] = record.get("cwd")
                yield Event(
                    kind="session.start",
                    provenance=context.provenance(line.locator),
                    agent=context.agent,
                    raw=record,
                    ts_utc=ts,
                    ts_precision=precision,
                    ts_source="timestamp" if ts else None,
                    actor="system",
                    user=context.user,
                    host=context.host,
                    session_id=state["session_id"],
                    project_path=state["cwd"],
                    payload={
                        "format_version": record.get("version"),
                        # A fork: the turns this session continues from are in another
                        # file, so a conversation starting mid-thought is a fork rather
                        # than a gap in the collection.
                        "parent_session": record.get("parentSession"),
                        "text": f"session {state['session_id']} began in {state['cwd']}"
                        + (
                            f", forked from {record['parentSession']}"
                            if record.get("parentSession")
                            else ""
                        ),
                    },
                    parse_problem=note,
                )
                continue

            if entry_type == "message":
                yield from self._message(context, line, record, state, common, note)
                continue

            if entry_type == "model_change":
                state["model"] = record.get("modelId")
                yield Event(
                    kind="config.snapshot",
                    provenance=context.provenance(line.locator),
                    agent=context.agent,
                    raw=record,
                    actor="user",
                    payload={
                        "models": [{"model": record.get("modelId")}],
                        "provider": record.get("provider"),
                        "text": f"the model was changed to {record.get('modelId')} "
                        f"({record.get('provider')})",
                    },
                    parse_problem=note,
                    **common,
                )
                continue

            if entry_type in ("compaction", "branch_summary"):
                # The same situation Codex's `compacted` record describes: the turns before
                # this point were rewritten, which is the usual explanation for a
                # transcript that appears to jump.
                yield Event(
                    kind="session.end",
                    provenance=context.provenance(line.locator),
                    agent=context.agent,
                    raw=record,
                    actor="system",
                    payload={
                        "compaction": entry_type == "compaction",
                        "entry_type": entry_type,
                        "text": (
                            "the conversation was compacted, so earlier turns were "
                            "rewritten or removed: "
                            if entry_type == "compaction"
                            else "a branch of this conversation was summarised: "
                        )
                        + text_of(record.get("summary") or record.get("message")),
                    },
                    parse_problem=note,
                    **common,
                )
                continue

            if entry_type == "thinking_level_change":
                yield Event(
                    kind="config.snapshot",
                    provenance=context.provenance(line.locator),
                    agent=context.agent,
                    raw=record,
                    actor="user",
                    payload={
                        "thinking_level": record.get("level") or record.get("thinkingLevel"),
                        "text": "the thinking level was changed",
                    },
                    parse_problem=note,
                    **common,
                )
                continue

            if entry_type in ("label", "session_info", "custom", "custom_message"):
                yield Event(
                    kind="config.snapshot",
                    provenance=context.provenance(line.locator),
                    agent=context.agent,
                    raw=record,
                    actor="system",
                    payload={"entry_type": entry_type, "text": text_of(record)},
                    parse_problem=note,
                    **common,
                )
                continue

            yield unparsed(
                context.provenance(line.locator),
                context.agent,
                record,
                f"entry type {entry_type!r} is not one this parser maps",
                ts_utc=ts,
                ts_precision=precision,
                ts_source=common["ts_source"],
                user=context.user,
                host=context.host,
                session_id=state["session_id"],
            )

    def _message(
        self,
        context: ParseContext,
        line: Line,
        record: dict[str, Any],
        state: dict[str, Any],
        common: dict[str, Any],
        note: str | None,
    ) -> Iterator[Event]:
        message = record.get("message")
        if not isinstance(message, dict):
            yield unparsed(
                context.provenance(line.locator),
                context.agent,
                record,
                "a message entry whose message is not an object",
                ts_utc=common["ts_utc"],
                ts_precision=common["ts_precision"],
                ts_source=common["ts_source"],
                user=context.user,
                host=context.host,
                session_id=state["session_id"],
            )
            return

        role = message.get("role")
        ids = {"message_id": record.get("id"), "parent_id": record.get("parentId")}
        usage = _mapping(message.get("usage"))
        models = (
            [
                {
                    "model": message.get("model") or state["model"],
                    "input_tokens": usage.get("input"),
                    "output_tokens": usage.get("output"),
                    "cost": usage.get("cost"),
                }
            ]
            if message.get("model") or state["model"]
            else []
        )

        if role == "user":
            yield Event(
                kind="user.prompt",
                provenance=context.provenance(line.locator),
                agent=context.agent,
                raw=record,
                actor="user",
                payload={"text": text_of(message.get("content")), **ids},
                parse_problem=note,
                **common,
            )
            return

        if role == "assistant":
            blocks = _blocks(message.get("content"))
            emitted = False
            thinking = "\n".join(
                str(block.get("thinking") or "")
                for block in blocks
                if block.get("type") == "thinking"
            ).strip()
            if thinking:
                emitted = True
                yield Event(
                    kind="assistant.thinking",
                    provenance=context.provenance(f"{line.locator}#thinking"),
                    agent=context.agent,
                    raw=record,
                    actor="assistant",
                    payload={
                        "text": thinking,
                        # A redacted thinking block means the provider withheld the
                        # reasoning, which is a different thing from the model not having
                        # reasoned, and the difference belongs in the case.
                        "redacted": any(
                            block.get("redacted")
                            for block in blocks
                            if block.get("type") == "thinking"
                        )
                        or None,
                        "models": models,
                        **ids,
                    },
                    parse_problem=note,
                    **common,
                )
            text = "\n".join(
                str(block.get("text") or "") for block in blocks if block.get("type") == "text"
            ).strip()
            calls = [block for block in blocks if block.get("type") == "toolCall"]
            if text or not calls:
                emitted = True
                yield Event(
                    kind="assistant.text",
                    provenance=context.provenance(line.locator),
                    agent=context.agent,
                    raw=record,
                    actor="assistant",
                    payload={
                        "text": text,
                        "models": models,
                        # "toolUse" against "stop" says whether the turn ended because the
                        # model wanted a tool or because it was finished, which is how a
                        # truncated conversation is told from a completed one.
                        "stop_reason": message.get("stopReason"),
                        "provider": message.get("provider"),
                        **ids,
                    },
                    parse_problem=note,
                    **common,
                )
            for index, block in enumerate(calls):
                emitted = True
                yield from self._tool_call(context, line, record, index, block, models, common, ids)
            unknown = [
                block
                for block in blocks
                if block.get("type") not in ("text", "thinking", "toolCall")
            ]
            for index, block in enumerate(unknown):
                emitted = True
                yield unparsed(
                    context.provenance(f"{line.locator}#block{index}"),
                    context.agent,
                    block,
                    f"content block type {block.get('type')!r} is not one this parser maps",
                    ts_utc=common["ts_utc"],
                    ts_precision=common["ts_precision"],
                    ts_source=common["ts_source"],
                    user=context.user,
                    host=context.host,
                    session_id=state["session_id"],
                )
            if not emitted:
                yield unparsed(
                    context.provenance(line.locator),
                    context.agent,
                    record,
                    "an assistant message with no content at all",
                    ts_utc=common["ts_utc"],
                    ts_precision=common["ts_precision"],
                    ts_source=common["ts_source"],
                    user=context.user,
                    host=context.host,
                    session_id=state["session_id"],
                )
            return

        if role == "toolResult":
            yield Event(
                kind="tool.result",
                provenance=context.provenance(line.locator),
                agent=context.agent,
                raw=record,
                actor="tool",
                payload={
                    "tool": message.get("toolName"),
                    "tool_use_id": message.get("toolCallId"),
                    "is_error": bool(message.get("isError")),
                    "output": message.get("content"),
                    "details": message.get("details"),
                    "text": text_of(message.get("content")),
                    **ids,
                },
                parse_problem=note,
                **common,
            )
            return

        if role == "system":
            sections = message.get("sections")
            yield Event(
                kind="config.snapshot",
                provenance=context.provenance(line.locator),
                agent=context.agent,
                raw=record,
                actor="system",
                payload={
                    # Which prompt sections were in force, and which tools were handed to
                    # or taken from the model mid-session. The second is the answer to
                    # "what was this agent able to do at that moment".
                    "sections": sorted(sections) if isinstance(sections, dict) else None,
                    "tools_added": message.get("toolsAdded"),
                    "tools_removed": message.get("toolsRemoved"),
                    "text": text_of(message.get("content")) or text_of(sections),
                    **ids,
                },
                parse_problem=note,
                **common,
            )
            return

        yield unparsed(
            context.provenance(line.locator),
            context.agent,
            record,
            f"message role {role!r} is not one this parser maps",
            ts_utc=common["ts_utc"],
            ts_precision=common["ts_precision"],
            ts_source=common["ts_source"],
            user=context.user,
            host=context.host,
            session_id=state["session_id"],
        )

    def _tool_call(
        self,
        context: ParseContext,
        line: Line,
        record: dict[str, Any],
        index: int,
        block: dict[str, Any],
        models: list[dict[str, Any]],
        common: dict[str, Any],
        ids: dict[str, Any],
    ) -> Iterator[Event]:
        name = str(block.get("name") or "")
        arguments = _mapping(block.get("arguments"))
        payload: dict[str, Any] = {
            "tool": name,
            "tool_use_id": block.get("id"),
            "input": arguments,
            "models": models,
            **ids,
        }
        # A namespaced tool came from an external server rather than from the agent itself,
        # which is what the mcp facet is for: "which servers did this agent reach" should
        # be an indexed query and not a scan over tool names.
        namespace = block.get("namespace")
        if namespace:
            payload["mcp"] = [{"server": str(namespace), "tool": name}]

        yield Event(
            kind="mcp.call" if namespace else "tool.call",
            provenance=context.provenance(f"{line.locator}#tool{index}"),
            agent=context.agent,
            raw=record,
            actor="assistant",
            payload=payload,
            **common,
        )

        effect_kind, effect_payload = self._effect(name, arguments)
        if effect_kind:
            yield Event(
                kind=effect_kind,
                provenance=context.provenance(f"{line.locator}#effect{index}"),
                agent=context.agent,
                raw=record,
                actor="assistant",
                payload={"tool": name, "tool_use_id": block.get("id"), **effect_payload},
                **common,
            )

    def _effect(self, name: str, arguments: dict[str, Any]) -> tuple[str | None, dict[str, Any]]:
        if name in _COMMAND:
            command = arguments.get("command") or arguments.get("cmd")
            if not command:
                return None, {}
            rendered = (
                " ".join(str(part) for part in command)
                if isinstance(command, list)
                else str(command)
            )
            return "command.exec", {
                "commands": [
                    {
                        "command": rendered,
                        "executable": first_word(rendered),
                        "cwd": arguments.get("cwd") or arguments.get("directory"),
                    }
                ],
                "description": arguments.get("description"),
            }
        path = next(
            (str(arguments[key]) for key in _PATH_KEYS if isinstance(arguments.get(key), str)),
            None,
        )
        if name in _FILE_READ and path:
            return "file.read", {"files": [{"path": path, "operation": "read"}]}
        if name in _FILE_WRITE and path:
            content = arguments.get("content") or arguments.get("new_string")
            return "file.write", {
                "files": [
                    {
                        "path": path,
                        "operation": "write",
                        "bytes": len(str(content).encode("utf-8")) if content else None,
                    }
                ]
            }
        if name in _NETWORK:
            url = arguments.get("url") or arguments.get("uri")
            query = arguments.get("query") or arguments.get("prompt")
            if not url and not query:
                return None, {}
            return "network.request", {
                "network": [{"url": str(url), "host": urlsplit(str(url)).netloc}] if url else None,
                "query": query,
                "text": str(query or url),
            }
        return None, {}


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _blocks(value: Any) -> list[dict[str, Any]]:
    """An assistant message's content as a list of blocks.

    A string content is wrapped as a text block rather than rejected: the format allows
    both, and treating a string as an error would lose the turn.
    """
    if isinstance(value, str):
        return [{"type": "text", "text": value}]
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [
            item if isinstance(item, dict) else {"type": "text", "text": str(item)}
            for item in value
            if item is not None
        ]
    return []


__all__ = ["PiParser"]
