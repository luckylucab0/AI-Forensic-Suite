"""Parse opencode's SQLite store against the schema the agent builds it from.

The first store read as a conversation rather than as rows, and the pattern the other
SQLite agents will follow: `sqlite_store` opens the file safely, this module maps the tables
whose schema somebody actually read, and every table it does not map goes back through the
uninterpreted reading. A store is therefore never half read with the other half silently
absent, which is the failure ADR 0022 exists to prevent.

Sources, both fetched and read rather than inferred: the generated migration the agent
creates the database from,
https://raw.githubusercontent.com/anomalyco/opencode/dev/packages/core/src/database/schema.gen.ts
and the record shape stored in the session_message data column,
https://raw.githubusercontent.com/anomalyco/opencode/dev/packages/schema/src/session-message.ts

Three tables carry the conversation.

`session` is the header: the working directory, the agent, the model, the token counts, the
cost, the parent session for a fork, the share URL, and the archive time. `session_input`
is the user's prompt as it was admitted, with its own time. `session_message` is the turn
stream, one row per message, the record in a JSON `data` column and its type repeated in a
`type` column. `message` and `part` are the older pair; the vendor schema still creates them
and this module has not verified what their `data` holds, so they are returned uninterpreted
rather than guessed at.

Three things about the reading are worth stating.

A prompt can appear twice, once in `session_input` and once as a `user` message. Those are
two different records: one is a prompt being admitted, with its delivery and the sequence it
was admitted at, and the other is the turn as the model saw it. Both are emitted, with their
own provenance, because collapsing them would decide for the analyst which is the evidence.

Times are epoch milliseconds throughout. opencode's schema names the type
DateTimeUtcFromMillis, so that is the vendor's statement about its own clock rather than
something inferred from the magnitude of a number.

The store also holds OAuth tokens, in `account`, `control_account` and `credential`. They
are not withheld here. The catalogue names those columns in `contains_credentials` so an
export can redact them, and the conversations and the tokens sit in one container:
withholding the container to protect the tokens would throw away the evidence.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from typing import Any
from urllib.parse import urlsplit

from agentforensics.model import Event, unparsed
from agentforensics.parsers.base import ParseContext, first_word, normalise_ts, text_of
from agentforensics.parsers.sqlite_generic import rows_as_events
from agentforensics.parsers.sqlite_store import StoreError, describe, open_store, rows_of, tables

# The tables this module claims to understand. Everything else in the store, including the
# older message and part pair, goes through the uninterpreted reading.
MAPPED = ("session", "session_input", "session_message")

# opencode's own tool names, for the facets. Only an exact match produces one: a tool this
# does not know still becomes a tool.call with its input intact, which costs an index rather
# than the evidence.
_COMMAND = ("bash", "shell")
_FILE_READ = ("read", "glob", "grep", "list")
_FILE_WRITE = ("write", "edit", "patch", "multiedit")
_NETWORK = ("webfetch", "websearch", "fetch")

_PATH_KEYS = ("filePath", "file_path", "path", "absolute_path")


class OpencodeParser:
    """opencode's session store, read against the vendor's schema."""

    name = "opencode"

    _STORES = frozenset({"opencode.db"})

    def handles(self, artifact_id: str | None) -> bool:
        return artifact_id in self._STORES

    def parse(self, context: ParseContext) -> Iterator[Event]:
        try:
            with open_store(context.local_path) as connection:
                listed = {table.name: table for table in tables(connection)}
                # Sessions first, because a message row carries neither the working
                # directory nor the agent, and a timeline without the directory cannot say
                # which working copy a command ran in.
                events, headers = _sessions(context, connection, listed)
                yield from events
                yield from _inputs(context, connection, listed, headers)
                yield from _messages(context, connection, listed, headers)
                for name, table in sorted(listed.items()):
                    if name not in MAPPED:
                        yield from rows_as_events(context, connection, table)
        except StoreError as exc:
            yield describe(context, str(exc))


# ------------------------------------------------------------------------ sessions


def _sessions(
    context: ParseContext, connection: sqlite3.Connection, listed: dict[str, Any]
) -> tuple[list[Event], dict[str, dict[str, Any]]]:
    """The session rows, as events and as the header every later row inherits."""
    table = listed.get("session")
    events: list[Event] = []
    headers: dict[str, dict[str, Any]] = {}
    if table is None:
        return events, headers

    for locator, values, problem in rows_of(connection, table):
        if problem:
            events.append(
                unparsed(
                    context.provenance(locator),
                    context.agent,
                    values or None,
                    problem,
                    user=context.user,
                    host=context.host,
                )
            )
            continue
        session_id = _text(values.get("id"))
        header = {
            "project_path": _text(values.get("directory")),
            "agent_name": _text(values.get("agent")),
            "model": _text(values.get("model")),
            "title": _text(values.get("title")),
        }
        if session_id:
            headers[session_id] = header

        common: dict[str, Any] = {
            "user": context.user,
            "host": context.host,
            "session_id": session_id or None,
            "project_path": header["project_path"],
        }
        ts, precision, note = normalise_ts(values.get("time_created"))
        events.append(
            Event(
                kind="session.start",
                provenance=context.provenance(locator),
                agent=context.agent,
                raw=values,
                ts_utc=ts,
                ts_precision=precision,
                ts_source="time_created" if ts else None,
                actor="system",
                client=_text(values.get("version")),
                payload={
                    "text": header["title"] or f"session {session_id}",
                    "agent_name": header["agent_name"],
                    "models": [{"model": header["model"]}] if header["model"] else None,
                    # A fork: the turns this session continues from are in another row, so a
                    # conversation that starts mid-thought is a fork rather than a gap in
                    # the collection.
                    "parent_session": _text(values.get("parent_id")),
                    "cost": values.get("cost"),
                    "tokens": {
                        "input": values.get("tokens_input"),
                        "output": values.get("tokens_output"),
                        "reasoning": values.get("tokens_reasoning"),
                        "cache_read": values.get("tokens_cache_read"),
                        "cache_write": values.get("tokens_cache_write"),
                    },
                    # A shared conversation left the device, which is one of the questions
                    # this suite exists to answer.
                    "share_url": _text(values.get("share_url")),
                },
                parse_problem=note,
                **common,
            )
        )

        archived, archived_precision, archived_note = normalise_ts(values.get("time_archived"))
        if archived:
            events.append(
                Event(
                    kind="session.end",
                    provenance=context.provenance(f"{locator} archived"),
                    agent=context.agent,
                    raw=values,
                    ts_utc=archived,
                    ts_precision=archived_precision,
                    ts_source="time_archived",
                    actor="system",
                    payload={"text": "this session was archived"},
                    parse_problem=archived_note,
                    **common,
                )
            )
    return events, headers


# -------------------------------------------------------------------------- prompts


def _inputs(
    context: ParseContext,
    connection: sqlite3.Connection,
    listed: dict[str, Any],
    headers: dict[str, dict[str, Any]],
) -> Iterator[Event]:
    """The prompts as they were admitted.

    Worth having beside the user messages: `delivery` says how the prompt reached the agent,
    and a prompt that was admitted and never promoted into a turn is one the agent took and
    did not answer, which no message row would show.
    """
    table = listed.get("session_input")
    if table is None:
        return
    for locator, values, problem in rows_of(connection, table):
        if problem:
            yield unparsed(
                context.provenance(locator),
                context.agent,
                values or None,
                problem,
                user=context.user,
                host=context.host,
            )
            continue
        session_id = _text(values.get("session_id"))
        header = headers.get(session_id or "", {})
        ts, precision, note = normalise_ts(values.get("time_created"))
        yield Event(
            kind="user.prompt",
            provenance=context.provenance(locator),
            agent=context.agent,
            raw=values,
            ts_utc=ts,
            ts_precision=precision,
            ts_source="time_created" if ts else None,
            actor="user",
            user=context.user,
            host=context.host,
            session_id=session_id or None,
            project_path=header.get("project_path"),
            payload={
                "text": _text(values.get("prompt")),
                "delivery": _text(values.get("delivery")),
                "admitted_seq": values.get("admitted_seq"),
                # Null means the prompt was taken and never became a turn.
                "promoted_seq": values.get("promoted_seq"),
                "source_table": "session_input",
            },
            parse_problem=note,
        )


# --------------------------------------------------------------------------- turns


def _messages(
    context: ParseContext,
    connection: sqlite3.Connection,
    listed: dict[str, Any],
    headers: dict[str, dict[str, Any]],
) -> Iterator[Event]:
    table = listed.get("session_message")
    if table is None:
        return
    for locator, values, problem in rows_of(connection, table):
        if problem:
            yield unparsed(
                context.provenance(locator),
                context.agent,
                values or None,
                problem,
                user=context.user,
                host=context.host,
            )
            continue

        session_id = _text(values.get("session_id"))
        header = headers.get(session_id or "", {})
        data, data_problem = _document(values.get("data"))
        ts, precision, note = normalise_ts(values.get("time_created"))
        common: dict[str, Any] = {
            "user": context.user,
            "host": context.host,
            "session_id": session_id or None,
            "project_path": header.get("project_path"),
        }
        problems = [part for part in (note, data_problem) if part]
        # The type is in the row and in the record. The row's copy is used, because a row
        # whose data will not parse still has to land somewhere sensible.
        kind = _text(values.get("type")) or _text(data.get("type") if data else None)

        if data is None:
            yield unparsed(
                context.provenance(locator),
                context.agent,
                values,
                " ".join(problems) or "the data column is not a JSON object",
                ts_utc=ts,
                ts_precision=precision,
                ts_source="time_created" if ts else None,
                **common,
            )
            continue

        yield from _message_events(
            context, locator, values, data, kind, ts, precision, problems, common, header
        )


def _message_events(
    context: ParseContext,
    locator: str,
    values: dict[str, Any],
    data: dict[str, Any],
    kind: str,
    ts: str | None,
    precision: Any,
    problems: list[str],
    common: dict[str, Any],
    header: dict[str, Any],
) -> Iterator[Event]:
    """One session_message row, as the events its record type calls for."""
    note = " ".join(problems) or None
    timing: dict[str, Any] = {
        "ts_utc": ts,
        "ts_precision": precision,
        "ts_source": "time_created" if ts else None,
    }

    if kind == "user":
        yield Event(
            kind="user.prompt",
            provenance=context.provenance(locator),
            agent=context.agent,
            raw=data,
            actor="user",
            payload={
                "text": _text(data.get("text")),
                "files": [
                    {"path": _text(item.get("uri")), "operation": "unknown"}
                    for item in _items(data.get("files"))
                    if item.get("uri")
                ]
                or None,
                "subagents": [_text(item.get("name")) for item in _items(data.get("agents"))]
                or None,
                "source_table": "session_message",
            },
            parse_problem=note,
            **timing,
            **common,
        )
        return

    if kind in ("system", "synthetic"):
        # Text the harness put into the conversation rather than the user or the model.
        # instruction.source with scope session, because this is the part of a system
        # prompt that is on the endpoint, recorded verbatim rather than reconstructed. The
        # vendor's schema says only that a synthetic message is text, so its meaning is not
        # claimed here beyond that.
        yield Event(
            kind="instruction.source",
            provenance=context.provenance(locator),
            agent=context.agent,
            raw=data,
            actor="system",
            payload={
                "text": _text(data.get("text")),
                "scope": "session",
                "origin": kind,
                "instructions": [{"path": context.original_path, "scope": "session"}],
            },
            parse_problem=note
            if kind == "system"
            else " ".join(
                filter(
                    None,
                    [
                        note,
                        "opencode calls this a synthetic message and its schema says only "
                        "that it is text the harness inserted, so what it means is not "
                        "claimed here",
                    ],
                )
            ),
            **timing,
            **common,
        )
        return

    if kind == "shell":
        yield Event(
            kind="command.exec",
            provenance=context.provenance(locator),
            agent=context.agent,
            raw=data,
            actor="assistant",
            payload={
                "text": _text(data.get("command")),
                "commands": [
                    {
                        "command": _text(data.get("command")),
                        "executable": first_word(_text(data.get("command"))),
                        "cwd": header.get("project_path"),
                    }
                ],
                "output": _text(data.get("output")),
                "tool_use_id": _text(data.get("callID")),
            },
            parse_problem=note,
            **timing,
            **common,
        )
        return

    if kind in ("agent-switched", "model-switched"):
        model = _model(data.get("model"))
        yield Event(
            kind="config.snapshot",
            provenance=context.provenance(locator),
            agent=context.agent,
            raw=data,
            actor="user",
            payload={
                "text": f"the agent was changed to {_text(data.get('agent'))}"
                if kind == "agent-switched"
                else f"the model was changed to {model}",
                "agent_name": _text(data.get("agent")) or None,
                "models": [{"model": model}] if model else None,
            },
            parse_problem=note,
            **timing,
            **common,
        )
        return

    if kind == "compaction":
        yield Event(
            kind="session.end",
            provenance=context.provenance(locator),
            agent=context.agent,
            raw=data,
            actor="system",
            payload={
                "text": _text(data.get("summary")),
                "compaction": True,
                "reason": _text(data.get("reason")),
            },
            parse_problem=note,
            **timing,
            **common,
        )
        return

    if kind == "assistant":
        yield from _assistant(context, locator, data, note, timing, common, header)
        return

    # A type the vendor added after this parser was written. Kept with its record, its time
    # and its session, so it sorts into the timeline where it belongs and an analyst can see
    # that something was here.
    yield unparsed(
        context.provenance(locator),
        context.agent,
        data,
        f"message type {kind!r} is not one this parser maps",
        ts_utc=ts,
        ts_precision=precision,
        ts_source="time_created" if ts else None,
        **common,
    )


def _assistant(
    context: ParseContext,
    locator: str,
    data: dict[str, Any],
    note: str | None,
    timing: dict[str, Any],
    common: dict[str, Any],
    header: dict[str, Any],
) -> Iterator[Event]:
    """An assistant turn: its text, its reasoning, and each tool it called.

    One event per content block, with the block's index in the locator, because the event id
    is derived from provenance and two blocks of the same kind in one row would otherwise
    collapse into one event and the turn would lose a call.
    """
    model = _model(data.get("model"))
    emitted = False
    for index, block in enumerate(_items(data.get("content"))):
        block_type = _text(block.get("type"))
        where = f"{locator} content:{index}"
        if block_type == "text" and _text(block.get("text")):
            emitted = True
            yield Event(
                kind="assistant.text",
                provenance=context.provenance(where),
                agent=context.agent,
                raw=block,
                actor="assistant",
                payload={
                    "text": _text(block.get("text")),
                    "models": [{"model": model}] if model else None,
                },
                parse_problem=note,
                **timing,
                **common,
            )
        elif block_type == "reasoning" and _text(block.get("text")):
            emitted = True
            yield Event(
                kind="assistant.thinking",
                provenance=context.provenance(where),
                agent=context.agent,
                raw=block,
                actor="assistant",
                payload={"text": _text(block.get("text"))},
                parse_problem=note,
                **timing,
                **common,
            )
        elif block_type == "tool":
            emitted = True
            yield from _tool(context, where, block, note, timing, common, header)
        else:
            emitted = True
            yield unparsed(
                context.provenance(where),
                context.agent,
                block,
                f"content block type {block_type!r} is not one this parser maps",
                ts_utc=timing["ts_utc"],
                ts_precision=timing["ts_precision"],
                ts_source=timing["ts_source"],
                **common,
            )

    if not emitted:
        # A turn that carried nothing at all is still a turn: the model was asked and the
        # record says it answered with nothing, which is different from no record.
        yield Event(
            kind="assistant.text",
            provenance=context.provenance(locator),
            agent=context.agent,
            raw=data,
            actor="assistant",
            payload={
                "text": "",
                "models": [{"model": model}] if model else None,
                "finish": _text(data.get("finish")),
            },
            parse_problem=note,
            **timing,
            **common,
        )


def _tool(
    context: ParseContext,
    where: str,
    block: dict[str, Any],
    note: str | None,
    timing: dict[str, Any],
    common: dict[str, Any],
    header: dict[str, Any],
) -> Iterator[Event]:
    """One tool block: the call, its facet, and the result where the state carries one."""
    name = _text(block.get("name"))
    state = _mapping(block.get("state"))
    arguments = _mapping(state.get("input"))
    call_id = _text(block.get("id"))

    facet_kind, facet = _facet(name, arguments, header)
    payload: dict[str, Any] = {
        "tool": name,
        "tool_use_id": call_id,
        "input": arguments,
        "text": name,
        **facet,
    }
    yield Event(
        kind="tool.call",
        provenance=context.provenance(where),
        agent=context.agent,
        raw=block,
        actor="assistant",
        payload=payload,
        parse_problem=note,
        **timing,
        **common,
    )

    if facet_kind:
        yield Event(
            kind=facet_kind,
            provenance=context.provenance(where),
            agent=context.agent,
            raw=block,
            actor="assistant",
            payload={"tool": name, "tool_use_id": call_id, **facet},
            parse_problem=note,
            **timing,
            **common,
        )

    status = _text(state.get("status"))
    if status in ("completed", "error"):
        output = "\n".join(
            _text(item.get("text")) or _text(item.get("uri"))
            for item in _items(state.get("content"))
        ).strip()
        yield Event(
            kind="tool.result",
            provenance=context.provenance(f"{where} result"),
            agent=context.agent,
            raw=state,
            actor="tool",
            payload={
                "tool": name,
                "tool_use_id": call_id,
                "output": output or text_of(state.get("result")),
                "text": output or text_of(state.get("result")),
                "is_error": status == "error",
                "error": text_of(state.get("error")) if status == "error" else None,
            },
            parse_problem=note,
            **timing,
            **common,
        )


def _facet(
    name: str, arguments: dict[str, Any], header: dict[str, Any]
) -> tuple[str | None, dict[str, Any]]:
    """The facet a known tool produces, or nothing at all for a tool this does not know."""
    lowered = name.lower()
    if lowered in _COMMAND:
        command = _text(arguments.get("command"))
        if not command:
            return None, {}
        return "command.exec", {
            "commands": [
                {
                    "command": command,
                    "executable": first_word(command),
                    "cwd": _text(arguments.get("cwd")) or header.get("project_path"),
                }
            ]
        }
    path = next((_text(arguments.get(key)) for key in _PATH_KEYS if arguments.get(key)), "")
    if lowered in _FILE_READ and path:
        return "file.read", {"files": [{"path": path, "operation": "read"}]}
    if lowered in _FILE_WRITE and path:
        content = arguments.get("content") or arguments.get("newString")
        return "file.write", {
            "files": [
                {
                    "path": path,
                    "operation": "write",
                    "bytes": len(str(content).encode("utf-8")) if content else None,
                }
            ]
        }
    if lowered in _NETWORK:
        url = _text(arguments.get("url"))
        query = _text(arguments.get("query"))
        if not url and not query:
            return None, {}
        return "network.request", {
            "network": [{"url": url, "host": urlsplit(url).netloc}] if url else None,
            "query": query or None,
        }
    return None, {}


# ------------------------------------------------------------------------- helpers


def _document(value: Any) -> tuple[dict[str, Any] | None, str | None]:
    """The JSON in a data column, or the reason it is not an object."""
    if isinstance(value, dict):
        return value, None
    if not isinstance(value, str) or not value.strip():
        return None, "the data column is empty"
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        return None, f"the data column is not valid JSON: {exc}"
    if not isinstance(parsed, dict):
        return None, f"the data column holds a JSON {type(parsed).__name__}, not an object"
    return parsed, None


def _mapping(value: Any) -> dict[str, Any]:
    """A nested object, or an empty one. A tool state the vendor changes the shape of must
    cost the facet and not the record."""
    return value if isinstance(value, dict) else {}


def _items(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _model(value: Any) -> str:
    """A model reference, which the vendor writes as a string or as provider and id."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        provider = _text(value.get("providerID") or value.get("provider"))
        model = _text(value.get("modelID") or value.get("model") or value.get("id"))
        return f"{provider}/{model}" if provider and model else model or provider
    return ""


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ("" if value is None else str(value))


__all__ = ["MAPPED", "OpencodeParser"]
