"""Parse Amazon Q Developer CLI's state database against the vendor's own types.

The second SQLite store read as a conversation rather than as rows. Four tables are mapped
here and every other one goes back through the uninterpreted reading, so the store is never
half read with the other half silently absent.

Sources, all fetched and read: the SQL migrations the agent creates the database from,
https://github.com/aws/amazon-q-developer-cli/tree/main/crates/chat-cli/src/database/sqlite_migrations
the conversation state that is stored as JSON in the conversations table,
https://raw.githubusercontent.com/aws/amazon-q-developer-cli/main/crates/chat-cli/src/cli/chat/conversation.rs
the message types inside it,
https://raw.githubusercontent.com/aws/amazon-q-developer-cli/main/crates/chat-cli/src/cli/chat/message.rs
and the tool argument names,
https://raw.githubusercontent.com/aws/amazon-q-developer-cli/main/crates/chat-cli/src/cli/chat/tools/tool_index.json

Four things about this store exist nowhere else, and each shaped the reading.

**The conversations table is keyed by the working directory.** The vendor's own accessor
takes a path and uses it as the key, so activity maps to a project without the project
having to still exist. That key becomes the event's `project_path`.

**A trimmed history is still on disk.** `valid_history_range` is the slice the agent sends
to the model; entries outside it were dropped from what the model sees and are still in the
file. They are emitted like any other turn, with a note saying they were outside the range,
because "the agent forgot this" and "this did not happen" are different findings.

**The transcript is the agent's own human-readable rendering**, user turns prefixed with
"> ", and it holds errors posted in the chat. It survives the trimming above, so it travels
on the session event rather than being dropped as a duplicate of the history.

**The history table is a shell command log**, with the command, the shell, the pid, the
working directory, the exit code and the timing. That is an execution record independent of
the shell's own history file, and independent of the agent's transcript.

Two Rust serialisation details matter for reading the JSON, and both come from the derives
rather than from a guess. The enums carry no serde tag attribute, so serde's default
external tagging applies: a user message's content is `{"Prompt": {"prompt": "..."}}` and an
assistant message is `{"Response": {...}}` or `{"ToolUse": {...}}`. And no struct renames its
fields, so every field name is the Rust one, in snake case.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from typing import Any

from agentforensics.model import Event, unparsed
from agentforensics.parsers.base import ParseContext, first_word, normalise_ts, text_of
from agentforensics.parsers.sqlite_generic import rows_as_events
from agentforensics.parsers.sqlite_store import StoreError, describe, open_store, rows_of, tables

# The tables this module claims to understand.
MAPPED = ("conversations", "history", "state", "auth_kv")

# The built-in tool names, from the shipped tool specification rather than from prose. Two
# spellings for one thing: the CLI exposes execute_cmd on Windows and execute_bash
# elsewhere, so both have to map to a command.
_COMMAND = ("execute_bash", "execute_cmd")
_FILE_READ = "fs_read"
_FILE_WRITE = "fs_write"
_AWS = "use_aws"
_SUBAGENT = "delegate"


class AmazonQParser:
    """The CLI's data.sqlite3, read against the vendor's schema and types."""

    name = "amazonq"

    _STORES = frozenset({"amazonq.cli_state_database"})

    def handles(self, artifact_id: str | None) -> bool:
        return artifact_id in self._STORES

    def parse(self, context: ParseContext) -> Iterator[Event]:
        try:
            with open_store(context.local_path) as connection:
                listed = {table.name: table for table in tables(connection)}
                yield from _conversations(context, connection, listed)
                yield from _shell_history(context, connection, listed)
                yield from _settings(context, connection, listed)
                for name, table in sorted(listed.items()):
                    if name not in MAPPED:
                        yield from rows_as_events(context, connection, table)
        except StoreError as exc:
            yield describe(context, str(exc))


# ------------------------------------------------------------------ conversations


def _conversations(
    context: ParseContext, connection: sqlite3.Connection, listed: dict[str, Any]
) -> Iterator[Event]:
    table = listed.get("conversations")
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
        # The key is the working directory the conversation belongs to, which the vendor's
        # accessor states by taking a path and using it as the key.
        cwd = _text(values.get("key")) or None
        state, state_problem = _document(values.get("value"))
        if state is None:
            yield unparsed(
                context.provenance(locator),
                context.agent,
                values,
                state_problem or "the conversation value is not a JSON object",
                user=context.user,
                host=context.host,
                project_path=cwd,
            )
            continue
        yield from _conversation(context, locator, state, cwd)


def _conversation(
    context: ParseContext, locator: str, state: dict[str, Any], cwd: str | None
) -> Iterator[Event]:
    session_id = _text(state.get("conversation_id")) or None
    model = _text(state.get("model")) or _model_name(state.get("model_info"))
    common: dict[str, Any] = {
        "user": context.user,
        "host": context.host,
        "session_id": session_id,
        "project_path": cwd,
    }
    history = [entry for entry in state.get("history") or [] if isinstance(entry, dict)]
    start, end = _range(state.get("valid_history_range"), len(history))

    # The header. Its raw is the state without the history, which becomes events of its
    # own: keeping both would put the whole conversation in the case twice.
    header = {key: value for key, value in state.items() if key != "history"}
    yield Event(
        kind="session.start",
        provenance=context.provenance(locator),
        agent=context.agent,
        raw=header,
        actor="system",
        payload={
            "text": f"conversation {session_id} in {cwd}",
            "models": [{"model": model}] if model else None,
            "mcp_enabled": state.get("mcp_enabled"),
            "turns": len(history),
            # The slice the agent still sends to the model. Everything outside it is on
            # disk and was dropped from what the model sees.
            "valid_history_range": [start, end],
            # The agent's own human-readable rendering, which holds errors posted in the
            # chat and survives the trimming above.
            "transcript": [line for line in state.get("transcript") or [] if isinstance(line, str)],
            "context_files": _context_files(state.get("context_manager")),
        },
        **common,
    )

    summary = state.get("latest_summary")
    if isinstance(summary, list) and summary and isinstance(summary[0], str):
        yield Event(
            kind="session.end",
            provenance=context.provenance(f"{locator} summary"),
            agent=context.agent,
            raw=summary,
            actor="system",
            payload={"text": summary[0], "compaction": True},
            **common,
        )

    # A prompt the user had queued and that was never sent. What somebody was about to ask
    # is evidence, and no turn records it.
    queued = state.get("next_message")
    if isinstance(queued, dict):
        yield from _user_message(
            context, f"{locator} next_message", queued, common, sent=False, outside=False
        )

    for index, entry in enumerate(history):
        outside = not (start <= index < end)
        where = f"{locator} entry:{index}"
        user_message = entry.get("user")
        if isinstance(user_message, dict):
            yield from _user_message(context, f"{where} user", user_message, common, True, outside)
        assistant = entry.get("assistant")
        if isinstance(assistant, dict):
            yield from _assistant_message(
                context, f"{where} assistant", assistant, common, model, outside, cwd
            )
        if not isinstance(user_message, dict) and not isinstance(assistant, dict):
            yield unparsed(
                context.provenance(where),
                context.agent,
                entry,
                "this history entry has neither a user nor an assistant message",
                **common,
            )

    # Who wrote which lines of a file, which the agent tracks for its own writes. Direct
    # evidence of what the agent changed, and it carries no time of its own.
    tracker = state.get("file_line_tracker")
    if isinstance(tracker, dict):
        for path in sorted(tracker):
            metrics = tracker[path] if isinstance(tracker[path], dict) else {}
            yield Event(
                kind="file.write",
                provenance=context.provenance(f"{locator} file_line_tracker:{path}"),
                agent=context.agent,
                raw={"path": path, **metrics},
                actor="assistant",
                payload={
                    "files": [{"path": path, "operation": "write"}],
                    "lines_added_by_agent": metrics.get("lines_added_by_agent"),
                    "lines_removed_by_agent": metrics.get("lines_removed_by_agent"),
                    "text": f"the agent changed {path}",
                },
                # No time: the tracker records counts and not when. The turn that did the
                # writing is the dated record, and inventing a time here would put a
                # fabricated moment on the timeline.
                parse_problem="this record carries line counts and no time of its own",
                **common,
            )

    # A stashed main conversation, put aside when the user entered tangent mode. Surfaced
    # rather than expanded: it holds a second whole conversation, and reading it as one
    # needs a verified pass of its own.
    tangent = state.get("tangent_state")
    if isinstance(tangent, dict):
        ts, precision, note = normalise_ts(tangent.get("tangent_start_time"))
        yield unparsed(
            context.provenance(f"{locator} tangent_state"),
            context.agent,
            tangent,
            "this conversation has a stashed main conversation from tangent mode. It holds "
            "its own history and transcript, which this parser does not expand: the whole "
            "structure is in raw and is worth reading by hand " + (note or ""),
            ts_utc=ts,
            ts_precision=precision,
            ts_source="tangent_start_time" if ts else None,
            **common,
        )


def _user_message(
    context: ParseContext,
    where: str,
    message: dict[str, Any],
    common: dict[str, Any],
    sent: bool,
    outside: bool,
) -> Iterator[Event]:
    """One user message, which is either a prompt or the results of the agent's tool calls.

    The vendor's enum is externally tagged, so the content arrives as a single-key object
    naming which of the three it is.
    """
    ts, precision, note = normalise_ts(message.get("timestamp"))
    timing: dict[str, Any] = {
        "ts_utc": ts,
        "ts_precision": precision,
        "ts_source": "timestamp" if ts else None,
    }
    problems = [part for part in (note, _outside_note(outside)) if part]
    content = _mapping(message.get("content"))
    tag, body = _tagged(content)

    if tag in ("Prompt", "CancelledToolUses"):
        prompt = _text(body.get("prompt"))
        if prompt or tag == "Prompt":
            yield Event(
                kind="user.prompt",
                provenance=context.provenance(where),
                agent=context.agent,
                raw=message,
                actor="user",
                payload={
                    "text": prompt,
                    "additional_context": _text(message.get("additional_context")) or None,
                    # False means the prompt was queued and never sent.
                    "sent": sent,
                    "cancelled_tool_uses": tag == "CancelledToolUses",
                    "images": len(message.get("images") or []) or None,
                },
                parse_problem=" ".join(problems) or None,
                **timing,
                **common,
            )

    for index, result in enumerate(body.get("tool_use_results") or []):
        if not isinstance(result, dict):
            continue
        status = _text(result.get("status"))
        output = "\n".join(_result_text(block) for block in result.get("content") or []).strip()
        yield Event(
            kind="tool.result",
            provenance=context.provenance(f"{where} result:{index}"),
            agent=context.agent,
            raw=result,
            actor="tool",
            payload={
                "tool_use_id": _text(result.get("tool_use_id")) or None,
                "output": output,
                "text": output,
                # The vendor's status enum, lower-cased by serde's default for a unit
                # variant, so a value it adds later still reads as itself.
                "is_error": status.lower() == "error",
                "cancelled": tag == "CancelledToolUses",
            },
            parse_problem=" ".join(problems) or None,
            **timing,
            **common,
        )

    if tag is None and content:
        yield unparsed(
            context.provenance(where),
            context.agent,
            message,
            "the user message content is not one of the three shapes the vendor's enum "
            "defines, so what it holds is not claimed here",
            **timing,
            **common,
        )


def _assistant_message(
    context: ParseContext,
    where: str,
    message: dict[str, Any],
    common: dict[str, Any],
    model: str,
    outside: bool,
    cwd: str | None,
) -> Iterator[Event]:
    """One assistant message: its text, and one event per tool it called."""
    tag, body = _tagged(message)
    note = _outside_note(outside)
    # The assistant message carries no time of its own; the user message of the same
    # history entry is the dated record, and the entry is one exchange.
    timing: dict[str, Any] = {"ts_utc": None, "ts_precision": "absent", "ts_source": None}

    if tag is None:
        yield unparsed(
            context.provenance(where),
            context.agent,
            message,
            "the assistant message is not one of the two shapes the vendor's enum defines",
            **timing,
            **common,
        )
        return

    yield Event(
        kind="assistant.text",
        provenance=context.provenance(where),
        agent=context.agent,
        raw=body,
        actor="assistant",
        payload={
            "text": _text(body.get("content")),
            "models": [{"model": model}] if model else None,
            "message_id": _text(body.get("message_id")) or None,
        },
        parse_problem=note,
        **timing,
        **common,
    )

    for index, use in enumerate(body.get("tool_uses") or []):
        if not isinstance(use, dict):
            continue
        yield from _tool_use(context, f"{where} tool:{index}", use, common, note, timing, cwd)


def _tool_use(
    context: ParseContext,
    where: str,
    use: dict[str, Any],
    common: dict[str, Any],
    note: str | None,
    timing: dict[str, Any],
    cwd: str | None,
) -> Iterator[Event]:
    name = _text(use.get("name"))
    # The original name as well, because the agent renames a tool it exposes to the model
    # and only the original says which tool actually ran.
    original = _text(use.get("orig_name")) or name
    arguments = _mapping(use.get("args"))
    call_id = _text(use.get("id")) or None

    events = list(_facets(original, arguments, cwd))
    payload: dict[str, Any] = {
        "tool": name,
        "tool_use_id": call_id,
        "input": arguments,
        "text": name,
    }
    if original != name:
        payload["original_tool"] = original
    if original == _SUBAGENT:
        payload["subagent"] = _text(arguments.get("agent")) or None
    for _, facet in events:
        payload.update(facet)

    yield Event(
        kind="tool.call",
        provenance=context.provenance(where),
        agent=context.agent,
        raw=use,
        actor="assistant",
        payload=payload,
        parse_problem=note,
        **timing,
        **common,
    )
    for index, (kind, facet) in enumerate(events):
        yield Event(
            kind=kind,
            provenance=context.provenance(f"{where} facet:{index}"),
            agent=context.agent,
            raw=use,
            actor="assistant",
            payload={"tool": name, "tool_use_id": call_id, **facet},
            parse_problem=note,
            **timing,
            **common,
        )


def _facets(
    name: str, arguments: dict[str, Any], cwd: str | None
) -> Iterator[tuple[str, dict[str, Any]]]:
    """Every facet one tool call produces, from the vendor's own argument names."""
    if name in _COMMAND:
        command = _text(arguments.get("command"))
        if command:
            yield (
                "command.exec",
                {
                    "commands": [
                        {"command": command, "executable": first_word(command), "cwd": cwd}
                    ],
                    "text": command,
                },
            )
        return

    if name == _FILE_WRITE:
        path = _text(arguments.get("path"))
        if path:
            content = arguments.get("file_text") or arguments.get("new_str")
            yield (
                "file.write",
                {
                    "files": [
                        {
                            "path": path,
                            # create, str_replace, insert or append: the vendor puts the
                            # variant in the command argument.
                            "operation": "write",
                            "bytes": len(str(content).encode("utf-8")) if content else None,
                        }
                    ],
                    "text": path,
                },
            )
        return

    if name == _FILE_READ:
        # A list of operations, each with its own path, so one call can read several files.
        paths = [
            _text(operation.get("path"))
            for operation in arguments.get("operations") or []
            if isinstance(operation, dict) and operation.get("path")
        ]
        if paths:
            yield (
                "file.read",
                {
                    "files": [{"path": path, "operation": "read"} for path in paths],
                    "text": ", ".join(paths),
                },
            )
        return

    if name == _AWS:
        service = _text(arguments.get("service_name"))
        operation = _text(arguments.get("operation_name"))
        if service or operation:
            # A network.request with no host facet on purpose. The record names a service,
            # a region and an operation, and not an endpoint. Building
            # "<service>.<region>.amazonaws.com" from them would put a hostname in the case
            # that the evidence never contained, and an analyst would quote it.
            yield (
                "network.request",
                {
                    "aws_service": service or None,
                    "aws_operation": operation or None,
                    "aws_region": _text(arguments.get("region")) or None,
                    "aws_profile": _text(arguments.get("profile_name")) or None,
                    "text": f"{service} {operation}".strip(),
                },
            )


# ------------------------------------------------------------------ shell history


def _shell_history(
    context: ParseContext, connection: sqlite3.Connection, listed: dict[str, Any]
) -> Iterator[Event]:
    """The shell command log, which is a record of execution the transcript does not hold."""
    table = listed.get("history")
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
        command = _text(values.get("command"))
        # The unit of start_time is not stated in the migrations or in the module that
        # reads them, so it is left to normalise_ts, which tells seconds from milliseconds
        # by magnitude and puts the reading it used on the event.
        ts, precision, note = normalise_ts(values.get("start_time"))
        yield Event(
            kind="command.exec",
            provenance=context.provenance(locator),
            agent=context.agent,
            raw=values,
            ts_utc=ts,
            ts_precision=precision,
            ts_source="start_time" if ts else None,
            actor="user",
            user=context.user,
            # The row's own hostname, which is the endpoint this command ran on and can
            # differ from the host the collection was taken from.
            host=_text(values.get("hostname")) or context.host,
            session_id=_text(values.get("session_id")) or None,
            project_path=_text(values.get("cwd")) or None,
            payload={
                "text": command,
                "commands": [
                    {
                        "command": command,
                        "executable": first_word(command),
                        "cwd": _text(values.get("cwd")) or None,
                        "exit_code": values.get("exit_code"),
                        "shell": _text(values.get("shell")) or None,
                        "pid": values.get("pid"),
                        "duration_ms": values.get("duration"),
                    }
                ],
            },
            parse_problem=note,
        )


# ---------------------------------------------------------------------- settings


def _settings(
    context: ParseContext, connection: sqlite3.Connection, listed: dict[str, Any]
) -> Iterator[Event]:
    """The two key-value tables.

    The vendor put the credentials in `auth_kv` rather than in `state` deliberately, with a
    comment saying so, and that split is worth keeping: a credential's presence and its key
    are recorded, and its value is left in raw rather than rendered as the event's text. The
    catalogue names these keys in contains_credentials so an export can redact them.
    """
    for name in ("state", "auth_kv"):
        table = listed.get(name)
        if table is None:
            continue
        secret = name == "auth_kv"
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
            key = _text(values.get("key"))
            yield Event(
                kind="config.snapshot",
                provenance=context.provenance(locator),
                agent=context.agent,
                raw=values,
                actor="system",
                user=context.user,
                host=context.host,
                payload={
                    "key": key,
                    "table": name,
                    "credential": secret,
                    "text": f"{key} is set" if secret else f"{key} = {_short(values.get('value'))}",
                },
                parse_problem="this row holds credential material. Its value is in raw and "
                "is not rendered as the event's text; the catalogue names the key so an "
                "export can redact it"
                if secret
                else None,
            )


# ----------------------------------------------------------------------- helpers


def _mapping(value: Any) -> dict[str, Any]:
    """A nested object, or an empty one. A shape the vendor changes must cost the mapping
    and not the record."""
    return value if isinstance(value, dict) else {}


def _tagged(value: dict[str, Any]) -> tuple[str | None, dict[str, Any]]:
    """An externally tagged Rust enum: one key naming the variant, holding its fields.

    serde's default for an enum with no tag attribute, which is what these types use. A
    shape with more than one key is not one of them and is reported rather than guessed at.
    """
    if len(value) != 1:
        return None, {}
    ((tag, body),) = value.items()
    return tag, body if isinstance(body, dict) else {}


def _range(value: Any, length: int) -> tuple[int, int]:
    """The valid history range, clamped to the history that is actually there."""
    if isinstance(value, list) and len(value) == 2:
        try:
            start, end = int(value[0]), int(value[1])
        except TypeError, ValueError:
            return 0, length
        return max(0, start), min(length, end)
    return 0, length


def _outside_note(outside: bool) -> str | None:
    if not outside:
        return None
    return (
        "this turn is outside the conversation's valid history range, so the agent no "
        "longer sends it to the model. It is still on disk and still happened"
    )


def _result_text(block: Any) -> str:
    """One tool result block, which is externally tagged Json or Text."""
    if isinstance(block, dict):
        tag, _ = _tagged(block)
        if tag == "Text":
            return _text(next(iter(block.values()), ""))
        return text_of(block)
    return _text(block)


def _context_files(manager: Any) -> list[str] | None:
    """The sticky context files a conversation carries, where the manager names them."""
    if not isinstance(manager, dict):
        return None
    found: list[str] = []
    for value in manager.values():
        if isinstance(value, list):
            found.extend(str(item) for item in value if isinstance(item, str))
    return sorted(set(found)) or None


def _model_name(info: Any) -> str:
    if isinstance(info, dict):
        return _text(info.get("model_id") or info.get("model_name") or info.get("name"))
    return ""


def _document(value: Any) -> tuple[dict[str, Any] | None, str | None]:
    if isinstance(value, dict):
        return value, None
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    if not isinstance(value, str) or not value.strip():
        return None, "the value column is empty"
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        return None, f"the value column is not valid JSON: {exc}"
    if not isinstance(parsed, dict):
        return None, f"the value column holds a JSON {type(parsed).__name__}, not an object"
    return parsed, None


def _short(value: Any, limit: int = 200) -> str:
    rendered = value if isinstance(value, str) else text_of(value)
    return rendered if len(rendered) <= limit else rendered[:limit] + "..."


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ("" if value is None else str(value))


__all__ = ["MAPPED", "AmazonQParser"]
