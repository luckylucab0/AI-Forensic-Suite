"""Parse Hermes's state.db against the schema its vendor documents.

The store whose documentation is the best of any agent read so far, and the one where that
matters most: it holds the conversation, the exact system prompt that was in force for each
session, the reasoning text where the provider exposed it, and a record of whether the
session was driven from the command line or from a messaging platform.

Source, fetched and read rather than inferred, for the tables, the columns, the compaction
behaviour and the clock:
https://raw.githubusercontent.com/NousResearch/hermes-agent/main/website/docs/developer-guide/session-storage.md

Two tables are mapped. `sessions` is the header: the model, the working directory and git
branch, the system prompt, the parent session for a compression split, the token and cost
counters, and `source`, which the vendor documents as `cli`, `telegram`, `discord` and so
on. `messages` is the turn stream, one row per message, with the role, the content, the
tool calls as a JSON string, and the reasoning in its own columns. Everything else in the
store, including the three FTS5 shadow tables, goes back through the uninterpreted reading,
so the store is never half read with the other half silently absent (ADR 0022).

Five things about this store decide how it has to be read.

**A compacted conversation is archived, not deleted.** The vendor states it plainly: "In
place compaction archives old rows with `active=0` and inserts the retained context as
`active=1` rows. A protected message can therefore legitimately appear in both generations
with identical content and timestamp. Do not delete these archive rows as duplicates." So
every row becomes an event and none is deduplicated, and the generation travels on the
event. A reader that collapsed the two generations would delete the pre-compaction history
from the case, which is the history an analyst is usually looking for.

**A reply can be absent from the column that holds replies.** The vendor states that a
reasoning-only clean stop leaves `content` empty with the text in `reasoning`, and that a
final reply may live only in `codex_message_items`. An assistant row with empty content is
therefore not an empty turn, and reading only `content` would show a conversation where the
agent said nothing.

**The system prompt is an instruction source.** It is in a database row rather than a file
on disk, which is why it gets the scope `session`: it applied to one session and to nothing
else, and the managed, user and project scopes describe files that apply more widely. That
answers the question the instruction surface exists for without claiming the prompt was a
file that could be found on the filesystem.

**`source` and `user_id` are the remote-operation evidence.** The vendor documents `source`
as the platform tag and `user_id` as the principal on the other end: a messaging adapter
stores the platform sender id, an authenticated `hermes serve` session stores
`<provider>:<user id>`, and an anonymous loopback, subagent or cron session leaves it empty.
A session driven from a chat platform is a different finding from one driven at the console,
so both fields travel on every event of that session.

**No tool is interpreted.** The vendor documents that `tool_calls` is a JSON list and names
none of the tools, so a call becomes a `tool.call` with its arguments intact and nothing is
claimed about what it did. No command, file or network facet is derived here: naming a file
this parser only guessed at would put paths in the files facet that the agent may never have
touched. The arguments are in the event for an analyst to read.

Timestamps are Unix epoch floats, which the vendor states ("Timestamps are Unix epoch
floats (`time.time()`)"), so the unit is read rather than inferred from the magnitude of a
number. The note the shared helper adds for a magnitude reading is dropped for that reason,
and any other note it produces is kept: a value large enough to look like milliseconds
contradicts the documentation and is worth an analyst's attention.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from typing import Any

from agentforensics.model import Event, TsPrecision, unparsed
from agentforensics.parsers.base import ParseContext, normalise_ts, text_of
from agentforensics.parsers.sqlite_generic import rows_as_events
from agentforensics.parsers.sqlite_store import (
    StoreError,
    describe,
    open_store,
    rows_of,
    sidecar,
    tables,
)

# The tables this module claims to understand. Everything else, the FTS5 shadows included,
# goes through the uninterpreted reading.
MAPPED = ("sessions", "messages")

# What the vendor's own documentation calls the reading of these columns, carried into
# ts_source so a case says where a time came from rather than only what it was.
_SESSION_CLOCK = "started_at, documented as a Unix epoch float"
_SESSION_END_CLOCK = "ended_at, documented as a Unix epoch float"
_MESSAGE_CLOCK = "timestamp, documented as a Unix epoch float"

# The note normalise_ts adds when it reads a number as epoch seconds. Here that is not a
# reading it had to make: the vendor states the unit. Any other note it returns is kept.
_MAGNITUDE_NOTE = "read as epoch seconds"


class HermesParser:
    """Hermes's session store, read against the vendor's documented schema."""

    name = "hermes"

    _STORES = frozenset({"hermes.state_db", "hermes.state_snapshot_transcripts"})

    def handles(self, artifact_id: str | None) -> bool:
        return artifact_id in self._STORES

    def parse(self, context: ParseContext) -> Iterator[Event]:
        beside = sidecar(context)
        if beside is not None:
            # A database's own log or shared-memory file, which this entry claims along
            # with the database. It is not a store and must not be reported as one that
            # could not be read.
            yield beside
            return
        try:
            with open_store(context.local_path) as connection:
                listed = {table.name: table for table in tables(connection)}
                # Sessions first: a message row carries neither the working directory nor
                # the model nor the platform it came from, and a timeline without those
                # cannot say which working copy a turn belonged to or who drove it.
                events, headers = _sessions(context, connection, listed)
                yield from events
                yield from _messages(context, connection, listed, headers)
                for name, table in sorted(listed.items()):
                    if name not in MAPPED:
                        yield from rows_as_events(context, connection, table)
        except StoreError as exc:
            yield describe(context, str(exc))


def _time(value: Any, source: str) -> tuple[str | None, TsPrecision, str | None, str | None]:
    """One documented epoch column, as (timestamp, precision, source, problem)."""
    ts, precision, note = normalise_ts(value)
    if note == _MAGNITUDE_NOTE:
        note = None
    return ts, precision, source if ts else None, note


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _header_of(headers: dict[str, dict[str, Any]], session_id: str) -> dict[str, Any]:
    return headers.get(session_id, {})


# --------------------------------------------------------------------------- sessions


def _sessions(
    context: ParseContext, connection: sqlite3.Connection, listed: dict[str, Any]
) -> tuple[list[Event], dict[str, dict[str, Any]]]:
    """The session rows: a start event, the system prompt, an end event where there is one.

    Returns the events and the header every message row inherits.
    """
    table = listed.get("sessions")
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
            "model": _text(values.get("model")),
            # Documented as workspace fields on the sessions table. Absent in an older
            # database, which is why nothing here requires them.
            "project_path": _text(values.get("cwd")) or None,
            "git_branch": _text(values.get("git_branch")) or None,
            "source": _text(values.get("source")),
            "user_id": _text(values.get("user_id")),
        }
        if session_id:
            headers[session_id] = header

        common: dict[str, Any] = {
            "user": context.user,
            "host": context.host,
            "client": "hermes",
            "session_id": session_id or None,
            "project_path": header["project_path"],
            "git_branch": header["git_branch"],
        }
        models = [{"model": header["model"]}] if header["model"] else []
        ts, precision, source, note = _time(values.get("started_at"), _SESSION_CLOCK)
        events.append(
            Event(
                kind="session.start",
                provenance=context.provenance(locator),
                agent=context.agent,
                raw=values,
                ts_utc=ts,
                ts_precision=precision,
                ts_source=source,
                actor="system",
                payload=_session_payload(values, header, models),
                parse_problem=note,
                **common,
            )
        )

        prompt = _text(values.get("system_prompt"))
        if prompt:
            events.append(_system_prompt(context, locator, values, prompt, common))

        ended = values.get("ended_at")
        if ended not in (None, ""):
            end_ts, end_precision, end_source, end_note = _time(ended, _SESSION_END_CLOCK)
            reason = _text(values.get("end_reason"))
            events.append(
                Event(
                    kind="session.end",
                    provenance=context.provenance(f"{locator}#end"),
                    agent=context.agent,
                    raw=values,
                    ts_utc=end_ts,
                    ts_precision=end_precision,
                    ts_source=end_source,
                    actor="system",
                    payload={
                        "text": "the session ended"
                        + (f", reason {reason}" if reason else " and the row records no reason"),
                        "end_reason": reason or None,
                        "models": models,
                    },
                    parse_problem=end_note,
                    **common,
                )
            )
    return events, headers


def _session_payload(
    values: dict[str, Any], header: dict[str, Any], models: list[dict[str, Any]]
) -> dict[str, Any]:
    """The session header as an analyst reads it.

    `source` and `user_id` are first because they answer a question no other agent's store
    answers: whether somebody drove this agent from a chat platform rather than from the
    console in front of them.
    """
    payload: dict[str, Any] = {
        "source": header["source"] or None,
        "user_id": header["user_id"] or None,
        "title": _text(values.get("title")) or None,
        "models": models,
        "parent_session_id": _text(values.get("parent_session_id")) or None,
    }
    # A parent session means the conversation was split by compression rather than started
    # fresh, so the history before the split is in another session's rows.
    if payload["parent_session_id"]:
        payload["text"] = (
            "this session continues another one: the vendor documents parent_session_id as "
            "the lineage of a compression-triggered split, so the earlier turns are in "
            "session " + payload["parent_session_id"]
        )
    counters = {
        key: values.get(key)
        for key in (
            "message_count",
            "tool_call_count",
            "api_call_count",
            "input_tokens",
            "output_tokens",
            "cache_read_tokens",
            "cache_write_tokens",
            "reasoning_tokens",
        )
        if values.get(key) not in (None, "")
    }
    if counters:
        # Worth carrying: a message_count higher than the rows present says the store lost
        # or archived turns, which is a question rather than an answer but the numbers are
        # the only way to ask it.
        payload["counters"] = counters
    billing = {
        key: values.get(key)
        for key in ("billing_provider", "billing_base_url", "billing_mode", "actual_cost_usd")
        if values.get(key) not in (None, "")
    }
    if billing:
        payload["billing"] = billing
    return payload


def _system_prompt(
    context: ParseContext,
    locator: str,
    values: dict[str, Any],
    prompt: str,
    common: dict[str, Any],
) -> Event:
    """The session's system prompt, as an instruction source.

    Scope `session` rather than `user` or `project`, and the distinction is the point. The
    managed, user and project scopes describe files that apply to everything, to one person
    or to one checkout. This prompt applied to one session, is not a file on the filesystem,
    and could not be found by looking for one. Presenting it at any wider scope would say
    the agent was told this everywhere, which the row does not support.

    No timestamp of its own. The prompt is part of the environment that session ran in and
    the session.start event already carries the time; a second time here would present the
    session's clock as the instruction's own.
    """
    return Event(
        kind="instruction.source",
        provenance=context.provenance(f"{locator}#system_prompt"),
        agent=context.agent,
        raw={"system_prompt": prompt},
        ts_utc=None,
        ts_precision="absent",
        actor="system",
        payload={
            "text": prompt,
            # The facet the case indexes. The path is the store plus the column, because
            # that is where this instruction was found and there is no file to name.
            "instructions": [
                {
                    "path": f"{context.original_path}#sessions.system_prompt",
                    "scope": "session",
                }
            ],
            "scope": "session",
            "file": "sessions.system_prompt",
            "bytes": len(prompt.encode("utf-8", "surrogatepass")),
            "lines": prompt.count("\n") + 1,
            "in_database": True,
            "session_title": _text(values.get("title")) or None,
        },
        **common,
    )


# --------------------------------------------------------------------------- messages


def _messages(
    context: ParseContext,
    connection: sqlite3.Connection,
    listed: dict[str, Any],
    headers: dict[str, dict[str, Any]],
) -> Iterator[Event]:
    """The turn stream. One event per record, and more than one where a row holds more."""
    table = listed.get("messages")
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
        header = _header_of(headers, session_id)
        common: dict[str, Any] = {
            "user": context.user,
            "host": context.host,
            "client": "hermes",
            "session_id": session_id or None,
            "project_path": header.get("project_path"),
            "git_branch": header.get("git_branch"),
        }
        models = [{"model": header["model"]}] if header.get("model") else []
        ts, precision, source, note = _time(values.get("timestamp"), _MESSAGE_CLOCK)
        timing: dict[str, Any] = {
            "ts_utc": ts,
            "ts_precision": precision,
            "ts_source": source,
        }
        generation = _generation(values)
        notes = [text for text in (note, generation["note"]) if text]
        role = _text(values.get("role")).lower()

        if role == "user":
            yield Event(
                kind="user.prompt",
                provenance=context.provenance(locator),
                agent=context.agent,
                raw=values,
                actor="user",
                payload=_message_payload(values, header, models, generation),
                parse_problem=" ".join(notes) or None,
                **timing,
                **common,
            )
            continue

        if role == "system":
            # A system-role row is the same kind of evidence as sessions.system_prompt: what
            # the agent was told to obey, at the scope of one session.
            payload = _message_payload(values, header, models, generation)
            payload["instructions"] = [
                {"path": f"{context.original_path}#messages.content", "scope": "session"}
            ]
            payload["scope"] = "session"
            payload["file"] = "messages.content"
            payload["in_database"] = True
            yield Event(
                kind="instruction.source",
                provenance=context.provenance(locator),
                agent=context.agent,
                raw=values,
                actor="system",
                payload=payload,
                parse_problem=" ".join(notes) or None,
                **timing,
                **common,
            )
            continue

        if role == "tool":
            yield Event(
                kind="tool.result",
                provenance=context.provenance(locator),
                agent=context.agent,
                raw=values,
                actor="tool",
                payload=_tool_result_payload(values, generation),
                parse_problem=" ".join(notes) or None,
                **timing,
                **common,
            )
            continue

        if role == "assistant":
            yield from _assistant(
                context, locator, values, header, models, generation, timing, common, notes
            )
            continue

        yield unparsed(
            context.provenance(locator),
            context.agent,
            values,
            f"a messages row whose role {role!r} is not one this parser maps",
            ts_utc=ts,
            ts_precision=precision,
            ts_source=source,
            user=context.user,
            host=context.host,
            session_id=session_id or None,
            project_path=header.get("project_path"),
        )


def _assistant(
    context: ParseContext,
    locator: str,
    values: dict[str, Any],
    header: dict[str, Any],
    models: list[dict[str, Any]],
    generation: dict[str, Any],
    timing: dict[str, Any],
    common: dict[str, Any],
    notes: list[str],
) -> Iterator[Event]:
    """One assistant row, which can hold a reply, its reasoning and several tool calls.

    Each of the three becomes its own event, because collapsing them would make the reply
    and the reasoning one turn, and the vendor's own history surfaces keep them apart. The
    reply is the interesting case: the documentation states that a reasoning-only clean stop
    leaves `content` empty with the text in `reasoning`, and that a final reply can live only
    in `codex_message_items`. So a row with no content is not a turn where nothing was said.
    """
    content = _text(values.get("content"))
    reasoning = _text(values.get("reasoning")) or _text(values.get("reasoning_content"))
    items, items_problem = _json_of(values.get("codex_message_items"))
    items_text = text_of(items) if items else ""
    problems = list(notes)
    if items_problem:
        problems.append(items_problem)

    if content:
        yield Event(
            kind="assistant.text",
            provenance=context.provenance(locator),
            agent=context.agent,
            raw=values,
            actor="assistant",
            payload=_message_payload(values, header, models, generation),
            parse_problem=" ".join(problems) or None,
            **timing,
            **common,
        )
    elif items_text:
        # The reply existed and the column that holds replies is empty. Surfaced as the
        # reply it is, with the reason it was found somewhere else, because a reader that
        # only looked at `content` would show this turn as silence.
        payload = _message_payload(values, header, models, generation)
        payload["text"] = items_text
        payload["text_source"] = "codex_message_items"
        yield Event(
            kind="assistant.text",
            provenance=context.provenance(f"{locator}#items"),
            agent=context.agent,
            raw=values,
            actor="assistant",
            payload=payload,
            parse_problem=" ".join(
                [
                    *problems,
                    "the content column is empty and the reply was taken from "
                    "codex_message_items, which the vendor documents as where a final "
                    "Responses reply can live",
                ]
            ),
            **timing,
            **common,
        )

    if reasoning:
        payload = _message_payload(values, header, models, generation)
        payload["text"] = reasoning
        payload["reasoning_column"] = (
            "reasoning" if _text(values.get("reasoning")) else "reasoning_content"
        )
        if not content and not items_text:
            # The vendor's documented reasoning-only stop. Said out loud, because an
            # assistant turn with reasoning and no reply is either that documented case or a
            # truncated write, and an analyst needs to know which one the format allows.
            payload["reasoning_only_reply"] = True
        yield Event(
            kind="assistant.thinking",
            provenance=context.provenance(f"{locator}#reasoning"),
            agent=context.agent,
            raw=values,
            actor="assistant",
            payload=payload,
            parse_problem=" ".join(problems) or None,
            **timing,
            **common,
        )

    calls, calls_problem = _json_of(values.get("tool_calls"))
    if calls_problem:
        # A truncated argument list is still evidence of what the agent was about to do, so
        # the string is kept as itself rather than dropped.
        yield Event(
            kind="tool.call",
            provenance=context.provenance(f"{locator}#calls"),
            agent=context.agent,
            raw=values,
            actor="assistant",
            payload={
                "tool": _text(values.get("tool_name")) or None,
                "input": {"tool_calls": values.get("tool_calls")},
                "models": models,
            },
            parse_problem=" ".join([*problems, calls_problem]),
            **timing,
            **common,
        )
        return

    for index, call in enumerate(calls if isinstance(calls, list) else []):
        yield Event(
            kind="tool.call",
            provenance=context.provenance(f"{locator}#call:{index}"),
            agent=context.agent,
            raw=values,
            actor="assistant",
            payload=_tool_call_payload(call, values, models, generation),
            parse_problem=" ".join(problems) or None,
            **timing,
            **common,
        )


def _tool_call_payload(
    call: Any, values: dict[str, Any], models: list[dict[str, Any]], generation: dict[str, Any]
) -> dict[str, Any]:
    """One entry of the tool_calls list.

    The OpenAI-style shape, `{id, type, function: {name, arguments}}`, is read where it is
    there and the whole entry is carried either way. The arguments are a JSON string in that
    shape and are parsed when they parse; a string that does not parse is kept as itself.
    Nothing is claimed about what the tool did: the vendor documents the column as a list of
    tool call objects and names no tools, so no command, file or network facet is derived.
    """
    mapping: dict[str, Any] = call if isinstance(call, dict) else {}
    inner = mapping.get("function")
    function: dict[str, Any] = inner if isinstance(inner, dict) else {}
    name = (
        _text(function.get("name"))
        or _text(mapping.get("name"))
        or _text(values.get("tool_name"))
        or None
    )
    arguments: Any = function.get("arguments", mapping.get("arguments"))
    problem = None
    if isinstance(arguments, str) and arguments.strip():
        parsed, problem = _json_of(arguments)
        if problem is None:
            arguments = parsed
    payload: dict[str, Any] = {
        "tool": name,
        "tool_use_id": _text(mapping.get("id")) or _text(values.get("tool_call_id")) or None,
        "input": arguments if isinstance(arguments, dict) else {"arguments": arguments},
        "call": mapping or call,
        "models": models,
    }
    if problem:
        payload["arguments_problem"] = problem
    payload.update(generation["payload"])
    return payload


def _tool_result_payload(values: dict[str, Any], generation: dict[str, Any]) -> dict[str, Any]:
    """A tool-role row. No error flag is claimed: the documented columns carry none."""
    payload: dict[str, Any] = {
        "tool": _text(values.get("tool_name")) or None,
        "tool_use_id": _text(values.get("tool_call_id")) or None,
        "text": _text(values.get("content")),
    }
    payload.update(generation["payload"])
    return payload


def _message_payload(
    values: dict[str, Any],
    header: dict[str, Any],
    models: list[dict[str, Any]],
    generation: dict[str, Any],
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "text": _text(values.get("content")),
        "models": models,
        "source": header.get("source") or None,
        "user_id": header.get("user_id") or None,
    }
    for key in ("finish_reason", "token_count", "platform_message_id", "display_kind"):
        value = values.get(key)
        if value not in (None, ""):
            payload[key] = value
    payload.update(generation["payload"])
    return payload


def _generation(values: dict[str, Any]) -> dict[str, Any]:
    """Which compaction generation a message row belongs to.

    The vendor documents compaction as archiving the old rows with `active=0` and inserting
    the retained context as `active=1`, and warns that a protected message legitimately
    appears in both with identical content and timestamp. Nothing is deduplicated here for
    that reason. What the analyst gets instead is the flag, because "this turn is in the
    pre-compaction generation" and "this turn is live" are different statements about the
    same text, and an archived row is history that was kept rather than history that was
    deleted.

    An older database has no such column, and absent is reported as absent rather than as
    live: claiming a row is current when the store never said so would be an invention.
    """
    active = values.get("active")
    compacted = values.get("compacted")
    payload: dict[str, Any] = {}
    note = None
    if active in (0, "0", False):
        payload["compaction_generation"] = "archived"
        note = (
            "this row is a compaction archive (active=0), which the vendor documents as "
            "history kept rather than deleted, so it may repeat a live row word for word"
        )
    elif active in (1, "1", True):
        payload["compaction_generation"] = "live"
    if compacted not in (None, ""):
        payload["compacted"] = compacted
    return {"payload": payload, "note": note}


def _json_of(value: Any) -> tuple[Any, str | None]:
    """A column the vendor documents as a JSON string, as an object.

    A string that will not parse is returned as itself with the reason, never dropped: a
    truncated argument list is still evidence of what the agent was about to do.
    """
    if value in (None, ""):
        return None, None
    if isinstance(value, (dict, list)):
        return value, None
    if not isinstance(value, str):
        return value, f"expected a JSON string and found {type(value).__name__}"
    try:
        return json.loads(value), None
    except ValueError as exc:
        return value, f"a column documented as JSON did not parse: {exc}"


__all__ = ["MAPPED", "HermesParser"]
