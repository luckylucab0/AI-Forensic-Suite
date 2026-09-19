"""Read Codex's thread history database, which holds the conversation after the file is gone.

Codex keeps seven SQLite databases beside its rollout files, and one of them is a
projection of the rollouts into rows: `thread_history_1.sqlite`. Every item of every
conversation is in it, with its own millisecond timestamp, its turn and its position in the
rollout file it came from. That makes it the one place an examination can still read a
conversation whose `rollout-*.jsonl` has been deleted, rotated out or compressed away, and
the place to compare against when a rollout file is present but looks short.

The other six databases are the agent's own runtime state: its logs, its goals, its
memories in two generations, its queue and the main state database. Their rows are carried
uninterpreted rather than mapped, for the reason the generic reader exists: this module has
read the thread history schema and not theirs, and a guess at a column's meaning produces a
case that reads as answered while being wrong. The memories databases are worth an
analyst's attention regardless, because content that persists there influences later
sessions the person may not connect to it.

Sources, fetched and read:

- the seven filenames and the home they sit in,
  https://raw.githubusercontent.com/openai/codex/main/codex-rs/state/src/sqlite.rs
- the four tables and every migration that shaped them,
  https://github.com/openai/codex/tree/main/codex-rs/state/thread_history_migrations
- the nineteen item shapes, from the vendor's own published JSON Schema for its app server
  protocol, codex-rs/app-server-protocol/schema/json/v2/ThreadItemsListResponse.json

The tables, as the migrations leave them:

    thread_items(thread_id, turn_id, item_id, rollout_ordinal, created_at_ms, item_json,
                 item_type, updated_at_ordinal)
    thread_realtime_items(thread_id, item_id, rollout_ordinal, created_at_ms, item_type,
                          item_json)
    thread_turns(thread_id, turn_id, rollout_ordinal, status, error_json, started_at,
                 completed_at, duration_ms, first_user_item_id, final_agent_item_id,
                 rollout_byte_offset, rollout_end_ordinal, rollout_end_byte_offset)
    thread_history_projection_state(thread_id, next_rollout_byte_offset,
                                    next_rollout_ordinal)

`item_type` is the item's own `type` field, which the vendor's own migration copies out of
the JSON with `json_extract(item_json, '$.type')`, so the column and the document cannot
disagree about what a row is.

**What is mapped and what is not.** The nineteen item types are mapped to the event model
where the schema says plainly what a field is: a command with its working directory and
exit code, a file change with its paths, an MCP call with its server and tool. An item type
this module does not map is still an event, with its type named and its document carried
whole, which is the difference between a record nobody has read and a record nobody kept.

`thread_turns` is read and deliberately not mapped to a kind. A turn is a request and the
work done on it, and the event model has no kind for that boundary; choosing one would put
something untrue in a case. The rows are carried whole with that as their stated reason,
and every item event names the turn it belongs to, which is what grouping them needs.

**Times.** `created_at_ms` is milliseconds since the epoch, and a turn's `started_at` and
`completed_at` are the same. They are the agent's own clock on the endpoint, not the
collection's.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

from agentforensics.model import Actor, Event, unparsed
from agentforensics.parsers.base import ParseContext, text_of
from agentforensics.parsers.sqlite_generic import rows_as_events
from agentforensics.parsers.sqlite_store import (
    StoreError,
    Table,
    describe,
    open_store,
    rows_of,
    tables,
)

# The tables this module has read. Dispatch is on the table and not on the file name: the
# vendor puts the schema version in the name, seven of them, and the catalogue's own note
# says the next one will be state_6.sqlite. A parser keyed on a name is wrong at the next
# release; a parser keyed on the tables in front of it is not.
ITEMS = "thread_items"
REALTIME_ITEMS = "thread_realtime_items"
TURNS = "thread_turns"
PROJECTION = "thread_history_projection_state"

_TURNS_NOTE = (
    "this table's schema is read and the row is carried whole rather than mapped: a turn is "
    "a request and the work done on it, and the event model has no kind for that boundary. "
    "The items of this turn are their own events and each names this turn_id"
)
_PROJECTION_NOTE = (
    "this table's schema is read and the row is carried whole rather than mapped: it is the "
    "projector's position in the rollout file, which says how much of that file had been "
    "read into this database and not anything the agent did"
)

# How each item type becomes an event. The kind comes first because it is the claim; the
# reader is what fills the payload. Every one of these rests on the vendor's published
# schema for the item, and a type that is not here is carried as a record rather than
# guessed at.
#
# Two mappings are worth their comment here rather than in the reader:
#
# hookPrompt is an instruction.source and not a user.prompt. It is text a hook put in front
# of the model, which is the injected-instruction question this tool exists to answer, and
# calling it a user prompt would credit it to the person.
#
# subAgentActivity has four kinds in the vendor's enum and they do not share one event kind:
# a subagent starting and finishing are the boundaries of another conversation, and an
# interaction with one is the parent agent calling it.


def _ms(value: Any) -> str | None:
    """Milliseconds since the epoch, as the format the rest of the case is in.

    The unit is the column's own name, `created_at_ms`, and that is the whole basis for
    reading it this way. The turn table's time columns are not named with a unit and are
    not read as times anywhere in this module.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        moment = datetime.fromtimestamp(value / 1000, tz=UTC)
    except OverflowError, OSError, ValueError:
        return None
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


class CodexStateParser:
    """Codex's thread history, and the honest floor under its six other state databases."""

    name = "codex_state"

    _STORES = frozenset({"codex.state_databases", "codex.sqlite_glob"})

    def handles(self, artifact_id: str | None) -> bool:
        return artifact_id in self._STORES

    def parse(self, context: ParseContext) -> Iterator[Event]:
        try:
            with open_store(context.local_path) as connection:
                listed = {table.name: table for table in tables(connection)}
                for name, table in sorted(listed.items()):
                    if name == ITEMS and _has(table, "item_json", "thread_id"):
                        yield from _items(context, connection, table, turns=True)
                    elif name == REALTIME_ITEMS and _has(table, "item_json", "thread_id"):
                        yield from _items(context, connection, table, turns=False)
                    elif name == TURNS and _has(table, "turn_id", "status"):
                        yield from _turns(context, connection, table)
                    elif name == PROJECTION and _has(table, "next_rollout_ordinal"):
                        yield from rows_as_events(context, connection, table, _PROJECTION_NOTE)
                    else:
                        # The other six databases, and any table here whose columns are not
                        # the ones the migrations declare. Read as rows: a store half read
                        # with the other half silently absent is the failure this project
                        # does not accept.
                        yield from rows_as_events(context, connection, table)
        except StoreError as exc:
            yield describe(context, str(exc))


def _turns(context: ParseContext, connection: sqlite3.Connection, table: Table) -> Iterator[Event]:
    """One request and the work done on it, carried whole with a description of itself.

    Not given a time. The migrations declare started_at and completed_at as integers and do
    not say what unit they are in, and this module has not found the code that writes them.
    A time read at the wrong scale puts a turn in 1970 or in the year 58000, and either one
    is a worse answer than no time: the items of the turn carry their own, from a column
    whose name states its unit.
    """
    for locator, values, problem in rows_of(connection, table):
        status = text_of((values or {}).get("status")) or "unknown"
        duration = (values or {}).get("duration_ms")
        turn = text_of((values or {}).get("turn_id")) or "unknown"
        described = f"turn {turn} is {status}"
        if isinstance(duration, int) and not isinstance(duration, bool):
            # The column names its own unit, which is the only reason this one is read.
            described += f", after {duration} ms"
        if (values or {}).get("error_json"):
            described += ", and it recorded an error"
        yield unparsed(
            context.provenance(locator),
            context.agent,
            values or None,
            problem or _TURNS_NOTE,
            user=context.user,
            host=context.host,
            session_id=text_of((values or {}).get("thread_id")) or None,
            payload={"table": table.name, "text": described},
        )


def _has(table: Table, *columns: str) -> bool:
    """Whether the table declares these columns, read off its own CREATE statement."""
    sql = (table.sql or "").lower()
    return all(column.lower() in sql for column in columns)


def _items(
    context: ParseContext, connection: sqlite3.Connection, table: Table, *, turns: bool
) -> Iterator[Event]:
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
        yield _item(context, locator, values, turns=turns)


def _item(context: ParseContext, locator: str, values: dict[str, Any], *, turns: bool) -> Event:
    """One projected item of a conversation."""
    document, document_problem = _document(values.get("item_json"))
    declared = text_of(values.get("item_type")) or None
    # The type out of the document where the document has one, because that is what the
    # column is copied from. They agree by construction; where they do not, the document is
    # the record and the disagreement is said rather than resolved silently.
    inner = text_of((document or {}).get("type")) or None
    item_type = inner or declared
    disagreement = (
        f"the item_type column says {declared!r} and the document says {inner!r}, so this "
        "row was written by something other than the agent that wrote the rest"
        if declared and inner and declared != inner
        else None
    )

    kind, payload, mapping_problem = _map(item_type, document)
    common: dict[str, Any] = {
        "user": context.user,
        "host": context.host,
        "session_id": text_of(values.get("thread_id")) or None,
    }
    payload = dict(payload)
    payload["item_type"] = item_type
    payload["item_id"] = text_of(values.get("item_id")) or None
    if turns:
        # Which request this item belongs to. The turn table is carried whole rather than
        # mapped, so this is how the two are joined.
        payload["turn_id"] = text_of(values.get("turn_id")) or None
    # Where the item sits in the rollout file this database was projected from. It is how a
    # row here is lined up against a rollout that still exists, and how a gap shows up when
    # one does not.
    payload["rollout_ordinal"] = values.get("rollout_ordinal")

    when = _ms(values.get("created_at_ms"))
    problems = [part for part in (document_problem, disagreement, mapping_problem) if part]
    return Event(
        kind=kind,
        provenance=context.provenance(locator),
        agent=context.agent,
        raw=values,
        ts_utc=when,
        ts_precision="exact" if when else "absent",
        ts_source="created_at_ms" if when else None,
        actor=_ACTORS.get(kind, "system"),
        payload=payload,
        parse_problem=" ".join(problems) or None,
        **common,
    )


# Who the event is about, by kind. The agent is the actor for everything it did, the person
# for what they typed, and the system for a record about the conversation rather than in it.
_ACTORS: dict[str, Actor] = {
    "user.prompt": "user",
    "assistant.text": "assistant",
    "assistant.thinking": "assistant",
    "tool.call": "assistant",
    "command.exec": "assistant",
    "file.write": "assistant",
    "file.read": "assistant",
    "mcp.call": "assistant",
    "network.request": "assistant",
    "plan.write": "assistant",
    "tool.result": "tool",
}


def _document(value: Any) -> tuple[dict[str, Any] | None, str | None]:
    """The item's own JSON, which the column holds as text."""
    if isinstance(value, dict):
        return value, None
    if not isinstance(value, str) or not value.strip():
        return (
            None,
            "the item_json column is empty, so this row records an item and not its content",
        )
    try:
        parsed = json.loads(value)
    except ValueError as exc:
        return None, f"item_json is not valid JSON: {exc}"
    if not isinstance(parsed, dict):
        return None, "item_json is valid JSON and not an object, which no item shape is"
    return parsed, None


def _map(
    item_type: str | None, document: dict[str, Any] | None
) -> tuple[str, dict[str, Any], str | None]:
    """The kind and the payload for one item, from the vendor's published schema for it."""
    body = document or {}
    if item_type == "userMessage":
        texts = [
            text_of(part.get("text"))
            for part in body.get("content") or []
            if isinstance(part, dict) and part.get("type") == "text"
        ]
        other = [
            part
            for part in body.get("content") or []
            if isinstance(part, dict) and part.get("type") != "text"
        ]
        return (
            "user.prompt",
            {
                "text": "\n".join(part for part in texts if part) or None,
                # An image, a URL or a file attached to the prompt. Counted and carried
                # rather than turned into text it is not: a prompt that reads as empty here
                # and had an image in it is a prompt somebody would call empty in a report.
                "input": other or None,
                "client_id": text_of(body.get("clientId")) or None,
            },
            None,
        )
    if item_type == "hookPrompt":
        fragments = body.get("fragments") or []
        return (
            "instruction.source",
            {
                "text": "\n".join(
                    text_of(part.get("text"))
                    for part in fragments
                    if isinstance(part, dict) and text_of(part.get("text"))
                )
                or None,
                # No instructions facet: that facet is a path to join against a collected
                # file, and a hook's prompt has no path. What it has is the run that
                # produced it.
                "hook_runs": sorted(
                    {
                        text_of(part.get("hookRunId"))
                        for part in fragments
                        if isinstance(part, dict) and text_of(part.get("hookRunId"))
                    }
                )
                or None,
            },
            None,
        )
    if item_type == "agentMessage":
        return (
            "assistant.text",
            {
                "text": text_of(body.get("text")) or None,
                # Where the model cited its own memory back at the person. It is how
                # something written in an earlier session reaches this one.
                "memory_citation": body.get("memoryCitation"),
                "phase": text_of(body.get("phase")) or None,
            },
            None,
        )
    if item_type == "reasoning":
        summary = [text_of(part) for part in body.get("summary") or []]
        content = [text_of(part) for part in body.get("content") or []]
        return (
            "assistant.thinking",
            {"text": "\n".join(part for part in summary + content if part) or None},
            None,
        )
    if item_type == "plan":
        return "plan.write", {"text": text_of(body.get("text")) or None}, None
    if item_type == "commandExecution":
        command = text_of(body.get("command"))
        return (
            "command.exec",
            {
                "text": text_of(body.get("aggregatedOutput")) or None,
                "commands": [
                    {
                        "command": command,
                        "executable": command.split()[0] if command.split() else None,
                        "cwd": text_of(body.get("cwd")) or None,
                        "exit_code": body.get("exitCode"),
                    }
                ]
                if command
                else None,
                "status": text_of(body.get("status")) or None,
                "duration_ms": body.get("durationMs"),
                # agent, userShell, or one of the two unified exec values. It is the
                # difference between the agent running a command and the person running one
                # in the same session, which is a question every examination asks.
                "source": text_of(body.get("source")) or None,
            },
            None,
        )
    if item_type == "fileChange":
        return (
            "file.write",
            {
                "files": [
                    {
                        "path": text_of(change.get("path")),
                        "operation": _OPERATIONS.get(
                            text_of((change.get("kind") or {}).get("type")), "write"
                        ),
                    }
                    for change in body.get("changes") or []
                    if isinstance(change, dict) and text_of(change.get("path"))
                ]
                or None,
                "status": text_of(body.get("status")) or None,
                # The diffs themselves, which are what the change actually was. Carried
                # whole: a case that says a file was written and cannot say what was
                # written into it answers half the question.
                "output": [change.get("diff") for change in body.get("changes") or []] or None,
            },
            None,
        )
    if item_type == "mcpToolCall":
        server = text_of(body.get("server"))
        return (
            "mcp.call",
            {
                "tool": text_of(body.get("tool")) or None,
                "mcp": [{"server": server, "tool": text_of(body.get("tool")) or None}]
                if server
                else None,
                "input": body.get("arguments"),
                "output": body.get("result"),
                "is_error": bool(body.get("error")),
                "status": text_of(body.get("status")) or None,
                "duration_ms": body.get("durationMs"),
            },
            None,
        )
    if item_type == "webSearch":
        action = body.get("action")
        url = text_of(action.get("url")) if isinstance(action, dict) else None
        return (
            "network.request",
            {
                "text": text_of(body.get("query")) or None,
                # Only where the item names one. A search names a query and not a host, and
                # a host invented from a query would put a destination in a case that the
                # agent never contacted.
                "network": [{"host": _host(url), "url": url}] if _host(url) else None,
                "output": body.get("results"),
            },
            None,
        )
    if item_type == "imageView":
        path = text_of(body.get("path"))
        return (
            "file.read",
            {"files": [{"path": path, "operation": "read"}] if path else None},
            None,
        )
    if item_type == "functionCallOutput":
        return (
            "tool.result",
            {
                "tool": text_of(body.get("name")) or None,
                "output": body.get("output"),
                "text": _output_text(body.get("output")),
                "namespace": text_of(body.get("namespace")) or None,
            },
            None,
        )
    if item_type in ("dynamicToolCall", "collabAgentToolCall"):
        return (
            "tool.call",
            {
                "tool": text_of(body.get("tool")) or None,
                "input": body.get("arguments") if "arguments" in body else body.get("prompt"),
                "output": body.get("contentItems"),
                "status": text_of(body.get("status")) or None,
                # A collaboration item names the threads on both sides of it, which is how
                # one agent handing work to another is followed across conversations.
                "sender_thread": text_of(body.get("senderThreadId")) or None,
                "receiver_threads": body.get("receiverThreadIds"),
            },
            None,
        )
    if item_type == "subAgentActivity":
        activity = text_of(body.get("kind"))
        payload = {
            "text": f"a subagent {activity or 'activity'}: {text_of(body.get('agentPath'))}",
            "subagent": text_of(body.get("agentPath")) or None,
            "agent_thread_id": text_of(body.get("agentThreadId")) or None,
            "activity": activity or None,
        }
        # The vendor's four kinds do not share one event kind: starting and finishing are
        # the boundaries of another conversation, and an interaction is this agent calling
        # into it.
        if activity == "started":
            return "session.start", payload, None
        if activity in ("completed", "interrupted"):
            return "session.end", payload, None
        return "tool.call", {**payload, "tool": "subAgent"}, None
    if item_type == "contextCompaction":
        return (
            "session.end",
            {
                "text": "the conversation was compacted, so earlier turns were rewritten or "
                "removed from what the model could see",
                "compaction": True,
            },
            None,
        )
    if item_type == "sleep":
        return (
            "tool.call",
            {"tool": "sleep", "duration_ms": body.get("durationMs")},
            None,
        )
    if item_type == "imageGeneration":
        saved = text_of(body.get("savedPath"))
        return (
            "tool.call",
            {
                "tool": "imageGeneration",
                "text": text_of(body.get("revisedPrompt")) or None,
                "files": [{"path": saved, "operation": "write"}] if saved else None,
                "status": text_of(body.get("status")) or None,
            },
            None,
        )
    if item_type in ("enteredReviewMode", "exitedReviewMode"):
        return (
            "config.snapshot",
            {
                "text": "the agent entered review mode"
                if item_type == "enteredReviewMode"
                else "the agent left review mode",
                "input": body.get("review"),
            },
            None,
        )
    return (
        "unparsed.record",
        {"text": None},
        f"item type {item_type!r} is not one of the nineteen this parser maps, so the item is "
        "carried whole rather than interpreted",
    )


# A patch's kind, as the vendor's enum spells it, in the operations the event model has.
_OPERATIONS = {"add": "write", "update": "write", "delete": "delete"}


def _host(url: str | None) -> str | None:
    """The host of a URL, without importing a parser's worth of assumptions about one."""
    if not url or "://" not in url:
        return None
    rest = url.split("://", 1)[1]
    host = rest.split("/", 1)[0].split("@")[-1].split(":")[0]
    return host or None


def _output_text(output: Any) -> str | None:
    """A function call's output as text, where it is text or is a list of text pieces."""
    if isinstance(output, str):
        return output or None
    if isinstance(output, dict):
        return text_of(output.get("content")) or text_of(output.get("text")) or None
    if isinstance(output, list):
        pieces = [
            text_of(part.get("text")) if isinstance(part, dict) else text_of(part)
            for part in output
        ]
        return "\n".join(piece for piece in pieces if piece) or None
    return None
