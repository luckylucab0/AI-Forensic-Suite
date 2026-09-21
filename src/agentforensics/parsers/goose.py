"""Parse Goose's session store as a conversation, against the schema the agent builds it from.

Three catalogue entries are one product's record of what it was asked and what it did, and
all three arrived in a case as rows and lines nobody had read: `goose.sessions_db` and
`goose.sessions_db_windows` through the generic SQLite reader, `goose.sessions_jsonl_legacy`
through the generic line reader. The store is the same conversation in two containers, which
is why one module claims all three: the product moved from a file per session to a database
at 1.10.0 and left the files behind, and its own documentation says the legacy files remain
on disk and are no longer managed, so an endpoint can hold both and the older one is the
half a user cannot delete from the product's own interface.

Sources, fetched and read rather than inferred:

- the message model, which both containers store verbatim,
  https://raw.githubusercontent.com/block/goose/main/crates/goose-provider-types/src/conversation/message.rs
- how a tool call and a tool result are serialised inside it,
  https://raw.githubusercontent.com/block/goose/main/crates/goose-provider-types/src/conversation/tool_result_serde.rs
- the database schema, as the CREATE TABLE statements the product executes,
  https://raw.githubusercontent.com/block/goose/main/crates/goose/src/session/session_manager.rs
- the legacy file layout, one metadata line then one message per line,
  https://raw.githubusercontent.com/block/goose/main/crates/goose/src/session/legacy.rs
- the permission values a confirmation is answered with,
  https://raw.githubusercontent.com/block/goose/main/crates/goose-provider-types/src/permission.rs
- the extension model, which says what an enabled extension is and which kinds are servers,
  https://raw.githubusercontent.com/block/goose/main/crates/goose/src/agents/extension.rs
- the tool names and argument names of the built-in developer extension,
  https://raw.githubusercontent.com/block/goose/main/crates/goose/src/agents/platform_extensions/developer/mod.rs

**A message is a role, a time and a list of typed content blocks.** The blocks are what a
timeline needs: `text` is the turn, `thinking` is the reasoning, `toolRequest` is a call,
`toolResponse` is its result, and a confirmation is a permission decision with a name on it.
The block type is the serde tag `type` in camelCase, and the mapping here is keyed on the
vendor's own spelling of it rather than on a guess at the shape of the block.

**Two things this store records that the product does not show.** A message carries
`metadata.userVisible`, and the product's own queries count and display only the messages
where it is true, so a message with it false was in the conversation and never on the
screen. And the product's reader skips a row whose role is neither `user` nor `assistant`
outright, with `_ => continue`: such a row is not in the product's own reading of the
session at all. Both are carried here, the first as a field on the event and the second as
a record with the reason on it, because a record the product hides is the one an
investigation is most likely to turn on.

**Which tool call went to an MCP server is answered from the session and not from the
name.** Goose advertises a tool as `extension__tool` and the separator is the vendor's, but
a built-in extension and an MCP server are advertised the same way, so the name alone does
not say which. The session row's own `extension_data` holds the enabled extensions with
their `type`, and `stdio` and `streamable_http` are the two that are servers. So an
`mcp.call` is emitted only where that state names the extension as one, and a call whose
extension is not in it stays a `tool.call` with the extension recorded. A conversation with
no such state, which is every legacy file that never had one, therefore produces no MCP
claim rather than a guessed one.

**What this module does not map, and how the events say so.** A content block type the
vendor adds after this was written becomes `unparsed.record` saying the type is not one this
parser maps, with its time and its session, so it sorts into the timeline where it belongs.
Records the vendor does define are carried the same way with a different sentence, because
the event model has no kind for them rather than because nobody read them: `actionRequired`
in its two elicitation forms, `systemNotification`, `error`, and what is inside an `image` or
`document` attachment, which is a file format this module has read none of. The turn the
attachment rode on is an event either way, with the attachment's name and media type on it.
Every table of the database this module does not map, `schema_version`, `usage_ledger` and
the provider inventory tables, goes through the uninterpreted row reading so the store is
never half read with the other half silently absent. And `goose.llm_request_logs`, which is
the same family and holds the raw provider payload rather than the product's own record of a
turn, is deliberately left with the generic line reader: its shape is the provider's wire
format and differs per provider, so a mapping for it would rest on nothing this module has
read.

**The clock.** A message time is epoch seconds, which the vendor states in a comment beside
the query that orders by it, and the product itself divides a value above ten thousand
million by a thousand to cope with the milliseconds an older version wrote. The shared
timestamp helper draws that line at a hundred thousand million instead. The band between the
two is the years 2286 to 5138 read as seconds and 1970 to 1973 read as milliseconds, so no
record a collection can hold falls in it, and the reading is recorded on every event either
way.
"""

from __future__ import annotations

import json
import sqlite3
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
from agentforensics.parsers.sqlite_generic import rows_as_events
from agentforensics.parsers.sqlite_store import (
    StoreError,
    Table,
    describe,
    open_store,
    rows_of,
    sidecar,
    tables,
)

# The two catalogue entries that are the database, and the one that is the file per session
# the product stopped managing. Separate sets because the containers are read differently
# and the same mapping is applied to what comes out of both.
STORES = frozenset({"goose.sessions_db", "goose.sessions_db_windows"})
LEGACY_SESSIONS = frozenset({"goose.sessions_jsonl_legacy"})

# The tables whose CREATE statement this module has read. Everything else in the database
# goes through the uninterpreted row reading, including the usage ledger: its columns are
# known and the event model has no kind for a per-request token and cost row, so the rows
# are carried rather than filed as something they are not.
MAPPED = ("sessions", "messages", "threads", "thread_messages")

# The extension kinds that are a server rather than code inside the agent's own process.
# `stdio` is a command the agent speaks MCP to and `streamable_http` is a URL it speaks MCP
# to; `builtin` and `platform` are neither.
SERVER_KINDS = frozenset({"stdio", "streamable_http", "sse"})

# The key the enabled extensions are stored under inside a session's extension_data. The
# product builds it as "{extension_name}.{version}" and the state's own name and version are
# `enabled_extensions` and `v0`.
ENABLED_EXTENSIONS_KEY = "enabled_extensions.v0"

# The built-in developer tools, by the name the product advertises, and the argument each
# one names its subject in. Only an exact match produces a facet: a tool this does not know
# is still a tool.call with its arguments intact, which costs an index rather than evidence.
_COMMAND_TOOLS = frozenset({"shell"})
_WRITE_TOOLS = frozenset({"write", "edit"})
_READ_TOOLS = frozenset({"tree"})
_IMAGE_TOOL = "read_image"

# Said on a record whose shape the vendor defines and the event model has no kind for. A
# different sentence from the one for a block type nobody mapped, because the two send the
# next reader to different places: this one to the event model, that one to the vendor.
NO_KIND = (
    "this is a Goose {what} and the event model has no kind for it, so the record is "
    "carried whole rather than filed as something it is not"
)

# Said on a row the product's own reader drops. It is not a defect in the evidence and it is
# not an unmapped format: it is a record the product cannot see.
UNKNOWN_ROLE = (
    "this message's role is {role!r}, and the product's own reader accepts only 'user' and "
    "'assistant' and skips every other row outright, so this turn is not in the session as "
    "the product reads it. Its content is here in raw"
)

# Said on a message the product stores and does not show. Carried as a note as well as a
# field, because a report quoting a conversation has to be able to say which of its turns a
# user could have seen.
NOT_SHOWN = (
    "this message is marked userVisible false, and the product counts and displays only the "
    "messages where that is true, so it was in the conversation and not on the screen"
)

# Said on the first line of a legacy session file that is a message rather than a header.
# The product reads the first line as the session metadata and fails the whole file when it
# will not deserialise, so such a file is one the product itself cannot load.
NO_HEADER = (
    "the first line of this session file is a message and not the session header the "
    "product reads there, so the product cannot load this session at all. The line is "
    "mapped as the message it is"
)

# Said where a legacy session file carries no created time. The product falls back to the
# filesystem and then to the file name, which encodes a local wall-clock time; neither is
# the session's own clock, so no timestamp is invented here.
NO_SESSION_TIME = (
    "this session header carries no created_at, so the event has no time of its own. The "
    "product falls back to the file's own timestamps and then to the file name, which "
    "encodes a local wall-clock time rather than UTC: the artifact event for this path "
    "carries the filesystem's times, attributed to the filesystem"
)


class GooseParser:
    """Goose's session store, in both the containers it has had."""

    name = "goose"

    def handles(self, artifact_id: str | None) -> bool:
        return artifact_id in STORES or artifact_id in LEGACY_SESSIONS

    def parse(self, context: ParseContext) -> Iterator[Event]:
        if context.artifact_id in LEGACY_SESSIONS:
            yield from _legacy_file(context)
            return
        yield from _database(context)


# ------------------------------------------------------------------------ the database


def _database(context: ParseContext) -> Iterator[Event]:
    beside = sidecar(context)
    if beside is not None:
        # A database's own log or shared-memory file, which this entry claims along with
        # the database. It is not a store and must not be reported as one that could not
        # be read.
        yield beside
        return
    try:
        with open_store(context.local_path) as connection:
            listed = {table.name: table for table in tables(connection)}
            # Sessions first: a message row carries neither the working directory nor the
            # enabled extensions, and without the directory a timeline cannot say which
            # working copy a command ran in.
            events, headers = _sessions(context, connection, listed)
            yield from events
            thread_events, thread_headers = _threads(context, connection, listed)
            yield from thread_events
            yield from _rows_as_messages(
                context, connection, listed.get("messages"), headers, ("session_id",)
            )
            yield from _rows_as_messages(
                context,
                connection,
                listed.get("thread_messages"),
                {**thread_headers, **headers},
                ("session_id", "thread_id"),
            )
            for name, table in sorted(listed.items()):
                if name not in MAPPED:
                    yield from rows_as_events(context, connection, table)
    except StoreError as exc:
        yield describe(context, str(exc))


def _sessions(
    context: ParseContext, connection: sqlite3.Connection, listed: dict[str, Table]
) -> tuple[list[Event], dict[str, dict[str, Any]]]:
    """The session rows, as events and as the header every message row inherits."""
    table = listed.get("sessions")
    events: list[Event] = []
    headers: dict[str, dict[str, Any]] = {}
    if table is None:
        return events, headers

    for locator, values, problem in rows_of(connection, table):
        if problem:
            events.append(_broken_row(context, locator, values, problem))
            continue
        session_id = _text(values.get("id"))
        header = _header(
            session_id,
            _text(values.get("working_dir")),
            _mapping(_document(values.get("extension_data"))[0]),
        )
        if session_id:
            headers[session_id] = header
        events.extend(_session_events(context, locator, values, header))
    return events, headers


def _session_events(
    context: ParseContext, locator: str, values: dict[str, Any], header: dict[str, Any]
) -> Iterator[Event]:
    """One session row: its start, the recipe it was told to obey, and its archiving."""
    common = _common(context, header)
    ts, precision, note = normalise_ts(values.get("created_at"))
    model_config, model_problem = _document(values.get("model_config_json"))
    model = _model(_text(values.get("provider_name")), model_config)
    recipe, recipe_problem = _document(values.get("recipe_json"))
    problems = [part for part in (note, model_problem, recipe_problem) if part]

    yield Event(
        kind="session.start",
        provenance=context.provenance(locator),
        agent=context.agent,
        raw=values,
        ts_utc=ts,
        ts_precision=precision,
        ts_source="created_at" if ts else None,
        actor="system",
        payload={
            "text": _text(values.get("name")) or _text(values.get("description")) or "a session",
            "models": [{"model": model}] if model else None,
            # Which of the product's own session kinds this is. A scheduled or subagent
            # session was not somebody sitting at a keyboard, and a timeline that read
            # every session as a person's is wrong about who acted.
            "session_kind": _text(values.get("session_type")) or None,
            # The approval posture the session ran under. Not a permission.change: the
            # column is the mode in force and the product's default is `auto`, so filing
            # it as a change would make every default session read as a mid-session bypass.
            "goose_mode": _text(values.get("goose_mode")) or None,
            "permissions": [
                {
                    "decision": "in_force",
                    "mode": _text(values.get("goose_mode")),
                    "subject": "every tool call in this session",
                }
            ]
            if values.get("goose_mode")
            else None,
            "extensions": header["extensions"] or None,
            # A forked or resumed session: the turns it continues from are in another row,
            # so a conversation starting mid-thought is a fork rather than a gap.
            "parent_session": _text(values.get("parent_session_id")) or None,
            "schedule_id": _text(values.get("schedule_id")) or None,
            "tokens": {
                "input": values.get("input_tokens"),
                "output": values.get("output_tokens"),
                "total": values.get("total_tokens"),
                "cache_read": values.get("cache_read_tokens"),
                "cache_write": values.get("cache_write_tokens"),
            },
            "cost": values.get("accumulated_cost"),
        },
        parse_problem=" ".join(problems) or None,
        **common,
    )

    if isinstance(recipe, dict) and (recipe.get("instructions") or recipe.get("prompt")):
        # A recipe is a template the session was started from, and it carries the
        # instructions and the opening prompt the model was given. That is the part of a
        # system prompt that is on the endpoint, so it belongs in the instruction surface.
        yield Event(
            kind="instruction.source",
            provenance=context.provenance(f"{locator} recipe"),
            agent=context.agent,
            raw=recipe,
            ts_utc=ts,
            ts_precision=precision,
            ts_source="created_at" if ts else None,
            actor="system",
            payload={
                "text": "\n".join(
                    part
                    for part in (_text(recipe.get("instructions")), _text(recipe.get("prompt")))
                    if part
                ),
                "scope": "session",
                "origin": "recipe",
                "title": _text(recipe.get("title")) or None,
                "instructions": [{"path": context.original_path, "scope": "session"}],
            },
            **common,
        )

    archived, archived_precision, archived_note = normalise_ts(values.get("archived_at"))
    if archived:
        yield Event(
            kind="session.end",
            provenance=context.provenance(f"{locator} archived"),
            agent=context.agent,
            raw=values,
            ts_utc=archived,
            ts_precision=archived_precision,
            ts_source="archived_at",
            actor="system",
            payload={"text": "this session was archived"},
            parse_problem=archived_note,
            **common,
        )


def _threads(
    context: ParseContext, connection: sqlite3.Connection, listed: dict[str, Table]
) -> tuple[list[Event], dict[str, dict[str, Any]]]:
    """The thread rows, which are a conversation the product groups messages under.

    A separate table from `sessions` and added by a later migration, with its own name,
    working directory and archive time. Read as a conversation for the same reason a session
    is: its messages are in `thread_messages` and carry no directory of their own.
    """
    table = listed.get("threads")
    events: list[Event] = []
    headers: dict[str, dict[str, Any]] = {}
    if table is None:
        return events, headers

    for locator, values, problem in rows_of(connection, table):
        if problem:
            events.append(_broken_row(context, locator, values, problem))
            continue
        thread_id = _text(values.get("id"))
        header = _header(thread_id, _text(values.get("working_dir")), {})
        if thread_id:
            headers[thread_id] = header
        ts, precision, note = normalise_ts(values.get("created_at"))
        events.append(
            Event(
                kind="session.start",
                provenance=context.provenance(locator),
                agent=context.agent,
                raw=values,
                ts_utc=ts,
                ts_precision=precision,
                ts_source="created_at" if ts else None,
                actor="system",
                payload={
                    "text": _text(values.get("name")) or "a thread",
                    # Which container this conversation is, because the two live in one
                    # database and an analyst counting conversations has to know.
                    "container": "thread",
                },
                parse_problem=note,
                **_common(context, header),
            )
        )
        archived, archived_precision, archived_note = normalise_ts(values.get("archived_at"))
        if archived:
            events.append(
                Event(
                    kind="session.end",
                    provenance=context.provenance(f"{locator} archived"),
                    agent=context.agent,
                    raw=values,
                    ts_utc=archived,
                    ts_precision=archived_precision,
                    ts_source="archived_at",
                    actor="system",
                    payload={"text": "this thread was archived", "container": "thread"},
                    parse_problem=archived_note,
                    **_common(context, header),
                )
            )
    return events, headers


def _rows_as_messages(
    context: ParseContext,
    connection: sqlite3.Connection,
    table: Table | None,
    headers: dict[str, dict[str, Any]],
    keys: tuple[str, ...],
) -> Iterator[Event]:
    """One message table, row by row, as the events each row's content blocks call for.

    Both message tables have the same five columns that matter, `role`, `content_json`,
    `created_timestamp`, `metadata_json` and `message_id`, so one reading serves both. Which
    column names the conversation differs, which is what `keys` is for.
    """
    if table is None:
        return
    for locator, values, problem in rows_of(connection, table):
        if problem:
            yield _broken_row(context, locator, values, problem)
            continue
        session_id = next((_text(values.get(key)) for key in keys if values.get(key)), "")
        header = headers.get(session_id) or _header(session_id, "", {})
        content, content_problem = _array(values.get("content_json"))
        metadata, metadata_problem = _document(values.get("metadata_json"))
        message = {
            "id": values.get("message_id"),
            "role": values.get("role"),
            "created": values.get("created_timestamp"),
            "content": content if content is not None else values.get("content_json"),
            "metadata": metadata or {},
        }
        problems = [part for part in (content_problem, metadata_problem) if part]
        if content is None:
            # The column that holds the turn will not parse. The row is still the record
            # that a turn happened, with whatever the column held, so it is kept whole.
            ts, precision, note = _message_time(values.get("created_timestamp"))
            yield unparsed(
                context.provenance(locator),
                context.agent,
                values,
                " ".join([*problems, *([note] if note else [])]),
                ts_utc=ts,
                ts_precision=precision,
                ts_source="created_timestamp" if ts else None,
                **_common(context, header),
            )
            continue
        yield from _message_events(context, locator, message, header, problems)


# ------------------------------------------------------------------ the legacy file


def _legacy_file(context: ParseContext) -> Iterator[Event]:
    """One pre-1.10.0 session file: a metadata line, then a message per line.

    The session id is the file's stem, which is what the product uses: `load_session` is
    handed the file stem as the session name and overwrites whatever the metadata line says
    with it.
    """
    session_id = context.local_path.stem

    header = _header(session_id, "", {})
    first = True
    for line in iter_lines(context.local_path):
        if not line.ok:
            # A first line that is not a JSON object is the header the product would have
            # read, so the file is one it cannot load and no later line becomes the header
            # instead: it reads the first line and only the first line as the metadata.
            first = False
            yield _broken_line(context, line, header)
            continue
        record = line.value
        if first:
            first = False
            if not _looks_like_message(record):
                events, header = _legacy_header(context, line, record, session_id)
                yield from events
                continue
            # A file whose first line is a message has no header, which is a file the
            # product itself refuses to load. Said once, on the message the line is.
            yield from _message_events(context, line.locator, record, header, [NO_HEADER])
            continue
        yield from _message_events(context, line.locator, record, header, [])


def _legacy_header(
    context: ParseContext, line: Line, record: dict[str, Any], session_id: str
) -> tuple[list[Event], dict[str, Any]]:
    """The metadata line, as a session start and as the header the messages inherit."""
    header = _header(
        session_id,
        _text(record.get("working_dir")),
        _mapping(record.get("extension_data")),
    )
    ts, precision, note = normalise_ts(record.get("created_at"))
    model = _model(
        _text(record.get("provider_name")),
        _mapping(record.get("model_config")),
    )
    problems = [part for part in (note, None if ts else NO_SESSION_TIME) if part]
    event = Event(
        kind="session.start",
        provenance=context.provenance(line.locator),
        agent=context.agent,
        raw=record,
        ts_utc=ts,
        ts_precision=precision,
        ts_source="created_at" if ts else None,
        actor="system",
        payload={
            # `description` is the older spelling of the name, and the product still reads
            # it as an alias for it.
            "text": _text(record.get("name")) or _text(record.get("description")) or "a session",
            "models": [{"model": model}] if model else None,
            "session_kind": _text(record.get("session_type")) or None,
            "goose_mode": _text(record.get("goose_mode")) or None,
            "extensions": header["extensions"] or None,
            "schedule_id": _text(record.get("schedule_id")) or None,
            "message_count": record.get("message_count"),
            # The pre-1.10.0 file kept the token counts flat rather than nested, which is
            # why the product migrates them into a usage object when it reads one.
            "tokens": {
                "input": record.get("input_tokens"),
                "output": record.get("output_tokens"),
                "total": record.get("total_tokens"),
            },
        },
        parse_problem=" ".join(problems) or None,
        **_common(context, header),
    )
    return [event], header


def _broken_line(context: ParseContext, line: Line, header: dict[str, Any]) -> Event:
    """A line that is not a JSON object, kept with the text the reader choked on."""
    return unparsed(
        context.provenance(line.locator),
        context.agent,
        {"line": line.text, "value": line.value},
        line.problem or "the line is not a JSON object",
        payload={"text": line.text},
        **_common(context, header),
    )


# --------------------------------------------------------------------- one message


def _message_events(
    context: ParseContext,
    locator: str,
    message: dict[str, Any],
    header: dict[str, Any],
    problems: list[str],
) -> Iterator[Event]:
    """One message, as one event per content block.

    One event per block, with the block's index in the locator, because the event id is
    derived from provenance and two blocks of the same kind in one message would otherwise
    collapse into one event and the turn would lose a call.
    """
    common = _common(context, header)
    role = _text(message.get("role"))
    ts, precision, note = _message_time(message.get("created"))
    metadata = _mapping(message.get("metadata"))
    shown = metadata.get("userVisible")
    notes = [*problems, *([note] if note else [])]
    if shown is False:
        notes.append(NOT_SHOWN)
    timing: dict[str, Any] = {
        "ts_utc": ts,
        "ts_precision": precision,
        "ts_source": "created" if ts else None,
    }

    if role not in ("user", "assistant"):
        yield unparsed(
            context.provenance(locator),
            context.agent,
            message,
            " ".join([*notes, UNKNOWN_ROLE.format(role=role)]),
            ts_utc=ts,
            ts_precision=precision,
            ts_source="created" if ts else None,
            payload={"text": text_of(message.get("content"))},
            **common,
        )
        return

    blocks = message.get("content")
    if not isinstance(blocks, list) or not blocks:
        # A turn that carried nothing at all is still a turn: the record says the model was
        # asked and answered with nothing, which is different from no record.
        yield unparsed(
            context.provenance(locator),
            context.agent,
            message,
            " ".join([*notes, "this message carries no content block"]),
            ts_utc=ts,
            ts_precision=precision,
            ts_source="created" if ts else None,
            **common,
        )
        return

    for index, block in enumerate(blocks):
        where = f"{locator} content:{index}"
        if not isinstance(block, dict):
            yield unparsed(
                context.provenance(where),
                context.agent,
                block,
                " ".join([*notes, "this content block is not an object"]),
                **timing,
                **common,
            )
            continue
        yield from _block_events(context, where, block, role, metadata, header, notes, timing)


def _block_events(
    context: ParseContext,
    where: str,
    block: dict[str, Any],
    role: str,
    metadata: dict[str, Any],
    header: dict[str, Any],
    notes: list[str],
    timing: dict[str, Any],
) -> Iterator[Event]:
    """One content block, as the event its own type calls for."""
    kind = _text(block.get("type"))
    common = _common(context, header)
    note = " ".join(notes) or None
    models = _models_of(metadata)

    if kind == "text":
        yield from _text_block(context, where, block, role, metadata, note, models, timing, common)
        return

    if kind == "thinking":
        yield Event(
            kind="assistant.thinking",
            provenance=context.provenance(where),
            agent=context.agent,
            raw=block,
            actor="assistant",
            payload={"text": _text(block.get("thinking"))},
            parse_problem=note,
            **timing,
            **common,
        )
        return

    if kind == "redactedThinking":
        # The provider returned the reasoning encrypted. The block is the record that there
        # was reasoning here, and its content is not readable on the endpoint at all.
        yield Event(
            kind="assistant.thinking",
            provenance=context.provenance(where),
            agent=context.agent,
            raw=block,
            actor="assistant",
            payload={"text": "", "redacted": True},
            parse_problem=" ".join(
                filter(
                    None,
                    [
                        note,
                        "the provider returned this reasoning redacted, so the record is "
                        "that there was reasoning and not what it said",
                    ],
                )
            ),
            **timing,
            **common,
        )
        return

    if kind in ("image", "document"):
        yield from _attachment(context, where, block, kind, role, note, timing, common)
        return

    if kind == "toolRequest":
        yield from _tool_request(context, where, block, header, note, timing, common)
        return

    if kind == "toolResponse":
        yield from _tool_response(context, where, block, note, timing, common)
        return

    if kind == "toolConfirmationRequest":
        yield _confirmation(
            context,
            where,
            block,
            _text(block.get("toolName")),
            "asked",
            note,
            timing,
            common,
        )
        return

    if kind == "actionRequired":
        yield from _action_required(context, where, block, note, timing, common)
        return

    if kind in ("systemNotification", "error"):
        what = (
            f"system notification of type {_text(block.get('notificationType')) or 'unknown'}"
            if kind == "systemNotification"
            else f"provider error of kind {_text(block.get('kind')) or 'unknown'}"
        )
        yield unparsed(
            context.provenance(where),
            context.agent,
            block,
            " ".join(filter(None, [note, NO_KIND.format(what=what)])),
            payload={"text": _text(block.get("msg")) or _text(block.get("message"))},
            **timing,
            **common,
        )
        return

    # A block type the vendor added after this parser was written. Kept with its time and
    # its session, so it sorts into the timeline where it belongs and an analyst can see
    # that something was here.
    yield unparsed(
        context.provenance(where),
        context.agent,
        block,
        " ".join(filter(None, [note, f"content block type {kind!r} is not one this parser maps"])),
        payload={"text": text_of(block)},
        **timing,
        **common,
    )


def _text_block(
    context: ParseContext,
    where: str,
    block: dict[str, Any],
    role: str,
    metadata: dict[str, Any],
    note: str | None,
    models: list[dict[str, Any]] | None,
    timing: dict[str, Any],
    common: dict[str, Any],
) -> Iterator[Event]:
    """A text block, which is the turn itself.

    A user-role text block is the prompt, except where the message is marked `turnContext`.
    The vendor calls that "a per-turn context event appended by the agent", so it is text
    the harness put into the conversation rather than something somebody typed, and reading
    it as a prompt would answer "what did the user ask" with the agent's own words.
    """
    text = _text(block.get("text"))
    flags = {
        "user_visible": metadata.get("userVisible"),
        "agent_visible": metadata.get("agentVisible"),
        # A steer is a message injected into a run that was already going, which is a user
        # interrupting rather than a user starting a turn.
        "steer": metadata.get("steer") or None,
    }
    if role == "assistant":
        yield Event(
            kind="assistant.text",
            provenance=context.provenance(where),
            agent=context.agent,
            raw=block,
            actor="assistant",
            payload={"text": text, "models": models, **flags},
            parse_problem=note,
            **timing,
            **common,
        )
        return
    if metadata.get("turnContext"):
        yield Event(
            kind="instruction.source",
            provenance=context.provenance(where),
            agent=context.agent,
            raw=block,
            actor="system",
            payload={
                "text": text,
                "scope": "session",
                "origin": "turn_context",
                "instructions": [{"path": context.original_path, "scope": "session"}],
                **flags,
            },
            parse_problem=" ".join(
                filter(
                    None,
                    [
                        note,
                        "the vendor calls this a per-turn context event appended by the "
                        "agent, so it is text the harness added and not a prompt somebody "
                        "typed",
                    ],
                )
            ),
            **timing,
            **common,
        )
        return
    yield Event(
        kind="user.prompt",
        provenance=context.provenance(where),
        agent=context.agent,
        raw=block,
        actor="user",
        payload={"text": text, **flags},
        parse_problem=note,
        **timing,
        **common,
    )


def _attachment(
    context: ParseContext,
    where: str,
    block: dict[str, Any],
    kind: str,
    role: str,
    note: str | None,
    timing: dict[str, Any],
    common: dict[str, Any],
) -> Iterator[Event]:
    """An image or a document carried inside a turn.

    Both are base64 in a `data` field with a `mimeType` beside it, and a document may carry
    a `name`. The turn is the event; the bytes stay in raw. A document's payload is not read
    any further, which the event says: what is inside a base64 attachment is a file format
    question and this module has read none of them.
    """
    name = _text(block.get("name"))
    mime = _text(block.get("mimeType"))
    described = f"[{kind}: {name or mime or 'no type given'}]"
    yield Event(
        kind="assistant.text" if role == "assistant" else "user.prompt",
        provenance=context.provenance(where),
        agent=context.agent,
        raw=block,
        actor="assistant" if role == "assistant" else "user",
        payload={
            "text": described,
            "attachment": {"kind": kind, "name": name or None, "mime_type": mime or None},
        },
        parse_problem=" ".join(
            filter(None, [note, NO_KIND.format(what=f"{kind} attachment's own content")])
        ),
        **timing,
        **common,
    )


def _tool_request(
    context: ParseContext,
    where: str,
    block: dict[str, Any],
    header: dict[str, Any],
    note: str | None,
    timing: dict[str, Any],
    common: dict[str, Any],
) -> Iterator[Event]:
    """A tool call: the call, the MCP claim where the session supports one, and its facet.

    The call itself is a result: the vendor serialises it as `{"status": "success", "value":
    {"name": ..., "arguments": ...}}` or as `{"status": "error", "error": ...}`, the second
    being a call the model produced that could not be built. Both are calls that happened
    and the error one is the more interesting of the two.
    """
    call_id = _text(block.get("id"))
    call = _mapping(block.get("toolCall"))
    status = _text(call.get("status"))
    value = _mapping(call.get("value"))
    name = _text(value.get("name"))
    arguments = _mapping(value.get("arguments"))
    extension, tool = _tool_name_parts(name)
    failed = status == "error"

    facet_kind, facet = _facet(tool, arguments, header)
    yield Event(
        kind="tool.call",
        provenance=context.provenance(where),
        agent=context.agent,
        raw=block,
        actor="assistant",
        payload={
            "tool": name or None,
            "tool_use_id": call_id or None,
            "input": arguments or None,
            "text": name or _text(call.get("error")),
            # The extension half of the advertised name, kept whether or not anything here
            # knows what that extension was. It is how a call is tied back to the server or
            # the built-in that served it.
            "extension": extension,
            "is_error": failed or None,
            "error": _text(call.get("error")) or None if failed else None,
            **facet,
        },
        parse_problem=" ".join(
            filter(
                None,
                [
                    note,
                    "the product recorded this tool call as an error, which is a call the "
                    "model produced that could not be built into a request"
                    if failed
                    else None,
                ],
            )
        )
        or None,
        **timing,
        **common,
    )

    if extension and extension in header["servers"]:
        # The session's own enabled-extensions state names this extension as a server, so
        # the call left the agent's process for one.
        yield Event(
            kind="mcp.call",
            provenance=context.provenance(where),
            agent=context.agent,
            raw=block,
            actor="assistant",
            payload={
                "text": name,
                "tool": name,
                "tool_use_id": call_id or None,
                "mcp": [{"server": extension, "tool": tool}],
                "input": arguments or None,
            },
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
            payload={"tool": name, "tool_use_id": call_id or None, **facet},
            parse_problem=note,
            **timing,
            **common,
        )


def _tool_response(
    context: ParseContext,
    where: str,
    block: dict[str, Any],
    note: str | None,
    timing: dict[str, Any],
    common: dict[str, Any],
) -> Iterator[Event]:
    """A tool result, which the vendor serialises the same two ways as a call."""
    call_id = _text(block.get("id"))
    result = _mapping(block.get("toolResult"))
    status = _text(result.get("status"))
    value = _mapping(result.get("value"))
    output = "\n".join(
        _text(item.get("text")) or text_of(item)
        for item in value.get("content") or []
        if isinstance(item, dict)
    ).strip()
    failed = status == "error" or bool(value.get("isError"))
    error = _text(result.get("error")) if status == "error" else None
    yield Event(
        kind="tool.result",
        provenance=context.provenance(where),
        agent=context.agent,
        raw=block,
        actor="tool",
        payload={
            "tool_use_id": call_id or None,
            "output": output or error,
            "text": output or error,
            "is_error": failed,
            "error": error,
        },
        parse_problem=note,
        **timing,
        **common,
    )


def _action_required(
    context: ParseContext,
    where: str,
    block: dict[str, Any],
    note: str | None,
    timing: dict[str, Any],
    common: dict[str, Any],
) -> Iterator[Event]:
    """A block the agent is waiting on somebody for, of four kinds the vendor tags.

    Two of them are a permission decision about a tool, which is what this suite exists to
    record. The other two are an elicitation, a structured question the harness puts to the
    user and its answer, and the event model has no kind for those.
    """
    data = _mapping(block.get("data"))
    action = _text(data.get("actionType"))
    if action == "toolConfirmation":
        yield _confirmation(
            context, where, block, _text(data.get("toolName")), "asked", note, timing, common
        )
        return
    if action == "toolConfirmationResponse":
        # The answer, in the product's own words: always_allow, allow_once, cancel,
        # deny_once or always_deny. Carried verbatim rather than collapsed to yes or no,
        # because "always" is a decision about every later call as well as this one.
        yield _confirmation(
            context,
            where,
            block,
            _text(data.get("id")),
            _text(data.get("permission")) or "unknown",
            note,
            timing,
            common,
        )
        return
    yield unparsed(
        context.provenance(where),
        context.agent,
        block,
        " ".join(
            filter(None, [note, NO_KIND.format(what=f"action of type {action or 'unknown'}")])
        ),
        payload={"text": _text(data.get("message")) or text_of(data)},
        **timing,
        **common,
    )


def _confirmation(
    context: ParseContext,
    where: str,
    block: dict[str, Any],
    subject: str,
    decision: str,
    note: str | None,
    timing: dict[str, Any],
    common: dict[str, Any],
) -> Event:
    """A permission decision about one tool call, asked or answered."""
    return Event(
        kind="permission.decision",
        provenance=context.provenance(where),
        agent=context.agent,
        raw=block,
        # The request comes from the harness and the answer from the person at the
        # keyboard, and the difference is which of the two is being recorded.
        actor="system" if decision == "asked" else "user",
        payload={
            "permissions": [{"decision": decision, "subject": subject, "mode": None}],
            "text": f"{decision}: {subject}" if subject else decision,
        },
        parse_problem=note,
        **timing,
        **common,
    )


# -------------------------------------------------------------------------- facets


def _facet(
    tool: str, arguments: dict[str, Any], header: dict[str, Any]
) -> tuple[str | None, dict[str, Any]]:
    """The facet a built-in developer tool produces, or nothing for a tool this does not know.

    Keyed on the unqualified tool name, because the product advertises the same tool both
    with and without its extension prefix depending on how the extension was registered.
    """
    if tool in _COMMAND_TOOLS:
        command = _text(arguments.get("command"))
        if not command:
            return None, {}
        return "command.exec", {
            "commands": [
                {
                    "command": command,
                    "executable": first_word(command),
                    # The tool runs in the session's working directory, which the tool's own
                    # arguments never name.
                    "cwd": header["project_path"] or None,
                }
            ]
        }
    if tool in _WRITE_TOOLS:
        path = _text(arguments.get("path"))
        if not path:
            return None, {}
        content = arguments.get("content")
        return "file.write", {
            "files": [
                {
                    "path": path,
                    "operation": "write",
                    "bytes": len(str(content).encode("utf-8")) if content else None,
                }
            ]
        }
    if tool in _READ_TOOLS:
        path = _text(arguments.get("path"))
        if not path:
            return None, {}
        return "file.read", {"files": [{"path": path, "operation": "read"}]}
    if tool == _IMAGE_TOOL:
        # The vendor documents this argument as a local file path or an http(s) URL, so
        # which of the two it is decides what the call did.
        source = _text(arguments.get("source"))
        if not source:
            return None, {}
        if source.startswith(("http://", "https://")):
            return "network.request", {
                "network": [{"url": source, "host": urlsplit(source).netloc}]
            }
        return "file.read", {"files": [{"path": source, "operation": "read"}]}
    return None, {}


# ------------------------------------------------------------------------- helpers


def _header(session_id: str, working_dir: str, extension_data: dict[str, Any]) -> dict[str, Any]:
    """What every record of one conversation inherits from its header row or line."""
    extensions = _extensions(extension_data)
    return {
        "session_id": session_id or None,
        "project_path": working_dir,
        "extensions": extensions,
        "servers": frozenset(
            entry["name"] for entry in extensions if entry["kind"] in SERVER_KINDS and entry["name"]
        ),
    }


def _common(context: ParseContext, header: dict[str, Any]) -> dict[str, Any]:
    return {
        "user": context.user,
        "host": context.host,
        "session_id": header["session_id"],
        "project_path": header["project_path"] or None,
    }


def _extensions(extension_data: Any) -> list[dict[str, Any]]:
    """The extensions enabled for one conversation, from its own extension state.

    Nested twice: the state is stored under a versioned key inside `extension_data`, and the
    list is under `extensions` inside that. A shape that is not the one the vendor writes
    returns nothing rather than a partial list, because what this decides is whether a tool
    call went to an MCP server, and a wrong answer there is worse than no answer. The list
    itself also goes onto the session event, where it is the inventory of what that
    conversation could reach.
    """
    if not isinstance(extension_data, dict):
        return []
    state = extension_data.get(ENABLED_EXTENSIONS_KEY)
    if not isinstance(state, dict):
        return []
    out = []
    for entry in state.get("extensions") or []:
        if not isinstance(entry, dict):
            continue
        out.append(
            {
                "name": _text(entry.get("name")),
                "kind": _text(entry.get("type")),
                "uri": _text(entry.get("uri")) or None,
                "cmd": _text(entry.get("cmd")) or None,
            }
        )
    return out


def _tool_name_parts(name: str) -> tuple[str | None, str]:
    """An advertised tool name split at the vendor's separator.

    `split_once` in the product's own words: the first `__` separates the extension from
    the tool, and a name with none is a tool an extension registered unprefixed, whose
    owner is only in metadata this store does not carry.
    """
    extension, separator, tool = name.partition("__")
    return (extension, tool) if separator else (None, name)


def _message_time(value: Any) -> tuple[str | None, Any, str | None]:
    """A message's own clock, which the vendor states is epoch seconds."""
    return normalise_ts(value)


def _models_of(metadata: dict[str, Any]) -> list[dict[str, Any]] | None:
    """The model a turn was produced by, and what it cost, from the message's metadata."""
    inference = _mapping(metadata.get("inference"))
    usage = _mapping(metadata.get("usage"))
    model = _model(
        _text(inference.get("provider")),
        {
            "model_name": _text(inference.get("resolvedModel"))
            or _text(inference.get("requestedModel"))
        },
    )
    if not model and not usage:
        return None
    return [
        {
            # None rather than an empty string where the metadata records a cost and no
            # model, because the facet is keyed on the model and a blank one would index a
            # turn under a name nobody can search for.
            "model": model or None,
            "input_tokens": usage.get("inputTokens"),
            "output_tokens": usage.get("outputTokens"),
            "cost": usage.get("cost"),
        }
    ]


def _model(provider: str, model_config: Any) -> str:
    """A model reference as provider and name, which is how this product names one."""
    name = ""
    if isinstance(model_config, dict):
        name = _text(model_config.get("model_name"))
    if provider and name:
        return f"{provider}/{name}"
    return name or provider


def _looks_like_message(record: dict[str, Any]) -> bool:
    """Whether a legacy file's first line is a message rather than the session header."""
    return "role" in record and "content" in record


def _broken_row(context: ParseContext, locator: str, values: dict[str, Any], problem: str) -> Event:
    return unparsed(
        context.provenance(locator),
        context.agent,
        values or None,
        problem,
        user=context.user,
        host=context.host,
    )


def _document(value: Any) -> tuple[dict[str, Any] | None, str | None]:
    """The JSON in a text column, or the reason it is not an object."""
    if isinstance(value, dict):
        return value, None
    if not isinstance(value, str) or not value.strip():
        return None, None
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        return None, f"a column holding JSON is not valid JSON: {exc}"
    if not isinstance(parsed, dict):
        return None, f"a column holding JSON holds a {type(parsed).__name__}, not an object"
    return parsed, None


def _array(value: Any) -> tuple[list[Any] | None, str | None]:
    """The JSON array a content column holds, or the reason it is not one."""
    if isinstance(value, list):
        return value, None
    if not isinstance(value, str) or not value.strip():
        return None, "the content column is empty"
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        return None, f"the content column is not valid JSON: {exc}"
    if not isinstance(parsed, list):
        return None, f"the content column holds a JSON {type(parsed).__name__}, not an array"
    return parsed, None


def _mapping(value: Any) -> dict[str, Any]:
    """A nested object, or an empty one.

    A field the vendor changes the shape of has to cost the reading of that field and not
    the record it is in, which is what this makes cheap enough to do at every level.
    """
    return value if isinstance(value, dict) else {}


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ("" if value is None else str(value))


__all__ = [
    "ENABLED_EXTENSIONS_KEY",
    "LEGACY_SESSIONS",
    "MAPPED",
    "NOT_SHOWN",
    "NO_HEADER",
    "NO_KIND",
    "NO_SESSION_TIME",
    "SERVER_KINDS",
    "STORES",
    "UNKNOWN_ROLE",
    "GooseParser",
]
