"""Parse Zed's agent thread store, which keeps its conversations compressed.

This is the store that motivated raising the project's Python floor (ADR 0024). Zed writes
each thread as one row whose content is a zstd frame in a BLOB column, which makes it the
worst shape a store can have for an examination: `strings` over the file finds nothing, a
keyword search matches nothing, and a reader that recorded the column by hash would leave a
case saying Zed held some opaque blobs. An analyst reading that concludes the agent was not
used. With zstd in the standard library the frame is decompressed in the store reader, so
the JSON inside reaches this parser like any other document.

Sources, both fetched and read: the table and the compression,
https://raw.githubusercontent.com/zed-industries/zed/main/crates/agent/src/db.rs
and the record shapes inside the compressed document,
https://raw.githubusercontent.com/zed-industries/zed/main/crates/agent/src/thread.rs

The row carries the header: the thread id, the title (the column is called `summary`), the
created and updated times, the parent thread for a fork, and the workspace folders the
thread was opened against. `created_at` arrived in a later migration, so an older row has
none, and this parser says which of the two times it used rather than presenting the last
change as the beginning.

**A Zed thread has no per-turn timestamps.** The store keeps one time for the thread and
none for the messages inside it, so every turn here is an event with no time of its own.
That is a limit of the evidence and not of the reading: an analyst placing a Zed turn on a
timeline has the thread's window and the order of the messages, and nothing finer. Inventing
a time per turn from the thread's would put fabricated moments on a timeline, which is worse
than a gap.

Two record shapes are mapped as far as the vendor's types go and no further. A tool use and
a tool result are carried whole, in the payload and in raw, with a note saying that their
inner shape is defined in another crate this parser has not read. They are on the timeline
and searchable; what is not claimed is which file or command they touched. Guessing that
would produce facets an analyst would query and trust.

Serde's default external tagging applies throughout, because none of these types carries a
tag attribute: a user message is `{"User": {...}}`, its text is `{"Text": "..."}`, and the
unit variant that marks a resumed thread is the bare string `"Resume"`.
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
    BLOB_NOTE,
    StoreError,
    describe,
    open_store,
    rows_of,
    sidecar,
    tables,
)

# The one table whose schema and contents this module has read.
MAPPED = ("threads",)

# What the inner shape of a tool record is not claimed to be. Said on the event rather than
# only in this file, because an analyst reading a case has the event and not the source.
_TOOL_NOTE = (
    "Zed defines the inner shape of a tool use and its result in a crate this parser has "
    "not read, so the record is carried whole and no file, command or destination is "
    "claimed from it"
)


class ZedParser:
    """Zed's threads.db, read against the vendor's schema."""

    name = "zed"

    _STORES = frozenset({"zed.threads_db"})

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
                yield from _threads(context, connection, listed)
                for name, table in sorted(listed.items()):
                    if name not in MAPPED:
                        yield from rows_as_events(context, connection, table)
        except StoreError as exc:
            yield describe(context, str(exc))


def _threads(
    context: ParseContext, connection: sqlite3.Connection, listed: dict[str, Any]
) -> Iterator[Event]:
    table = listed.get("threads")
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
        yield from _thread(context, locator, values)


def _thread(context: ParseContext, locator: str, values: dict[str, Any]) -> Iterator[Event]:
    session_id = _text(values.get("id")) or None
    opened = folders(values.get("folder_paths"), values.get("folder_paths_order"))
    common: dict[str, Any] = {
        "user": context.user,
        "host": context.host,
        "session_id": session_id,
        # The first of the workspace folders in the order the person opened them, which the
        # second column restores. All of them are in the payload: a thread opened against
        # two folders belongs to both, and the event model has one project_path.
        "project_path": opened[0] if opened else None,
    }

    created, created_precision, created_note = normalise_ts(values.get("created_at"))
    updated, updated_precision, updated_note = normalise_ts(values.get("updated_at"))
    ts: str | None
    precision: TsPrecision
    source: str
    note: str | None
    if created:
        ts, precision, source = created, created_precision, "created_at"
        note = created_note
    else:
        # created_at arrived in a later migration, so an older row has none. Using the last
        # change instead is stated rather than quietly substituted: it is when the thread
        # was last touched, not when it began.
        ts, precision, source = updated, updated_precision, "updated_at"
        note = " ".join(
            part
            for part in (
                updated_note,
                "this row has no created_at, which Zed added in a later migration, so the "
                "time on this event is when the thread was last changed and not when it "
                "started",
            )
            if part
        )

    document, document_problem = _document(values.get("data"))
    header = {key: value for key, value in values.items() if key != "data"}
    if document is not None:
        header["data"] = {key: item for key, item in document.items() if key != "messages"}

    yield Event(
        kind="session.start",
        provenance=context.provenance(locator),
        agent=context.agent,
        raw=header,
        ts_utc=ts,
        ts_precision=precision,
        ts_source=source if ts else None,
        actor="system",
        payload={
            "text": _text(values.get("summary")) or _text((document or {}).get("title")),
            "updated_at": updated,
            "folder_paths": opened or None,
            # A fork, or a subagent thread: its turns continue from another row.
            "parent_session": _text(values.get("parent_id")) or None,
            "models": _models(document),
            "profile": _text((document or {}).get("profile")) or None,
            "thinking_enabled": (document or {}).get("thinking_enabled"),
            "thinking_effort": (document or {}).get("thinking_effort"),
            "tokens": (document or {}).get("cumulative_token_usage"),
            "detailed_summary": _text((document or {}).get("detailed_summary")) or None,
            # The worktrees the thread opened against, as the agent recorded them at the
            # start. Kept because it says which working copies were in scope even when the
            # folders have since moved.
            "initial_project_snapshot": (document or {}).get("initial_project_snapshot"),
            "subagent_context": (document or {}).get("subagent_context"),
            "messages": len((document or {}).get("messages") or []),
        },
        parse_problem=" ".join(part for part in (note, document_problem) if part) or None,
        **common,
    )

    if document is None:
        return
    for index, message in enumerate(document.get("messages") or []):
        yield from _message(context, f"{locator} message:{index}", message, common)


def _message(
    context: ParseContext, where: str, message: Any, common: dict[str, Any]
) -> Iterator[Event]:
    """One message of a thread.

    No timestamp on any of these: Zed keeps one time for the thread and none for the turns
    inside it. Their order is the evidence about sequence, and the thread's window is the
    evidence about when.
    """
    timing: dict[str, Any] = {"ts_utc": None, "ts_precision": "absent", "ts_source": None}

    # The unit variant serialises as a bare string, which is the one shape here that is not
    # an object.
    if message == "Resume":
        yield Event(
            kind="config.snapshot",
            provenance=context.provenance(where),
            agent=context.agent,
            raw=message,
            actor="system",
            payload={"text": "the thread was resumed here"},
            **timing,
            **common,
        )
        return

    tag, body = _tagged(message)
    if tag == "User":
        yield from _user(context, where, body, timing, common)
        return
    if tag == "Agent":
        yield from _agent(context, where, body, timing, common)
        return
    if tag == "Compaction":
        # CompactionInfo is itself an enum: a Summary wrapping a string, or a
        # ProviderNative carrying the provider's own items. Only the first has text a
        # person can read; the second is rendered rather than interpreted.
        inner_tag, _ = _tagged(body)
        yield Event(
            kind="session.end",
            provenance=context.provenance(where),
            agent=context.agent,
            raw=body,
            actor="system",
            payload={
                "text": _text(_untagged(body)) if inner_tag == "Summary" else text_of(body),
                "compaction": True,
                "compaction_kind": inner_tag,
            },
            **timing,
            **common,
        )
        return

    yield unparsed(
        context.provenance(where),
        context.agent,
        message,
        f"message shape {tag!r} is not one of the four the vendor's enum defines",
        **timing,
        **common,
    )


def _user(
    context: ParseContext,
    where: str,
    body: dict[str, Any],
    timing: dict[str, Any],
    common: dict[str, Any],
) -> Iterator[Event]:
    """A user turn, which is one prompt however many pieces the vendor stores it in."""
    texts: list[str] = []
    mentions: list[dict[str, Any]] = []
    images = 0
    unknown: list[Any] = []
    for item in body.get("content") or []:
        tag, inner = _tagged(item)
        if tag == "Text":
            texts.append(_text(_untagged(item)))
        elif tag == "Mention":
            # A URI rather than a path: Zed's mentions address a file, a symbol, a rule or
            # another thread, and which of those it is comes from a type in another crate.
            # Carried as the vendor wrote it rather than read as a file path.
            mentions.append(
                {"uri": _text(inner.get("uri")), "content": _text(inner.get("content"))}
            )
        elif tag == "Image":
            images += 1
        else:
            unknown.append(item)

    yield Event(
        kind="user.prompt",
        provenance=context.provenance(where),
        agent=context.agent,
        raw=body,
        actor="user",
        payload={
            "text": "\n".join(text for text in texts if text),
            "mentions": mentions or None,
            "images": images or None,
            "message_id": _text(body.get("id")) or None,
        },
        parse_problem=(
            f"{len(unknown)} content item(s) are not one of the three shapes the vendor's "
            "enum defines and are in raw"
        )
        if unknown
        else None,
        **timing,
        **common,
    )


def _agent(
    context: ParseContext,
    where: str,
    body: dict[str, Any],
    timing: dict[str, Any],
    common: dict[str, Any],
) -> Iterator[Event]:
    """An agent turn: text, reasoning, and the tools it called."""
    for index, item in enumerate(body.get("content") or []):
        tag, inner = _tagged(item)
        at = f"{where} content:{index}"
        if tag == "Text":
            yield Event(
                kind="assistant.text",
                provenance=context.provenance(at),
                agent=context.agent,
                raw=item,
                actor="assistant",
                payload={"text": _text(_untagged(item))},
                **timing,
                **common,
            )
        elif tag == "Thinking":
            yield Event(
                kind="assistant.thinking",
                provenance=context.provenance(at),
                agent=context.agent,
                raw=item,
                actor="assistant",
                payload={
                    "text": _text(inner.get("text")),
                    "signature": _text(inner.get("signature")) or None,
                },
                **timing,
                **common,
            )
        elif tag == "RedactedThinking":
            yield Event(
                kind="assistant.thinking",
                provenance=context.provenance(at),
                agent=context.agent,
                raw=item,
                actor="assistant",
                # Redacted means the provider withheld the reasoning, which is a different
                # thing from the model not having reasoned, and the difference belongs in
                # the case.
                payload={"text": "", "redacted": True},
                parse_problem="the provider withheld this reasoning, so the case holds the "
                "fact of it and not its content",
                **timing,
                **common,
            )
        elif tag == "ToolUse":
            yield Event(
                kind="tool.call",
                provenance=context.provenance(at),
                agent=context.agent,
                raw=item,
                actor="assistant",
                payload={
                    "tool": _text(inner.get("name")) or None,
                    "tool_use_id": _text(inner.get("id")) or None,
                    "input": inner.get("input"),
                    "text": _text(inner.get("name")),
                },
                parse_problem=_TOOL_NOTE,
                **timing,
                **common,
            )
        else:
            yield unparsed(
                context.provenance(at),
                context.agent,
                item,
                f"content shape {tag!r} is not one of the four the vendor's enum defines",
                **timing,
                **common,
            )

    results = body.get("tool_results")
    if isinstance(results, dict):
        # Keyed by the tool use id, which is how a result is paired with its call.
        for call_id in sorted(results):
            yield Event(
                kind="tool.result",
                provenance=context.provenance(f"{where} result:{call_id}"),
                agent=context.agent,
                raw=results[call_id],
                actor="tool",
                payload={
                    "tool_use_id": call_id,
                    "output": text_of(results[call_id]),
                    "text": text_of(results[call_id]),
                },
                parse_problem=_TOOL_NOTE,
                **timing,
                **common,
            )


# ----------------------------------------------------------------------- helpers


def _document(value: Any) -> tuple[dict[str, Any] | None, str | None]:
    """The thread's JSON, which the store reader has already decompressed.

    A dictionary carrying the blob marker means the reader could not turn the column into
    text: a frame that would not decompress, one that expands past the ingest limit, or
    bytes that are not a frame at all. Its own note says which, and it is passed along
    rather than replaced, because that note is the finding.
    """
    if isinstance(value, dict) and value.get(BLOB_NOTE):
        return None, f"the thread content could not be read: {value.get('note')}"
    if isinstance(value, dict):
        return value, None
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    if not isinstance(value, str) or not value.strip():
        return None, "the thread's data column is empty"
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        return None, f"the thread's data column is not valid JSON: {exc}"
    if not isinstance(parsed, dict):
        return None, f"the thread's data holds a JSON {type(parsed).__name__}, not an object"
    return parsed, None


def folders(value: Any, order: Any = None) -> list[str]:
    # Public because the sidebar store writes its two path columns the same way and reads
    # them with this. A copy in the other module would be a second place to fix.
    """The workspace folders, in the order the person opened them.

    Two columns, and reading only the first one gets the answer wrong twice. The vendor
    serialises a path list as the paths joined with a newline, sorted lexicographically,
    plus a comma separated list of the index each path had before that sort. Source, fetched
    and read:
    https://raw.githubusercontent.com/zed-industries/zed/main/crates/util/src/path_list.rs

    So `folder_paths` alone is in an order nobody chose, and this parser used to also split
    it on commas, which is not a separator the vendor writes: a working copy whose directory
    name contains a comma came out as two paths, and the first of them became the thread's
    project path. A truncated path on an event is worse than no path, because it looks like
    an answer.

    The vendor's own reader discards the order when it does not describe the paths, and so
    does this one, for the same reason: an order of the wrong length cannot be applied and
    guessing at it would reorder somebody's working copies.
    """
    if isinstance(value, list):
        return [str(item) for item in value if item]
    if not isinstance(value, str) or not value.strip():
        return []
    # split, not splitlines: the separator is the newline the vendor writes, and a path is
    # allowed to hold anything else a filesystem allows.
    paths = [part for part in value.split("\n") if part.strip()]
    indices = [
        int(part) for part in str(order or "").split(",") if part.strip().lstrip("-").isdigit()
    ]
    if sorted(indices) != list(range(len(paths))):
        # Not an order over these paths. The vendor falls back to the lexicographic order it
        # stored, which is the order they are already in.
        return paths
    return [path for _, path in sorted(zip(indices, paths, strict=True))]


def _models(document: dict[str, Any] | None) -> list[dict[str, Any]] | None:
    model = (document or {}).get("model")
    if isinstance(model, str) and model:
        return [{"model": model}]
    if isinstance(model, dict):
        provider = _text(model.get("provider") or model.get("provider_id"))
        name = _text(model.get("model") or model.get("model_id") or model.get("id"))
        if provider and name:
            return [{"model": f"{provider}/{name}"}]
        if name or provider:
            return [{"model": name or provider}]
    return None


def _tagged(value: Any) -> tuple[str | None, dict[str, Any]]:
    """An externally tagged Rust enum: one key naming the variant, holding its fields.

    serde's default for an enum with no tag attribute, which is what all of these use. A
    shape with more than one key is not one of them and is reported rather than guessed at.
    """
    if not isinstance(value, dict) or len(value) != 1:
        return None, {}
    ((tag, body),) = value.items()
    return tag, body if isinstance(body, dict) else {}


def _untagged(value: Any) -> Any:
    """The payload of a single-key object, for a variant that wraps one value."""
    if isinstance(value, dict) and len(value) == 1:
        return next(iter(value.values()))
    return value


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ("" if value is None else str(value))


__all__ = ["MAPPED", "ZedParser"]
