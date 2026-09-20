"""Parse the task trees Cline, Roo Code and Kilo Code write.

One module for three agents because Roo Code and Kilo Code are forks of Cline and kept its
storage layout: a directory per task, under the editor's global storage, holding the same
files under the same names.
Sources:
  https://github.com/cline/cline/blob/main/apps/vscode/src/core/storage/disk.ts
  https://github.com/RooCodeInc/Roo-Code/blob/main/src/utils/storage.ts

Four files matter, and each answers a different question.

`api_conversation_history.json` is a JSON array of the provider's own message parameters,
which for these agents means the Anthropic message shape: a role and a content that is
either a string or a list of typed blocks. It is what the model was actually sent, which
makes it the authoritative record of the conversation and the only one of the four that
carries tool calls with their arguments.

`ui_messages.json` is the agent's own log of what the user saw, and it carries something
the API history does not: `ask` entries. An `ask` is the agent stopping to request
permission, and the message that follows says what happened next. That is the difference
between an agent that was allowed to run a command and one that ran it unasked, so these
are mapped as permission events rather than as chat.

`task_metadata.json` records which files were in context and the model usage. `context
_history.json` records how the context was truncated, which is the usual explanation for a
conversation that appears to lose its own earlier turns.

All four are whole JSON documents rather than line-delimited, so a truncated write loses
the file rather than its last record. A task directory whose history will not parse while
its sibling files do is that, and it is reported as such.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any
from urllib.parse import urlsplit

from agentforensics.model import Event, unparsed
from agentforensics.parsers.base import (
    ParseContext,
    first_word,
    normalise_ts,
    read_json,
    text_of,
)

# The tool names this family uses. Only an exact match produces a facet.
_COMMAND = ("execute_command",)
_FILE_READ = ("read_file",)
_FILE_WRITE = (
    "write_to_file",
    "replace_in_file",
    "apply_diff",
    "insert_content",
    "search_and_replace",
    "new_rule",
)
_NETWORK = ("browser_action", "web_fetch", "fetch_instructions")
_MCP = ("use_mcp_tool", "access_mcp_resource")

# What an `ask` in the UI log is asking for, as the agent spells it. Kept as a set rather
# than matched loosely: an ask type nobody here knows still becomes a permission event, but
# with its own type recorded rather than guessed at.
# The locator for an event about a whole file rather than a record inside one. Every event
# carries one: a null locator would leave a record with nowhere to point, and the unified
# format requires provenance precise enough to go back and look.
DOCUMENT = "document"

_PERMISSION_ASKS = frozenset(
    {
        "command",
        "tool",
        "browser_action_launch",
        "use_mcp_server",
        "auto_approval_max_req_reached",
    }
)


class ClineParser:
    """Cline, Roo Code and Kilo Code task directories."""

    name = "cline"

    # Kilo Code's task tree is catalogued unverified, and it is still claimed here. The
    # uncertainty in that entry is about whether the directory is at that path, not about
    # what is in it: the file names are this family's, and this parser dispatches on the
    # file name. Reading a file that turns up there costs nothing and refusing to would
    # leave a transcript unread for a reason that has nothing to do with its format.
    _API_HISTORY = frozenset(
        {
            "cline.data_tasks",
            "cline.vscode_task_transcripts",
            "kilo_code.extension_id_legacy_tree",
            "roo_code.tasks",
        }
    )

    def handles(self, artifact_id: str | None) -> bool:
        return artifact_id in self._API_HISTORY

    def parse(self, context: ParseContext) -> Iterator[Event]:
        """Dispatch on the file's own name, because one catalogue entry claims four files.

        The entry is the task directory, so a single artifact id arrives holding the API
        history, the UI log, the metadata and the context history. Reading the name is the
        only way to tell them apart, and a name this does not know is reported rather than
        guessed at.
        """
        name = context.local_path.name
        session = _task_id(context.original_path)
        if name == "api_conversation_history.json":
            yield from self._api_history(context, session)
        elif name == "ui_messages.json":
            yield from self._ui_messages(context, session)
        elif name == "task_metadata.json":
            yield from self._metadata(context, session)
        elif name == "context_history.json":
            yield from self._context_history(context, session)
        elif name in ("_index.json", "history_item.json", "settings.json"):
            yield from self._index(context, session, name)
        else:
            yield unparsed(
                context.provenance(DOCUMENT),
                context.agent,
                _evidence(context),
                f"{name!r} is in a task directory but is not a file this parser maps",
                user=context.user,
                host=context.host,
                session_id=session,
            )

    # ------------------------------------------------------------- api history

    def _api_history(self, context: ParseContext, session: str | None) -> Iterator[Event]:
        value, problem = self._document(context, session, "list")
        if problem is not None:
            yield problem
            return
        for index, message in enumerate(value if isinstance(value, list) else []):
            locator = f"index:{index}"
            if not isinstance(message, dict):
                yield unparsed(
                    context.provenance(locator),
                    context.agent,
                    message,
                    f"a conversation entry is a JSON {type(message).__name__}, not an object",
                    user=context.user,
                    host=context.host,
                    session_id=session,
                )
                continue
            # The API history carries no timestamps: it is the provider's message array,
            # and the provider is not told when anything happened. Stated as absent rather
            # than filled in from the file's own mtime, which would date every turn in a
            # task to the moment the task last changed.
            common: dict[str, Any] = {
                "ts_utc": None,
                "ts_precision": "absent",
                "ts_source": None,
                "user": context.user,
                "host": context.host,
                "session_id": session,
            }
            role = message.get("role")
            blocks = _blocks(message.get("content"))

            if role == "user":
                # A user entry in this file is not always a person. The agent puts tool
                # results here too, because that is where the provider's API expects them,
                # so the two are told apart by block type rather than by role.
                results = [block for block in blocks if block.get("type") == "tool_result"]
                text = _text_blocks(blocks)
                for inner, block in enumerate(results):
                    yield Event(
                        kind="tool.result",
                        provenance=context.provenance(f"{locator}#result{inner}"),
                        agent=context.agent,
                        raw=message,
                        actor="tool",
                        payload={
                            "tool_use_id": block.get("tool_use_id"),
                            "is_error": bool(block.get("is_error")),
                            "output": block.get("content"),
                            "text": text_of(block.get("content")),
                        },
                        **common,
                    )
                if text or not results:
                    yield Event(
                        kind="user.prompt",
                        provenance=context.provenance(locator),
                        agent=context.agent,
                        raw=message,
                        actor="user",
                        payload={"text": text, "index": index},
                        **common,
                    )
            elif role == "assistant":
                text = _text_blocks(blocks)
                thinking = "\n".join(
                    str(block.get("thinking") or "")
                    for block in blocks
                    if block.get("type") in ("thinking", "redacted_thinking")
                ).strip()
                calls = [block for block in blocks if block.get("type") == "tool_use"]
                if thinking:
                    yield Event(
                        kind="assistant.thinking",
                        provenance=context.provenance(f"{locator}#thinking"),
                        agent=context.agent,
                        raw=message,
                        actor="assistant",
                        payload={"text": thinking, "index": index},
                        **common,
                    )
                if text or not calls:
                    yield Event(
                        kind="assistant.text",
                        provenance=context.provenance(locator),
                        agent=context.agent,
                        raw=message,
                        actor="assistant",
                        payload={"text": text, "index": index},
                        **common,
                    )
                for inner, block in enumerate(calls):
                    yield from self._tool_use(context, message, locator, inner, block, common)
            else:
                yield unparsed(
                    context.provenance(locator),
                    context.agent,
                    message,
                    f"message role {role!r} is not one this parser maps",
                    user=context.user,
                    host=context.host,
                    session_id=session,
                )

    def _tool_use(
        self,
        context: ParseContext,
        message: dict[str, Any],
        locator: str,
        index: int,
        block: dict[str, Any],
        common: dict[str, Any],
    ) -> Iterator[Event]:
        name = str(block.get("name") or "")
        arguments = _mapping(block.get("input"))
        payload: dict[str, Any] = {
            "tool": name,
            "tool_use_id": block.get("id"),
            "input": arguments,
        }
        if name in _MCP:
            # The server and tool are arguments here rather than part of the tool name, so
            # the facet is built from them: "which external servers did this agent reach"
            # has to be an indexed query whichever agent is being asked.
            payload["mcp"] = [
                {
                    "server": str(arguments.get("server_name") or ""),
                    "tool": str(arguments.get("tool_name") or arguments.get("uri") or ""),
                }
            ]
        yield Event(
            kind="mcp.call" if name in _MCP else "tool.call",
            provenance=context.provenance(f"{locator}#tool{index}"),
            agent=context.agent,
            raw=message,
            actor="assistant",
            payload=payload,
            **common,
        )
        effect_kind, effect_payload = self._effect(name, arguments)
        if effect_kind:
            yield Event(
                kind=effect_kind,
                provenance=context.provenance(f"{locator}#effect{index}"),
                agent=context.agent,
                raw=message,
                actor="assistant",
                payload={"tool": name, "tool_use_id": block.get("id"), **effect_payload},
                **common,
            )

    def _effect(self, name: str, arguments: dict[str, Any]) -> tuple[str | None, dict[str, Any]]:
        if name in _COMMAND:
            command = arguments.get("command")
            if not command:
                return None, {}
            return "command.exec", {
                "commands": [
                    {
                        "command": str(command),
                        "executable": first_word(str(command)),
                        "cwd": arguments.get("cwd"),
                    }
                ],
                # Whether the agent asked before running it, as the call itself records it.
                "requires_approval": arguments.get("requires_approval"),
            }
        path = arguments.get("path") or arguments.get("file_path")
        if name in _FILE_READ and path:
            return "file.read", {"files": [{"path": str(path), "operation": "read"}]}
        if name in _FILE_WRITE and path:
            content = arguments.get("content") or arguments.get("diff")
            return "file.write", {
                "files": [
                    {
                        "path": str(path),
                        "operation": "write",
                        "bytes": len(str(content).encode("utf-8")) if content else None,
                    }
                ]
            }
        if name in _NETWORK:
            url = arguments.get("url")
            if not url:
                return None, {}
            return "network.request", {
                "network": [{"url": str(url), "host": urlsplit(str(url)).netloc}],
                "text": str(url),
            }
        return None, {}

    # -------------------------------------------------------------- ui messages

    def _ui_messages(self, context: ParseContext, session: str | None) -> Iterator[Event]:
        """The agent's own log of the exchange, which is where the approvals are.

        This file is the only one that says whether the agent stopped to ask. An `ask`
        entry is a request for permission, and its `text` says what for. Mapped as a
        permission decision rather than as chat, because "were controls bypassed" is
        answered from these entries and from nothing else in a task directory.
        """
        value, problem = self._document(context, session, "list")
        if problem is not None:
            yield problem
            return
        for index, entry in enumerate(value if isinstance(value, list) else []):
            locator = f"index:{index}"
            if not isinstance(entry, dict):
                yield unparsed(
                    context.provenance(locator),
                    context.agent,
                    entry,
                    f"a UI log entry is a JSON {type(entry).__name__}, not an object",
                    user=context.user,
                    host=context.host,
                    session_id=session,
                )
                continue
            ts, precision, note = normalise_ts(entry.get("ts"))
            common: dict[str, Any] = {
                "ts_utc": ts,
                "ts_precision": precision,
                "ts_source": "ts" if ts else None,
                "user": context.user,
                "host": context.host,
                "session_id": session,
            }
            kind = entry.get("type")
            ask = entry.get("ask")
            say = entry.get("say")
            text = text_of(entry.get("text"))

            if kind == "ask":
                yield Event(
                    kind="permission.decision",
                    provenance=context.provenance(locator),
                    agent=context.agent,
                    raw=entry,
                    actor="system",
                    payload={
                        "permissions": [
                            {
                                # The agent asked; whether anybody said yes is in what
                                # follows, so the decision is recorded as unanswered here
                                # rather than assumed. An assumed approval would be the
                                # worst possible defect in this field.
                                "decision": "asked",
                                "subject": str(ask or ""),
                                "mode": None,
                            }
                        ],
                        "ask": ask,
                        "known_ask_type": (ask in _PERMISSION_ASKS) or None,
                        "text": text,
                        "partial": entry.get("partial"),
                    },
                    parse_problem=note,
                    **common,
                )
                continue

            if kind == "say":
                # `say` covers everything the agent told the user, including its own
                # narration of what it did. Mapped by subtype, and an unknown subtype
                # becomes assistant text rather than being dropped.
                if say in ("user_feedback", "user_feedback_diff"):
                    yield Event(
                        kind="user.prompt",
                        provenance=context.provenance(locator),
                        agent=context.agent,
                        raw=entry,
                        actor="user",
                        payload={"text": text, "say": say},
                        parse_problem=note,
                        **common,
                    )
                elif say == "reasoning":
                    yield Event(
                        kind="assistant.thinking",
                        provenance=context.provenance(locator),
                        agent=context.agent,
                        raw=entry,
                        actor="assistant",
                        payload={"text": text, "say": say},
                        parse_problem=note,
                        **common,
                    )
                else:
                    yield Event(
                        kind="assistant.text",
                        provenance=context.provenance(locator),
                        agent=context.agent,
                        raw=entry,
                        actor="assistant",
                        payload={"text": text, "say": say, "images": entry.get("images")},
                        parse_problem=note,
                        **common,
                    )
                continue

            yield unparsed(
                context.provenance(locator),
                context.agent,
                entry,
                f"UI log entry type {kind!r} is not one this parser maps",
                ts_utc=ts,
                ts_precision=precision,
                ts_source=common["ts_source"],
                user=context.user,
                host=context.host,
                session_id=session,
            )

    # ----------------------------------------------------------------- the rest

    def _metadata(self, context: ParseContext, session: str | None) -> Iterator[Event]:
        value, problem = self._document(context, session, "dict")
        if problem is not None:
            yield problem
            return
        document = _mapping(value)
        files = document.get("files_in_context")
        yield Event(
            kind="config.snapshot",
            provenance=context.provenance(DOCUMENT),
            agent=context.agent,
            raw=document,
            actor="system",
            user=context.user,
            host=context.host,
            session_id=session,
            payload={
                # Every file the agent had in its context, which is a different claim from
                # every file it read: a file can enter the context through a mention or an
                # editor tab without a tool call naming it. So the operation is "unknown"
                # rather than "read". That keeps the question an analyst asks indexed, did
                # this agent touch that path, without the case claiming something it does
                # not know.
                "files": [
                    {"path": str(entry.get("path")), "operation": "unknown"}
                    for entry in _dicts(files)
                    if entry.get("path")
                ],
                "files_in_context": files,
                "models": [{"model": str(name)} for name in _mapping(document.get("model_usage"))],
                "model_usage": document.get("model_usage"),
                "environment_history": document.get("environment_history"),
                "text": f"{len(_dicts(files))} file(s) were in this task's context",
            },
        )

    def _context_history(self, context: ParseContext, session: str | None) -> Iterator[Event]:
        """How the context was truncated, which explains a conversation losing its start."""
        value, problem = self._document(context, session, None)
        if problem is not None:
            yield problem
            return
        yield Event(
            kind="session.end",
            provenance=context.provenance(DOCUMENT),
            agent=context.agent,
            raw=value,
            actor="system",
            user=context.user,
            host=context.host,
            session_id=session,
            payload={
                "compaction": True,
                "text": "this task's context was edited or truncated, so the conversation "
                "the model saw is not the whole of the history file",
            },
        )

    def _index(self, context: ParseContext, session: str | None, name: str) -> Iterator[Event]:
        value, problem = self._document(context, session, None)
        if problem is not None:
            yield problem
            return
        document = _mapping(value)
        ts, precision, note = normalise_ts(document.get("ts") or document.get("createdAt"))
        yield Event(
            kind="config.snapshot",
            provenance=context.provenance(DOCUMENT),
            agent=context.agent,
            raw=value,
            ts_utc=ts,
            ts_precision=precision,
            ts_source="ts" if ts else None,
            actor="system",
            user=context.user,
            host=context.host,
            session_id=session,
            project_path=document.get("workspace") or document.get("cwd"),
            payload={
                "file": name,
                "task": document.get("task"),
                "text": text_of(document.get("task")) or f"{name} for task {session}",
            },
            parse_problem=note,
        )

    def _document(
        self, context: ParseContext, session: str | None, expect: str | None
    ) -> tuple[Any, Event | None]:
        """One whole JSON document, or an event saying why it is not one.

        These files are not line-delimited, so there is no partial read to fall back on: a
        truncated write costs the file. Returning an event rather than raising keeps that
        visible in the case as a record rather than as a parser failure with no detail.
        """
        value, problem, relaxed = read_json(context.local_path)
        problem = problem or relaxed
        if problem is not None:
            return None, unparsed(
                context.provenance(DOCUMENT),
                context.agent,
                _evidence(context),
                f"{context.local_path.name} {problem}",
                user=context.user,
                host=context.host,
                session_id=session,
            )
        if expect == "list" and not isinstance(value, list):
            return None, unparsed(
                context.provenance(DOCUMENT),
                context.agent,
                value,
                f"{context.local_path.name} is a JSON {type(value).__name__}, not the array "
                "this format writes",
                user=context.user,
                host=context.host,
                session_id=session,
            )
        if expect == "dict" and not isinstance(value, dict):
            return None, unparsed(
                context.provenance(DOCUMENT),
                context.agent,
                value,
                f"{context.local_path.name} is a JSON {type(value).__name__}, not the object "
                "this format writes",
                user=context.user,
                host=context.host,
                session_id=session,
            )
        return value, None


def _evidence(context: ParseContext) -> Any:
    """What a file-level unparsed event carries as its raw.

    An unparsed record with nothing in `raw` tells a reader only that something went wrong,
    which is the one thing they could already see. These files are whole documents, so the
    evidence is the document: the decoded value when it decodes, and the text itself when it
    does not, which is the case that matters most, because a truncated write is what a
    reader has to be able to look at.
    """
    value, problem, relaxed = read_json(context.local_path)
    problem = problem or relaxed
    if problem is None:
        return value
    try:
        return context.local_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return f"the file could not be read: {exc}"


def _task_id(original_path: str) -> str | None:
    """The task directory's name, which is the only session identifier these files have.

    Taken from the path because none of the four files carries it inside. A path that does
    not look like a task directory returns nothing rather than a guess: an invented session
    id would group unrelated turns into one conversation.
    """
    parts = original_path.replace("\\", "/").rstrip("/").split("/")
    if len(parts) >= 2 and parts[-2] not in ("tasks", ""):
        return parts[-2]
    return None


def _blocks(value: Any) -> list[dict[str, Any]]:
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


def _text_blocks(blocks: list[dict[str, Any]]) -> str:
    return "\n".join(
        str(block.get("text") or "") for block in blocks if block.get("type") == "text"
    ).strip()


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _dicts(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


__all__ = ["ClineParser"]
