"""Read Continue's session store: the per-session file and the index beside it.

Two files, and the interesting thing about them is what the transcript does not have.

**`<sessionId>.json`** is a `Session`: an id, a title, a workspace directory and a
`history` of items. Source, fetched and read, as the vendor's own type declaration:
https://raw.githubusercontent.com/continuedev/continue/main/core/index.d.ts
There is not one timestamp in it. Not on the session, not on a message. The only clock in
this store is `dateCreated` in the index, and it is the moment the session was first saved.
So every turn out of this file is undated, deliberately, and the one exception is a
reasoning block, which carries `startAt` as epoch milliseconds.

**`sessions.json`** is the index: one `BaseSessionMetadata` per session with `sessionId`,
`title`, `dateCreated`, `workspaceDirectory` and `messageCount`. Source, fetched and read:
https://raw.githubusercontent.com/continuedev/continue/main/core/util/history.ts
Three things in that writer matter for a case and none of them is obvious from the data.

1. `dateCreated` is `String(Date.now())`, so it is epoch milliseconds in a string and not
   a date. Read as a date it is unparseable and the session loses its only time.
2. `messageCount` counts the assistant messages alone, not the turns. An analyst comparing
   it against the length of `history` finds a mismatch that is not evidence of anything.
3. The reader that builds the session list drops every entry that carries `session_id`
   rather than `sessionId`, calling it the old format. Such a session is in the file and
   not in the product's own list, which is worth seeing rather than passing over.

The vendor's delete removes the file and the index entry together, so a file with no entry,
or an entry with no file, is the shape left by something other than the product's own
delete. The catalogue entry says so and this parser gives a case the two halves to compare.

**What is read out of a history item.** The message, by role, and then three things beside
it that the format carries and most transcripts do not: `toolCallStates`, each with the
status the vendor's own enum defines; `contextItems`, which name the files and URLs that
were put in front of the model; and `appliedRules`, which name the rule files that shaped
the turn, with the source that produced each one.

**What is not read.** A tool call state of `canceled` is not a permission decision. The
vendor's own comment says canceled "by user or system", and a case that turned that into a
refusal an analyst could quote would be inventing the half that matters. The status is on
the event and the word is the vendor's.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any
from urllib.parse import urlsplit

from agentforensics.model import Event, unparsed
from agentforensics.parsers.base import ParseContext, normalise_ts, read_json, text_of
from agentforensics.parsers.instructions import hidden_characters

# The file that lists the sessions rather than holding one.
INDEX = "sessions.json"

# The roles the vendor's ChatMessage union allows, mapped to what they are in this format.
# A role that is not one of these is carried whole: the union can grow, and a new role read
# as an old one would be wrong and silent.
ROLES = {
    "user": "user.prompt",
    "assistant": "assistant.text",
    "thinking": "assistant.thinking",
    "system": "instruction.source",
    "tool": "tool.result",
}

# Who acted, per role, so an event says whether a person or the model produced it.
ACTORS: dict[str, str] = {
    "user": "user",
    "assistant": "assistant",
    "thinking": "assistant",
    "system": "system",
    "tool": "tool",
}

# The statuses a tool call can be left in, from the vendor's own ToolStatus union, with what
# each one means there. Carried onto the event rather than interpreted: only `errored` is
# unambiguous enough to set the error flag a case queries.
STATUS_MEANING = {
    "generating": "the arguments were still being streamed from the model",
    "generated": "the call was complete and waiting to be approved",
    "calling": "the tool was running",
    "errored": "the tool failed",
    "done": "the tool finished",
    "canceled": "the call was canceled, and the vendor's own note says this is by the user "
    "or by the system, so it is not read here as a refusal somebody made",
}

# Said on every event out of a session file, because the absence is the finding.
NO_TIME = (
    "this store carries no timestamp on a session or on a turn: the only clock in it is "
    "dateCreated in sessions.json, which is when the session was first saved. Nothing here "
    "is dated from it, because that would put a whole conversation at one instant"
)

# Said on an index entry the product's own list drops.
OLD_FORMAT = (
    "this entry names the session under session_id rather than sessionId, which the "
    "vendor's own reader treats as the old format and filters out of the session list. It "
    "is in the file and not in the product's list of conversations"
)

# Said on the message count, which is not the number of messages.
COUNT_MEANING = (
    "messageCount is the number of assistant messages in the session, not the number of "
    "turns, so it does not match the length of a history and a mismatch is not a deletion"
)


class ContinueSessionsParser:
    """Continue's per-session file and the index that lists them."""

    name = "continue_sessions"

    _SESSIONS = frozenset({"continue.sessions"})

    def handles(self, artifact_id: str | None) -> bool:
        return artifact_id in self._SESSIONS

    def parse(self, context: ParseContext) -> Iterator[Event]:
        """One catalogue entry claims the index and every session file, so the name decides.

        The index has a fixed name and the session files are named by their id, which is
        also where the vendor recovers an id from when a file will not parse.
        """
        document, problem, relaxed = read_json(context.local_path)
        problem = problem or relaxed
        if problem is not None:
            yield unparsed(
                context.provenance("$"),
                context.agent,
                None,
                problem,
                user=context.user,
                host=context.host,
                session_id=_from_name(context.local_path.name),
            )
            return
        if context.local_path.name == INDEX:
            yield from self._index(context, document)
            return
        yield from self._session(context, document)

    # ---------------------------------------------------------------- the index

    def _index(self, context: ParseContext, document: Any) -> Iterator[Event]:
        if not isinstance(document, list):
            yield unparsed(
                context.provenance("$"),
                context.agent,
                document,
                "the session index is not a list, which is the only shape the vendor's "
                "reader accepts, so it holds no entries this parser can read",
                user=context.user,
                host=context.host,
            )
            return
        for index, entry in enumerate(document):
            yield self._entry(context, index, entry)

    def _entry(self, context: ParseContext, index: int, entry: Any) -> Event:
        at = f"$[{index}]"
        if not isinstance(entry, dict):
            return unparsed(
                context.provenance(at),
                context.agent,
                entry,
                "an index entry that is not an object",
                user=context.user,
                host=context.host,
            )
        # The old key first, because an entry that carries it is the one the product hides.
        old = _text(entry.get("session_id"))
        session = _text(entry.get("sessionId")) or old
        # String(Date.now()), so epoch milliseconds in a string. normalise_ts reads a
        # numeric string as epoch, which is the whole reason this field is usable at all.
        when, precision, note = normalise_ts(entry.get("dateCreated"))
        return Event(
            kind="session.start",
            provenance=context.provenance(at),
            agent=context.agent,
            raw=entry,
            ts_utc=when,
            ts_precision=precision,
            ts_source="the index's dateCreated, which is when the session was first saved"
            if when
            else None,
            actor="system",
            user=context.user,
            host=context.host,
            session_id=session,
            project_path=_text(entry.get("workspaceDirectory")),
            payload={
                "text": _text(entry.get("title")),
                "assistant_messages": entry.get("messageCount"),
                "count_meaning": COUNT_MEANING,
                "hidden_from_the_session_list": bool(old and not entry.get("sessionId")),
            },
            parse_problem=" ".join(
                part
                for part in (note, OLD_FORMAT if old and not entry.get("sessionId") else None)
                if part
            )
            or None,
        )

    # --------------------------------------------------------------- a session

    def _session(self, context: ParseContext, document: Any) -> Iterator[Event]:
        if not isinstance(document, dict):
            yield unparsed(
                context.provenance("$"),
                context.agent,
                document,
                "a session file that is not an object",
                user=context.user,
                host=context.host,
                session_id=_from_name(context.local_path.name),
            )
            return

        # The vendor recovers the id from the file name when it loads a session, so the
        # name wins over a field that a partial write could have left behind.
        session = _from_name(context.local_path.name) or _text(document.get("sessionId"))
        project = _text(document.get("workspaceDirectory"))
        common: dict[str, Any] = {
            "user": context.user,
            "host": context.host,
            "session_id": session,
            "project_path": project,
            "agent": context.agent,
        }
        usage = _mapping(document.get("usage"))
        history = _list(document.get("history"))

        yield Event(
            kind="config.snapshot",
            provenance=context.provenance("$"),
            raw={key: value for key, value in document.items() if key != "history"},
            ts_utc=None,
            ts_precision="absent",
            actor="system",
            payload={
                "text": _text(document.get("title")),
                # chat, agent, plan or background. The one field in this store that says
                # whether a person was driving, and the vendor writes it only when it is set.
                "mode": _text(document.get("mode")),
                "models": [
                    {
                        "model": _text(document.get("chatModelTitle")),
                        "input_tokens": usage.get("promptTokens"),
                        "output_tokens": usage.get("completionTokens"),
                        "cost": usage.get("totalCost"),
                    }
                ]
                if document.get("chatModelTitle") or usage
                else [],
                "turns": len(history),
            },
            parse_problem=NO_TIME,
            **common,
        )

        for index, item in enumerate(history):
            yield from self._item(context, common, index, item)

    def _item(
        self, context: ParseContext, common: dict[str, Any], index: int, item: Any
    ) -> Iterator[Event]:
        at = f"$.history[{index}]"
        if not isinstance(item, dict):
            yield unparsed(
                context.provenance(at),
                context.agent,
                item,
                "a history item that is not an object",
                user=context.user,
                host=context.host,
                session_id=common.get("session_id"),
            )
            return

        message = _mapping(item.get("message"))
        role = _text(message.get("role")) or ""
        kind = ROLES.get(role)
        reasoning = _mapping(item.get("reasoning"))
        # The one clock in a session file, and it is only on a reasoning block: epoch
        # milliseconds from the moment the model started thinking.
        when, precision, timing = normalise_ts(reasoning.get("startAt"))
        note = " ".join(part for part in (timing, NO_TIME) if part)

        if kind is None:
            yield unparsed(
                context.provenance(at),
                context.agent,
                item,
                f"a message role of {role!r}, which is not one of the five the vendor's "
                "ChatMessage union names. The union can grow, so it is carried whole",
                user=context.user,
                host=context.host,
                session_id=common.get("session_id"),
                project_path=common.get("project_path"),
            )
        elif kind == "instruction.source":
            # A system message in the history is the prompt this session was run under, and
            # it is on the endpoint, so it is evidence. The path is the file holding it,
            # not a claim about a base prompt the vendor compiles in.
            text = text_of(message.get("content"))
            yield Event(
                kind="instruction.source",
                provenance=context.provenance(f"{at}.message"),
                raw=message,
                ts_utc=None,
                ts_precision="absent",
                actor="system",
                payload={
                    "text": text,
                    "instructions": [{"path": f"{context.original_path}#{at}", "scope": "session"}],
                    "scope": "session",
                    "hidden_characters": hidden_characters(text),
                    # In the payload rather than as a parse problem, for the reason the
                    # scope caveat is: the instruction surface counts a file with a parse
                    # problem as one that was not fully read, and this file was read
                    # completely. What is missing is a time, which is a different claim.
                    "timing_note": NO_TIME,
                },
                parse_problem=None,
                **common,
            )
        else:
            yield Event(
                kind=kind,
                provenance=context.provenance(f"{at}.message"),
                raw=message,
                ts_utc=when if role == "thinking" else None,
                ts_precision=precision if role == "thinking" else "absent",
                ts_source="the reasoning block's startAt" if role == "thinking" and when else None,
                actor=ACTORS.get(role, "unknown"),  # type: ignore[arg-type]
                payload=_message_payload(role, message, item),
                parse_problem=note if role == "thinking" else NO_TIME,
                **common,
            )

        yield from self._tools(context, common, at, item)
        yield from self._context_items(context, common, at, item)
        yield from self._rules(context, common, at, item)

    def _tools(
        self, context: ParseContext, common: dict[str, Any], at: str, item: dict[str, Any]
    ) -> Iterator[Event]:
        """Each tool call the item left behind, in the state the vendor recorded it in."""
        for position, state in enumerate(_list(item.get("toolCallStates"))):
            if not isinstance(state, dict):
                continue
            call = _mapping(state.get("toolCall"))
            function = _mapping(call.get("function"))
            status = _text(state.get("status")) or ""
            yield Event(
                kind="tool.call",
                provenance=context.provenance(f"{at}.toolCallStates[{position}]"),
                raw=state,
                ts_utc=None,
                ts_precision="absent",
                actor="assistant",
                payload={
                    "tool": _text(function.get("name")),
                    "tool_use_id": _text(state.get("toolCallId")) or _text(call.get("id")),
                    # The arguments as the model produced them, and the vendor's own parse
                    # of the same string. Both, because a string that failed to parse is
                    # the evidence when a call did something unexpected.
                    "input": state.get("parsedArgs"),
                    "arguments": _text(function.get("arguments")),
                    "output": state.get("output"),
                    "status": status,
                    "status_meaning": STATUS_MEANING.get(status),
                    # Only errored is unambiguous. A canceled call is canceled by the user
                    # or by the system and the file does not say which.
                    "is_error": status == "errored",
                },
                parse_problem=NO_TIME,
                **common,
            )

    def _context_items(
        self, context: ParseContext, common: dict[str, Any], at: str, item: dict[str, Any]
    ) -> Iterator[Event]:
        """What was put in front of the model with this turn.

        The vendor types a context item's uri as file or url and nothing else, so a file is
        a file the agent was given and a url is one it was given the contents of. That is a
        different act from a tool call and the event says so, but it is the same question an
        analyst asks of every agent: which files and which destinations.
        """
        files = []
        urls = []
        for entry in _list(item.get("contextItems")):
            uri = _mapping(_mapping(entry).get("uri"))
            value = _text(uri.get("value"))
            if not value:
                continue
            if uri.get("type") == "file":
                files.append({"path": value, "operation": "read", "from_context": True})
            elif uri.get("type") == "url":
                # The host is what the format requires and what a case queries: "which
                # destinations did this endpoint reach" is a question about hosts, and a
                # URL that will not split still names one as an empty string rather than
                # dropping the record.
                urls.append({"url": value, "host": urlsplit(value).netloc})
        if files:
            yield Event(
                kind="file.read",
                provenance=context.provenance(f"{at}.contextItems"),
                raw=item.get("contextItems"),
                ts_utc=None,
                ts_precision="absent",
                actor="assistant",
                payload={"files": files, "from_context": True},
                parse_problem=NO_TIME,
                **common,
            )
        if urls:
            yield Event(
                kind="network.request",
                provenance=context.provenance(f"{at}.contextItems"),
                raw=item.get("contextItems"),
                ts_utc=None,
                ts_precision="absent",
                actor="assistant",
                payload={"network": urls, "from_context": True},
                parse_problem=NO_TIME,
                **common,
            )

    def _rules(
        self, context: ParseContext, common: dict[str, Any], at: str, item: dict[str, Any]
    ) -> Iterator[Event]:
        """The rule files the vendor recorded as having shaped this turn.

        This is the instruction surface with something no other agent's transcript has: not
        which rule files exist on the endpoint, but which of them applied to a given turn,
        with the vendor's own word for where each came from.
        """
        for position, rule in enumerate(_list(item.get("appliedRules"))):
            if not isinstance(rule, dict):
                continue
            path = _text(rule.get("sourceFile"))
            yield Event(
                kind="instruction.source",
                provenance=context.provenance(f"{at}.appliedRules[{position}]"),
                raw=rule,
                ts_utc=None,
                ts_precision="absent",
                actor="system",
                payload={
                    "text": _text(rule.get("description")) or _text(rule.get("name")),
                    # The path when the rule came from a file. A rule with no source file
                    # is one the product built in, and it carries no path, which the event
                    # states rather than filling in with the session file's own name.
                    "instructions": [{"path": path, "scope": "project"}] if path else [],
                    "scope": "project" if path else "unknown",
                    "rule_name": _text(rule.get("name")) or _text(rule.get("slug")),
                    # default-agent, rules-block, .continuerules, agentFile and the rest of
                    # the vendor's RuleSource union, carried as written.
                    "rule_source": _text(rule.get("source")),
                    "always_apply": rule.get("alwaysApply"),
                    "globs": rule.get("globs"),
                    "timing_note": NO_TIME,
                },
                parse_problem=None
                if path
                else "this rule names no source file, so nothing says where on the endpoint "
                "it came from",
                **common,
            )


def _message_payload(role: str, message: dict[str, Any], item: dict[str, Any]) -> dict[str, Any]:
    """The facets one message earns, by role."""
    usage = _mapping(message.get("usage"))
    payload: dict[str, Any] = {"text": text_of(message.get("content"))}
    if role == "tool":
        payload["tool_use_id"] = _text(message.get("toolCallId"))
        payload["output"] = message.get("content")
    if role in ("assistant", "thinking") and usage:
        payload["models"] = [
            {
                "input_tokens": usage.get("promptTokens"),
                "output_tokens": usage.get("completionTokens"),
            }
        ]
    if role == "thinking" and _text(message.get("redactedThinking")):
        # The provider returned reasoning the product may not show. It is in the file, so
        # it is in the case, and the event says which of the two this text is.
        payload["redacted_thinking"] = message.get("redactedThinking")
    summary = _text(item.get("conversationSummary"))
    if summary:
        # What the product kept when it compacted the conversation. It explains a session
        # that appears to lose its own earlier turns, so it travels with the turn it was
        # written on rather than being dropped.
        payload["conversation_summary"] = summary
    return payload


def _from_name(name: str) -> str | None:
    """The session id in a file name, which is where the vendor's own loader takes it from."""
    if name == INDEX or not name.endswith(".json"):
        return None
    return name[: -len(".json")] or None


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


__all__ = ["COUNT_MEANING", "INDEX", "NO_TIME", "OLD_FORMAT", "ContinueSessionsParser"]
