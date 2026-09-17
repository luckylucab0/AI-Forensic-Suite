"""Parse Claude Code's on-disk records.

Three formats, all line-delimited JSON, all with the same problem: the record types are not
a closed set. The vendor adds one when it adds a feature, and a transcript written by a
version newer than this parser will contain types it has never seen. So the mapping is
written the other way round from the usual: a type this module recognises becomes the
events it stands for, and everything else becomes an unparsed record carrying the original
line. A transcript from next year's version therefore still produces a readable timeline
with visible holes, rather than an empty one.

The one structural thing worth knowing before reading the code: a single assistant record
holds a list of content blocks, and one record legitimately produces several events. A turn
that thinks, answers and calls two tools is five events sharing a line number, which is why
the event id hashes the kind along with the locator.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from agentforensics.model import Event, unparsed
from agentforensics.parsers.base import (
    Line,
    ParseContext,
    first_word,
    iter_lines,
    normalise_ts,
    text_of,
)

# Tool names whose effect is worth a facet row, mapped to what they do. Taken from the
# vendor's own tool reference. A name not in here still produces a tool.call event with its
# input kept verbatim: the list decides what gets an indexed facet, never what is recorded.
_FILE_READ = ("Read", "NotebookRead", "Glob", "Grep")
_FILE_WRITE = ("Write", "Edit", "MultiEdit", "NotebookEdit")
_COMMAND = ("Bash", "BashOutput", "KillShell")
_NETWORK = ("WebFetch", "WebSearch")


class ClaudeCodeParser:
    """Transcripts, the prompt history file and subagent transcripts."""

    name = "claude_code"

    # Taken from the catalogue's own ids. Four transcript entries rather than one because
    # the vendor keeps conversations in four places: the live session, a session set aside
    # when it was superseded, a subagent's own transcript, and a workflow run's journal.
    # All four are the same line-delimited format, and leaving any of them out would drop a
    # conversation that is on disk.
    _TRANSCRIPTS = frozenset(
        {
            "claude_code.transcripts",
            "claude_code.transcripts_set_aside",
            "claude_code.subagent_transcripts",
            "claude_code.workflow_runs",
        }
    )
    _HISTORY = frozenset({"claude_code.history_jsonl"})

    def handles(self, artifact_id: str | None) -> bool:
        return artifact_id in self._TRANSCRIPTS or artifact_id in self._HISTORY

    def parse(self, context: ParseContext) -> Iterator[Event]:
        if context.artifact_id in self._HISTORY:
            yield from self._history(context)
            return
        yield from self._transcript(context)

    # ------------------------------------------------------------- transcripts

    def _transcript(self, context: ParseContext) -> Iterator[Event]:
        for line in iter_lines(context.local_path):
            if not line.ok:
                yield unparsed(
                    context.provenance(line.locator),
                    self.name,
                    line.text or None,
                    line.problem or "the line could not be read",
                    user=context.user,
                    host=context.host,
                )
                continue
            yield from self._record(context, line, line.value)

    def _record(self, context: ParseContext, line: Line, record: dict[str, Any]) -> Iterator[Event]:
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
            # The vendor's own word for how the agent was driven: a terminal, an editor
            # extension, the desktop application. It is how a case tells apart two sessions
            # that share a transcript directory.
            "client": record.get("entrypoint") or record.get("client"),
        }
        record_type = record.get("type")
        message = _mapping(record.get("message"))
        model = message.get("model")

        if record_type == "user":
            content = message.get("content")
            # A user record whose content is a tool result is the harness reporting back,
            # not the person typing. Attributing it to the user would put the output of
            # every command in the analyst's list of what the user asked for.
            results = _blocks(content, "tool_result")
            if results:
                for index, block in enumerate(results):
                    yield Event(
                        kind="tool.result",
                        provenance=context.provenance(f"{line.locator}#result{index}"),
                        agent=self.name,
                        raw=record,
                        actor="tool",
                        payload={
                            "tool_use_id": block.get("tool_use_id"),
                            "is_error": bool(block.get("is_error")),
                            "text": text_of(block.get("content")),
                        },
                        parse_problem=note,
                        **common,
                    )
                return
            yield Event(
                kind="user.prompt",
                provenance=context.provenance(line.locator),
                agent=self.name,
                raw=record,
                actor="user",
                payload={"text": text_of(content), "uuid": record.get("uuid")},
                parse_problem=note,
                **common,
            )
            return

        if record_type == "assistant":
            yield from self._assistant(context, line, record, message, model, common, note)
            return

        if record_type == "permission-mode":
            # The agent's approval mode changing mid-session, which is the record the
            # question "were safety controls bypassed" turns on.
            yield Event(
                kind="permission.decision",
                provenance=context.provenance(line.locator),
                agent=self.name,
                raw=record,
                actor="user",
                payload={
                    "permissions": [{"mode": record.get("mode"), "decision": "mode_change"}],
                    "mode": record.get("mode"),
                },
                parse_problem=note,
                **common,
            )
            return

        if record_type in ("summary", "compact", "compact_boundary"):
            yield Event(
                kind="session.end",
                provenance=context.provenance(line.locator),
                agent=self.name,
                raw=record,
                actor="system",
                payload={"text": text_of(record.get("summary") or record.get("payload"))},
                parse_problem=note,
                **common,
            )
            return

        # A type this parser does not know. Kept as a record rather than guessed at, and
        # with whatever timestamp and session it carried, so it still sorts into the
        # timeline in the right place and an analyst can see there was something here.
        yield unparsed(
            context.provenance(line.locator),
            self.name,
            record,
            f"record type {record_type!r} is not one this parser maps",
            ts_utc=ts,
            ts_precision=precision,
            ts_source="timestamp" if ts else None,
            user=context.user,
            host=context.host,
            session_id=record.get("sessionId"),
            project_path=record.get("cwd"),
            git_branch=record.get("gitBranch"),
            client=record.get("entrypoint"),
        )

    def _assistant(
        self,
        context: ParseContext,
        line: Line,
        record: dict[str, Any],
        message: dict[str, Any],
        model: str | None,
        common: dict[str, Any],
        note: str | None,
    ) -> Iterator[Event]:
        content = message.get("content")
        usage = _mapping(message.get("usage"))
        models = (
            [
                {
                    "model": model,
                    "input_tokens": usage.get("input_tokens"),
                    "output_tokens": usage.get("output_tokens"),
                }
            ]
            if model
            else []
        )
        blocks = content if isinstance(content, list) else [{"type": "text", "text": content}]
        emitted = False

        for index, block in enumerate(blocks):
            if not isinstance(block, dict):
                yield unparsed(
                    context.provenance(f"{line.locator}#block{index}"),
                    self.name,
                    block,
                    f"a content block that is a {type(block).__name__}, not an object",
                    ts_utc=common["ts_utc"],
                    ts_precision=common["ts_precision"],
                    ts_source=common["ts_source"],
                    user=context.user,
                    session_id=common["session_id"],
                )
                emitted = True
                continue
            block_type = block.get("type")
            if block_type == "thinking":
                emitted = True
                yield Event(
                    kind="assistant.thinking",
                    provenance=context.provenance(f"{line.locator}#think{index}"),
                    agent=self.name,
                    raw=record,
                    actor="assistant",
                    payload={"text": text_of(block), "models": models},
                    parse_problem=note,
                    **common,
                )
            elif block_type == "text":
                emitted = True
                yield Event(
                    kind="assistant.text",
                    provenance=context.provenance(f"{line.locator}#text{index}"),
                    agent=self.name,
                    raw=record,
                    actor="assistant",
                    payload={
                        "text": text_of(block),
                        "models": models,
                        "message_id": message.get("id"),
                    },
                    parse_problem=note,
                    **common,
                )
            elif block_type == "tool_use":
                emitted = True
                yield from self._tool_use(context, line, record, block, index, models, common, note)
            else:
                emitted = True
                yield unparsed(
                    context.provenance(f"{line.locator}#block{index}"),
                    self.name,
                    block,
                    f"content block type {block_type!r} is not one this parser maps",
                    ts_utc=common["ts_utc"],
                    ts_precision=common["ts_precision"],
                    ts_source=common["ts_source"],
                    user=context.user,
                    session_id=common["session_id"],
                )

        if not emitted:
            # An assistant record with no content at all. Rare, and a record all the same.
            yield unparsed(
                context.provenance(line.locator),
                self.name,
                record,
                "an assistant record with no content blocks",
                ts_utc=common["ts_utc"],
                ts_precision=common["ts_precision"],
                ts_source=common["ts_source"],
                user=context.user,
                session_id=common["session_id"],
            )

    def _tool_use(
        self,
        context: ParseContext,
        line: Line,
        record: dict[str, Any],
        block: dict[str, Any],
        index: int,
        models: list[dict[str, Any]],
        common: dict[str, Any],
        note: str | None,
    ) -> Iterator[Event]:
        """One tool call, as the call itself plus whatever it did.

        Two events rather than one where the tool had an effect, because an analyst asks
        two different questions: what did the agent try, and what got touched. The call
        keeps the input verbatim; the effect carries the facets.
        """
        name = str(block.get("name") or "")
        arguments = _mapping(block.get("input"))
        payload: dict[str, Any] = {
            "tool": name,
            "tool_use_id": block.get("id"),
            "input": arguments,
            "models": models,
        }

        # An MCP tool is named for the server it came from, which the vendor spells with
        # this prefix. Recorded as a facet so "which external servers did this agent reach"
        # is an indexed query rather than a scan over tool names.
        if name.startswith("mcp__"):
            parts = name.split("__")
            payload["mcp"] = [
                {"server": parts[1] if len(parts) > 1 else "", "tool": "__".join(parts[2:])}
            ]

        yield Event(
            kind="mcp.call" if name.startswith("mcp__") else "tool.call",
            provenance=context.provenance(f"{line.locator}#tool{index}"),
            agent=self.name,
            raw=record,
            actor="assistant",
            payload=payload,
            parse_problem=note,
            **common,
        )

        effect_kind, effect_payload = self._effect(name, arguments)
        if effect_kind:
            yield Event(
                kind=effect_kind,
                provenance=context.provenance(f"{line.locator}#effect{index}"),
                agent=self.name,
                raw=record,
                actor="assistant",
                payload={"tool": name, "tool_use_id": block.get("id"), **effect_payload},
                parse_problem=note,
                **common,
            )

    def _effect(self, name: str, arguments: dict[str, Any]) -> tuple[str | None, dict[str, Any]]:
        """What a named tool did, in the model's own terms."""
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
                "description": arguments.get("description"),
            }
        if name in _FILE_WRITE:
            path = (
                arguments.get("file_path")
                or arguments.get("path")
                or arguments.get("notebook_path")
            )
            if not path:
                return None, {}
            body = arguments.get("content") or arguments.get("new_string") or ""
            return "file.write", {
                "files": [
                    {"path": str(path), "operation": "write", "bytes": len(str(body)) or None}
                ]
            }
        if name in _FILE_READ:
            path = arguments.get("file_path") or arguments.get("path") or arguments.get("pattern")
            if not path:
                return None, {}
            return "file.read", {"files": [{"path": str(path), "operation": "read"}]}
        if name in _NETWORK:
            url = arguments.get("url") or arguments.get("query")
            if not url:
                return None, {}
            return "network.request", {
                "network": [{"host": _host_of(str(url)), "url": str(url), "method": "GET"}]
            }
        return None, {}

    # ---------------------------------------------------------- prompt history

    def _history(self, context: ParseContext) -> Iterator[Event]:
        """The arrow-up history: what the user typed, without the conversation around it.

        Worth parsing separately from the transcripts because it outlives them. A user who
        deleted a session still has its prompts here, which makes a prompt with no matching
        transcript one of the more interesting things a case can contain.
        """
        for line in iter_lines(context.local_path):
            if not line.ok:
                yield unparsed(
                    context.provenance(line.locator),
                    self.name,
                    line.text or None,
                    line.problem or "the line could not be read",
                    user=context.user,
                    host=context.host,
                )
                continue
            record = _mapping(line.value)
            ts, precision, note = normalise_ts(record.get("timestamp"))
            yield Event(
                kind="prompt.history",
                provenance=context.provenance(line.locator),
                agent=self.name,
                raw=record,
                ts_utc=ts,
                ts_precision=precision,
                ts_source="timestamp" if ts else None,
                actor="user",
                user=context.user,
                host=context.host,
                project_path=record.get("project"),
                payload={"text": text_of(record.get("display"))},
                parse_problem=note,
            )


def _mapping(value: Any) -> dict[str, Any]:
    """A field that should be an object, as one.

    Agents write null where they mean an empty object, and change a field's shape between
    versions. Coercing here keeps every call site free of the check and means a surprising
    shape costs an empty mapping rather than an exception that abandons the rest of the
    file.
    """
    return value if isinstance(value, dict) else {}


def _blocks(content: Any, block_type: str) -> list[dict[str, Any]]:
    if not isinstance(content, list):
        return []
    return [b for b in content if isinstance(b, dict) and b.get("type") == block_type]


def _host_of(url: str) -> str:
    """The host part of a URL, without importing a parser for one field.

    Deliberately simple: a value that is not a URL at all, which is what a search query is,
    comes back as itself rather than as an empty string, so the facet row still carries
    something an analyst can read.
    """
    text = url.split("://", 1)[-1]
    return text.split("/", 1)[0].split("?", 1)[0]


__all__ = ["ClaudeCodeParser"]
