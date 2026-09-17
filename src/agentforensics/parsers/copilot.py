"""Parse GitHub Copilot CLI session event logs.

One record per line, each an envelope of `{type, id, timestamp, data}`. The event types are
lifecycle rather than message shapes, which makes this the cleanest of the three formats to
map: a user message, an assistant message, a tool starting and a tool finishing are each
their own type.

Two things worth knowing about it. The model is announced by a `session.model_change` event
and then applies to everything after it, so a case that wants to know which model wrote a
turn has to carry that state forward rather than looking at the turn. And a tool call from
an MCP server names the server in its own field rather than encoding it in the tool name,
which is more useful than the convention the other agents use: there is no prefix to parse
and no ambiguity about which part is the server.

The mapping was ported from the viewer, which had already been written against real event
logs, so the event types here are the ones that exist.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from agentforensics.model import Event, unparsed
from agentforensics.parsers.base import (
    ParseContext,
    first_word,
    iter_lines,
    normalise_ts,
    text_of,
)


class CopilotParser:
    """The per-session event log."""

    name = "copilot"

    _ARTIFACTS = frozenset({"copilot.session_event_log"})

    def handles(self, artifact_id: str | None) -> bool:
        return artifact_id in self._ARTIFACTS

    def parse(self, context: ParseContext) -> Iterator[Event]:
        state: dict[str, Any] = {
            "model": None,
            "session_id": _session_from_path(context),
            "cwd": None,
        }

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
            record = line.value
            ts, precision, note = normalise_ts(record.get("timestamp"))
            data = record.get("data") if isinstance(record.get("data"), dict) else {}
            event_type = str(record.get("type") or "")

            if data.get("model"):
                state["model"] = data["model"]
            if data.get("newModel"):
                state["model"] = data["newModel"]
            if data.get("cwd") or data.get("workingDirectory"):
                state["cwd"] = data.get("cwd") or data.get("workingDirectory")
            if data.get("sessionId"):
                state["session_id"] = data["sessionId"]

            common: dict[str, Any] = {
                "ts_utc": ts,
                "ts_precision": precision,
                "ts_source": "timestamp" if ts else None,
                "user": context.user,
                "host": context.host,
                "client": "copilot-cli",
                "session_id": state["session_id"],
                "project_path": state["cwd"],
            }
            models = [{"model": state["model"]}] if state["model"] else []

            emitted = list(
                self._map(context, line, record, data, event_type, state, models, common, note)
            )
            if emitted:
                yield from emitted
                continue

            yield unparsed(
                context.provenance(line.locator),
                self.name,
                record,
                f"event type {event_type!r} is not one this parser maps",
                ts_utc=ts,
                ts_precision=precision,
                ts_source="timestamp" if ts else None,
                user=context.user,
                session_id=state["session_id"],
                project_path=state["cwd"],
            )

    def _map(
        self,
        context: ParseContext,
        line: Any,
        record: dict[str, Any],
        data: dict[str, Any],
        event_type: str,
        state: dict[str, Any],
        models: list[dict[str, Any]],
        common: dict[str, Any],
        note: str | None,
    ) -> Iterator[Event]:
        if event_type == "session.start":
            yield Event(
                kind="session.start",
                provenance=context.provenance(line.locator),
                agent=self.name,
                raw=record,
                actor="system",
                payload={"version": data.get("copilotVersion"), "models": models},
                parse_problem=note,
                **common,
            )
            return

        if event_type in ("session.end", "session.task_complete"):
            yield Event(
                kind="session.end",
                provenance=context.provenance(line.locator),
                agent=self.name,
                raw=record,
                actor="system",
                payload={"text": text_of(data.get("summary")), "models": models},
                parse_problem=note,
                **common,
            )
            return

        if event_type == "session.model_change":
            # Its own event rather than only a state update, because which model was in use
            # when is a question a case gets asked and this record is the only answer.
            yield Event(
                kind="config.snapshot",
                provenance=context.provenance(line.locator),
                agent=self.name,
                raw=record,
                actor="user",
                payload={
                    "text": f"model changed to {data.get('newModel')}",
                    "models": [{"model": data.get("newModel")}] if data.get("newModel") else [],
                    "previous_model": data.get("previousModel") or data.get("oldModel"),
                },
                parse_problem=note,
                **common,
            )
            return

        if event_type == "user.message":
            yield Event(
                kind="user.prompt",
                provenance=context.provenance(line.locator),
                agent=self.name,
                raw=record,
                actor="user",
                payload={"text": text_of(data.get("content")), "models": models},
                parse_problem=note,
                **common,
            )
            return

        if event_type == "assistant.message":
            yield Event(
                kind="assistant.text",
                provenance=context.provenance(line.locator),
                agent=self.name,
                raw=record,
                actor="assistant",
                payload={"text": text_of(data.get("content")), "models": models},
                parse_problem=note,
                **common,
            )
            return

        if event_type == "reasoning":
            yield Event(
                kind="assistant.thinking",
                provenance=context.provenance(line.locator),
                agent=self.name,
                raw=record,
                actor="assistant",
                payload={"text": text_of(data.get("content")), "models": models},
                parse_problem=note,
                **common,
            )
            return

        if event_type == "tool.execution_start":
            yield from self._tool_start(context, line, record, data, models, common, note)
            return

        if event_type == "tool.execution_complete":
            yield Event(
                kind="tool.result",
                provenance=context.provenance(line.locator),
                agent=self.name,
                raw=record,
                actor="tool",
                payload={
                    "tool_use_id": data.get("toolCallId"),
                    "tool": data.get("toolName"),
                    "is_error": data.get("success") is False,
                    "text": text_of(data.get("result")),
                    "models": models,
                },
                parse_problem=note,
                **common,
            )
            return

        if event_type.startswith("subagent."):
            # A subagent is another agent run inside this one, and its own work may never
            # appear in this file. Recorded so that a case knows to look for it rather than
            # treating the gap as the end of the conversation.
            yield Event(
                kind="session.start" if event_type == "subagent.started" else "session.end",
                provenance=context.provenance(line.locator),
                agent=self.name,
                raw=record,
                actor="system",
                payload={
                    "text": f"{event_type}: "
                    + str(data.get("agentDisplayName") or data.get("agentName") or "")
                    + (f" ({data['error']})" if data.get("error") else ""),
                    "subagent": data.get("agentName"),
                    "models": models,
                },
                parse_problem=note,
                **common,
            )
            return

        if event_type in ("permission.request", "permission.decision", "tool.permission"):
            yield Event(
                kind="permission.decision",
                provenance=context.provenance(line.locator),
                agent=self.name,
                raw=record,
                actor="user",
                payload={
                    "permissions": [
                        {
                            "mode": data.get("mode"),
                            "decision": str(
                                data.get("decision") or data.get("outcome") or "unknown"
                            ),
                            "subject": data.get("toolName") or data.get("subject"),
                        }
                    ],
                    "models": models,
                },
                parse_problem=note,
                **common,
            )
            return

    def _tool_start(
        self,
        context: ParseContext,
        line: Any,
        record: dict[str, Any],
        data: dict[str, Any],
        models: list[dict[str, Any]],
        common: dict[str, Any],
        note: str | None,
    ) -> Iterator[Event]:
        arguments = data.get("arguments")
        if not isinstance(arguments, dict):
            arguments = (
                {"command": data["command"]}
                if data.get("command")
                else ({"arguments": arguments} if arguments is not None else {})
            )
        name = str(data.get("toolName") or "tool")
        payload: dict[str, Any] = {
            "tool": name,
            "tool_use_id": data.get("toolCallId"),
            "input": arguments,
            "models": models,
        }
        # This agent names the MCP server in its own field instead of encoding it in the
        # tool name, so there is no prefix to parse and no ambiguity about where the server
        # name ends.
        is_mcp = bool(data.get("mcpServerName"))
        if is_mcp:
            payload["mcp"] = [
                {
                    "server": str(data["mcpServerName"]),
                    "tool": str(data.get("mcpToolName") or name),
                }
            ]
        yield Event(
            kind="mcp.call" if is_mcp else "tool.call",
            provenance=context.provenance(line.locator),
            agent=self.name,
            raw=record,
            actor="assistant",
            payload=payload,
            parse_problem=note,
            **common,
        )

        command = arguments.get("command")
        if command:
            text = (
                " ".join(str(part) for part in command)
                if isinstance(command, list)
                else str(command)
            )
            yield Event(
                kind="command.exec",
                provenance=context.provenance(f"{line.locator}#exec"),
                agent=self.name,
                raw=record,
                actor="assistant",
                payload={
                    "tool": name,
                    "commands": [
                        {
                            "command": text,
                            "executable": first_word(text),
                            "cwd": arguments.get("cwd") or common.get("project_path"),
                        }
                    ],
                },
                parse_problem=note,
                **common,
            )


def _session_from_path(context: ParseContext) -> str | None:
    """The session id, taken from the directory the event log sits in.

    The records themselves do not always carry it, and the directory name is the session
    id: the vendor's own documentation describes one directory per session. Reading it from
    the path is what lets two sessions collected into one case stay apart.
    """
    parts = context.original_path.replace("\\", "/").split("/")
    if len(parts) >= 2 and parts[-1].endswith(".jsonl"):
        return parts[-2] or None
    return None


__all__ = ["CopilotParser"]
