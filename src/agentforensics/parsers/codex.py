"""Parse Codex CLI rollout files.

One record per line, each `{timestamp, type, payload}`. Four record types carry the
conversation and two carry context, and the shape of the fifth is the reason this parser
needs explaining: `event_msg` mirrors `response_item`, so mapping both would double every
turn in the timeline. They are counted by subtype and reported once per file as a single
event instead, which keeps the record visible without inflating the conversation.

Two other things the format does that a reader has to know about. A `compacted` record
means the conversation was rewritten to fit a context window, which is the usual
explanation for an apparent gap in a transcript and therefore has to be an event rather
than a skip. And the rollout files are compressed after seven days, so the ones a
collection finds uncompressed are the recent week: an absent older conversation is the
documented default rather than anything anybody did.

The mapping was ported from the viewer, which had already been written against real
rollouts, so the record and item types here are the ones that exist rather than the ones
that seemed likely.
"""

from __future__ import annotations

import json
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


class CodexParser:
    """Rollouts, archived sessions and the prompt history."""

    name = "codex"

    _ROLLOUTS = frozenset({"codex.rollouts", "codex.archived_sessions"})
    _HISTORY = frozenset({"codex.prompt_history"})

    def handles(self, artifact_id: str | None) -> bool:
        return artifact_id in self._ROLLOUTS or artifact_id in self._HISTORY

    def parse(self, context: ParseContext) -> Iterator[Event]:
        if context.artifact_id in self._HISTORY:
            yield from self._history(context)
            return
        yield from self._rollout(context)

    def _rollout(self, context: ParseContext) -> Iterator[Event]:
        # Session-wide facts arrive in their own records and apply to everything after
        # them, so they are carried forward rather than looked up per event.
        state: dict[str, Any] = {"cwd": None, "branch": None, "model": None, "session_id": None}
        mirrored: dict[str, int] = {}
        last_ts: str | None = None
        last_precision = "absent"

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
            if ts:
                last_ts, last_precision = ts, precision
            record_type = record.get("type")
            payload = _mapping(record.get("payload"))

            if record_type == "session_meta":
                yield from self._session_meta(
                    context, line, record, payload, state, ts, precision, note
                )
                continue
            if record_type == "turn_context":
                if payload.get("cwd"):
                    state["cwd"] = payload["cwd"]
                if payload.get("model"):
                    state["model"] = payload["model"]
                continue
            if record_type == "compacted":
                yield Event(
                    kind="session.end",
                    provenance=context.provenance(line.locator),
                    agent=self.name,
                    raw=record,
                    ts_utc=ts,
                    ts_precision=precision,
                    ts_source="timestamp" if ts else None,
                    actor="system",
                    user=context.user,
                    host=context.host,
                    session_id=state["session_id"],
                    project_path=state["cwd"],
                    git_branch=state["branch"],
                    payload={
                        "text": "the conversation was compacted, so earlier turns were "
                        "rewritten or removed from this file: " + text_of(payload.get("message")),
                        "compaction": True,
                    },
                    parse_problem=note,
                )
                continue
            if record_type == "event_msg":
                mirrored[str(payload.get("type") or "(no subtype)")] = (
                    mirrored.get(str(payload.get("type") or "(no subtype)"), 0) + 1
                )
                continue
            if record_type == "response_item":
                yield from self._response_item(
                    context, line, record, payload, state, ts, precision, note
                )
                continue

            yield unparsed(
                context.provenance(line.locator),
                self.name,
                record,
                f"record type {record_type!r} is not one this parser maps",
                ts_utc=ts,
                ts_precision=precision,
                ts_source="timestamp" if ts else None,
                user=context.user,
                session_id=state["session_id"],
                project_path=state["cwd"],
            )

        if mirrored:
            # One event for the whole file, so the records are accounted for without
            # doubling the conversation. The subtypes are kept because a new one appearing
            # is how a format change shows up.
            total = sum(mirrored.values())
            yield Event(
                kind="config.snapshot",
                provenance=context.provenance("event_msg-summary"),
                agent=self.name,
                raw={"event_msg_counts": mirrored},
                ts_utc=last_ts,
                ts_precision=last_precision if last_ts else "absent",  # type: ignore[arg-type]
                ts_source="the last timestamp in the file" if last_ts else None,
                actor="system",
                user=context.user,
                host=context.host,
                session_id=state["session_id"],
                project_path=state["cwd"],
                payload={
                    "text": f"{total} event_msg record(s) in this file mirror the "
                    "response_item records and are counted rather than mapped, so the "
                    "conversation is not doubled: "
                    + ", ".join(f"{key} x{mirrored[key]}" for key in sorted(mirrored)),
                    "event_msg_counts": mirrored,
                },
            )

    def _session_meta(
        self,
        context: ParseContext,
        line: Line,
        record: dict[str, Any],
        payload: dict[str, Any],
        state: dict[str, Any],
        ts: str | None,
        precision: str,
        note: str | None,
    ) -> Iterator[Event]:
        git = _mapping(payload.get("git"))
        state["cwd"] = payload.get("cwd") or state["cwd"]
        state["branch"] = git.get("branch") or state["branch"]
        state["model"] = payload.get("model") or payload.get("model_provider") or state["model"]
        state["session_id"] = payload.get("id") or payload.get("session_id") or state["session_id"]
        yield Event(
            kind="session.start",
            provenance=context.provenance(line.locator),
            agent=self.name,
            raw=record,
            ts_utc=ts,
            ts_precision=precision,  # type: ignore[arg-type]
            ts_source="timestamp" if ts else None,
            actor="system",
            client="codex-cli",
            user=context.user,
            host=context.host,
            session_id=state["session_id"],
            project_path=state["cwd"],
            git_branch=state["branch"],
            payload={
                "version": payload.get("cli_version"),
                "originator": payload.get("originator"),
                "instructions": _instructions(payload),
                "models": [{"model": state["model"]}] if state["model"] else [],
            },
            parse_problem=note,
        )

    def _response_item(
        self,
        context: ParseContext,
        line: Line,
        record: dict[str, Any],
        item: dict[str, Any],
        state: dict[str, Any],
        ts: str | None,
        precision: str,
        note: str | None,
    ) -> Iterator[Event]:
        common: dict[str, Any] = {
            "ts_utc": ts,
            "ts_precision": precision,
            "ts_source": "timestamp" if ts else None,
            "user": context.user,
            "host": context.host,
            "client": "codex-cli",
            "session_id": state["session_id"],
            "project_path": state["cwd"],
            "git_branch": state["branch"],
        }
        models = [{"model": state["model"]}] if state["model"] else []
        item_type = item.get("type")

        if item_type == "message":
            role = item.get("role")
            yield Event(
                kind="user.prompt" if role == "user" else "assistant.text",
                provenance=context.provenance(line.locator),
                agent=self.name,
                raw=record,
                actor="user" if role == "user" else "assistant",
                payload={"text": text_of(item.get("content")), "models": models},
                parse_problem=note,
                **common,
            )
            return

        if item_type == "reasoning":
            text = text_of(item.get("summary")) or text_of(item.get("content"))
            yield Event(
                kind="assistant.thinking",
                provenance=context.provenance(line.locator),
                agent=self.name,
                raw=record,
                actor="assistant",
                payload={"text": text, "models": models},
                parse_problem=note,
                **common,
            )
            return

        if item_type in ("function_call", "custom_tool_call", "local_shell_call"):
            name, arguments, problem = _call_arguments(item, item_type)
            payload: dict[str, Any] = {
                "tool": name,
                "tool_use_id": item.get("call_id") or item.get("id"),
                "input": arguments,
                "models": models,
            }
            yield Event(
                kind="tool.call",
                provenance=context.provenance(line.locator),
                agent=self.name,
                raw=record,
                actor="assistant",
                payload=payload,
                parse_problem=note or problem,
                **common,
            )
            command = arguments.get("command")
            if command:
                # A shell call is the one item type whose effect is unambiguous from the
                # record alone, which is why it gets its own event and a facet row. The
                # command can be a list, which is how the sandbox spells argv.
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
                                "cwd": arguments.get("workdir")
                                or arguments.get("cwd")
                                or state["cwd"],
                            }
                        ],
                    },
                    parse_problem=note,
                    **common,
                )
            return

        if item_type in ("function_call_output", "custom_tool_call_output"):
            output = item.get("output")
            failed = isinstance(output, dict) and output.get("success") is False
            yield Event(
                kind="tool.result",
                provenance=context.provenance(line.locator),
                agent=self.name,
                raw=record,
                actor="tool",
                payload={
                    "tool_use_id": item.get("call_id"),
                    "is_error": bool(failed),
                    "text": text_of(output),
                },
                parse_problem=note,
                **common,
            )
            return

        yield unparsed(
            context.provenance(line.locator),
            self.name,
            record,
            f"response_item type {item_type!r} is not one this parser maps",
            ts_utc=ts,
            ts_precision=precision,  # type: ignore[arg-type]
            ts_source="timestamp" if ts else None,
            user=context.user,
            session_id=state["session_id"],
            project_path=state["cwd"],
        )

    def _history(self, context: ParseContext) -> Iterator[Event]:
        for line in iter_lines(context.local_path):
            if not line.ok:
                yield unparsed(
                    context.provenance(line.locator),
                    self.name,
                    line.text or None,
                    line.problem or "the line could not be read",
                    user=context.user,
                )
                continue
            record = line.value
            ts, precision, note = normalise_ts(record.get("ts") or record.get("timestamp"))
            yield Event(
                kind="prompt.history",
                provenance=context.provenance(line.locator),
                agent=self.name,
                raw=record,
                ts_utc=ts,
                ts_precision=precision,
                ts_source="ts" if ts else None,
                actor="user",
                user=context.user,
                host=context.host,
                session_id=record.get("session_id"),
                payload={"text": text_of(record.get("text") or record.get("display"))},
                parse_problem=note,
            )


def _mapping(value: Any) -> dict[str, Any]:
    """A field that should be an object, as one. See the note in the Claude Code parser."""
    return value if isinstance(value, dict) else {}


def _call_arguments(item: dict[str, Any], item_type: str) -> tuple[str, dict[str, Any], str | None]:
    """The tool's name and its arguments, and a note when they had to be salvaged.

    Each of the three call shapes spells its arguments differently, and the function-call
    one spells them as a JSON string that can be truncated by a killed process. A string
    that will not parse is kept as itself rather than discarded: a partial argument list is
    still evidence of what the agent was about to do.
    """
    name = str(item.get("name") or item_type)
    if item_type == "function_call":
        raw = item.get("arguments")
        if isinstance(raw, dict):
            return name, raw, None
        try:
            parsed = json.loads(raw or "{}")
        except (TypeError, ValueError) as exc:
            return name, {"arguments": raw}, f"the argument JSON did not parse: {exc}"
        return name, parsed if isinstance(parsed, dict) else {"arguments": parsed}, None
    if item_type == "custom_tool_call":
        value = item.get("input")
        if isinstance(value, dict):
            return name, value, None
        return name, {"input": value}, None
    action = item.get("action")
    if isinstance(action, dict):
        return name, action, None
    return name, {"command": item.get("command")}, None


def _instructions(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Instruction files the session recorded, as facet rows.

    Codex names the ones it loaded in its session metadata, which makes the
    injected-instruction question answerable from the transcript itself rather than only
    from what was collected off the disk.
    """
    out = []
    for key in ("instructions", "user_instructions", "project_doc"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            out.append({"path": value, "scope": "unknown"})
        elif isinstance(value, list):
            out.extend({"path": str(item), "scope": "unknown"} for item in value if item)
    return out


__all__ = ["CodexParser"]
