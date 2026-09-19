"""Parse Codex CLI rollout files.

One record per line, each `{timestamp, type, payload}`. Four record types carry the
conversation and two carry context, and the shape of the fifth is the reason this parser
needs explaining: `event_msg` mirrors `response_item`, so mapping both as turns would show
every turn of the conversation twice. Each one becomes an event of its own anyway, at a
kind the conversation views do not read from, so the record keeps its line and its bytes in
the case without inflating the conversation.

Two other things the format does that a reader has to know about. A `compacted` record
means the conversation was rewritten to fit a context window, which is the usual
explanation for an apparent gap in a transcript and therefore has to be an event rather
than a skip. And the rollout files are compressed after seven days, so the uncompressed
ones are the recent week and everything older sits beside them under another extension.

**The compressed ones are read here too**, which is the whole reason this project requires
a Python with zstd in its standard library (ADR 0024). A reader that only took the plain
files would show the last seven days of a machine that has a year of conversations on it,
and would show it without saying anything was missing, which is the failure this project
treats as the worst one it can have. The compressed transcript is expanded and then read by
exactly the same code as a plain one, so a line of a year-old conversation produces the same
events as a line of yesterday's.

A locator on one of these is the line number **of the expanded transcript**, which is the
only line number the records have. The path on the event ends in the compressed extension,
so an analyst can see which it was, and checking a finding means expanding the file the same
way and counting.

The compression is done through a temporary file, so an interrupted compression leaves one
behind and the catalogue collects those too. Whether such a file is compressed depends on
when it was interrupted, so the bytes decide it here rather than the name: a file that
starts with a zstd frame is expanded and one that does not is read as the plain JSON Lines
it still is.

The mapping was ported from the viewer, which had already been written against real
rollouts, so the record and item types here are the ones that exist rather than the ones
that seemed likely.
"""

from __future__ import annotations

import compression.zstd as zstd
import json
import tempfile
from collections.abc import Iterator
from pathlib import Path
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
from agentforensics.parsers.sqlite_store import ZSTD_MAGIC

# How large one transcript is allowed to expand to. A rollout of a long session is tens of
# megabytes, so this is generous, and it is finite because a compressed file says nothing
# about its expanded size and a case should not be fillable by one of them. Reaching it is
# reported rather than quietly truncating a conversation an analyst then reads as complete.
MAX_EXPANDED = 512 * 1024 * 1024


def _expand(source: Path, destination: Path) -> tuple[Path | None, str | None]:
    """The transcript as plain JSON Lines, and what was wrong with getting there.

    Returns the path to read and a problem, either of which can be present on its own: a
    frame that stops early still expands the lines before the break, and those lines are
    evidence. Only a file that produced nothing comes back without a path.

    The bytes decide whether to expand, not the name. A file left behind by an interrupted
    compression can be either form depending on when it was interrupted, and the catalogue
    collects those files on purpose.
    """
    try:
        with source.open("rb") as handle:
            head = handle.read(len(ZSTD_MAGIC))
    except OSError as error:
        return None, f"the transcript could not be read: {error}"
    if head != ZSTD_MAGIC:
        # Not compressed, whatever the extension says. Read where it lies, which also means
        # no copy of a transcript is made for no reason.
        return source, None

    written = 0
    problem: str | None = None
    # Fed chunk by chunk through the incremental decompressor rather than read through a
    # file object, and the difference is the whole point of the branch below it: a stream
    # reader raises on a truncated frame and loses everything it had decoded, while this
    # one has already written it. A cut-off transcript is exactly the case where the
    # records before the cut are what an investigation has left.
    decompressor = zstd.ZstdDecompressor()
    try:
        with source.open("rb") as handle, destination.open("wb") as out:
            while chunk := handle.read(1024 * 1024):
                try:
                    piece = decompressor.decompress(chunk)
                except zstd.ZstdError as error:
                    problem = (
                        "the compressed transcript stopped part way through: "
                        f"{' '.join(str(error).split())}. The records before that point "
                        "are in the case and the ones after it are not"
                    )
                    break
                if written + len(piece) > MAX_EXPANDED:
                    out.write(piece[: MAX_EXPANDED - written])
                    written = MAX_EXPANDED
                    problem = (
                        f"this transcript expands past the ingest limit of {MAX_EXPANDED} "
                        "bytes, so the records after that point are not in the case. The "
                        "compressed file is in the bundle, at the path in this event's "
                        "provenance"
                    )
                    break
                out.write(piece)
                written += len(piece)
            else:
                if not decompressor.eof:
                    # The file ended before the frame did, which is what an interrupted
                    # compression leaves behind. Said in the same words as a frame that
                    # errored, because to an analyst it is the same fact.
                    problem = (
                        "the compressed transcript stopped part way through: the file ends "
                        "before the frame does. The records before that point are in the "
                        "case and the ones after it are not"
                    )
    except OSError as error:
        problem = f"the transcript could not be expanded: {error}"
    if not written:
        return None, problem or "the compressed transcript expanded to nothing"
    return destination, problem


class CodexParser:
    """Rollouts, archived sessions and the prompt history."""

    name = "codex"

    _ROLLOUTS = frozenset({"codex.rollouts", "codex.archived_sessions"})
    _COMPRESSED = frozenset({"codex.rollouts_compressed"})
    _HISTORY = frozenset({"codex.prompt_history"})

    def handles(self, artifact_id: str | None) -> bool:
        return (
            artifact_id in self._ROLLOUTS
            or artifact_id in self._COMPRESSED
            or artifact_id in self._HISTORY
        )

    def parse(self, context: ParseContext) -> Iterator[Event]:
        if context.artifact_id in self._HISTORY:
            yield from self._history(context)
            return
        if context.artifact_id in self._COMPRESSED:
            yield from self._compressed(context)
            return
        yield from self._rollout(context)

    def _compressed(self, context: ParseContext) -> Iterator[Event]:
        """A rollout that was compressed after its seven days, read as if it were not."""
        with tempfile.TemporaryDirectory(prefix="afx-codex-") as workspace:
            expanded, problem = _expand(context.local_path, Path(workspace) / "rollout.jsonl")
            if expanded is None:
                yield unparsed(
                    context.provenance("file"),
                    context.agent,
                    None,
                    problem or "the compressed transcript could not be expanded",
                    user=context.user,
                    host=context.host,
                )
                return
            yield from self._rollout(context, path=expanded)
            if problem:
                # The lines that did expand are already in the case above. This says where
                # the reading stopped, which is the difference between a conversation that
                # ended and a file that was cut off.
                yield unparsed(
                    context.provenance("file"),
                    context.agent,
                    None,
                    problem,
                    user=context.user,
                    host=context.host,
                )

    def _rollout(self, context: ParseContext, path: Path | None = None) -> Iterator[Event]:
        # Session-wide facts arrive in their own records and apply to everything after
        # them, so they are carried forward rather than looked up per event.
        state: dict[str, Any] = {"cwd": None, "branch": None, "model": None, "session_id": None}

        for line in iter_lines(path if path is not None else context.local_path):
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
                # A mirror of a response_item, so mapping it as a turn would show every
                # turn of the conversation twice. It is still a line on disk, and a record
                # is never dropped, so it becomes one event of its own at a kind the
                # conversation views do not read from: the record stays in the case with
                # its line and its bytes, and the conversation stays honest. The subtype
                # goes into the payload because a subtype nobody has seen before is how a
                # format change announces itself.
                #
                # The generated Velociraptor artifact maps this record exactly the same
                # way, one row per line marked mirrored_event_msg. That is deliberate:
                # scripts/check_velociraptor_vql.py compares the two readings record for
                # record, and the two producers of this one format have to agree on which
                # records exist.
                subtype = str(payload.get("type") or "(no subtype)")
                yield Event(
                    kind="config.snapshot",
                    provenance=context.provenance(line.locator),
                    agent=self.name,
                    raw=record,
                    ts_utc=ts,
                    ts_precision=precision,
                    ts_source="timestamp" if ts else None,
                    actor="system",
                    client="codex-cli",
                    user=context.user,
                    host=context.host,
                    session_id=state["session_id"],
                    project_path=state["cwd"],
                    git_branch=state["branch"],
                    payload={
                        "text": f"an event_msg record of subtype {subtype}, which mirrors "
                        "a response_item and is therefore kept as a record rather than "
                        "mapped as a turn: " + text_of(payload),
                        "mirrored_event_msg": True,
                        "item_type": subtype,
                        "models": [{"model": state["model"]}] if state["model"] else [],
                    },
                    parse_problem=note,
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
