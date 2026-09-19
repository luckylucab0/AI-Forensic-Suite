"""Read a line-delimited agent log the suite has no verified mapping for, record by record.

This module exists because the two producers of the unified format disagreed, and the one
that read less was the one an analyst uses. The generated Velociraptor query returns every
record of an unmapped JSON Lines log, uninterpreted, through its `generic_jsonl`
normalizer. The analyzer had no such reading: a collected log with no parser became one
`artifact.fs` event saying the file existed and nothing at all about the nineteen thousand
records in it. So a fleet hunt over the endpoints showed a conversation and the case built
from the collection of the same endpoint showed a file name, which is the failure this
project treats as the worst one it can have (non-negotiable 6): silently showing nothing
makes an analyst conclude nothing was there.

This is the same floor `sqlite_generic` puts under the databases, and it is deliberately
the same rule. Nothing is read out of a record except what the record literally says: a
field *named* as a time is read as a time, a field *named* as a session or a working copy
is read as one, a field *named* as text is text when it is text. Everything else, which is
most of it, stays in `raw` for a person. Every event says on itself that this is an
uninterpreted reading, so the log shows up as evidence somebody still has to look at
rather than as an answer.

The field names are the ones the endpoint query reads, in the order it reads them, because
two producers of one format that disagree about which field is the timestamp are worse than
one that never claimed to know. The one place this module goes further is precision: the
query calls every time it finds a second, and `normalise_ts` here works out whether the
value was epoch seconds, epoch milliseconds or an ISO string, and says so on the event.
That is a better reading of the same field rather than a different one.

It is a floor, not a ceiling. An agent-specific parser written against a vendor source is
placed ahead of this one in `PARSERS` and takes its artifact over, exactly as the verified
SQLite parsers take a store over from the generic reader. Until somebody has read a format
against its vendor, its records are visible and marked as unread, which is the honest state
to leave a case in.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from agentforensics.model import Event, unparsed
from agentforensics.parsers.base import ParseContext, iter_lines, normalise_ts

# Every line-delimited artifact in the catalogue, written out rather than derived from the
# format field at runtime, for the reason `sqlite_generic.STORES` is written out: a parser
# is handed an artifact id and not a catalogue entry, and a log added to the catalogue
# should be read because somebody decided it should be. tests/unit/test_jsonl_generic.py
# asserts that this set is exactly the catalogue's jsonl artifacts, so adding one there
# fails CI until it is listed here.
LOGS = frozenset(
    {
        "amp.ledger",
        "chatgpt_desktop.macos_codex_home",
        "claude_code.history_jsonl",
        "claude_code.mcp_logs",
        "claude_code.subagent_transcripts",
        "claude_code.transcripts",
        "claude_code.transcripts_set_aside",
        "claude_code.workflow_runs",
        "claude_desktop.cowork_audit_log",
        "codex.archived_sessions",
        "codex.prompt_history",
        "codex.rollouts",
        "continue.dev_data",
        "copilot.session_event_log",
        "cursor.agent_transcripts_jsonl",
        "devin.acp_events",
        "factory_droid.sessions",
        "goose.sessions_jsonl_legacy",
        "hermes.sessions_dir",
        "junie.cli_sessions",
        "junie.matterhorn_project_logs",
        "kiro.acp_wire_record",
        "kiro.cli_session_files",
        "kiro.ide_session_files",
        "pi.sessions",
        "qwen_code.conversation_transcript",
        "qwen_code.prompt_terminal_ledger",
        "qwen_code.usage_history",
        "windsurf.cascade_transcripts",
    }
)

# The fields a record is read for, by exact name and in this order. These are the names the
# generated Velociraptor query reads, kept in step with it by a test, because the two
# producers of this format have to agree about which field is the timestamp of a record
# neither of them has a mapping for.
#
# Short and literal on purpose: every name added here on a hunch is a chance to attach the
# wrong time to an event, and a wrong time on a timeline is the kind of mistake that
# survives into a report.
TIME_FIELDS = ("timestamp", "ts", "createdAt", "time")
SESSION_FIELDS = ("sessionId", "session_id")
PROJECT_FIELDS = ("cwd", "workspace")
TEXT_FIELDS = ("text", "content")

# What every event out of this parser says about itself, in the words the endpoint query
# uses for the same situation. Addressed to the analyst reading the case rather than to a
# developer, and it ends with what to do about it, because a reader who does not know a
# parser is missing reads an uninterpreted record as an empty one.
UNINTERPRETED = (
    "this collection has no verified mapping for this agent log format, so the record is "
    "returned uninterpreted. Everything it contained is in raw. Re-read this log once a "
    "parser for it exists."
)


class JsonlGenericParser:
    """The reading of last resort for a line-delimited log, and the only one most have."""

    name = "jsonl_generic"

    def handles(self, artifact_id: str | None) -> bool:
        return artifact_id in LOGS

    def parse(self, context: ParseContext) -> Iterator[Event]:
        for line in iter_lines(context.local_path):
            record = line.value if line.ok else None
            if not isinstance(record, dict):
                # A syntax error, a line truncated by a process that was killed mid-write, a
                # value that is not an object, or a file that would not decode. The text is
                # kept whole and the reason travels with it, which is the same answer a
                # verified parser gives for a line it cannot read.
                yield unparsed(
                    context.provenance(line.locator),
                    context.agent,
                    line.text or None,
                    line.problem or "the line could not be read",
                    user=context.user,
                    host=context.host,
                )
                continue
            yield self._record(context, line.locator, record)

    def _record(self, context: ParseContext, locator: str, record: dict[str, Any]) -> Event:
        """One record, with only what it plainly says read out of it."""
        field, raw_time = _first(record, TIME_FIELDS)
        when, precision, note = normalise_ts(raw_time)
        text = _literal_text(record)
        return unparsed(
            context.provenance(locator),
            context.agent,
            record,
            # The timing note first if there is one, because it qualifies a value that is
            # already on the event, and then the statement that nobody has read this format.
            " ".join(part for part in (note, UNINTERPRETED) if part),
            ts_utc=when,
            ts_precision=precision,
            # Named, so that the difference between a field this suite has verified to be
            # the agent's own clock and a field that merely carries a time-like name stays
            # visible in the case.
            ts_source=f"the field named {field}" if when and field else None,
            user=context.user,
            host=context.host,
            session_id=_session(record),
            project_path=_project(record),
            payload={"text": text} if text is not None else {},
        )


def _first(record: dict[str, Any], fields: tuple[str, ...]) -> tuple[str | None, Any]:
    """The first of these field names the record carries a usable value under."""
    for field in fields:
        value = record.get(field)
        if value not in (None, "", [], {}):
            return field, value
    return None, None


def _session(record: dict[str, Any]) -> str | None:
    """A session id, only where the record names one and it is a string or a number.

    A structured value under a name like `sessionId` is something other than an id, and
    stringifying it would put a rendered object into the column a case groups conversations
    by.
    """
    _, value = _first(record, SESSION_FIELDS)
    if isinstance(value, str):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    return None


def _project(record: dict[str, Any]) -> str | None:
    """The working copy, only where the record names it as a plain path."""
    _, value = _first(record, PROJECT_FIELDS)
    return value if isinstance(value, str) else None


def _literal_text(record: dict[str, Any]) -> str | None:
    """The record's text, where the record holds text rather than a structure.

    This is the endpoint query's `TextOf` in Python, and it stops where that stops. A string
    is text. A list of typed content blocks is text when every block carries one, and is
    left alone otherwise, because a block type nobody has mapped is exactly the thing this
    module refuses to guess at. Anything else stays in `raw`, where nothing is lost: the
    whole record is there either way, and a payload built out of a guess would be the part
    an analyst quotes.
    """
    _, value = _first(record, TEXT_FIELDS)
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        inner = value.get("text")
        return inner if isinstance(inner, str) else None
    if isinstance(value, list):
        parts = []
        for item in value:
            if isinstance(item, str):
                parts.append(item)
                continue
            inner = item.get("text") if isinstance(item, dict) else None
            if not isinstance(inner, str):
                return None
            parts.append(inner)
        return "".join(parts) if parts else None
    return None


__all__ = [
    "LOGS",
    "PROJECT_FIELDS",
    "SESSION_FIELDS",
    "TEXT_FIELDS",
    "TIME_FIELDS",
    "UNINTERPRETED",
    "JsonlGenericParser",
]
