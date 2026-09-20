"""Read a plain text log line by line, reading nothing out of a line but its own timestamp.

Twenty-nine catalogue entries are text logs and nothing read any of them, so a collected
debug log reached a case as one artifact event saying the file existed and nothing at all
about the lines in it. That is the same defect the reader for line-delimited JSON was
written to fix, in the format most agents write their own diagnostics in, and these files
are worth the reading twice over. A debug log is written whether or not the conversation
was kept: it outlives a deleted transcript, it records the endpoint the agent talked to and
the tools it started, and for several products it is the only artifact with a clock in it.

The rule here is the same floor the other generic readers put down. One line is one record.
Nothing is read out of a line except the timestamp the line itself starts with, and every
event says on itself that nobody has mapped this format, so a log shows up as evidence
somebody still has to look at rather than as an answer.

**The timestamp.** A log line that begins with a date and a time is dated by it, which is a
statement about the bytes rather than a reading of the format: the value is at the front of
the line, in one of the two spellings these files use, optionally in brackets. Anything
else is undated, including the continuation lines of a stack trace, which belong to the
line above them in a way no reader can prove. A time in the middle of a line is left alone,
because a line that mentions a date is not a line that happened then.

**Where it stops.** A log can be gigabytes. This reader stops after a set number of lines
and says so in an event of its own, which is the one thing a truncating reader must never
do quietly: the file, whole, is in the bundle under its hash, and the case says where the
reading ended rather than letting a report rest on a log that was read to the middle.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from agentforensics.model import UNINTERPRETED_MARK, Event, TsPrecision, unparsed
from agentforensics.parsers.base import ParseContext, normalise_ts, text_lines

# Every text log in the catalogue, written out rather than derived from the format field at
# runtime, for the reason `jsonl_generic.LOGS` is written out: a parser is handed an
# artifact id and not a catalogue entry, and a log added to the catalogue should be read
# because somebody decided it should be. tests/unit/test_text_log.py asserts that this set
# is exactly the catalogue's text and Markdown logs, so adding one there fails CI until it
# is listed here.
LOGS = frozenset(
    {
        "amazonq.cli_logs",
        "amp.thread_logs",
        "claude_code.debug_logs",
        "claude_code.usage_data",
        "claude_code.usage_reports",
        "claude_desktop.app_logs",
        "claude_desktop.coworkd_service_log",
        "cline.connector_settings_and_logs",
        "codex.log_dir",
        "continue.logs",
        "copilot.logs",
        "crosscutting.npm_debug_logs",
        "cursor.agent_data_cleanup_marker",
        "cursor.logs",
        "factory_droid.logs",
        "goose.cli_logs",
        "goose.desktop_log",
        "goose.server_logs",
        "hermes.logs",
        "jetbrains_ai.ide_logs",
        "jetbrains_ai.log_data",
        "junie.jcp_outbox",
        "kiro.cli_log",
        "lmstudio.macos_app_support_and_logs",
        "ollama.logs",
        "opencode.log",
        "pi.debug_log",
        "qwen_code.debug_logs",
        "qwen_code.plan_files",
        "windsurf.plugin_log",
        "zed.logs",
    }
)

# What every event out of this module says about itself, in the words the other generic
# readers use for the same situation.
UNINTERPRETED = (
    "this line comes from a log nobody has mapped, so the record "
    f"{UNINTERPRETED_MARK}. The line is in raw whole. Re-read this file once a parser for "
    "it exists."
)

# How many lines of one file are read. Generous, because a debug log of a long session is
# hundreds of thousands of lines and all of them are evidence, and finite, because a case
# that swallowed a rotating gigabyte log would be unusable for the conversation it was
# opened for. Reaching it is always reported.
MAX_LINES = 200_000

# Said where the reading stopped short, as its own event, so the stop is on the timeline
# rather than in a field somebody has to go looking for.
TRUNCATED = (
    "this log is longer than the {limit} lines this reader takes from one file, so the "
    "lines after {limit} are not in the case. The whole file is in the bundle, at the path "
    "in this event's provenance"
)

# A timestamp at the very start of the line, in the two spellings these files use: the ISO
# one with a T, and the one with a space that the logging libraries of three languages
# write by default. The fraction may be separated by a comma, which is what Python's own
# logging module writes, and the whole thing may be in brackets. Anchored at the start on
# purpose: a date in the middle of a line is something the line is about, not when it
# happened.
_LEADING_TIME = re.compile(
    r"^[\[\(]?"
    r"(?P<when>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"
    r"(?:[.,]\d{1,9})?"
    r"(?:Z|z|[+-]\d{2}:?\d{2})?)"
    r"[\]\)]?"
)


class TextLogParser:
    """The reading of last resort for a plain text log."""

    name = "text_log"

    def handles(self, artifact_id: str | None) -> bool:
        return artifact_id in LOGS

    def parse(self, context: ParseContext) -> Iterator[Event]:
        read = 0
        for line in text_lines(context.local_path):
            if not line.text.strip():
                # A blank line separates entries in most of these files and carries nothing
                # of its own. Skipped rather than reported, because an event per blank line
                # would bury the lines that say something.
                continue
            if read >= MAX_LINES:
                yield unparsed(
                    context.provenance(f"line:{line.number}"),
                    context.agent,
                    None,
                    TRUNCATED.format(limit=MAX_LINES),
                    user=context.user,
                    host=context.host,
                )
                return
            read += 1
            yield _record(context, line.number, line.text, line.problem)


def _record(context: ParseContext, number: int, text: str, problem: str | None) -> Event:
    """One line, dated by itself where it dates itself."""
    when, precision, timing = _leading_time(text)
    return unparsed(
        context.provenance(f"line:{number}"),
        context.agent,
        {"line": text},
        # Whatever was odd about reading the line first, then the timing note, then the
        # statement that nobody has read this format.
        " ".join(part for part in (problem, timing, UNINTERPRETED) if part),
        ts_utc=when,
        ts_precision=precision,
        ts_source="the timestamp at the start of the line" if when else None,
        user=context.user,
        host=context.host,
        payload={"text": text},
    )


def _leading_time(text: str) -> tuple[str | None, TsPrecision, str | None]:
    """The timestamp the line starts with, if it starts with one."""
    found = _LEADING_TIME.match(text)
    if not found:
        return None, "absent", None
    # A comma before the fraction is what Python's logging module writes and is not ISO
    # 8601, so it is turned into the separator the standard uses before the value is read.
    # Nothing else about the value is changed.
    value = found.group("when").replace(",", ".")
    when, precision, note = normalise_ts(value)
    return when, precision, note


__all__ = ["LOGS", "MAX_LINES", "TRUNCATED", "UNINTERPRETED", "TextLogParser"]
