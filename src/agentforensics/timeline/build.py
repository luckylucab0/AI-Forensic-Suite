"""Build and export a device-wide timeline from a case.

One ordered sequence across every agent, which is the thing the unified event model exists
to make possible: an analyst reading a case wants to know what happened on this device in
what order, not what happened inside each of nine agents separately.

Two rules shape this module, and both are about not lying to the reader.

An event with no timestamp still appears. A great many agent records carry no time at all,
and leaving them out of the timeline would make them invisible in the one view an analyst
reads first. They are grouped at the start, labelled, and counted in the header, so the
reader sees that there are events whose position is unknown rather than seeing nothing.

Precision is carried on every row. Two events inside the same second, one from an agent
that writes microseconds and one from a file's modification time, cannot be ordered against
each other, and a timeline that presented them as ordered would invite a conclusion the
evidence does not support.
"""

from __future__ import annotations

import csv
import json
import sqlite3
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import Any, TextIO

from agentforensics.model import Case

# What a row carries in every format. Held here rather than per exporter so the three
# formats cannot drift into describing different things.
COLUMNS = (
    "ts_utc",
    "ts_precision",
    "ts_source",
    "kind",
    "agent",
    "actor",
    "user",
    "host",
    "client",
    "session_id",
    "project_path",
    "git_branch",
    "summary",
    "artifact_id",
    "original_path",
    "locator",
    "file_sha256",
    "event_id",
    "parse_problem",
)

FORMATS = ("csv", "jsonl", "timesketch")


@dataclass(frozen=True, slots=True)
class Filters:
    """What to include. Everything by default, because a timeline's job is completeness."""

    agents: tuple[str, ...] = ()
    kinds: tuple[str, ...] = ()
    since: str | None = None
    until: str | None = None
    session_id: str | None = None
    # Filesystem events are one per collected file and can outnumber the conversation by an
    # order of magnitude on a large collection, so there has to be a way to set them aside.
    # Off by default: for an artifact with no internal timestamps they are the only temporal
    # evidence there is.
    exclude_artifact_fs: bool = False


def rows(case: Case, filters: Filters | None = None) -> Iterator[sqlite3.Row]:
    """Every matching event, in timeline order.

    Undated events come first, which is a deliberate reading of "in order": their position
    is unknown, and putting them at the front makes them the first thing a reader meets
    rather than a tail nobody scrolls to. Within a timestamp the ordering falls back to the
    path and the locator so that two runs produce the same file, which is what makes a diff
    of two timelines meaningful.
    """
    filters = filters or Filters()
    where: list[str] = []
    parameters: list[Any] = []

    # Columns are written qualified here rather than being rewritten afterwards: the first
    # version patched the clause with string replacement, which is the kind of thing that
    # works until a filter value happens to contain a column name.
    if filters.agents:
        placeholders = ",".join("?" * len(filters.agents))
        where.append(f"e.agent IN ({placeholders})")
        parameters.extend(filters.agents)
    if filters.kinds:
        placeholders = ",".join("?" * len(filters.kinds))
        where.append(f"e.kind IN ({placeholders})")
        parameters.extend(filters.kinds)
    if filters.session_id:
        where.append("e.session_id = ?")
        parameters.append(filters.session_id)
    if filters.exclude_artifact_fs:
        where.append("e.kind != 'artifact.fs'")
    # A time bound keeps the undated events, because excluding them would turn "what
    # happened that week" into "what happened that week, minus whatever had no clock".
    if filters.since:
        where.append("(e.ts_utc IS NULL OR e.ts_utc >= ?)")
        parameters.append(filters.since)
    if filters.until:
        where.append("(e.ts_utc IS NULL OR e.ts_utc <= ?)")
        parameters.append(filters.until)

    clause = (" WHERE " + " AND ".join(where)) if where else ""
    # Every fragment in `where` is a literal written above; every value the caller supplied
    # travels in `parameters` as a bound placeholder. The interpolation is of this module's
    # own text, which is why the check below is suppressed rather than worked around.
    select = (
        "SELECT e.event_id, e.kind, e.agent, e.ts_utc, e.ts_precision, e.ts_source, "
        "       e.actor, e.client, e.session_id, e.project_path, e.git_branch, "
        "       e.artifact_id, e.original_path, e.locator, e.file_sha256, e.payload, "
        "       e.raw, e.parse_problem, u.name AS user, h.name AS host "
        "  FROM events e "
        "  LEFT JOIN users u ON u.user_id = e.user_id "
        "  LEFT JOIN hosts h ON h.host_id = e.host_id "
    )
    order = " ORDER BY e.ts_utc IS NOT NULL, e.ts_utc, e.original_path, e.locator, e.kind"
    sql = select + clause + order
    yield from case.query(sql, parameters)


def summarise(row: sqlite3.Row) -> str:
    """One line describing what happened, for the column a human reads first.

    Built from the payload the parser produced, and deliberately not truncated: a prompt
    cut off at eighty characters is how a timeline hides the half of a sentence that
    mattered. A long line is the reader's problem to scroll; a short one is this tool's
    mistake to have made.
    """
    payload = _payload(row)
    kind = row["kind"]

    if kind == "unparsed.record":
        return f"unreadable record: {row['parse_problem'] or 'no reason recorded'}"
    for key in ("text", "description"):
        if payload.get(key):
            return " ".join(str(payload[key]).split())
    if payload.get("commands"):
        return "; ".join(
            str(c.get("command", "")) for c in payload["commands"] if isinstance(c, dict)
        )
    if payload.get("files"):
        return ", ".join(
            f"{c.get('operation', '?')} {c.get('path', '?')}"
            for c in payload["files"]
            if isinstance(c, dict)
        )
    if payload.get("network"):
        return ", ".join(
            str(c.get("url") or c.get("host")) for c in payload["network"] if isinstance(c, dict)
        )
    if payload.get("mcp"):
        return ", ".join(
            f"{c.get('server')}/{c.get('tool')}" for c in payload["mcp"] if isinstance(c, dict)
        )
    if payload.get("permissions"):
        return ", ".join(
            f"{c.get('decision')} {c.get('subject') or c.get('mode') or ''}".strip()
            for c in payload["permissions"]
            if isinstance(c, dict)
        )
    if payload.get("tool"):
        return (
            f"{payload['tool']} {json.dumps(payload.get('input', {}), sort_keys=True, default=str)}"
        )
    if payload.get("path"):
        return str(payload["path"])
    return ""


def _payload(row: sqlite3.Row) -> dict[str, Any]:
    try:
        value = json.loads(row["payload"])
    except TypeError, ValueError:
        return {}
    return value if isinstance(value, dict) else {}


def record(row: sqlite3.Row) -> dict[str, Any]:
    """One timeline row as a mapping, in COLUMNS order.

    Public because the local web UI serves the same rows over HTTP. A second renderer with
    its own idea of what a timeline row holds would let the exported file and the screen
    disagree about the same case, and a report is written from one of the two.
    """
    return {
        "ts_utc": row["ts_utc"],
        "ts_precision": row["ts_precision"],
        "ts_source": row["ts_source"],
        "kind": row["kind"],
        "agent": row["agent"],
        "actor": row["actor"],
        "user": row["user"],
        "host": row["host"],
        "client": row["client"],
        "session_id": row["session_id"],
        "project_path": row["project_path"],
        "git_branch": row["git_branch"],
        "summary": summarise(row),
        "artifact_id": row["artifact_id"],
        "original_path": row["original_path"],
        "locator": row["locator"],
        "file_sha256": row["file_sha256"],
        "event_id": row["event_id"],
        "parse_problem": row["parse_problem"],
    }


def write(
    case: Case,
    stream: TextIO,
    fmt: str = "csv",
    filters: Filters | None = None,
) -> tuple[int, int]:
    """Write a timeline. Returns (rows written, rows with no timestamp)."""
    if fmt not in FORMATS:
        raise ValueError(f"unknown timeline format: {fmt}")
    writer = {"csv": _write_csv, "jsonl": _write_jsonl, "timesketch": _write_timesketch}[fmt]
    return writer(case, stream, filters)


def _write_csv(case: Case, stream: TextIO, filters: Filters | None) -> tuple[int, int]:
    # lineterminator so that a Windows run and a POSIX run produce the same bytes: a
    # timeline is hashed and compared, and csv's default would make the two differ.
    out = csv.DictWriter(stream, fieldnames=list(COLUMNS), lineterminator="\n")
    out.writeheader()
    written = undated = 0
    for row in rows(case, filters):
        out.writerow(record(row))
        written += 1
        undated += row["ts_utc"] is None
    return written, undated


def _write_jsonl(case: Case, stream: TextIO, filters: Filters | None) -> tuple[int, int]:
    written = undated = 0
    for row in rows(case, filters):
        out = record(row)
        # The whole original record travels with the row in this format, because this is
        # the one meant to be read back by a tool rather than by a person, and a tool that
        # has the original does not have to trust the mapping.
        out["raw"] = _raw(row)
        stream.write(json.dumps(out, sort_keys=True, ensure_ascii=False, default=str) + "\n")
        written += 1
        undated += row["ts_utc"] is None
    return written, undated


def _write_timesketch(case: Case, stream: TextIO, filters: Filters | None) -> tuple[int, int]:
    """Timesketch's own JSONL shape.

    Three fields are mandatory there: a message, a datetime and a timestamp description. An
    event with no datetime cannot be imported at all, so those are written with the
    timestamp description saying so and a datetime this tool does not have. Rather than
    inventing one, they are skipped from the import and counted in the return value, and
    the caller warns. Silently dropping them into a sketch with a fabricated date would put
    a wrong time in front of an analyst, which is worse than an honest gap.

    The importer at the other end makes the same mistake this refuses to, which is why the
    shape of a timestamp is checked where events are built rather than trusted here. It
    parses the date with pandas in mixed-format mode and, when that fails, coerces the
    value rather than refusing it, so an unparseable timestamp arrives as an event dated
    1970 and sorted into the wrong place with nothing saying so. Read on 2026-09-21 from
    the import client's own source, importer_client/python/timesketch_import_client:
    `pandas.to_datetime(data_frame['datetime'], utc=True, format='mixed')` with a fallback
    to `errors='coerce'`. Both spellings this suite can write, Z and an explicit offset,
    parse there; the check exists so that no third spelling can appear.
    """
    written = undated = 0
    for row in rows(case, filters):
        if row["ts_utc"] is None:
            undated += 1
            continue
        out = record(row)
        stream.write(
            json.dumps(
                {
                    "message": f"{row['agent']} {row['kind']}: {out['summary']}",
                    "datetime": row["ts_utc"],
                    "timestamp_desc": f"{row['ts_source'] or 'unknown source'} "
                    f"({row['ts_precision']} precision)",
                    "data_type": f"agentforensics:{row['kind']}",
                    **{k: v for k, v in out.items() if v is not None},
                },
                sort_keys=True,
                ensure_ascii=False,
                default=str,
            )
            + "\n"
        )
        written += 1
    return written, undated


def _raw(row: sqlite3.Row) -> Any:
    try:
        return json.loads(row["raw"])
    except TypeError, ValueError:
        return row["raw"]


def header_notes(case: Case, written: int, undated: int, fmt: str) -> list[str]:
    """What the caller should say alongside a timeline it just wrote.

    A timeline is the view an analyst trusts most and questions least, so the numbers that
    qualify it travel with it rather than living in a different command's output.
    """
    counts = case.counts()
    notes = [f"{written} row(s) written"]
    if fmt == "timesketch" and undated:
        notes.append(
            f"{undated} event(s) have no timestamp and are NOT in this file: the format "
            "requires one, and inventing a date would put a wrong time in front of a "
            "reader. Export as csv or jsonl to see them."
        )
    elif undated:
        notes.append(
            f"{undated} event(s) have no timestamp and are listed first, because their "
            "position in the sequence is unknown rather than early"
        )
    unreadable = counts["events_unreadable"]
    if unreadable:
        notes.append(
            f"{unreadable} record(s) in this case could not be read and appear as rows "
            "carrying the original text and the reason"
        )
    if counts["events_uninterpreted"]:
        notes.append(
            f"{counts['events_uninterpreted']} record(s) were read and are in a format "
            "nobody has mapped yet, so they appear with their content in raw and no "
            "reading of it. They are evidence somebody still has to look at, which is a "
            "different thing from a record that could not be read"
        )
    if counts["artifacts_unparsed"]:
        notes.append(
            f"{counts['artifacts_unparsed']} collected file(s) have no parser yet, so they "
            "contribute only their filesystem timestamps to this timeline"
        )
    if counts["collection_gaps"]:
        notes.append(
            f"{counts['collection_gaps']} gap(s) were reported by the collection itself, "
            "so this timeline is of what was collected, not of what happened"
        )
    return notes


def parse_kinds(values: Sequence[str] | None) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values or ()))


__all__ = [
    "COLUMNS",
    "FORMATS",
    "Filters",
    "header_notes",
    "record",
    "rows",
    "summarise",
    "write",
]
