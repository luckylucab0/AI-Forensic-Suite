"""What a case looks like through the local read-only API.

Every projection in here is a plain function from an open case to JSON-able data, with no
HTTP anywhere near it. That split is deliberate: the questions a projection answers are
where the forensic care is, and they have to be testable without a socket, a port or a
browser. `server.py` is then only routing and hardening.

Three shapes in here are decisions rather than plumbing.

A session's events are served in the unified log format, the same one `afx normalize` and
the Velociraptor artifact write. The viewer therefore reads a case through the reader it
already has, and there is no third event shape that could disagree with the other two. See
docs/UNIFIED_FORMAT.md.

A session's identity is derived, not stored. A case holds events, and what a viewer calls a
session is a group of them: one agent, one host, one user, one working directory, one
session id. The group's key is a hash of exactly those six values, so the same case always
produces the same keys and a bookmarked URL still resolves after a re-ingest.

Every count that qualifies a case travels with it. Records nothing could parse, events with
no timestamp, files collected and never read, holes the collection itself reported, and
whether anybody has run the rules at all. A viewer that showed only what was understood
would read as completeness, which is the one failure this suite must not have.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from itertools import islice
from typing import Any

from agentforensics import __version__
from agentforensics.model import Case
from agentforensics.model.schema import SCHEMA_VERSION
from agentforensics.timeline import Filters, record, rows
from agentforensics.unified import FORMAT_NAME, FORMAT_VERSION

# Bumped when the shape of a response changes in a way a reader has to know about. The
# viewer reads it out of /api/case and refuses a version it was not written for, rather
# than rendering half a case from fields it guessed at.
API_VERSION = 1

# How many events one page of a session or a timeline carries by default, and the ceiling a
# caller can ask for. Paged because ADR 0006 chose the standard library over a framework
# and accepted worse streaming as the cost: a session projection is assembled in memory, so
# it has to be bounded. The default is large enough that a normal conversation arrives in
# one request.
DEFAULT_PAGE = 2000
MAX_PAGE = 20000


class ApiError(Exception):
    """A request that named something the case does not have."""


# ---------------------------------------------------------------------------- case


def case_summary(case: Case) -> dict[str, Any]:
    """The case as a whole: what is in it, where it came from, and what is missing.

    The marker field is `afx_api`. The viewer probes for it to decide whether it is being
    served by `afx serve` or is just an HTML file somebody opened, and a probe needs
    something unambiguous to find: a 200 with the wrong JSON is not a case.
    """
    counts = case.counts()
    bundles = [
        dict(row)
        for row in case.query(
            "SELECT bundle_uuid, source_kind, source_path, tool_name, tool_version, "
            "       format_version, collected_os, collected_host, collector_user, "
            "       elevated, started_utc, finished_utc, local_timezone, "
            "       local_timezone_name, manifest_sha256, ingested_utc "
            "  FROM bundles ORDER BY bundle_uuid"
        )
    ]
    agents = [
        dict(row)
        for row in case.query(
            "SELECT agent, count(*) AS events, "
            "       sum(CASE WHEN kind = 'unparsed.record' THEN 1 ELSE 0 END) AS unparsed, "
            "       min(ts_utc) AS first_ts, max(ts_utc) AS last_ts "
            "  FROM events GROUP BY agent ORDER BY events DESC, agent"
        )
    ]
    kinds = [
        dict(row)
        for row in case.query(
            "SELECT kind, count(*) AS events FROM events GROUP BY kind ORDER BY kind"
        )
    ]
    gaps = [
        dict(row)
        for row in case.query(
            "SELECT bundle_uuid, kind, detail, reason FROM collection_gaps "
            " ORDER BY bundle_uuid, kind, detail"
        )
    ]
    scans = [
        dict(row)
        for row in case.query(
            "SELECT run_id, started_utc, finished_utc, rules_run, events_read, findings, "
            "       tool_version FROM scan_runs ORDER BY started_utc DESC"
        )
    ]
    return {
        "afx_api": API_VERSION,
        "tool": "agentforensics",
        "tool_version": __version__,
        "unified_format": {"name": FORMAT_NAME, "version": FORMAT_VERSION},
        "case": {"path": str(case.path), "schema_version": SCHEMA_VERSION},
        "counts": counts,
        "bundles": bundles,
        "agents": agents,
        "kinds": kinds,
        "collection_gaps": gaps,
        "scan_runs": scans,
        # Said as its own field rather than left to be inferred from an empty list. A case
        # with no findings and a case nobody scanned look identical otherwise, and those
        # are opposite conclusions.
        "scanned": bool(scans),
    }


# ------------------------------------------------------------------ sessions and groups

# One row per derived session. The two CASE expressions are what put the filesystem events
# in a group of their own: they are one per collected file rather than part of a
# conversation, and on a large collection they outnumber it by an order of magnitude. They
# are still served, in their own group, because for an artifact with no internal timestamps
# they are the only temporal evidence there is.
_GROUPS_SQL = """
SELECT e.agent                                                             AS agent,
       h.name                                                              AS host,
       u.name                                                              AS user,
       CASE WHEN e.kind = 'artifact.fs' THEN 1 ELSE 0 END                  AS files,
       CASE WHEN e.kind = 'artifact.fs' THEN NULL ELSE e.project_path END  AS project_path,
       CASE WHEN e.kind = 'artifact.fs' THEN NULL ELSE e.session_id END    AS session_id,
       count(*)                                                            AS events,
       min(e.ts_utc)                                                       AS first_ts,
       max(e.ts_utc)                                                       AS last_ts,
       sum(CASE WHEN e.kind = 'unparsed.record' THEN 1 ELSE 0 END)         AS unparsed,
       sum(CASE WHEN e.ts_utc IS NULL THEN 1 ELSE 0 END)                   AS undated,
       group_concat(DISTINCT e.kind)                                       AS kinds
  FROM events e
  LEFT JOIN hosts h ON h.host_id = e.host_id
  LEFT JOIN users u ON u.user_id = e.user_id
 GROUP BY agent, host, user, files, project_path, session_id
 ORDER BY files, agent, project_path IS NULL, project_path, host, user,
          first_ts IS NULL, first_ts, session_id
"""

# The six values a session is grouped by, in the order they go into its key.
_GROUP_FIELDS = ("agent", "host", "user", "files", "project_path", "session_id")


def _group_key(row: sqlite3.Row) -> str:
    """A stable key for one derived session.

    Derived from the group's own values rather than from a counter, so the same case always
    produces the same keys: a link an analyst pasted into a report still opens the same
    session after the case is rebuilt from the same bundle.

    An absent value and an empty one are hashed differently. A session id that is null and
    one that is the empty string are different claims about the evidence, and two groups
    that collided onto one key would silently merge two sessions into one transcript.
    """
    digest = hashlib.sha256()
    for field in _GROUP_FIELDS:
        value = row[field]
        digest.update(b"\x01" if value is None else b"\x02")
        digest.update(str("" if value is None else value).encode("utf-8"))
        digest.update(b"\x00")
    return digest.hexdigest()[:32]


def sessions(case: Case) -> list[dict[str, Any]]:
    """Every derived session in the case, with the counts a sidebar shows."""
    out = []
    for row in case.query(_GROUPS_SQL):
        key = _group_key(row)
        out.append(
            {
                "key": key,
                # The path the viewer fetches this session's events from. Handed out by the
                # server rather than assembled in the browser, so the URL shape stays this
                # module's business.
                "path": f"api/sessions/{key}/events",
                "agent": row["agent"],
                "host": row["host"],
                "user": row["user"],
                "project_path": row["project_path"],
                "session_id": row["session_id"],
                "files": bool(row["files"]),
                "events": int(row["events"]),
                "unparsed": int(row["unparsed"] or 0),
                "undated": int(row["undated"] or 0),
                "first_ts": row["first_ts"],
                "last_ts": row["last_ts"],
                "kinds": sorted((row["kinds"] or "").split(",")),
            }
        )
    return out


def projects(case: Case) -> dict[str, Any]:
    """The sessions grouped the way the viewer's sidebar shows them.

    Grouped by agent, working directory, host and user, because one case can hold several
    agents, several users and several hosts at once, which is what comes back from a fleet
    collection. A session with no session id of its own is not dropped: it becomes a group
    named for what it is, so that a prompt from a history file is visible rather than
    absent.
    """
    groups: dict[str, dict[str, Any]] = {}
    for session in sessions(case):
        agent = session["agent"] or "unknown agent"
        host = f" · {session['host']}" if session["host"] else ""
        user = f" · {session['user']}" if session["user"] else ""
        if session["files"]:
            group_id = f"files:{agent}{host}{user}"
            name = f"{agent}: files on disk{host}{user}"
        else:
            cwd = session["project_path"] or "(no working directory recorded)"
            group_id = f"case:{agent}|{cwd}{host}{user}"
            name = f"{agent} · {cwd}{host}{user}"
        group = groups.setdefault(group_id, {"id": group_id, "name": name, "sessions": []})
        group["sessions"].append(session)
    return {
        "afx_api": API_VERSION,
        "projects": [groups[key] for key in sorted(groups)],
    }


def session_records(
    case: Case, key: str, *, offset: int = 0, limit: int = DEFAULT_PAGE
) -> tuple[list[dict[str, Any]], int | None]:
    """One page of a session's events, as unified log records.

    Returns the records and the offset to ask for next, or None when the page was the last
    one. Whether more remain is answered by reading one row past the page rather than by
    comparing against a count, because a count taken in a second query could disagree with
    the page if the case is being written while it is read, which is exactly what happens
    when an analyst opens a case during an ingest.
    """
    group = _resolve(case, key)
    limit = max(1, min(int(limit), MAX_PAGE))
    offset = max(0, int(offset))
    parameters = [group[field] for field in _GROUP_FIELDS] + [limit + 1, offset]
    fetched = case.query(_SESSION_SQL, parameters)
    more = len(fetched) > limit
    page = fetched[:limit]
    return [_unified(row) for row in page], (offset + len(page)) if more else None


def _resolve(case: Case, key: str) -> dict[str, Any]:
    """The group one key names, or an error naming what went wrong.

    Re-derived per request rather than held in memory. The case is a file that can grow
    while it is being served, and a cached group list would serve a session list that no
    longer matches the case it claims to describe.
    """
    for session in sessions(case):
        if session["key"] == key:
            return session
    raise ApiError(f"no session {key} in this case")


# The columns every unified record is built from. One select, used by the session page
# and by the single-event lookup, so the two cannot come back describing different fields.
_EVENT_SELECT = """
SELECT e.event_id, e.kind, e.agent, e.ts_utc, e.ts_precision, e.ts_source, e.actor,
       e.client, e.session_id, e.project_path, e.git_branch, e.artifact_id,
       e.original_path, e.locator, e.file_sha256, e.bundle_uuid, e.payload, e.raw,
       e.parse_problem, u.name AS user, h.name AS host
  FROM events e
  LEFT JOIN hosts h ON h.host_id = e.host_id
  LEFT JOIN users u ON u.user_id = e.user_id
"""

# The six values a session's key was derived from, matched back with IS rather than =, so
# that a null working directory matches the group whose working directory is null. With =
# every group that has one would come back empty, which would look like a session that
# holds no events.
# Ordered the same way the timeline is: an event with no timestamp comes first, because its
# position is unknown rather than early, and a reader must meet it rather than have to
# scroll past everything to find it.
#
# The locator is sorted by length before content, which looks odd and is on purpose. A
# locator is text ("line:9", "byte:4096", "table:x rowid:5") because those are different
# things, and sorting text puts "line:10" before "line:9". Comparing length first restores
# numeric order for the decimal numbers that share a prefix, which is every locator a
# line-delimited transcript produces, and a transcript read out of order is a transcript
# nobody can follow.
_SESSION_SQL = (
    _EVENT_SELECT
    + """
 WHERE e.agent IS ?
   AND h.name IS ?
   AND u.name IS ?
   AND (CASE WHEN e.kind = 'artifact.fs' THEN 1 ELSE 0 END) IS ?
   AND (CASE WHEN e.kind = 'artifact.fs' THEN NULL ELSE e.project_path END) IS ?
   AND (CASE WHEN e.kind = 'artifact.fs' THEN NULL ELSE e.session_id END) IS ?
 ORDER BY e.ts_utc IS NULL DESC, e.ts_utc, e.original_path,
          length(e.locator), e.locator, e.kind
 LIMIT ? OFFSET ?
"""
)


def event_record(case: Case, event_id: str) -> dict[str, Any]:
    """One event by its id, as a unified record. What a finding links to."""
    found = case.query(_EVENT_SELECT + " WHERE e.event_id = ?", [event_id])
    if not found:
        raise ApiError(f"no event {event_id} in this case")
    return _unified(found[0])


def _unified(row: sqlite3.Row) -> dict[str, Any]:
    """One stored event as one unified log record.

    Built from the row rather than by reconstructing an `Event` and converting it. The
    model validates on construction, so a row whose stored precision and timestamp
    disagreed, from an older build or a parser since fixed, would raise here and cost the
    whole page. A record must be servable whatever state it is in: that is the difference
    between a viewer that shows a problem and one that shows nothing.

    `event_id` is the stored one. A reader recomputes it from the provenance and reports a
    disagreement rather than correcting it, which is what makes a mismatch visible instead
    of quietly resolved.
    """
    payload = _decode(row["payload"])
    return {
        "v": FORMAT_VERSION,
        "agent": row["agent"],
        "kind": row["kind"],
        "event_id": row["event_id"],
        "ts_utc": row["ts_utc"],
        "ts_precision": row["ts_precision"],
        "ts_source": row["ts_source"],
        "actor": row["actor"],
        "client": row["client"],
        "host": row["host"],
        "user": row["user"],
        "session_id": row["session_id"],
        "project_path": row["project_path"],
        "git_branch": row["git_branch"],
        "payload": payload if isinstance(payload, dict) else {"payload": payload},
        "parse_problem": row["parse_problem"],
        "provenance": {
            "bundle_uuid": row["bundle_uuid"],
            "original_path": row["original_path"],
            "sha256": row["file_sha256"],
            "artifact_id": row["artifact_id"],
            "locator": row["locator"],
        },
        "raw": _decode(row["raw"]),
        "producer": f"agentforensics/{__version__} (case)",
    }


def _decode(text: Any) -> Any:
    """Stored JSON back into a value, and the text itself when it is not JSON.

    Returning the text is the point. A column that cannot be decoded is evidence of
    something having gone wrong at ingest, and handing the reader the characters that are
    actually in the case is more use than an empty object standing where a record was.
    """
    if text is None:
        return None
    try:
        return json.loads(text)
    except TypeError, ValueError:
        return {"__undecodable__": str(text)}


# ------------------------------------------------------------------------- timeline


def timeline(
    case: Case,
    *,
    offset: int = 0,
    limit: int = DEFAULT_PAGE,
    agents: tuple[str, ...] = (),
    kinds: tuple[str, ...] = (),
    since: str | None = None,
    until: str | None = None,
    session_id: str | None = None,
    exclude_artifact_fs: bool = False,
) -> dict[str, Any]:
    """A page of the device-wide timeline, in the same shape the exports write.

    The rows come from the timeline module rather than from a query of its own, so the CSV
    an analyst attaches to a report and the table they read on screen cannot describe the
    same case differently.
    """
    limit = max(1, min(int(limit), MAX_PAGE))
    offset = max(0, int(offset))
    filters = Filters(
        agents=agents,
        kinds=kinds,
        since=since,
        until=until,
        session_id=session_id,
        exclude_artifact_fs=exclude_artifact_fs,
    )
    # islice over the cursor rather than LIMIT in SQL: the filter clause lives in the
    # timeline module, and reaching in to add paging to it would be a second place that
    # decides what a timeline contains. SQLite streams the rows, so the cost of skipping is
    # the rows skipped, not the whole table.
    stream = rows(case, filters)
    page = list(islice(stream, offset, offset + limit + 1))
    more = len(page) > limit
    page = page[:limit]
    return {
        "afx_api": API_VERSION,
        "rows": [record(row) for row in page],
        "offset": offset,
        "next_offset": (offset + len(page)) if more else None,
        "undated": sum(1 for row in page if row["ts_utc"] is None),
    }


# ------------------------------------------------------------------------- findings


def findings(case: Case) -> dict[str, Any]:
    """What the rules found, and the fact of their having run.

    The scan runs travel with the findings for the same reason the collector records a glob
    it declined to search: an empty list means nothing until a reader knows whether anybody
    looked.
    """
    scans = [
        dict(row)
        for row in case.query(
            "SELECT run_id, started_utc, finished_utc, rules_run, rule_ids, events_read, "
            "       findings, tool_version FROM scan_runs ORDER BY started_utc DESC"
        )
    ]
    out = []
    for row in case.query(
        "SELECT f.finding_id, f.rule_id, f.pack, f.severity, f.title, f.ts_utc, f.agent, "
        "       f.session_id, f.summary, f.matched, f.event_count, f.rule_sha256, "
        "       f.scanned_utc, u.name AS user "
        "  FROM findings f LEFT JOIN users u ON u.user_id = f.user_id "
        " ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
        "          WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, "
        "          f.ts_utc IS NULL DESC, f.ts_utc, f.rule_id"
    ):
        finding = dict(row)
        finding["matched"] = _decode(finding["matched"])
        finding["event_ids"] = [
            str(event["event_id"])
            for event in case.query(
                "SELECT event_id FROM finding_events WHERE finding_id = ? ORDER BY event_id",
                [finding["finding_id"]],
            )
        ]
        out.append(finding)
    return {
        "afx_api": API_VERSION,
        "findings": out,
        "scan_runs": scans,
        "scanned": bool(scans),
    }


# ------------------------------------------------------------------------ artifacts


# The scopes in the order an analyst reads them: whose instruction won. Managed policy is
# an administrator's and applies to everybody, a project file arrives with a checkout and is
# reachable by anyone who can open a pull request, and the local override is the one person
# working in that directory. The order is presentation only; no agent's real precedence is
# claimed here, because that is the agent's runtime behaviour and not a fact on disk.
_SCOPE_ORDER = ("managed", "user", "project", "local", "session", "unknown")

# How much of one instruction file this view carries inline. The whole text is one request
# away at /api/events/<event_id>, which the view says in its own note, so nothing is hidden
# and an overview of two hundred files does not ship a megabyte of prose to draw a table.
PREVIEW = 400


def instructions(case: Case) -> dict[str, Any]:
    """Everything the agents were told to obey, as collected from the endpoint.

    The view an analyst opens to answer what standing instructions were in force and
    whether any of them were planted. One row per instruction file, grouped by scope, with
    the tools a skill granted itself and the characters a reviewer could not see.

    The note is part of the answer and not decoration. For nearly every agent the vendor's
    base prompt is compiled into the binary or arrives from its server, so it is not on the
    endpoint at all. A view that showed this as "the system prompt" would answer a question
    the evidence cannot, and an analyst would quote it.
    """
    rows = [
        dict(row)
        for row in case.query(
            "SELECT e.event_id, e.agent, e.artifact_id, e.original_path, e.project_path, "
            "       e.payload, e.parse_problem, e.file_sha256, "
            "       h.name AS host, u.name AS user, "
            "       a.status AS catalogue_status, a.mtime_utc, a.size "
            "  FROM events e "
            "  LEFT JOIN hosts h ON h.host_id = e.host_id "
            "  LEFT JOIN users u ON u.user_id = e.user_id "
            "  LEFT JOIN artifacts a ON a.bundle_uuid = e.bundle_uuid "
            "                       AND a.original_path = e.original_path "
            " WHERE e.kind = 'instruction.source' "
            " ORDER BY e.agent, e.original_path"
        )
    ]

    out = []
    for row in rows:
        decoded = _decode(row.pop("payload"))
        payload = decoded if isinstance(decoded, dict) else {}
        if not isinstance(decoded, dict):
            # Kept rather than dropped. A payload column that will not decode is evidence
            # that something went wrong at ingest, and an empty row standing where an
            # instruction file was is the one reading this view must never produce.
            row["payload_problem"] = f"the stored payload is not an object: {decoded!r}"
        text = payload.get("text") or ""
        row.update(
            {
                "scope": payload.get("scope") or "unknown",
                # Why the scope is what it is, where the parser could not settle it. A
                # separate field from parse_problem, because a file whose tier is unknown
                # was still read: counting it as unreadable told an analyst the collection
                # had failed when it had not.
                "scope_problem": payload.get("scope_problem"),
                "title": payload.get("title"),
                "declared_name": payload.get("declared_name"),
                "declared_description": payload.get("declared_description"),
                # A skill naming its own tools has widened what the agent may do, in a
                # document rather than in a settings file. It is the one field here that is
                # a permission question, so it travels with the instruction.
                "declared_tools": payload.get("declared_tools") or [],
                "executable": bool(payload.get("executable")),
                "prompt_field": payload.get("prompt_field"),
                "hidden_characters": payload.get("hidden_characters") or [],
                "bytes": payload.get("bytes"),
                "lines": payload.get("lines"),
                "chars": len(text),
                "preview": text[:PREVIEW],
                # Said explicitly rather than left for the reader to work out from a length,
                # because a preview mistaken for a whole file is a wrong reading of evidence.
                "preview_is_whole_file": len(text) <= PREVIEW,
            }
        )
        out.append(row)

    by_scope = {
        scope: sum(1 for row in out if row["scope"] == scope)
        for scope in _SCOPE_ORDER
        if any(row["scope"] == scope for row in out)
    }
    return {
        "afx_api": API_VERSION,
        "instructions": out,
        "scope_order": list(_SCOPE_ORDER),
        "by_scope": by_scope,
        "counts": {
            "files": len(out),
            "with_declared_tools": sum(1 for row in out if row["declared_tools"]),
            "with_hidden_characters": sum(1 for row in out if row["hidden_characters"]),
            "executable": sum(1 for row in out if row["executable"]),
            "unreadable": sum(1 for row in out if row["parse_problem"]),
            "scope_unknown": sum(1 for row in out if row["scope"] == "unknown"),
        },
        "note": (
            "This is the instruction surface that was on the endpoint: instruction files, "
            "skills, commands, output styles, rules, steering files and hook scripts. It is "
            "not a system prompt. Every agent here builds its prompt at runtime from a base "
            "prompt that is compiled into the product or fetched from the vendor, and that "
            "part is not on the endpoint and is not in this case. Assembly order is the "
            "agent's own behaviour, so the grouping below is presentation and not a claim "
            "about which file won. Each row's whole text is at /api/events/<event_id>."
        ),
    }


# --------------------------------------------------------------- corroboration


# One row per conversation per store that names it. artifact.fs is left out because it is
# the filesystem record of a file rather than anything inside one: counting it would make
# every collected file look like a store that knows about every conversation in it.
_CORROBORATION_SQL = """
SELECT e.agent        AS agent,
       e.session_id   AS session_id,
       e.artifact_id  AS artifact_id,
       count(*)       AS events,
       min(e.ts_utc)  AS first_ts,
       max(e.ts_utc)  AS last_ts
  FROM events e
 WHERE e.kind <> 'artifact.fs'
   AND e.session_id IS NOT NULL
   AND trim(e.session_id) <> ''
   AND e.artifact_id IS NOT NULL
 GROUP BY agent, session_id, artifact_id
 ORDER BY agent, session_id, artifact_id
"""

# What this view is and is not, carried with it. An analyst reading a list of conversations
# one store knows nothing about needs all three of these sentences before acting on it.
_CORROBORATION_NOTE = (
    "Several agents keep one conversation in more than one place: a transcript store and a "
    "sidebar index, a rollout file and the database that projects it, a prompt history and "
    "the session it belongs to. This view says which of the stores in this case name each "
    "conversation and which of them stay silent about it, so a conversation only one store "
    "remembers is visible rather than having to be noticed. Three limits travel with that. "
    "Silence is a lead and not a finding: a store may never have held a conversation, "
    "because it indexes only what was opened, or because the two were written by different "
    "generations of the same product. The comparison is by session id as each store spells "
    "it, so a pair of stores that share no conversation at all is far more likely to use "
    "two id spaces than to have lost every one, and each pair below says which of the two "
    "it looks like. And only stores that are in this case are compared: a store nobody "
    "collected cannot be silent, it is absent, which is a question for the artifacts view."
)


def corroboration(case: Case) -> dict[str, Any]:
    """Which stores name each conversation, and which stay silent about it.

    The question this answers is the one no single parser can: an agent's own two stores
    disagreeing about which conversations existed. Zed keeps its threads in one file and
    their metadata in another, Codex keeps rollout files and a database that projects them,
    and a conversation that reached one and not the other is either an ordinary gap in how
    the product writes or the trace of something removed. Neither the parser nor a rule can
    see it, because each of them sees one record at a time and this is about a record that
    is not there.

    Derived from the case rather than from a declared list of which store pairs with which.
    A store that names conversations is one that names conversations, whatever agent it
    belongs to, and a pairing table would be a second place to be wrong about an agent
    nobody has looked at yet.
    """
    seen: dict[tuple[str, str], dict[str, dict[str, Any]]] = {}
    names: dict[str, dict[str, set[str]]] = {}
    for row in case.query(_CORROBORATION_SQL):
        agent = row["agent"] or "unknown"
        session_id = str(row["session_id"])
        artifact_id = str(row["artifact_id"])
        seen.setdefault((agent, session_id), {})[artifact_id] = {
            "artifact_id": artifact_id,
            "events": int(row["events"]),
            "first_ts": row["first_ts"],
            "last_ts": row["last_ts"],
        }
        names.setdefault(agent, {}).setdefault(artifact_id, set()).add(session_id)

    out = []
    for (agent, session_id), found in sorted(seen.items()):
        # Every store of this agent that names conversations at all, minus the ones that
        # name this conversation. How many each of them does name travels with it: a store
        # that knows one conversation in forty is plainly not a peer of one that knows all
        # of them, and saying so here is cheaper than an analyst working it out.
        silent = [
            {"artifact_id": artifact_id, "names_sessions": len(sessions_named)}
            for artifact_id, sessions_named in sorted(names.get(agent, {}).items())
            if artifact_id not in found
        ]
        named_by = [found[artifact_id] for artifact_id in sorted(found)]
        out.append(
            {
                "agent": agent,
                "session_id": session_id,
                "named_by": named_by,
                "silent": silent,
                "stores": len(named_by),
                "events": sum(entry["events"] for entry in named_by),
                "first_ts": min(
                    (entry["first_ts"] for entry in named_by if entry["first_ts"]), default=None
                ),
                "last_ts": max(
                    (entry["last_ts"] for entry in named_by if entry["last_ts"]), default=None
                ),
            }
        )

    return {
        "afx_api": API_VERSION,
        "agents": [_agent_corroboration(agent, names[agent]) for agent in sorted(names)],
        "sessions": out,
        "counts": {
            "sessions": len(out),
            "in_one_store": sum(1 for row in out if row["stores"] == 1 and row["silent"]),
            "corroborated": sum(1 for row in out if row["stores"] > 1),
        },
        "note": _CORROBORATION_NOTE,
    }


def _agent_corroboration(agent: str, named: dict[str, set[str]]) -> dict[str, Any]:
    """One agent's stores, and what each pair of them agrees about."""
    artifacts_here = sorted(named)
    pairs = []
    for index, left in enumerate(artifacts_here):
        for right in artifacts_here[index + 1 :]:
            both = named[left] & named[right]
            pairs.append(
                {
                    "left": left,
                    "right": right,
                    "both": len(both),
                    "left_only": len(named[left] - named[right]),
                    "right_only": len(named[right] - named[left]),
                    # Said rather than left to be read out of a zero. Two stores of one
                    # agent that share no conversation are usually two id spaces, and an
                    # analyst told "every conversation is missing from both" would go
                    # looking for a deletion that never happened.
                    "overlap": "none"
                    if not both
                    else "partial"
                    if (named[left] != named[right])
                    else "complete",
                }
            )
    return {
        "agent": agent,
        "sessions": len(set().union(*named.values())) if named else 0,
        "artifacts": [
            {"artifact_id": artifact_id, "sessions": len(named[artifact_id])}
            for artifact_id in artifacts_here
        ],
        "pairs": pairs,
    }


def artifacts(case: Case) -> dict[str, Any]:
    """Every file the collection carried, read or not, plus the holes it reported.

    This is the view that qualifies every other one. The difference between no events from
    an agent and nothing from that agent having been collected is the difference between
    two opposite conclusions, and it is only visible here.
    """
    out = [
        dict(row)
        for row in case.query(
            "SELECT a.bundle_uuid, a.artifact_id, a.agent, a.category, a.original_path, "
            "       a.sha256, a.size, a.status, a.collected, a.reason, a.mtime_utc, "
            "       a.birthtime_utc, a.symlink, a.changed_while_reading, a.parser, "
            "       a.parse_status, a.parse_detail, a.events_parsed, a.records_unparsed, "
            "       u.name AS user "
            "  FROM artifacts a LEFT JOIN users u ON u.user_id = a.user_id "
            " ORDER BY a.agent IS NULL, a.agent, a.original_path"
        )
    ]
    for entry in out:
        entry["collected"] = bool(entry["collected"])
        entry["changed_while_reading"] = (
            None if entry["changed_while_reading"] is None else bool(entry["changed_while_reading"])
        )
    gaps = [
        dict(row)
        for row in case.query(
            "SELECT bundle_uuid, kind, detail, reason FROM collection_gaps "
            " ORDER BY bundle_uuid, kind, detail"
        )
    ]
    return {
        "afx_api": API_VERSION,
        "artifacts": out,
        "collection_gaps": gaps,
        "counts": case.counts(),
    }


__all__ = [
    "API_VERSION",
    "DEFAULT_PAGE",
    "MAX_PAGE",
    "PREVIEW",
    "ApiError",
    "artifacts",
    "case_summary",
    "event_record",
    "findings",
    "instructions",
    "projects",
    "session_records",
    "sessions",
    "timeline",
]
