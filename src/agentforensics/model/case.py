"""The case database, as the rest of the analyzer sees it.

One SQLite file per case. This module owns every write to it, so that the properties the
case has to have are enforced in one place rather than trusted at each call site.

Writes are idempotent. An event is keyed by its provenance-derived id, so ingesting the
same bundle twice leaves the case unchanged rather than doubling it. That matters more than
it sounds: re-ingest is what happens when a parser is fixed and a case is rebuilt, and an
analyst must be able to do that without wondering whether counts are now wrong.

Nothing in here deletes an event. Evidence is added and read; the way to discard a case is
to discard the file.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agentforensics.model.event import UNINTERPRETED_MARK, Event
from agentforensics.model.schema import SCHEMA_VERSION, apply_schema


class CaseError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class BundleRecord:
    """What a case stores about one ingested collection."""

    bundle_uuid: str
    source_kind: str
    source_path: str
    tool_name: str | None = None
    tool_version: str | None = None
    format_version: int | None = None
    collected_os: str | None = None
    collected_host: str | None = None
    collector_user: str | None = None
    elevated: bool | None = None
    started_utc: str | None = None
    finished_utc: str | None = None
    local_timezone: str | None = None
    local_timezone_name: str | None = None
    manifest_sha256: str | None = None


class Case:
    """An open case database."""

    def __init__(self, path: Path, connection: sqlite3.Connection) -> None:
        self.path = path
        self._connection = connection
        # Small caches so that an ingest of a hundred thousand events does not issue a
        # lookup per event for the two or three names they all share.
        self._users: dict[str, int] = {}
        self._hosts: dict[str, int] = {}

    # ---------------------------------------------------------------- lifecycle

    @classmethod
    def open(cls, path: Path, *, create: bool = True, read_only: bool = False) -> Case:
        """Open a case. `read_only` opens the file so that SQLite itself refuses a write.

        The read-only mode exists for the local web UI. A reader that only intends to read
        is not the same claim as a connection that cannot write: the first is a promise
        about this build's code, the second is enforced one layer down and holds even for a
        bug. A case is derived evidence, and a viewer must not be able to alter it.
        """
        if not create and not path.exists():
            raise CaseError(f"no case at {path}")
        existed = path.exists()
        if read_only:
            if not existed:
                raise CaseError(f"no case at {path}")
            # A URI connection is the only way to ask SQLite for a read-only handle.
            # as_uri() percent-encodes the path, which is what makes a path holding a
            # question mark or a hash land intact rather than being read as a query.
            connection = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
            connection.row_factory = sqlite3.Row
            case = cls(path, connection)
            case._check_version()
            return case
        path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(path)
        connection.row_factory = sqlite3.Row
        # Foreign keys are declared in the schema and are worth enforcing: an event whose
        # bundle row is missing would be an event with no provenance, which is the one
        # thing an event may not be.
        connection.execute("PRAGMA foreign_keys = ON")
        # A case is written once and read many times, often while it is still being built.
        # The write-ahead log lets a reader open it during an ingest, which is how an
        # analyst starts looking at a large collection before it finishes.
        connection.execute("PRAGMA journal_mode = WAL")
        case = cls(path, connection)
        if not existed:
            apply_schema(connection)
            connection.commit()
        case._check_version()
        return case

    def _check_version(self) -> None:
        try:
            row = self._connection.execute(
                "SELECT value FROM case_meta WHERE key = 'schema_version'"
            ).fetchone()
        except sqlite3.DatabaseError as exc:
            # A file that exists but is not this: an empty file, another tool's database, a
            # bundle somebody pointed at by mistake. An analyst gets a sentence rather than
            # a stack trace, because at this point in a session they are not debugging.
            raise CaseError(f"{self.path} is not a case database: {exc}") from exc
        if row is None:
            raise CaseError(f"{self.path} is not a case database")
        found = int(row["value"])
        if found != SCHEMA_VERSION:
            raise CaseError(
                f"{self.path} was written by schema version {found}, this build expects "
                f"{SCHEMA_VERSION}. Re-ingest the bundles into a new case rather than "
                "editing it: a partly migrated case is worse than two honest ones."
            )

    def close(self) -> None:
        self._connection.commit()
        self._connection.close()

    def __enter__(self) -> Case:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """One transaction around a whole ingest.

        An ingest either lands or does not. A case half-populated by a crash would have
        counts nobody could trust, and a count is what an analyst reads first.
        """
        try:
            yield self._connection
        except BaseException:
            self._connection.rollback()
            raise
        else:
            self._connection.commit()

    # ------------------------------------------------------------------- writes

    def set_meta(self, key: str, value: str) -> None:
        self._connection.execute(
            "INSERT OR REPLACE INTO case_meta (key, value) VALUES (?, ?)", (key, value)
        )

    def add_bundle(self, record: BundleRecord) -> None:
        """Record a collection. Re-ingesting the same one updates the row in place."""
        self._connection.execute(
            """
            INSERT INTO bundles (
                bundle_uuid, source_kind, source_path, tool_name, tool_version,
                format_version, collected_os, collected_host, collector_user, elevated,
                started_utc, finished_utc, local_timezone, local_timezone_name,
                manifest_sha256, ingested_utc
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(bundle_uuid) DO UPDATE SET
                source_kind = excluded.source_kind,
                source_path = excluded.source_path,
                ingested_utc = excluded.ingested_utc
            """,
            (
                record.bundle_uuid,
                record.source_kind,
                record.source_path,
                record.tool_name,
                record.tool_version,
                record.format_version,
                record.collected_os,
                record.collected_host,
                record.collector_user,
                None if record.elevated is None else int(record.elevated),
                record.started_utc,
                record.finished_utc,
                record.local_timezone,
                record.local_timezone_name,
                record.manifest_sha256,
                datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
            ),
        )

    def user_id(self, name: str | None) -> int | None:
        """The row id for a user name, creating the row the first time it is seen.

        Names are indirected through this table so that pseudonymizing a case later is an
        update to one small table rather than a rewrite of every event.
        """
        if not name:
            return None
        if name in self._users:
            return self._users[name]
        cursor = self._connection.execute(
            "INSERT INTO users (name) VALUES (?) ON CONFLICT(name) DO NOTHING", (name,)
        )
        if cursor.lastrowid and cursor.rowcount == 1:
            self._users[name] = int(cursor.lastrowid)
        else:
            row = self._connection.execute(
                "SELECT user_id FROM users WHERE name = ?", (name,)
            ).fetchone()
            self._users[name] = int(row["user_id"])
        return self._users[name]

    def host_id(self, name: str | None) -> int | None:
        if not name:
            return None
        if name in self._hosts:
            return self._hosts[name]
        cursor = self._connection.execute(
            "INSERT INTO hosts (name) VALUES (?) ON CONFLICT(name) DO NOTHING", (name,)
        )
        if cursor.lastrowid and cursor.rowcount == 1:
            self._hosts[name] = int(cursor.lastrowid)
        else:
            row = self._connection.execute(
                "SELECT host_id FROM hosts WHERE name = ?", (name,)
            ).fetchone()
            self._hosts[name] = int(row["host_id"])
        return self._hosts[name]

    def add_artifact(self, bundle_uuid: str, entry: dict[str, Any]) -> None:
        """Record one file the collection carried, parsed or not.

        Every manifest entry lands here, including the ones marked not collected. That is
        what lets a case answer the question its own reliability depends on: the difference
        between no events from an agent and nothing from that agent having been collected.
        """
        self._connection.execute(
            """
            INSERT INTO artifacts (
                bundle_uuid, artifact_id, agent, category, original_path, bundle_path,
                sha256, size, status, collected, reason, user_id, mtime_utc, atime_utc,
                ctime_utc, birthtime_utc, symlink, reparse_point, changed_while_reading
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(bundle_uuid, original_path) DO UPDATE SET
                sha256 = excluded.sha256,
                collected = excluded.collected,
                reason = excluded.reason
            """,
            (
                bundle_uuid,
                entry.get("artifact_id"),
                entry.get("agent"),
                entry.get("category"),
                entry["original_path"],
                entry.get("bundle_path"),
                entry.get("sha256"),
                entry.get("size"),
                entry.get("status"),
                int(bool(entry.get("collected"))),
                entry.get("reason"),
                self.user_id(entry.get("user")),
                entry.get("mtime_utc"),
                entry.get("atime_utc"),
                entry.get("ctime_utc"),
                entry.get("birthtime_utc"),
                entry.get("symlink"),
                _maybe_int(entry.get("reparse_point")),
                _maybe_int(entry.get("changed_while_reading")),
            ),
        )

    def set_parse_result(
        self,
        bundle_uuid: str,
        original_path: str,
        *,
        parser: str | None,
        status: str,
        detail: str | None = None,
        events: int = 0,
        unparsed_records: int = 0,
    ) -> None:
        """Record how the parsers got on with one file."""
        self._connection.execute(
            """
            UPDATE artifacts
               SET parser = ?, parse_status = ?, parse_detail = ?,
                   events_parsed = ?, records_unparsed = ?
             WHERE bundle_uuid = ? AND original_path = ?
            """,
            (parser, status, detail, events, unparsed_records, bundle_uuid, original_path),
        )

    def add_gap(self, bundle_uuid: str, kind: str, detail: str, reason: str | None) -> None:
        """Carry a hole in the collection into the case.

        The manifest already records these, but the manifest is not what somebody reads a
        year later. A pattern the collector declined to search is a gap in the evidence,
        and it has to be visible from inside the case.
        """
        self._connection.execute(
            """
            INSERT INTO collection_gaps (bundle_uuid, kind, detail, reason)
            VALUES (?,?,?,?)
            ON CONFLICT(bundle_uuid, kind, detail) DO UPDATE SET reason = excluded.reason
            """,
            (bundle_uuid, kind, detail, reason),
        )

    def add_events(self, events: Iterable[Event]) -> int:
        """Store events and their facets. Returns how many rows were new.

        The insert ignores a conflict rather than replacing, because the same evidence
        always produces the same row: a second ingest of one bundle has nothing to say that
        the first did not.
        """
        added = 0
        for event in events:
            cursor = self._connection.execute(
                """
                INSERT INTO events (
                    event_id, bundle_uuid, kind, agent, ts_utc, ts_precision, ts_source,
                    actor, client, host_id, user_id, session_id, project_path, git_branch,
                    artifact_id, original_path, file_sha256, locator, payload, raw,
                    parse_problem
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(event_id) DO NOTHING
                """,
                (
                    event.event_id,
                    event.provenance.bundle_uuid,
                    event.kind,
                    event.agent,
                    event.ts_utc,
                    event.ts_precision,
                    event.ts_source,
                    event.actor,
                    event.client,
                    self.host_id(event.host),
                    self.user_id(event.user),
                    event.session_id,
                    event.project_path,
                    event.git_branch,
                    event.provenance.artifact_id,
                    event.provenance.original_path,
                    event.provenance.sha256,
                    event.provenance.locator,
                    event.payload_json(),
                    event.raw_json(),
                    event.parse_problem,
                ),
            )
            if cursor.rowcount:
                added += 1
                self._add_facets(event)
        return added

    def _add_facets(self, event: Event) -> None:
        """Derive the indexed facets from one event's payload.

        Derived here rather than in each parser so that twelve parsers cannot disagree
        about what a file write is. A parser's job is to say what happened in its own
        agent's terms; turning that into the columns an analyst queries is this layer's.
        """
        payload = event.payload
        event_id = event.event_id
        connection = self._connection

        for entry in _as_dicts(payload.get("files")):
            path = entry.get("path")
            if not path:
                continue
            connection.execute(
                "INSERT OR IGNORE INTO facet_files (event_id, path, operation, bytes) "
                "VALUES (?,?,?,?)",
                (event_id, str(path), str(entry.get("operation") or "unknown"), entry.get("bytes")),
            )

        for entry in _as_dicts(payload.get("commands")):
            command = entry.get("command")
            if not command:
                continue
            connection.execute(
                "INSERT OR IGNORE INTO facet_commands "
                "(event_id, command, executable, cwd, exit_code) VALUES (?,?,?,?,?)",
                (
                    event_id,
                    str(command),
                    entry.get("executable") or _first_word(str(command)),
                    entry.get("cwd"),
                    entry.get("exit_code"),
                ),
            )

        for entry in _as_dicts(payload.get("network")):
            host = entry.get("host")
            if not host:
                continue
            connection.execute(
                "INSERT OR IGNORE INTO facet_network (event_id, host, url, method) "
                "VALUES (?,?,?,?)",
                (event_id, str(host), entry.get("url") or "", entry.get("method")),
            )

        for entry in _as_dicts(payload.get("mcp")):
            server = entry.get("server")
            if not server:
                continue
            connection.execute(
                "INSERT OR IGNORE INTO facet_mcp (event_id, server, tool) VALUES (?,?,?)",
                (event_id, str(server), entry.get("tool") or ""),
            )

        for entry in _as_dicts(payload.get("models")):
            model = entry.get("model")
            if not model:
                continue
            connection.execute(
                "INSERT OR IGNORE INTO facet_models "
                "(event_id, model, input_tokens, output_tokens, cost) VALUES (?,?,?,?,?)",
                (
                    event_id,
                    str(model),
                    entry.get("input_tokens"),
                    entry.get("output_tokens"),
                    entry.get("cost"),
                ),
            )

        for entry in _as_dicts(payload.get("permissions")):
            connection.execute(
                "INSERT OR IGNORE INTO facet_permissions (event_id, mode, decision, subject) "
                "VALUES (?,?,?,?)",
                (
                    event_id,
                    entry.get("mode") or "",
                    entry.get("decision") or "unknown",
                    entry.get("subject") or "",
                ),
            )

        for entry in _as_dicts(payload.get("instructions")):
            path = entry.get("path")
            if not path:
                continue
            connection.execute(
                "INSERT OR IGNORE INTO facet_instructions (event_id, path, scope) VALUES (?,?,?)",
                (event_id, str(path), entry.get("scope") or "unknown"),
            )

    # -------------------------------------------------------------------- reads

    def counts(self) -> dict[str, int]:
        """The numbers an analyst reads first, including the uncomfortable ones."""
        query = self._connection.execute
        out = {
            "bundles": query("SELECT count(*) AS n FROM bundles").fetchone()["n"],
            "artifacts": query("SELECT count(*) AS n FROM artifacts").fetchone()["n"],
            "artifacts_collected": query(
                "SELECT count(*) AS n FROM artifacts WHERE collected = 1"
            ).fetchone()["n"],
            "artifacts_unparsed": query(
                "SELECT count(*) AS n FROM artifacts "
                "WHERE collected = 1 AND parse_status IN ('unsupported', 'failed')"
            ).fetchone()["n"],
            "events": query("SELECT count(*) AS n FROM events").fetchone()["n"],
            "events_unparsed": query(
                "SELECT count(*) AS n FROM events WHERE kind = 'unparsed.record'"
            ).fetchone()["n"],
            # The part of that total which was read fine and has no verified mapping yet,
            # so the two opposite answers under one kind can be told apart. A line that did
            # not decode is a defect in the evidence; a row of a store nobody has read a
            # schema for is intact evidence with no reading yet, and there can be an
            # enormous number of those. Reported as one number, the first disappears into
            # the second and the word unreadable in front of the total is wrong about
            # nearly all of it.
            "events_uninterpreted": query(
                "SELECT count(*) AS n FROM events WHERE kind = 'unparsed.record' "
                "   AND parse_problem LIKE '%' || ? || '%'",
                (UNINTERPRETED_MARK,),
            ).fetchone()["n"],
            "events_without_timestamp": query(
                "SELECT count(*) AS n FROM events WHERE ts_utc IS NULL"
            ).fetchone()["n"],
            "collection_gaps": query("SELECT count(*) AS n FROM collection_gaps").fetchone()["n"],
        }
        return {key: int(value) for key, value in out.items()}

    def query(
        self, sql: str, parameters: Sequence[Any] | Mapping[str, Any] = ()
    ) -> list[sqlite3.Row]:
        """Read the case. Values are bound, never formatted into the statement."""
        return list(self._connection.execute(sql, parameters))


def _maybe_int(value: Any) -> int | None:
    return None if value is None else int(bool(value))


def _first_word(command: str) -> str:
    """The executable a command line invokes, best effort.

    Best effort is honest here: a shell line can set variables first, quote the path or
    pipe. The facet is an index to narrow a search, not a claim about what ran, and the
    full command line is in the same row for the analyst to read.
    """
    for token in command.split():
        if "=" in token and not token.startswith(("/", ".", "-")):
            continue  # a leading VAR=value assignment
        return token
    return ""


def _as_dicts(value: Any) -> list[dict[str, Any]]:
    """Normalise a payload facet field into a list of mappings.

    Tolerant on purpose: a parser that emits one mapping where the schema expects a list,
    or a string where it expects a mapping, should cost a slightly coarser facet row rather
    than an exception that abandons the rest of the file.
    """
    if value is None:
        return []
    if isinstance(value, dict):
        return [value]
    if isinstance(value, str):
        return [{"path": value}]
    if isinstance(value, list):
        out = []
        for item in value:
            if isinstance(item, dict):
                out.append(item)
            elif isinstance(item, str):
                out.append({"path": item, "command": item, "host": item, "server": item})
        return out
    return []


__all__ = ["BundleRecord", "Case", "CaseError"]
