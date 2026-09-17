"""The SQLite case database schema.

One file per case, so a case is a thing an analyst can copy, hash and hand over. SQLite
because it is in the standard library, it is a single file, it is readable by every
forensic tool an examiner already owns, and it needs no service running on a workstation
that may be air-gapped.

Three shapes in here are decisions rather than plumbing.

Identity is indirect. Events point at rows in `users` and `hosts` rather than carrying
names, so that pseudonymizing a case later is an update to two small tables instead of a
rewrite of every event.

Facets are separate indexed tables, derived once at ingest. The questions an analyst
actually asks, every file this agent wrote, every external host contacted ranked by
frequency, are then one indexed query rather than a scan that unpacks JSON on every row.

Nothing cascades on delete. A case is evidence: rows are added and read, and the way to
discard one is to discard the file. A foreign key that silently removed events when a
bundle row went away would be a way to lose evidence by accident.
"""

from __future__ import annotations

# 2 added the findings tables. No migration on purpose: this module's own rule is that a
# case is evidence, and the version check refuses an older file with a sentence telling the
# reader to re-ingest rather than editing it in place. Re-ingest is idempotent and cheap,
# and a partly migrated case is worse than two honest ones.
SCHEMA_VERSION = 2

# Kept as one statement per string so a migration can be expressed as a list of additions
# and the whole schema can be applied to an empty file in one transaction.
SCHEMA: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS case_meta (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """,
    """
    -- One row per collection ingested. A case can hold several: the same endpoint
    -- collected twice, or an endpoint and the SSH host it worked on.
    CREATE TABLE IF NOT EXISTS bundles (
        bundle_uuid     TEXT PRIMARY KEY,
        source_kind     TEXT NOT NULL,     -- native, kape, velociraptor, directory
        source_path     TEXT NOT NULL,
        tool_name       TEXT,
        tool_version    TEXT,
        format_version  INTEGER,
        collected_os    TEXT,
        collected_host  TEXT,
        collector_user  TEXT,
        elevated        INTEGER,
        started_utc     TEXT,
        finished_utc    TEXT,
        -- The endpoint's own offset and zone name, recorded once here rather than applied
        -- to every timestamp. Every ts_utc in this database is UTC; this is what turns one
        -- back into the wall-clock time a user would have seen, which is what a witness
        -- statement will be phrased in.
        local_timezone      TEXT,
        local_timezone_name TEXT,
        manifest_sha256 TEXT,
        ingested_utc    TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS users (
        user_id  INTEGER PRIMARY KEY,
        name     TEXT NOT NULL UNIQUE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS hosts (
        host_id  INTEGER PRIMARY KEY,
        name     TEXT NOT NULL UNIQUE
    )
    """,
    """
    -- Every file the collection carried, whether or not a parser understood it. This is
    -- the difference between "no events from this agent" and "nothing from this agent was
    -- collected", which are opposite conclusions and must never be confused.
    CREATE TABLE IF NOT EXISTS artifacts (
        artifact_row_id INTEGER PRIMARY KEY,
        bundle_uuid     TEXT NOT NULL REFERENCES bundles(bundle_uuid),
        artifact_id     TEXT,
        agent           TEXT,
        category        TEXT,
        original_path   TEXT NOT NULL,
        bundle_path     TEXT,
        sha256          TEXT,
        size            INTEGER,
        status          TEXT,              -- the catalogue's verified/unverified
        collected       INTEGER NOT NULL,
        reason          TEXT,              -- why it was not collected, when it was not
        user_id         INTEGER REFERENCES users(user_id),
        mtime_utc       TEXT,
        atime_utc       TEXT,
        ctime_utc       TEXT,
        birthtime_utc   TEXT,
        symlink         TEXT,
        reparse_point   INTEGER,
        changed_while_reading INTEGER,
        -- How the parsers got on with this file, so a case can be asked the one question
        -- that matters for its own reliability: what did we collect and fail to read.
        parser          TEXT,
        parse_status    TEXT,              -- parsed, unsupported, failed, skipped
        parse_detail    TEXT,
        events_parsed   INTEGER NOT NULL DEFAULT 0,
        records_unparsed INTEGER NOT NULL DEFAULT 0,
        UNIQUE (bundle_uuid, original_path)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS events (
        event_id      TEXT PRIMARY KEY,
        bundle_uuid   TEXT NOT NULL REFERENCES bundles(bundle_uuid),
        kind          TEXT NOT NULL,
        agent         TEXT NOT NULL,
        ts_utc        TEXT,
        ts_precision  TEXT NOT NULL,
        ts_source     TEXT,
        actor         TEXT NOT NULL,
        client        TEXT,
        host_id       INTEGER REFERENCES hosts(host_id),
        user_id       INTEGER REFERENCES users(user_id),
        session_id    TEXT,
        project_path  TEXT,
        git_branch    TEXT,
        artifact_id   TEXT,
        original_path TEXT NOT NULL,
        file_sha256   TEXT NOT NULL,
        locator       TEXT,
        payload       TEXT NOT NULL,
        raw           TEXT NOT NULL,
        parse_problem TEXT
    )
    """,
    # An event with no timestamp sorts before every timestamped one rather than being
    # dropped from the ordering, which is why ts_utc is first and nulls are not excluded.
    "CREATE INDEX IF NOT EXISTS events_ts ON events(ts_utc)",
    "CREATE INDEX IF NOT EXISTS events_kind_ts ON events(kind, ts_utc)",
    "CREATE INDEX IF NOT EXISTS events_agent_ts ON events(agent, ts_utc)",
    "CREATE INDEX IF NOT EXISTS events_session ON events(session_id, ts_utc)",
    "CREATE INDEX IF NOT EXISTS events_path ON events(original_path)",
    "CREATE INDEX IF NOT EXISTS events_problem ON events(parse_problem) WHERE parse_problem IS NOT NULL",
    """
    -- Files the agent read, wrote or snapshotted. The one facet that gets asked about in
    -- every case: what did it touch, and did it touch anything it should not have.
    CREATE TABLE IF NOT EXISTS facet_files (
        event_id  TEXT NOT NULL REFERENCES events(event_id),
        path      TEXT NOT NULL,
        operation TEXT NOT NULL,           -- read, write, delete, snapshot
        bytes     INTEGER,
        PRIMARY KEY (event_id, path, operation)
    )
    """,
    "CREATE INDEX IF NOT EXISTS facet_files_path ON facet_files(path)",
    """
    CREATE TABLE IF NOT EXISTS facet_commands (
        event_id    TEXT NOT NULL REFERENCES events(event_id),
        command     TEXT NOT NULL,
        -- The first word, so "every invocation of a package manager" is an indexed lookup
        -- rather than a LIKE over full command lines.
        executable  TEXT,
        cwd         TEXT,
        exit_code   INTEGER,
        PRIMARY KEY (event_id, command)
    )
    """,
    "CREATE INDEX IF NOT EXISTS facet_commands_exe ON facet_commands(executable)",
    """
    CREATE TABLE IF NOT EXISTS facet_network (
        event_id TEXT NOT NULL REFERENCES events(event_id),
        host     TEXT NOT NULL,
        url      TEXT,
        method   TEXT,
        PRIMARY KEY (event_id, host, url)
    )
    """,
    "CREATE INDEX IF NOT EXISTS facet_network_host ON facet_network(host)",
    """
    CREATE TABLE IF NOT EXISTS facet_mcp (
        event_id TEXT NOT NULL REFERENCES events(event_id),
        server   TEXT NOT NULL,
        tool     TEXT,
        PRIMARY KEY (event_id, server, tool)
    )
    """,
    "CREATE INDEX IF NOT EXISTS facet_mcp_server ON facet_mcp(server)",
    """
    CREATE TABLE IF NOT EXISTS facet_models (
        event_id     TEXT NOT NULL REFERENCES events(event_id),
        model        TEXT NOT NULL,
        input_tokens  INTEGER,
        output_tokens INTEGER,
        cost         REAL,
        PRIMARY KEY (event_id, model)
    )
    """,
    "CREATE INDEX IF NOT EXISTS facet_models_model ON facet_models(model)",
    """
    -- What the agent was allowed to do, and whether anybody said yes. The answer to
    -- "were safety controls bypassed" is assembled from this table and facet_commands.
    CREATE TABLE IF NOT EXISTS facet_permissions (
        event_id  TEXT NOT NULL REFERENCES events(event_id),
        mode      TEXT,                    -- the agent's own name for its approval mode
        decision  TEXT,                    -- allow, deny, always_allow, unknown
        subject   TEXT,                    -- the tool or command the decision was about
        PRIMARY KEY (event_id, mode, decision, subject)
    )
    """,
    """
    -- Which instruction files were in effect. The injected-instruction question is answered
    -- by joining this against the content the collection carried.
    CREATE TABLE IF NOT EXISTS facet_instructions (
        event_id TEXT NOT NULL REFERENCES events(event_id),
        path     TEXT NOT NULL,
        scope    TEXT,                     -- managed, user, project, local, unknown
        PRIMARY KEY (event_id, path)
    )
    """,
    "CREATE INDEX IF NOT EXISTS facet_instructions_path ON facet_instructions(path)",
    """
    -- What the rules found. One row per finding, and a finding is about evidence rather
    -- than about a rule: it names the rule and the version of the rule file that produced
    -- it, so a finding can be reproduced a year later against the same rule text even if
    -- the rule has since been edited. A rule that changed and left findings nobody can
    -- reproduce would leave opinions in a case where evidence is supposed to be.
    CREATE TABLE IF NOT EXISTS findings (
        finding_id   TEXT PRIMARY KEY,
        rule_id      TEXT NOT NULL,
        pack         TEXT NOT NULL,
        severity     TEXT NOT NULL,
        title        TEXT NOT NULL,
        -- The earliest timestamp among the events this finding rests on, or null when none
        -- of them had one. Null rather than the scan time: when a finding happened is a
        -- claim about the evidence, and the scan time is a claim about the examiner.
        ts_utc       TEXT,
        agent        TEXT,
        user_id      INTEGER REFERENCES users(user_id),
        session_id   TEXT,
        -- One line an analyst reads first, and what matched, as JSON. The second is empty
        -- for a rule marked redact: there the matched value is the credential itself, and
        -- a finding is exported and pasted into reports, so copying it into a second place
        -- would spread the credential rather than report it.
        summary      TEXT NOT NULL,
        matched      TEXT NOT NULL,
        event_count  INTEGER NOT NULL DEFAULT 1,
        rule_sha256  TEXT NOT NULL,
        scanned_utc  TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS findings_rule ON findings(rule_id)",
    "CREATE INDEX IF NOT EXISTS findings_severity ON findings(severity, ts_utc)",
    "CREATE INDEX IF NOT EXISTS findings_session ON findings(session_id)",
    """
    -- Which events a finding rests on. A separate table because an aggregate rule fires on
    -- a group: "twenty files read in one minute" is one finding over twenty events, and a
    -- finding that could only point at one of them would be a finding an analyst cannot
    -- check.
    CREATE TABLE IF NOT EXISTS finding_events (
        finding_id TEXT NOT NULL REFERENCES findings(finding_id),
        event_id   TEXT NOT NULL REFERENCES events(event_id),
        PRIMARY KEY (finding_id, event_id)
    )
    """,
    "CREATE INDEX IF NOT EXISTS finding_events_event ON finding_events(event_id)",
    """
    -- Every rule that ran, whether or not it found anything. This is the table that makes
    -- an empty findings list mean something: without it, a case with no findings and a case
    -- nobody scanned look identical, and those are opposite conclusions.
    CREATE TABLE IF NOT EXISTS scan_runs (
        run_id       TEXT PRIMARY KEY,
        started_utc  TEXT NOT NULL,
        finished_utc TEXT NOT NULL,
        rules_run    INTEGER NOT NULL,
        rule_ids     TEXT NOT NULL,
        events_read  INTEGER NOT NULL,
        findings     INTEGER NOT NULL,
        tool_version TEXT NOT NULL
    )
    """,
    """
    -- Patterns the collection declined to search, carried over from the manifest. A hole in
    -- the evidence has to be visible inside the case, not only in the bundle it came from,
    -- because the case is what somebody reads a year later.
    CREATE TABLE IF NOT EXISTS collection_gaps (
        bundle_uuid TEXT NOT NULL REFERENCES bundles(bundle_uuid),
        kind        TEXT NOT NULL,         -- refused_pattern, error, unparsable_agent_state
        detail      TEXT NOT NULL,
        reason      TEXT,
        PRIMARY KEY (bundle_uuid, kind, detail)
    )
    """,
)


def apply_schema(connection: object) -> None:
    """Create the schema on a connection that does not have it yet.

    Typed loosely on purpose: this module deliberately imports nothing, so that the schema
    can be read and applied by a script that does not want the rest of the package.
    """
    cursor = connection.cursor()  # type: ignore[attr-defined]
    for statement in SCHEMA:
        cursor.execute(statement)
    cursor.execute(
        "INSERT OR REPLACE INTO case_meta (key, value) VALUES ('schema_version', ?)",
        (str(SCHEMA_VERSION),),
    )


__all__ = ["SCHEMA", "SCHEMA_VERSION", "apply_schema"]
