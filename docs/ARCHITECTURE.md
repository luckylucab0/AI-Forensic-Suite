# Architecture

English | [Deutsch](ARCHITECTURE.de.md)

This document says how the parts fit together and why. Individual decisions, with the
cost each one accepts, are in [adr/](adr/).

## The pipeline

```
   endpoint                     analyst workstation
   ────────                     ───────────────────

  catalog/*.yaml  ──embedded──▶ collect.py / collect.ps1
        │                              │
        │                              ▼
        │                       evidence bundle  ──▶ verify ──▶ ingest ──▶ case.sqlite
        │                       manifest.json                                 │
        │                       chain_of_custody.jsonl              ┌─────────┼─────────┐
        │                       files/<original paths>              ▼         ▼         ▼
        │                                                        timeline   rules     serve
        └──generated──▶ Velociraptor / KAPE / MDE / KQL / osquery            scan    viewer
```

Two things are worth noticing in that picture.

The catalogue is upstream of everything. It is the only place that says where an agent
stores its data, and both collectors, all five collection-rule exporters and the generated
documentation are produced from it. Nothing downstream hardcodes a path. CI regenerates
every derived artifact and fails on any difference, so a path can never be right in one
place and stale in another.

The bundle is the boundary. Everything to the left of it happens on a machine under
investigation, possibly compromised, under time pressure, with no dependencies available.
Everything to the right happens offline on an analyst workstation and can afford to be
thorough. The bundle is the contract between the two, which is why it is specified
independently in [BUNDLE_FORMAT.md](BUNDLE_FORMAT.md) rather than being whatever the
collector happens to write.

## Components

### `catalog/`

One YAML file per agent, validated against `catalog/schema/catalog.schema.json`. The
schema lives next to the data, not inside the Python package, so CI and a collector can
validate without importing anything.

Each artifact entry answers: what it is (`id`, `agent`, `category`), where it is (`os`,
`paths` as globs with `~`, `%APPDATA%`, `%LOCALAPPDATA%` and `$XDG_DATA_HOME` placeholders
the collectors expand), what it is (`format`), who may read it (`sensitivity`), how long it
survives (`volatility`), how much we trust the entry (`status`, `source`) and what an
analyst should know (`notes`).

`status` is the field that keeps the catalogue honest. `verified` means a source URL
actually states that path and somebody fetched it. Everything else is `unverified`, is
still collected by glob, and is flagged as unverified in analyzer output. That flag is
load-bearing: it is the difference between "the agent was not used" and "we were never
sure where to look".

`volatility` is what makes the catalogue useful under time pressure. Several agents delete
their own history on a schedule, so the catalogue records what expires and how fast, and
the collection documentation orders artifacts by that rather than alphabetically.

### `collector/`

Two implementations of one specification: `collect.py` for POSIX systems, standard library
only, Python 3.8 or newer, and `collect.ps1` for Windows, PowerShell 5.1 or newer, no
modules. Each is a single file with the catalogue embedded as a JSON blob between marker
comments, written by `scripts/build_collectors.py`.

The single-file, zero-dependency constraint is not minimalism for its own sake. It is what
lets a collector be pushed through EDR live response, a remote shell or a USB stick and run
on a machine where nothing may be installed and nothing may be downloaded. Python 3.8 and
PowerShell 5.1 are the floors because those are what a corporate fleet actually has.

Two independent implementations of the same format will drift unless something stops them,
so three things do: a bundle conformance suite written once and run against a bundle from
either collector, a differential test in CI that diffs the two manifests modulo a
documented list of platform-specific fields, and the shared specification itself. The list
of fields allowed to differ is the interesting part, because it is where the operating
systems genuinely disagree: `birthtime` does not exist on Linux, `atime` is meaningless on
a volume mounted `noatime`, and `ctime` means inode change time on Unix but creation time
on Windows.

### The evidence bundle

A directory, optionally zipped: `manifest.json`, `chain_of_custody.jsonl`, and a `files/`
tree that mirrors original paths. See [BUNDLE_FORMAT.md](BUNDLE_FORMAT.md) for the field
list and the path encoding rules.

Mirroring original paths is what makes ingest uniform. A native bundle, a KAPE output tree
and a Velociraptor collection are all just a root plus original paths, so one adapter shape
handles all three, plus a mounted image root and an exported user profile.

The custody log is a hash chain: each record carries the hash of the previous one and of
the manifest. That makes it tamper-evident, not tamper-proof, and the documentation says
so. A file in a writable directory can always be rewritten; what a hash chain buys is that
it cannot be rewritten *quietly*.

### `src/agentforensics/`

- `catalog/` loads and validates the catalogue
- `bundle/` writes, reads, hashes and verifies bundles and the custody chain
- `ingest/` adapters for a native bundle, a KAPE tree, a Velociraptor collection, and a
  plain directory or mounted image root
- `parsers/` one module per agent or per format family, turning raw records into unified
  events. A parser is chosen by the catalogue entry that claimed the file, so it can never
  disagree with the catalogue about what a file is. A file with no parser is recorded as
  unsupported rather than skipped. Seven agents are read today: Claude Code, Codex CLI,
  Copilot CLI, Gemini CLI and Qwen Code (one module, because Qwen is a fork and both write
  the Gemini content shape), Pi, and Cline with its forks Roo Code and Kilo Code (one
  module for the same reason). Under all of those sits one module that is about a format
  rather than an agent: every SQLite store in the catalogue, twenty-eight of them across
  fifteen agents, is opened read-only from a copy and returned table by table and row by
  row. It reads nothing out of a row beyond what the row literally says, a column named as
  a time or as text, and every event it produces states that this is an uninterpreted
  reading. So a chat database nobody has a verified schema for is visible evidence somebody
  still has to look at, instead of a file the case merely says existed. A verified
  per-agent parser placed ahead of it takes an artifact over, one schema at a time, and
  opencode is the first: its module maps the three tables whose schema was read against the
  vendor's own generated migration and hands every other table, including the older message
  pair, back to the uninterpreted reading, so a store is never half read with the other half
  silently absent. Amazon Q's CLI store is the second, and it is the one whose store holds
  what no other artifact does: its conversations table is keyed by the working directory,
  its history table is a shell command log with exit codes, and its conversation state
  records which turns the agent has stopped sending to the model while keeping them on disk.
  Zed is the third, and it is the reason the Python floor moved: it writes each thread as a
  zstd frame in a BLOB, so the store reader decompresses one before any parser sees it, and
  every other SQLite store gains the same reading. A Zed thread carries one time for the
  whole thread and none for the turns inside it, which the parser states rather than filling
  in. A second floor of the same shape sits under the line-delimited logs: every JSON Lines
  artifact in the catalogue that no verified parser claims is read record by record, with
  the record whole in `raw` and nothing taken out of it but what it literally names, a
  field named as a time, a session, a working copy or text. That one exists because the two
  producers of the unified format had drifted apart and the analyzer was the side reading
  less: the generated endpoint query already returned every record of an unmapped log,
  while a case built from a collection of the same endpoint held one `artifact.fs` event
  per file and nothing about what was in it. A test fails now when that gap opens again in
  either direction. The third floor is the one that needed a decision rather than a rule
  (ADR 0027): a whole JSON document has no records of its own, so where the records are
  inside it is a question about what the document means. It is split by structure alone, one
  level deep. A root that is a list is one event per element; a root that is an object is one
  event for the document and then one per element of each top-level key whose value is a list
  of objects; anything else is one event. A document that nests its records deeper keeps them
  whole in the document event, which is visibly a partial reading rather than a wrong one.
  The credential stores are the one thing it does not claim, because a token in the payload
  of a timeline event is not what `--include-secrets` was for, and the file and its hash are
  in the case either way. What a record out of one of these documents *is* comes from the
  catalogue rather than from the document: an entry the catalogue files as configuration
  produces `config.snapshot` records and everything else produces `unparsed.record`. That
  is the difference between a case holding a configuration and the rules being able to read
  it, and it was worth four shipped rules that could not fire on a real collection at all.
  Beside
  it sits a second format-shaped module, `instructions/`, for the instruction surface: the
  sixty-three catalogue artifacts that hold skills, commands, output styles, rules, steering
  files and hook scripts. It reads each file whole, tells the scope apart from the working
  copies the collection recorded rather than from the path's shape, lifts a skill's front
  matter including the tools it grants itself, and counts the characters a reviewer cannot
  see. It does not claim to show a system prompt: the vendor's base prompt is not on the
  endpoint, and saying otherwise would answer a question the evidence cannot.
- `model/` the unified event model and the SQLite case schema
- `unified/` the event model on the wire: the JSON Lines format and its schema, plus
  the normalizer that turns a collection into one log without building a case
- `timeline/` timeline construction and exports (CSV, JSONL, Timesketch JSONL)
- `rules/` the declarative YAML rule engine
- `exporters/` the collection-rule generators, one module per target format
- `webui/` the local read-only API, which also serves the viewer
- `cli.py` the `agentforensics` command, aliased `afx`

### The unified event model

Every parser emits the same event shape regardless of which agent produced the record:
a deterministic `event_id` derived from provenance, a nullable `ts_utc` with an explicit
`ts_precision`, `agent`, `client`, `host`, `user`, `session_id`, `project_path`,
`git_branch`, `actor`, `kind`, a kind-specific `payload`, `provenance` (bundle id, original
path, file hash, line number or byte offset) and `raw`, the original record kept verbatim.

`raw` is not redundancy. It is the guarantee that a mapping mistake in a parser costs
interpretation and not evidence: the original record is always there to re-read.

`event_id` being derived from provenance rather than from a counter makes re-ingest
idempotent. The same evidence produces the same identifiers, so ingesting a bundle twice
does not double a case, and a finding from last week still points at the same event.

Event kinds are deliberately agent-neutral: `session.start`, `session.end`, `user.prompt`,
`assistant.text`, `assistant.thinking`, `tool.call`, `tool.result`, `file.read`,
`file.write`, `file.snapshot`, `command.exec`, `network.request`, `mcp.call`,
`permission.decision`, `permission.change`, `safety.refusal`, `config.snapshot`,
`instruction.source`, `memory.write`, `plan.write`, `prompt.history` and `artifact.fs`.

Four of those are worth a sentence. `permission.decision` is one request answered under the
rules in force, and `permission.change` is a change to the rules themselves: the bypass
question needs both, because one says what happened to a request and the other says who
moved the goalposts and when. `safety.refusal` is the model declining, which is not the same
as the harness denying a permission, and only some agents record it, so its absence is never
evidence that nothing was refused.

`instruction.source` is an instruction that was in force on the endpoint: a CLAUDE.md, a
skill, an output style, a rules or steering file, a hook script. It is not part of
`config.snapshot` because the two answer different questions and a timeline has to keep them
apart. A setting says how the agent was configured; an instruction is text the model was
told to obey, and whether the agent was manipulated by injected instructions is only about
the second. The name says source rather than prompt on purpose. The vendor's own base prompt
is compiled into the agent or comes from its server, so it is not on the endpoint at all,
and this kind carries the part of a system prompt that can be evidence rather than the whole
of one.

`artifact.fs` is the one that needs explaining: it carries the filesystem timestamps of an
artifact file itself. Some artifacts have no internal timestamps at all, and for those the
only temporal evidence is when the file was created, modified or last read. Without this
kind they would be invisible on a timeline.

Facets are derived once at ingest and stored in their own indexed tables: files touched,
commands executed, hosts and URLs contacted, MCP servers and tools used, models used, token
and cost figures where an agent records them, clients used, permission modes seen, and the
instruction files in effect. They exist so the questions an analyst actually asks, such as
every file an agent wrote across all sessions, or every external host contacted ranked by
frequency, are one indexed query rather than a scan over JSON payloads.

The identity columns point at `users` and `hosts` tables rather than holding names
directly. That indirection is there now so that pseudonymization later is a feature and not
a rewrite.

### The unified log

The same event model, serialized as JSON Lines, one event per record, defined by
`src/agentforensics/unified/agentlog.v1.schema.json`. `docs/UNIFIED_FORMAT.md` is the
reference; ADR 0018 records why it is the event model on the wire rather than a second
model.

It exists because three consumers need agent history in a form that is not a case database:
a fleet collection that returns many hosts at once, a collection tool that normalizes on the
endpoint and returns only the parsed result, and the viewer, which runs in a browser with no
server. Every record stands alone and carries its own version, so two logs concatenate into
a valid third one and a producer that emits rows rather than files can write the format
directly.

`afx normalize <source>` produces it through the same adapters and parsers as `afx ingest`,
which is what stops the two paths from reading a file differently. A test asserts that a log
and a case built from one source hold exactly the same events.

### The rule engine

Rules are YAML, one file per rule, and the match logic is data rather than code: field
selectors, operators, boolean composition and count thresholds. No rule can execute
anything. That is a security property, since rules come from a public repository and run
over text an attacker may control, and a reviewability property, since a rule can be read
and argued about by someone who does not write Python.

Every rule carries inline positive and negative test samples that pytest executes, so a
rule without tests cannot pass CI. Every rule also documents its known false positives,
because the honest claim for all of this is that a finding is a lead an analyst must
review, never a verdict.

What the packs deliberately do not cover is searching for one particular organization's
own data. That is a different product, it would put internal domains and code names into a
public repository, and it would pull the suite away from the question it exists to answer.
The packs stay focused on agent behavior: secrets that reached a transcript, dangerous
commands, sensitive paths, exfiltration indicators, permission bypass, anti-forensics,
prompt injection, supply chain and third-party endpoints.

Findings live in the case database next to the events they rest on, linked through a table
rather than a column, because an aggregate rule fires on a group: twenty files read in one
minute is one finding over twenty events, and a finding that could only point at one of
them would be a finding an analyst cannot check. A finding is keyed by its rule and its
evidence, so re-scanning a case after a rule is fixed leaves the counts intact rather than
doubling them.

Every scan is recorded whether or not anything fired, naming each rule that ran. Without
that record a case with no findings and a case nobody scanned look identical, and those are
opposite conclusions. It is the same rule the collection side follows for a glob it declined
to search.

### The viewer

`viewer/index.html` is a single dependency-free file that renders sessions read-only. It
predates the suite, is kept as a component, and stays usable entirely on its own.

Its data layer sits behind a two-method source interface, `listDir` and `readText`, over
opaque path strings. That is what makes three run modes possible without touching the
renderer: scraping a local directory listing, reading a folder through the browser's File
System Access API, and reading the local API that `serve` exposes. The first two work with
no install at all, which is why they are preserved rather than replaced.

The rule the viewer follows most strictly: never make a record disappear. A line that fails
to parse, a record type no parser knows, an assistant turn without an id, an unrecognized
event kind, all of these render as their own visible row, and the session header counts
unparsed lines. Silently rendering nothing would make an analyst conclude nothing was
there, which is the one failure mode a forensic tool must not have.

### The local web UI

`afx serve --case <db>` puts one case behind the viewer, on 127.0.0.1, read-only. Two
modules: `webui/api.py` turns a case into the data a viewer shows and knows nothing about
HTTP, so every projection is testable without a socket; `webui/server.py` binds the socket
and carries the hardening.

A session endpoint answers with the unified log format, not a shape of its own. The viewer
therefore reads a case with the reader it already had, and this project has exactly one wire
format for an agent event rather than a fourth one that could disagree with the other three.

A session is derived rather than stored. A case holds events; what the sidebar calls a
session is a group of them sharing six values (agent, host, user, whether they are
filesystem timestamps, working directory, session id), and the key in the URL is a hash of
exactly those. Same case, same keys, so a link into a session survives a re-ingest.

The hardening is part of the decision rather than a later concern, because a forensic
workstation is not a friendly network: loopback only with no option to change it, a random
per-run path token, a `Host` check against DNS rebinding, an `Origin` check, GET and HEAD
only, a request with a body refused unread, one explicit route table with no fallback, the
viewer served from an in-process byte string so there is no path to traverse, a content
security policy that forbids reaching off the server, and the case opened `mode=ro` so
SQLite refuses a write. ADR 0006 notes that such a list is the part most likely to rot, so
each item has its own test.

See ADR 0006 and ADR 0020, and docs/WEBUI.md.

## Cross-cutting decisions

**Offline, with no exceptions.** No network access at runtime, no telemetry, no update
check, no LLM or API call anywhere in the pipeline. This is a requirement of the problem,
not a preference: an analyst workstation may be air-gapped, evidence handling forbids
sending data anywhere, and an outbound request during an investigation can tip off a
subject. It is also why the local UI uses the standard library rather than a web framework
whose dependency tree would have to be vendored.

**Deterministic output.** Same input, same output, stable ordering everywhere, timestamps
in UTC ISO 8601 with the endpoint's own timezone recorded once in the manifest. Two runs
producing different bytes would make a diff meaningless and a hash unusable as a reference.

**Read-only evidence.** The collector and the analyzer never modify, move, rename or delete
a source artifact and never execute an agent binary on the target. Version information is
read from files. Where reading a file unavoidably touches its access time, that is recorded
rather than hidden.

**Few dependencies, permissively licensed.** The collectors have none at all. The analyzer
keeps them to a minimum, and each one is a decision with an ADR.

## Phases

| Phase | Content |
| --- | --- |
| 0 | Repository hygiene, sanitized viewer, tooling, CI, OpSec guard |
| 1 | Artifact catalogue, both collectors, bundle format, `verify`, synthetic fixtures |
| 2 | Collection rules generated for Velociraptor, KAPE, Defender live response, KQL, osquery |
| 3 | Analyzer core: ingest, parsers, event model, case database, timeline exports |
| 4 | Rule engine and starter packs |
| 5 | Local web UI: read-only API, viewer API source, case, timeline, findings and artifact views |

Deliberately out of scope for now: case management with triage states and notes, HTML and
PDF reporting, pseudonymization, and a shell fallback collector for hosts without Python.
