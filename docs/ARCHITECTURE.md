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
  unsupported rather than skipped, and the case counts those files and says which they are.
  37 modules read 396 of the catalogue's 488 artifacts, and what the rest is gets asserted
  rather than assumed: every entry in a format this suite reads is either read or carries a
  written reason why not, and the credential stores are exempt as a class because the
  collector withholds their content, which a test pins to credential stores alone. What is
  left needs format work, and until somebody does it the filesystem event is the honest
  answer. The three numbers in this paragraph are held against the catalogue and the parser
  registry by a test, because a count written into prose is true on the day it is written.

  **The agent parsers** are the ones written against a vendor source: Claude Code, Codex CLI
  and its projection into rows, Copilot CLI, Gemini CLI and Qwen Code (one module, because
  Qwen is a fork and both write the Gemini content shape), Pi, Cline with its forks Roo Code
  and Kilo Code and its separate SDK session store, Continue, Zed and its sidebar, Aider,
  Amazon Q, opencode, Hermes, and the VS Code state stores. Each takes its artifacts over
  from the floors below, one verified schema at a time.

  **The floors** are about formats rather than agents, and they exist so that a file nobody
  has mapped is visible in a case as records somebody still has to look at rather than as a
  file name with nothing behind it. Every one of them says on each event that the reading is
  uninterpreted, and the case counts those records separately from the records nothing could
  read: one is intact evidence with no reading yet, the other is a defect in the evidence.

  - **SQLite stores.** Opened read-only from a copy and returned table by table, row by row,
    reading nothing out of a row beyond what it literally says. A zstd frame in a BLOB is
    decompressed first, which is how one editor stores whole threads and why the Python
    floor is 3.14 (ADR 0024). The copy takes the `-wal` and `-shm` siblings with it, because
    a database in write-ahead-log mode keeps its newest transactions in the log and nowhere
    else. Every catalogued database now claims those siblings, and where one does not the
    case records a gap rather than staying quiet: such a store opens, every table is there,
    and the conversation stops before its last messages with SQLite reporting no error at
    all, which is the only failure in this pipeline that looks exactly like success
    (ADR 0032). A collection also carries a log as a file of its own, so one arrives at the
    parser that opens databases and is not one: it is named for what it is, and says
    whether the database it belongs to came with it, because a log whose database is here
    holds records the case already has and a log whose database is not holds records
    nothing can reach. Reporting it as a store that could not be read, which is what it
    used to get, is a loss claimed where there was none on two dozen entries at once.
  - **Line-delimited logs.** Every JSON Lines artifact no verified parser claims, record by
    record. That floor exists because the two producers of the unified format had drifted
    apart and the analyzer was the side reading less; a test fails now when the gap opens
    again in either direction.
  - **Whole documents.** JSON, YAML, TOML and property lists, through one shared reading
    (ADR 0027 for the rule, ADR 0028 for the other three formats). A document has no records
    of its own, so it is split by structure alone, one level deep, never by a guess at what
    it means. What a record *is* comes from the catalogue rather than from the document: an
    entry filed as configuration produces `config.snapshot` and everything else produces
    `unparsed.record`. That distinction is what lets a rule about a setting find one, and it
    was worth four shipped rules that could not fire on a real collection at all. A JSON
    document that is not strict JSON is read the way the product that wrote it reads it,
    with comments taken out and a trailing comma allowed, and the event says which of those
    it needed and carries the text as it stood on disk (ADR 0036). That is not a nicety:
    every editor here writes its settings in that dialect, and a strict reading answered
    with one sentence about the file and put the permissions, the servers and the endpoints
    in it into no event at all.
  - **Text logs.** One line is one record, dated only where the line begins with its own
    timestamp, because a line that mentions a date is not a line that happened then. The
    reading stops after a set number of lines and says so in an event of its own.
  - **Prose.** A chat export, a spilled tool result, a background subagent's output, a
    written plan, and the text behind a pasted-content placeholder: read whole, one event
    per file, because half a prompt reads in a report as what somebody asked.
  - **File snapshots.** The copy three agents keep of a file before they change it, which
    for a change that was never committed is the only place the original text exists. Read
    for its content, because that is what a rule about a credential or an injected
    instruction has to search, and explicit about the fact that a snapshot usually does not
    name the file it came from: one product's backups are named by a one-way digest of the
    original path, another documents the directory and not the naming inside it, and a
    third keeps both sides of an edit with nothing to say which is which. What the path
    states is read; what it does not state is said rather than inferred.
  - **Registry keys.** Four catalogue entries are read from the registry on a live Windows
    host and written into the bundle as JSON documents, with the key as the entry's
    original path (ADR 0033). Two of them are the managed policy that says what an agent
    was allowed to do, which on Windows can exist in the registry alone with no file
    anywhere, so a case that stayed quiet would read as a host with no policy rather than
    as one where nobody looked. One event per value; a key that exists and is empty gets an
    event of its own, because for a policy key that means the policy was not set and it is
    a different answer from a key that was never created. The time is the key's and never
    the value's, since the registry keeps none per value. The hive is a field rather than
    part of the path, because a policy under the user's own hive is one a non-administrator
    could have written.
  - **Text configuration.** The small files that say how an agent was set up, read whole,
    and two that are read a line at a time because a line is what an analyst compares
    against a path. An ignore file is the inverse of every other artifact here: it records
    what the agent was configured never to read, write or index, which is how a file
    somebody expected the agent to have touched gets explained, and a pattern added shortly
    before the period under investigation keeps material out of every transcript the agent
    wrote. A worktree include list is an inventory of the gitignored files the agent copies
    into every worktree it creates, which the vendor documents with environment files and
    secrets configuration as its examples, so a name in it says where copies of that file
    are. Two more lists join them for the same reason. The user's global git excludes,
    where one agent appends a pattern naming its own saved-permission file the first time
    it writes one, which makes that line the single marker that outlives every directory
    the agent owns. And an editor's index list, which is a file-name inventory rather than
    content: it says which files existed in a workspace and were in scope for upload to the
    vendor's indexing service, which is still an answer after the files are gone.
  - **Shell history.** Four shells and the agent's own recall file, each read the way its
    own writer writes it. This is where an agent's start line is, which is the brief's first
    question about an agent and is almost never inside the agent.
  - **Shell scripts that decide an environment.** Two artifacts, one format, opposite
    claims. One agent copies the user's shell to a script before it runs anything, and that
    file is the environment its commands actually ran in rather than a record that somebody
    once typed a line. The other is the shell profile itself, which is what every future
    session starts from, and it is where a collection can be invalidated before it begins:
    an exported variable that relocates an agent's home means the tree taken from the
    default path may be the wrong one or may not exist, and an exported base URL means the
    traffic went somewhere other than the vendor with nothing in any settings file to show
    it. Both spellings of an export are read, including fish's, which has no export
    keyword and is where a relocated agent home looks least like one. Only the three declarations a shell
    states unambiguously are read as such, an export, an alias and a function with its body;
    every other line is kept with the uninterpreted mark, because a reader that decided what
    an arbitrary line of shell means would be writing a shell. It is worth the reading twice
    over: what a wrapper function adds to a request is invisible in the command a transcript
    records, which shows the wrapper's name, and the vendor's own purge command leaves this
    directory alone.
  - **Encrypted stores.** One product keeps its conversations in an AES-GCM container around
    a protocol buffer. The container is opened only with a key the examiner supplies, under
    whichever framing authenticates, and the plaintext is walked by the wire format, so its
    fields are numbers rather than names and every record says so (ADR 0029).
  - **Key-value stores.** The two Electron desktop products keep their windows' state, and
    for one of them the prompts, where a browser engine keeps its: a LevelDB of immutable
    table files and a write-ahead log. Both are read, and the log matters most, because it
    holds what a running application wrote last and has not folded into a table yet. The
    reading stops at the records: what the bytes inside a value mean is the engine's own
    serialisation, nobody here has a source for it, and the text offered beside a record
    says it was extracted rather than decoded. The format is implemented in this package
    rather than taken from a dependency, together with the Snappy its blocks are
    compressed with (ADR 0031).
  - **The prompt library.** One editor keeps the prompts a user wrote for the agent in a
    memory-mapped B-tree store rather than in files, which makes it the one instruction
    artifact in this catalogue that a case could not show the text of. The page format is
    implemented here for the same reason as the one above: two named sub-databases, one
    mapping a prompt id to its title and the time it was last saved, the other mapping the
    same id to the text, and a prompt is the join of the two. The store never overwrites a
    page, so the pages its tree no longer points at hold earlier versions of prompts and
    the prompts somebody deleted. Those are read as well and every one of them says which
    it is, because a prompt that was removed last week is part of the answer to what the
    agent was told to obey and it is in no other artifact on the endpoint (ADR 0035). One
    further entry is a store of the same format that nobody has a source for, reported to
    be where an older build of that editor kept its conversations. It goes to the
    uninterpreted floor for the format, which returns every record with its key and its
    value and says on each one that nothing was decided about it.

  **The shadow repositories** are their own piece of the file-snapshot answer. Two agents
  snapshot what they are about to change by committing it into a repository, and where that
  repository is the agent's own the catalogue collects it whole. So the git object store is
  read here: a loose object is zlib around a type, a length and a body, and the commits, the
  trees and the file contents behind every checkpoint are in the bundle. A commit carries
  its own clock, which dates the capture where the reference log dates only the write. A
  packed repository is expanded: the pack format and its two delta encodings are
  implemented here, every object comes out as its own event located by its byte offset in
  the pack, and the ids come out the way git prints them, which is what ties a packed
  object to the reference that names it. An object that does not expand, a delta against a
  base the pack does not carry, is an event too, because the difference between a
  repository that held nothing and one this suite could not read is the whole point. These
  repositories are normally never garbage collected, so a pack in one is itself worth a
  look. A hook that is
  not one of git's disabled templates is filed as an instruction rather than as
  configuration, because it is a script the endpoint runs on its own. The same reader takes
  the git index one agent keeps beside each checkpoint, in a scratch directory it holds out
  of the system temporary directory on purpose: its own source says the reason is that the
  index and the path list beside it enumerate workspace paths. So that file is a listing of
  somebody's working copy at the moment of a checkpoint, untracked files included, with a
  size, a mode and the filesystem's own clock on every line, and nothing else in this
  catalogue is that.

  **The instruction surface** has its own format-shaped module for the artifacts that hold
  skills, commands, output styles, rules, steering files, subagent definitions and hook
  scripts. It reads each file whole, tells the scope apart from the working copies the
  collection recorded rather than from the path's shape, lifts a skill's front matter
  including the tools it grants itself, and counts the characters a reviewer cannot see. It
  does not claim to show a system prompt: the vendor's base prompt is not on the endpoint,
  and saying otherwise would answer a question the evidence cannot. The notes an agent wrote
  to itself are read the same way and filed as memories rather than instructions, because
  the instruction surface answers what the agent was told to obey and a note it wrote itself
  is a different question.

  **A file that is not text** is recorded by size and hash rather than as a page of
  replacement characters, in every one of these readers. A NUL byte in the first few
  kilobytes and a high share of characters that failed to decode are what decide it, and the
  threshold is high enough that a document written on a machine with another code page is
  still read as the document it is.

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
