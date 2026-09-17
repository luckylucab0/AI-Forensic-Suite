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
- `parsers/` one module per agent, turning raw records into unified events. A parser is
  chosen by the catalogue entry that claimed the file, so it can never disagree with the
  catalogue about what a file is. A file with no parser is recorded as unsupported
  rather than skipped.
- `model/` the unified event model and the SQLite case schema
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
`permission.decision`, `config.snapshot`, `memory.write`, `plan.write`, `prompt.history`
and `artifact.fs`.

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
prompt injection, supply chain and third-party endpoints. The engine and the packs are phase 4 work and `docs/RULES.md` does not exist yet.

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
| 5 | Local web UI: read-only API, viewer API source, timeline and findings views |

Deliberately out of scope for now: case management with triage states and notes, HTML and
PDF reporting, pseudonymization, and a shell fallback collector for hosts without Python.
