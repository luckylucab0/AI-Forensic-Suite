# AI Agent Forensic Suite

English | [Deutsch](README.de.md)

A local-first, offline forensic suite for the on-disk history of AI coding agents on
endpoints. It collects, verifies, parses and analyzes what agents like Claude Code,
OpenAI Codex CLI, GitHub Copilot, Gemini CLI, Cursor, Kiro, Cline and others leave
behind on macOS, Windows and Linux.

> **Status: early.** The transcript viewer is complete and usable on its own today. The
> artifact catalogue, the collectors, the bundle format, the analyzer, the rule engine and
> the local web UI are in. More per-agent parsers are what is still being built. See
> [Roadmap](#roadmap).

## Authorization and law come first

This tool reconstructs what a person typed, what files were read and written on their
machine, and where data went. That is personal data, and on a work device it is usually
personal data of an employee plus, incidentally, of everyone mentioned in their code and
messages.

Using it requires proper authorization. Depending on where you are, that can mean a
documented investigative mandate, works council or employee representative involvement,
a data protection assessment, or all of these. Collect the minimum you need for the
question you are actually answering, keep it no longer than you must, and follow
applicable law and your own internal policy. Nothing in this repository is legal advice,
and no default in this tool relieves you of that judgement. See
[SECURITY.md](SECURITY.md) for the dual-use considerations.

## What it answers

For one device and one user:

- Which AI agents were installed and used, and when
- What the user asked, in full, including prompts that were later deleted from the UI
- What the agent did: files read and written, commands run, network destinations, MCP
  servers and tools invoked, subagents spawned
- Which data left the device toward a model provider or a third party
- Whether safety controls were bypassed: permission modes, auto-approving hooks,
  managed settings overrides
- Whether anti-forensic steps were taken: retention lowered, history suppressed, a
  project purged
- What the agent was told to obey: the instruction files, skills, commands, output styles,
  rules and hook scripts that were in force, at which scope, and which of them hide
  characters a reviewer cannot see. Not the vendor's base prompt, which is built at runtime
  and never touches the endpoint
- Whether the agent was manipulated by injected instructions

Every answer is traceable to a source file, a hash and a line or byte offset, so it
survives being questioned in a report.

## Why time matters

Several agents delete their own history on a schedule. Claude Code sweeps transcripts
older than its `cleanupPeriodDays` setting, 30 days by default, and Gemini CLI defaults
to 30 days as well. An investigation that starts in week six has already lost week one.
The artifact catalogue records this volatility per artifact so you know what to collect
first, and the collectors are single files with no dependencies precisely so they can be
pushed through live-response tooling in minutes rather than scheduled for next week.

## Design constraints

These are not preferences, they are the reason the tool is shaped the way it is.

| Constraint | What it means in practice |
| --- | --- |
| Offline | No network access at runtime, no telemetry, no update checks, and no LLM or API calls anywhere in the pipeline. Analysis is deterministic and explainable. The web UI binds to `127.0.0.1` only. |
| Read-only evidence | The collector and the analyzer never modify, move, rename or delete a source artifact, and never execute an agent binary on the target. Version information is read from files. |
| Verifiable | Every collected file is hashed with SHA-256 and carries its original timestamps. Bundles verify offline. The chain of custody is a hash chain, so it is tamper-evident. |
| Deterministic | Same input, same output. Stable ordering everywhere, timestamps in UTC ISO 8601, the endpoint's own timezone recorded once in the manifest. |
| Cross-platform | Collectors and analyzer run on macOS, Windows and Linux. Windows drive letters, long paths, junctions and case insensitivity are handled explicitly, not hopefully. |
| Few dependencies | An analyst workstation may be air-gapped. The collectors have no dependencies at all. The analyzer keeps them to a minimum and permissively licensed. |
| No organization-specific content | Nothing in this repository names a company, a domain, a host, a code name or a person. Scope rules come from your own gitignored config. |

## The transcript viewer

`viewer/index.html` is one dependency-free HTML file that renders agent session logs
read-only, in a UI that mirrors the Claude Code terminal output. It works entirely on its
own, with no install and no backend, which is deliberate: an analyst can carry it on a USB
stick and open it on a machine where nothing may be installed.

### Supported log layouts

| Agent | Default location | Layout | Format |
| --- | --- | --- | --- |
| Claude Code | `~/.claude/projects/` | `projects/<dir>/<uuid>.jsonl` | one JSON event per line |
| OpenAI Codex CLI | `~/.codex/sessions/` | `sessions/YYYY/MM/DD/rollout-*-<uuid>.jsonl` | `{timestamp,type,payload}` per line |
| GitHub Copilot CLI | `~/.copilot/session-state/` | `session-state/<id>/events.jsonl` | `{type,id,timestamp,data}` per line |
| Any agent, via a unified log | one file, anywhere | one record per line | [the vendor-neutral format](docs/UNIFIED_FORMAT.md) |

Discovery probes each layout directly and under `.claude/`, `.codex/` and `.copilot/`,
so pointing the viewer at any one of those directories, or at a parent that contains
several, surfaces every agent's sessions together.

The last row is the general case. A unified agent log is one file holding normalized
records from any agent, produced either by `afx normalize <source>` or by the
`Custom.Forensics.AIAgents.UnifiedLog` Velociraptor artifact, which parses on the endpoint
and returns rows rather than files. The viewer groups such a log by agent, working
directory and session, so a collection covering many hosts and several agents opens as one
set of sessions. Records that belong to no session, such as a prompt read from a history
file or a store nobody has parsed, get a group of their own rather than being left out.

### Running it

**A. Serve an agent directory locally.**

```bash
cd ~/.claude   # or ~/.codex, ~/.copilot, or a parent of them
python3 -m http.server 8000
# then open http://localhost:8000/index.html
```

Copy `viewer/index.html` into that directory first, or serve the repository and point the
browser at `viewer/index.html`.

**B. Host the single file and pick a folder.** Click **Open local folder** in the sidebar
footer and choose your `.claude`, `.codex` or `.copilot` directory. This uses the
browser's [File System Access API](https://caniuse.com/native-filesystem-api), which
needs a Chromium-based browser (Chrome, Edge, Brave, Arc, Opera) in a secure context,
meaning `https://` or `http://localhost`. A `file://` page does not qualify, so the
button hides itself there. Firefox and Safari do not implement the API.

**C. Open a unified agent log.** Click **Open unified log** in the sidebar footer and pick
a `.jsonl` file. This is the one option that needs nothing at all: no server, no folder
access, and it works from a `file://` page, so an analyst with a log from a fleet
collection can open this page and that file and be reading. It is also the only way to see
an agent the viewer has no layout for, because the normalizing happened before the file
was written.

**D. Point it at a case database.** `afx serve --case case.db` opens one case behind this
same page, on 127.0.0.1 and read-only, and adds four views for the questions that are about
a case rather than a transcript. See [the local web UI](#the-local-web-ui).

No build step, no `npm install`, no backend. Everything runs in the browser. The only
thing the viewer writes anywhere is your theme choice, in `localStorage`.

### What the viewer shows

- **Sessions**, grouped by project, most recent first, with the session's real title and a
  colored dot for the originating client
- **A faithful transcript**: user prompts, grouped assistant turns, collapsible thinking
  blocks, markdown, and `Tool(summary)` one-liners with result previews
- **Full tool detail** on demand: complete JSON input and untruncated output, per turn or
  across the whole transcript
- **Two scoped searches**, one over message text and one over everything including tool
  input, output and thinking, with inline highlighting, a match counter, keyboard
  navigation, and automatic expansion of any collapsed block that contains a match
- **Cross-session tool usage**: every tool call from every session in one list, filterable
  by tool, by failures only, by free text, and scopeable to the open session alone
- **Filters inside one chat**: show only the prompts, only the answers, only the turns that
  used a tool, only the recorded reasoning, or only the rows that did not parse. A filter
  that takes rows off the screen says how many it hid, with one click to undo it
- **A heuristic secret scan** over tool input, tool output and assistant text, flagging
  likely keys, tokens and credentials, filterable by severity and by rule and scopeable to
  one session
- **Every record, always.** A line that fails to parse, a record type the parser does not
  know, an assistant turn without an id: all of these are rendered as their own visible
  row rather than dropped, and the session header counts unparsed lines. In a forensic
  tool, silently showing nothing is worse than showing an error, because the analyst
  concludes nothing was there.

### Known limitations

- The directory-listing mode understands the HTML index that Python's `http.server`
  emits. Other servers' autoindex formats are not parsed. Use mode B, C or D instead.
- Parsing happens in the browser, so a very large session is loaded into memory whole.
- The secret scan is regex-based heuristics, not a full scanner. Expect false positives
  and false negatives, and verify any finding.
- The parsers for everything other than Claude Code were built from the vendors' own
  source and format documentation, not from real transcripts. They preserve anything they
  do not recognize, but may need adjusting against new agent releases.

## The local web UI

```bash
uv run afx ingest /evidence/bundle-2026-09-17 --case case.db   # read a collection in
uv run afx scan --case case.db                                 # run the rule packs
uv run afx instructions --case case.db                        # what the agents were told to obey
uv run afx sessions --case case.db                            # conversations only one store remembers
uv run afx serve --case case.db                                # open it in a browser
uv run afx export --case case.db --out report/                 # the same views as files
```

`export` writes what `serve` shows, without a server: one CSV per view, named the way the
browser names its download, plus `afx-events.jsonl`, the case as a unified agent log that
the standalone viewer opens with nothing behind the page. Both go through the same
projections, so a file attached to a report and a table read on screen cannot describe one
case differently. Every view is written whole, and a view with nothing in it is written as
a file that says so rather than left out.

One agent keeps its conversations in an encrypted container. The key is the product's
rather than the user's and this repository ships none, so those files are read only when
you supply it:

```bash
uv pip install 'agentforensics[encrypted]'                     # the cipher, an optional extra
uv run afx ingest /evidence/bundle --case case.db --key windsurf=<key>
```

Without the key the files are still collected and hashed, and the case says they are an
encrypted store and what it would take to read them rather than saying nothing. See
[ADR 0029](docs/adr/0029-an-encrypted-store-is-read-only-with-the-analysts-key.md).

`serve` binds `127.0.0.1` only, opens the case read-only so SQLite itself refuses a write,
and puts every URL under a token generated for that run and printed on the console. No
telemetry, no update check, and a content security policy that forbids the page from
loading or contacting anything off this server.

It serves the same single-file viewer, with four views added: the case and the counts that
qualify it, the device-wide timeline across every agent, the rule findings, and every file
the collection carried whether or not a parser read it.

![The case view, with the counts that qualify the case](docs/images/webui-case.png)

The full walk-through, the API, and the rest of the screenshots are in
[docs/WEBUI.md](docs/WEBUI.md). All images there are of one synthetic case: no real agent
data appears anywhere in this repository.

## Roadmap

| Phase | Content | State |
| --- | --- | --- |
| 0 | Repository hygiene, sanitized viewer, tooling, CI, OpSec guard | done |
| 1 | Artifact catalogue, both collectors, evidence bundle format, `verify`, synthetic fixtures | done |
| 2 | Collection rules generated for Velociraptor, KAPE, Defender live response, KQL, osquery | done |
| 3 | Analyzer core: ingest adapters, per-agent parsers, unified event model, SQLite case database, unified log format, timeline exports | done |
| 4 | Declarative YAML rule engine and the starter rule packs | done |
| 5 | Local web UI: read-only API, viewer API source, case, timeline, findings and artifact views | done |

Not planned for now: case management with triage states, HTML and PDF reporting,
pseudonymization, and a shell fallback collector.

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), how the parts fit together
- [docs/COLLECTION.md](docs/COLLECTION.md), what to collect first and why, and how to
  run a collection
- [docs/SUPPORT.md](docs/SUPPORT.md), the generated support reference: which agents are
  read, how completely, and which of four reasons applies to everything that is not
- [docs/ARTIFACTS.md](docs/ARTIFACTS.md), the generated artifact reference, grouped by
  how fast each artifact disappears
- [docs/BUNDLE_FORMAT.md](docs/BUNDLE_FORMAT.md), the evidence bundle format
- [docs/RULES.md](docs/RULES.md), the generated detection reference: every rule with
  its condition, why an analyst cares, and the benign cases it is known to fire on
- [docs/UNIFIED_FORMAT.md](docs/UNIFIED_FORMAT.md), the vendor-neutral agent log: one
  JSON Lines record per event, whichever agent left the evidence and whichever tool
  read it
- [docs/WEBUI.md](docs/WEBUI.md), the local web UI: what `afx serve` exposes, what it
  refuses to do, and screenshots of every view
- [docs/adr/](docs/adr/), one short record per architecture decision, with the reasoning
  and the cost each one accepts
- [CONTRIBUTING.md](CONTRIBUTING.md), how to work in this repository, including the OpSec
  guard every contributor needs to understand
- [SECURITY.md](SECURITY.md), how to report a vulnerability, and the dual-use position

## License

[Elastic License 2.0](LICENSE). Use it, read it, change it and fork it, including in paid
work. What it forbids is providing the software to third parties as a hosted or managed
service that gives them a substantial set of its features, removing or obscuring the
licensing and copyright notices, and shipping a modified copy without saying it is
modified. See [NOTICE](NOTICE) for the short version of what a fork has to do.

This is not an OSI-approved open source licence. Versions published before 2026-09-17 were
released under the MIT License, and that grant stands for those versions.
