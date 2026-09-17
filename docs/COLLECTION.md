# Collecting agent artifacts

English | [Deutsch](COLLECTION.de.md)

Read this before a collection, not after. The order matters more than the completeness:
several of these artifacts are destroyed by ordinary use of the machine, and a few are gone
the moment it shuts down cleanly.

Using this requires proper authorization. See the README.

## The one thing to get right

Agents delete their own history. Claude Code sweeps transcripts older than
`cleanupPeriodDays`, 30 days by default, and the sweep runs **at startup**, so the next
time the user opens the agent they destroy the oldest evidence. Gemini CLI defaults to 30
days as well. Some artifacts are worse: Claude Code's image cache drops the directories of
every session but the current one on **every** sweep, whatever their age, so simply
starting a new session can wipe every attached image in the tree.

So the catalogue does not just record where things are. Every artifact carries a
`collect_priority`, and the collectors work in that order rather than alphabetically. The
generated reference [ARTIFACTS.md](ARTIFACTS.md) is grouped the same way.

| Priority | What it means | What to do |
| --- | --- | --- |
| `live_only` | Exists only while the agent or the session is running, or is deleted on a clean shutdown | Collect from the running machine. A powered-off image will not have it, and no amount of disk forensics brings it back |
| `first` | Rotated or swept aggressively, by count or on every sweep rather than after a comfortable interval | Collect before anything else that survives longer. Some of these the user destroys by starting another session |
| `normal` | Subject to the agent's ordinary retention period | Collect in the normal course |
| `durable` | Not covered by the retention sweep | Still collect it. This group routinely outlives the transcripts it describes, and when the transcripts are already gone it is often enough to establish that an agent ran, what it was allowed to do, and what the user asked |

Two consequences worth stating plainly. First, if the endpoint is still running, a live
collection is not a convenience, it is the only way to get the `live_only` group. Second, a
collection that comes back with only `durable` artifacts is not a failed collection: it
means the volatile evidence had already expired, which is itself a finding about how long
the investigation took to start.

## What the collectors do not do

- They never modify, move, rename or delete anything on the target, and they never execute
  an agent binary. Version information is read from files.
- They write only into `--out`. No temporary files elsewhere, no logs, no configuration.
- They do not copy the content of credential artifacts. Those are recorded as metadata plus
  a SHA-256, so their presence and identity are in the manifest without the bundle becoming
  a collection of live tokens. `--include-secrets` overrides that, and the choice is
  recorded in the manifest.
- They do not follow a symlink out of the profile being collected. Such a link is recorded
  with its target and skipped.

## Running a collection

macOS and Linux, Python 3.8 or newer, standard library only:

```bash
# The current user, on this machine
python3 collect.py --out /tmp/case-001

# Every profile, which needs elevation. Whether the run was elevated is recorded either
# way, so an unelevated --all-users produces an honest partial collection rather than a
# silent one.
sudo python3 collect.py --out /tmp/case-001 --all-users --zip

# A mounted image or an exported profile, collected on an analyst workstation
python3 collect.py --out ./bundle --root /mnt/evidence --os macos

# See what would be collected, without reading or writing anything
python3 collect.py --dry-run --json
```

Windows, PowerShell 5.1 or newer, no modules: `collect.ps1` takes the same options as
PowerShell parameters, so `--out` is `-Out`, `--all-users` is `-AllUsers`, `--dry-run` is
`-DryRun` and `--os` is `-TargetOs`.

```powershell
# The usual case: the profile of the logged-on user
powershell -ExecutionPolicy Bypass -File collect.ps1 -Out C:\case-001

# Every profile on the machine. Needs an elevated session, which the manifest records
powershell -ExecutionPolicy Bypass -File collect.ps1 -Out C:\case-001 -AllUsers -Zip

# A mounted image, collected on an analyst workstation
powershell -ExecutionPolicy Bypass -File collect.ps1 -Out .\bundle -Root E:\ -TargetOs windows

# See what would be collected, without reading or writing anything
powershell -ExecutionPolicy Bypass -File collect.ps1 -DryRun -Json
```

The two collectors produce the same bundle format, and CI proves it rather than asserting
it: both run over one synthetic profile and their manifests are compared field by field,
with only the fields under "Fields allowed to differ" in `docs/BUNDLE_FORMAT.md`
normalized away. `collect.ps1 -SelfTest` prints a fixed set of structures through its JSON
serializer, and CI checks those against Python's `json.dumps` byte for byte on real
Windows PowerShell 5.1.

Exit codes are part of the interface, because this gets driven from scripts and from
live-response sessions where the exit code is the only signal:

| Code | Meaning |
| --- | --- |
| 0 | Collected at least one artifact |
| 1 | Ran, but at least one error is recorded in the manifest |
| 2 | Could not run: bad arguments, output directory unusable |
| 3 | Ran successfully and found nothing |

Code 3 matters for a fleet sweep. "This host has no agent artifacts" is a useful answer,
and a sweep that cannot tell it apart from a crash draws a wrong picture of where agents
are in use.

## Finding the tree when it has moved

Several agents can be relocated by an environment variable. `CLAUDE_CONFIG_DIR` moves the
whole Claude Code directory, taking transcripts, prompt history and plugins with it. A
collection keyed on the default location then finds nothing, and nothing distinguishes that
from the agent never having been installed.

The collectors expand those variables from their own environment, which is right on a live
machine and wrong on a mounted image, where the variable was set in a shell profile that is
now just a file. So on an image, check the shell profiles and any process-environment
evidence before concluding an agent was absent. [ARTIFACTS.md](ARTIFACTS.md) lists the
relocating variables per agent.

## Project files need to be found before they can be collected

Instruction files (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.windsurfrules`,
`.kiro/steering/` and the rest) live inside the user's repositories, not under the profile.
They are also the surface through which injected instructions reach an agent, which makes
them among the most interesting files in a collection.

The collector cannot find them by expanding a profile, so it reads the agent's own state
for a list of working copies: for Claude Code the `projects` key of `~/.claude.json` is
authoritative, and the encoded directory names under `projects/` are a fallback hint. That
encoding replaces every non-alphanumeric character with a dash and is not reversible, so a
decoded name is only used when it happens to name a directory that exists.

The consequence: a repository the user cloned and never opened with an agent will not be
found, and a repository that has been deleted leaves only its encoded directory name
behind. Both are worth noting in a report rather than treating the list as complete.

## Verifying a bundle

```bash
agentforensics verify /tmp/case-001
agentforensics verify /tmp/case-001 --json
```

Verification re-derives every hash from the bytes on disk and reports three different
things, because they mean different things: a file the manifest lists and the bundle does
not have, a file whose bytes no longer match, and a file present in the bundle that no
manifest entry claims. It also checks the custody chain.

The custody chain is **tamper-evident, not tamper-proof**. It sits in a writable directory
and whoever can write it can rewrite the whole chain. What it buys is that a single record
cannot be removed or edited quietly. See [BUNDLE_FORMAT.md](BUNDLE_FORMAT.md).

## Deploying through other tooling

The catalogue is also rendered into the formats other tools already speak, so using it does
not require adopting this suite's collector. The output is committed under
`exporters/generated/` and CI fails if it drifts from the catalogue, for the same reason the
embedded catalogue inside the collectors is checked: a rule that lags the catalogue searches
last month's locations and reports a clean host.

```bash
uv run agentforensics export-collection            # every format, into exporters/generated
uv run agentforensics export-collection --format kape --out /tmp/rules
```

| Format | What you get | Use it for |
| --- | --- | --- |
| `velociraptor` | Three artifacts: a collection artifact that globs the catalogue paths and uploads what it finds, a metadata-only presence artifact, and a unified-log artifact that parses on the endpoint and returns the conversation as rows | Anything cross-platform. Its glob language is the closest to the catalogue's, so it has the fewest gaps |
| `kape` | One `.tkape` per agent plus a compound target | A Windows examiner who already works in KAPE |
| `mde` | A presence-check script and a runbook | A Defender live response session, one host at a time |
| `kql` | Advanced Hunting queries over file events and process events | Narrowing a fleet from the console, before touching any host |
| `osquery` | A pack of per-agent, per-platform file queries | A fleet that already runs osquery. Metadata only, so it is triage rather than collection |

### Velociraptor: collect the files, or return the conversation

The three Velociraptor artifacts answer three different questions, and a hunt that asks the
wrong one either takes gigabytes off every endpoint or comes back with nothing.

`Custom.Forensics.AIAgents.Presence` reports which agents left a trace and uploads nothing.
Start here on a fleet: the question "who has used an AI coding agent" is answerable from
directory existence, and answering it by uploading every transcript in the estate is both
slow and a data-protection problem of its own making.

`Custom.Forensics.AIAgents.Collect` uploads the files. Use it for a host you are going to
work on, and read the result with `afx ingest`, which gives you a case database, the
timeline and the full per-turn interpretation.

`Custom.Forensics.AIAgents.UnifiedLog` reads the agent logs where they are and returns them
as rows in the vendor-neutral format documented in [docs/UNIFIED_FORMAT.md](UNIFIED_FORMAT.md).
Nothing is uploaded and nothing is shipped to the endpoint. Use it when you want the
conversations from many hosts at once, or when uploading transcripts is not an option.

What the unified-log artifact deliberately does less of, stated here because a collection
tool that quietly does less than it appears to is worse than one that fails:

- **One row per record, never per content block.** An assistant turn that called three tools
  is one row. The complete record travels in `raw`, so nothing is lost; re-reading the log
  with this suite's own analyzer splits it further. What is coarse is the interpretation, not
  the evidence.
- **It interprets the five formats that have been read against their vendor**: the Claude
  Code transcript and prompt history, the Codex rollout and prompt history, and the Copilot
  CLI event log. Any other line-delimited agent log comes back record by record with kind
  `unparsed.record`, because a mapping invented for a format nobody has verified produces
  output that looks like an answer.
- **It does not read SQLite stores, JSON documents or binary session files.** Those come back
  as one `artifact.fs` row each, naming the path, the hash and the timestamps, so a store
  nobody has read is visible as a store nobody has read rather than as an agent that left
  nothing behind.
- **It checks its own reading.** Velociraptor's line reader is buffered, and a line longer
  than the buffer ends the scan and takes the rest of the file with it. Agent transcripts
  carry multi-megabyte lines whenever a tool output was large, so the artifact compares the
  bytes it read against each file's size and returns a record saying so when they do not add
  up. Raise `MaxLineSize` and collect again when you see one.
- **It does not use `parse_jsonl`.** That plugin skips a line it cannot decode. A skipped
  line reads as a line that was never there, which is exactly what a truncated or
  deliberately corrupted record would hide behind, so the artifact decodes lines itself and
  returns the ones it could not read.

Checking it needs a Velociraptor binary, which this repository does not ship.
`scripts/check_velociraptor_vql.py --runner <binary>` runs the artifact against a synthetic
profile inside a sandbox, validates every row against the format's schema, and compares the
records it returned against the records `afx normalize` reads from the same profile. Without
`--runner` it does nothing and says so. The static checks in
`tests/unit/test_velociraptor_unified.py` run everywhere and on every commit.

### What a generated rule cannot do, and why it says so

Every one of these tools has a narrower path language than the catalogue. KAPE addresses a
drive and a file mask. osquery has one wildcard depth per segment. Advanced Hunting sees
events rather than the filesystem and has no user-profile placeholder at all. Live response
fetches a file only by its exact name.

So every generated file carries, in its own header, the artifacts it could not express and
the reason for each. Read that section before you read the results. The recurring reasons:

- **Anchored at a working copy.** A project instruction file lives in a repository whose
  location is in the agent's own state file. Nothing static can find it. This is the
  largest group and it covers exactly the files a prompt-injection question is about.
- **Reachable only through a relocation variable.** The agent's tree was moved by an
  environment variable, so its location is whatever that variable says. One agent writes an
  entire second transcript to a path the operator chooses.
- **A registry key**, which is a different table or a different target type in each tool.
- **Platform scope.** KAPE and the live response package are Windows only, and they say how
  much of the catalogue that puts out of reach.

The collector reads all four of those. That is the honest division of labour: a generated
rule finds the hosts worth looking at, the collector gets the evidence.

An empty result from any of these means the paths it searched held nothing. It does not mean
the host is clean, and each generated file argues that point in its header, because the
person running the rule is often not the person who generated it.
