# The unified agent log

One format for the on-disk history of any AI coding agent, so that the question "what did
the agent do" has one answer shape whichever agent left the evidence and whichever tool
read it.

The schema is `src/agentforensics/unified/agentlog.v1.schema.json`. It is a file rather
than a definition inside the Python package on purpose: a Velociraptor query, a CI step or
somebody else's script can validate against it by reading a path, without installing
anything.

## Why it exists

The suite already reduces twelve agents with twelve transcript formats to one event model,
and stores it in a SQLite case database. That is the right shape for an examiner working
one device for a week. It is the wrong shape for three other situations, and those turn out
to be the common ones:

- A fleet hunt comes back with a thousand hosts and somebody wants the conversations, not a
  thousand databases.
- The normalization should happen on the endpoint, inside the collection tool that is
  already there, so that nothing has to be shipped to the endpoint and nothing but the
  parsed result has to come back.
- The viewer should open what came back, in a browser, with no server.

All three want a stream of records rather than a database, and all three want the same
stream. This is it.

## Shape

JSON Lines. One record per line, one event per record. There is no file header and no
required ordering, so:

- two logs concatenate into a valid third one, which is what merging a fleet collection is;
- a producer that emits rows rather than files, which is what a Velociraptor query is, can
  produce the format directly, because every record carries its own version;
- a reader can start on line one without seeking, and can stop anywhere.

A minimal record, with the long fields cut for reading:

```json
{
  "v": 1,
  "agent": "claude_code",
  "kind": "tool.call",
  "event_id": "9a445f697549b88dafa699957a7a3f66",
  "ts_utc": "2026-09-06T09:00:03.000Z",
  "ts_precision": "exact",
  "ts_source": "timestamp",
  "actor": "assistant",
  "client": "cli",
  "user": "alice",
  "session_id": "4f8c1e2a-0000-4000-8000-000000000001",
  "project_path": "/src/app",
  "git_branch": "main",
  "payload": {
    "tool": "Bash",
    "tool_use_id": "t1",
    "input": { "command": "npm ci" },
    "commands": [{ "command": "npm ci", "executable": "npm", "cwd": "/src/app" }]
  },
  "parse_problem": null,
  "provenance": {
    "bundle_uuid": "tree-2a8021959fa27c7f6df59aaa",
    "original_path": "/Users/alice/.claude/projects/-src-app/4f8c1e2a.jsonl",
    "sha256": "b10f318452866...",
    "artifact_id": "claude_code.transcripts",
    "locator": "line:12"
  },
  "raw": { "type": "assistant", "message": { "content": [{ "type": "tool_use" }] } },
  "producer": "agentforensics/0.1.0"
}
```

## The guarantees

These are the reasons to use the format rather than an ad hoc CSV, and each one is a test
in `tests/unit/test_unified_format.py`.

**The agent is always named.** `agent` is required and has no default. An event that cannot
be attributed to an agent is worth less than no event, because it will be counted anyway.

**Nothing is lost.** `raw` is required and holds the original record verbatim. A mapping
mistake therefore costs interpretation and not evidence: whatever a producer got wrong, the
original is still in the line to re-read. An event survives the round trip through the
format field for field, which is the test that keeps the promise honest.

**Nothing is hidden.** A record a producer could not read is written out with
`kind: "unparsed.record"`, the original in `raw` and the reason in `parse_problem`. Reading
is total in the same way: a line of a unified log that is not valid JSON comes back as an
event holding the whole line. A reader that skipped a bad line would let a tampered log
look clean, and in a forensic tool showing nothing makes an analyst conclude nothing was
there.

**Time is qualified or absent.** `ts_utc` is null when the record carried no time of its
own, and `ts_precision` says how much of the timestamp is real. Neither the ingest time nor
the file's modification time is ever presented as the event's own. `ts_source` names where
the time came from, so an analyst can tell the agent's own clock from the filesystem's.

**Every record is traceable.** `provenance` carries the collection, the absolute path on the
endpoint, the source file's hash and the position inside it. That is what a report is
challenged on.

**The identifier is checkable, not trusted.** `event_id` is derived from provenance and
kind, so a reader recomputes it. A reader that finds a mismatch records the disagreement
rather than correcting it: which producer read a file, and whether it agrees, is itself
evidence. `producer` names what normalized the record.

## Event kinds

The vocabulary is closed, and agent-neutral: a kind names what happened, not which agent it
happened in, so one query works across all of them.

| Kind | What it is |
| --- | --- |
| `session.start`, `session.end` | A conversation beginning and ending. A compaction ends a session too, and says so in the payload. |
| `user.prompt` | What the user asked. |
| `assistant.text`, `assistant.thinking` | What the agent answered, and its reasoning where the agent records it. |
| `tool.call`, `tool.result` | A tool call with its arguments, and its output. Joined by `payload.tool_use_id`. |
| `file.read`, `file.write`, `file.snapshot` | What the agent touched, derived from the tool call. |
| `command.exec` | A shell command the agent ran. |
| `network.request` | A destination the agent reached. |
| `mcp.call` | A call into an MCP server, with the server named separately from the tool. |
| `permission.decision` | One request answered under the rules in force. |
| `permission.change` | A change to the rules themselves. Separate because it answers the other half of the bypass question: who moved the goalposts and when. |
| `safety.refusal` | The model declining. Distinct from a permission denial: a denial is the harness saying no, a refusal is the model saying no. |
| `config.snapshot` | Configuration as it stood, including model changes mid-session. |
| `memory.write`, `plan.write` | The agent writing to its own persistent state. |
| `prompt.history` | A prompt from a history file rather than from a transcript. These outlive transcripts, so a prompt with no matching session is one of the more interesting things a collection can hold. |
| `artifact.fs` | The filesystem timestamps of an artifact file itself. For an artifact with no internal timestamps this is the only temporal evidence there is, and it is also what puts a collected file that no parser understands on the timeline. |
| `unparsed.record` | A record nothing could read, kept with its original text. |

## Payload vocabulary

`payload` carries what happened in fields a query can reach. Additional keys are allowed on
purpose: an agent-specific field nobody has mapped yet belongs there rather than nowhere.
The shared keys are `text`, `tool`, `tool_use_id`, `input`, `output`, `is_error`, and the
list-valued `files`, `commands`, `network`, `mcp`, `models`, `permissions` and
`instructions`. The schema documents each one.

Two notes on honesty in the payload. `text` is never shortened, because a truncated prompt
reads as a short prompt. And `permissions[].decision` is deliberately not a closed list: the
shared vocabulary is `allow`, `deny`, `always_allow`, `ask` and `unknown`, but an agent
whose records use a different word keeps that word rather than being coerced into one of
ours. Coercion there would destroy exactly the distinction an analyst is looking for.

## Producing it

```bash
# From a bundle, a collected tree, a KAPE output or a mounted profile
afx normalize <source> --out agents.jsonl

# Straight from the endpoint, inside a Velociraptor collection
# (see docs/COLLECTION.md)
```

`afx normalize` reads through the same source adapters and the same parsers as
`afx ingest`. That is deliberate: two code paths that both claim to normalize an agent's log
would eventually disagree about one, and there would be no way to tell which was right. A
test asserts that the log and a case built from the same source hold exactly the same
events.

The summary goes to stderr, always, so a log written to stdout stays a clean stream while
the numbers that qualify it still reach the operator. Those numbers are the point:

```
normalize: unified agent log, format version 1
normalize: directory source /evidence/host-1
normalize:   39 file(s): 9 parsed, 30 with no parser, 0 that failed
normalize:   112 record(s) written
normalize:   by agent: claude_code 81, cline 2, codex 14, copilot 11
normalize:   15 record(s) no parser could read, written to the log as unparsed.record
normalize:   30 file(s) were collected and have no parser. They are in the log as one
normalize:   artifact.fs record each, which says the file was there and when it was
normalize:   written, and nothing about its content.
normalize:   3 path(s) no catalogue entry claims, which is a lead rather than a non-event
```

Exit codes follow the rest of the tool: 0 for a clean run, 1 when the collection carried
paths nothing in the catalogue claims, 3 when nothing was found at all. A host with no agent
artifacts is a valid and useful answer and must not look like a crash.

## Versioning

`v` is an integer and it is on every record. Version 1 is what this document describes. A
future version that adds a field is still version 1, because a consumer that ignores an
unknown key keeps working and the schema allows additional payload keys by design. The
number changes only when an existing field changes meaning, which is the one case where a
consumer has to know.
