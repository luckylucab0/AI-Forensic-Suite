# ADR 0020: The local UI reads a case as a unified log, under a per-run token

- **Status:** accepted
- **Date:** 2026-09-17

## Context

ADR 0006 settled how the local web UI is built: `http.server`, an explicit route table, and
a hardening list that is part of the decision rather than a later concern. It did not settle
what the UI reads, and three questions were still open when `afx serve` was written.

The first is what a session endpoint returns. The viewer already had three readers: the
Claude Code transcript shape, the Codex rollout shape and the Copilot event shape, plus the
unified log from ADR 0018. A case is none of those: it is rows in SQLite with the payload
and the original record as JSON columns.

The second is what a session even is in a case. A case holds events, not sessions. The
viewer's sidebar needs groups, and the events carry the five values a group would be made
of: agent, host, user, working directory, session id. Nothing in the case stores the group
itself.

The third is who may read the server. A loopback HTTP server is reachable by every process
on the workstation and, through a browser, by every page the analyst has open. The case
holds other people's prompts, file contents and credentials-in-transcripts.

## Decision

**A session endpoint returns a unified log.** `/api/sessions/<key>/events` answers with the
format ADR 0018 defines, one record per line, byte-compatible with what `afx normalize` and
the Velociraptor artifact write. The viewer reads a case with the reader it already has.

**A session is derived, and its key is a hash of what it was derived from.** The six values
(agent, host, user, whether the events are filesystem timestamps, working directory,
session id) are hashed to a 32 character key. Absent and empty hash differently. The group
list is re-derived on every request rather than cached.

**Every URL lives under a random per-run token.** 32 bytes of entropy, printed on the
console as part of the URL, checked before the route table. The viewer finds the API by
probing its own origin for `/api/case` and looking for a marker field, rather than by
anything being injected into the HTML.

**The case is opened read-only.** `Case.open(..., read_only=True)` connects through a
`mode=ro` URI, so SQLite refuses a write rather than this code promising not to attempt one.

## Consequences

The viewer gains a case source without gaining a fourth event shape. There is one wire
format for an agent event in this project, and a bug in it is a bug in one place. The same
bytes an analyst sees on screen can be saved to a file and re-read by `afx scan`.

A link into a session survives a re-ingest of the same bundle, because the key is derived
from the evidence rather than from a row id. It does not survive a change to the grouping
rule, and that is the right trade: a key that stayed stable across a change in what it
names would point at something else under the same name.

Re-deriving the group list per request costs one `GROUP BY` over the events table per call.
On a case with a hundred thousand events that is milliseconds, and it is what lets an
analyst open a case while it is still being ingested and see the sessions that have landed.

The token means a bookmarked URL stops working when `afx serve` is restarted. That is the
point of it, and the console prints the new one. It also means the token appears in the
process list and in any access log, which is why `--access-log` is off by default.

The probe means the viewer makes one request that fails on a page nobody is serving a case
to. A failed local fetch is cheaper than the alternative, which was injecting a marker into
the HTML: that would have made the served copy differ from the file on disk, and the whole
point of printing the viewer's hash is that the two are the same bytes.

We would revisit the unified-format decision if the viewer ever needed something a unified
record cannot carry, and the token decision if a case ever had to be served to more than
one reader, at which point this is the wrong tool and an authenticated service is the right
one.

## Alternatives considered

- **A bespoke JSON shape per endpoint.** Fewer bytes on the wire, and a fourth definition
  of an agent event that could disagree with the other three.
- **Session rows stored in the case at ingest.** Stable ids without a hash, at the price of
  a table that can fall out of step with the events it summarizes, and a re-ingest that has
  to decide whether to rewrite it.
- **No token, loopback only.** Simpler, and readable by any page in the analyst's browser
  that guesses the port. Loopback stops another machine, not another tab.
- **A marker injected into the served HTML.** Direct, and it would make the served viewer a
  different file from the one in the repository, so its hash would attest nothing.
