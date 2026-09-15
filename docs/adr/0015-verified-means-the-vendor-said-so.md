# ADR 0015: verified means the vendor said so

- **Status:** accepted
- **Date:** 2026-09-15

## Context

The catalogue's honesty rule said that `status: verified` requires a source URL somebody
fetched whose page states the path. The rule was about whether a page states the path. It
said nothing about whose page it is, and the schema comment claimed the rule could be
checked mechanically when in fact nothing checked it.

The first verification pass over the 255 verified entries found the gap immediately.
Thirteen entries were marked verified on the strength of third-party research: five Cursor
entries and seven Windsurf entries rested on independent reverse engineering of two closed
source products, and one editor entry cited a different vendor's documentation for a path
that vendor does not own. A fourteenth cited a distribution's packaging repository rather
than the upstream project whose manual it contains.

None of those paths is wrong as far as anyone can tell. That is exactly the problem. A
third party who reverse-engineered a path writes it down with the same confidence as the
vendor, and an analyst reading the catalogue cannot tell the two apart from the path alone.
An analyst who collects nothing under a path marked verified concludes the agent was not
used. Under a path marked unverified, the same empty result reads as inconclusive, which
is the correct reading when the location was never confirmed by the party that chose it.

## Decision

Each agent catalogue file declares `vendor_sources`, a list of URL prefixes that count as
first party for that agent. An artifact may be `status: verified` only if its source URL
starts with one of them. `tests/unit/test_catalog.py` enforces it and names every offender
with its URL, and a second test fails if an agent file omits the list, because without it
the first test would pass silently for that whole agent.

Matching is a plain prefix test rather than a host test. A host test would accept any
repository on a code hosting site, which is where nearly all of the third-party research
lives.

Two deliberate widenings of first party:

- For a plugin that lives inside another vendor's application, that application's own
  source counts. The path an IDE's MCP client detector reads is stated by the party that
  reads it.
- The cross-cutting file has no single vendor, so its list is the union of the upstreams
  of the shells, package managers and operating system components it documents.

Third-party research stays in the catalogue. It carries `source_kind: community` and
`status: unverified`, and its note says who states the path and that no vendor source
does. The collector treats unverified entries exactly like verified ones.

## Consequences

Verified now means something an analyst can rely on in a report: the party that chose the
location is on record stating it. The count of verified entries drops, and for two closed
source products the entries that matter most, the transcript stores, are now unverified,
which reads as a weakness of the catalogue and is in fact an accurate description of what
is known about those two products.

A prefix list per agent is data that ages. A vendor that moves its documentation to a new
domain, or its code to a new organization, makes every entry for that agent fail the
check until the list is updated. That failure is loud and its message names the URL, which
is the right direction to fail in.

We would revisit this if a vendor's documentation became permanently unreachable while a
well-established independent description existed, and the cost of reporting the location
as unverified came to outweigh the cost of resting on a third party. Nothing in the
current catalogue is close to that line.

## Alternatives considered

- Keep the rule as it was and rely on review. It had already failed: thirteen entries got
  through, and review is not repeatable across contributors.
- Enforce it in the JSON Schema. The schema cannot produce a message naming the entry and
  its URL, and it is validated per file by tooling that must stay dependency free.
- Add a third status between verified and unverified. Two values that both mean "the
  collector collects this" already carry the operational meaning; a third would only push
  the judgement call onto the analyst reading the report.
