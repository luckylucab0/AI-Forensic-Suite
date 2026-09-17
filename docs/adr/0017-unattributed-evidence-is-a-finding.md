# ADR 0017: a file the catalogue does not claim is a finding, not a non-event

- **Status:** accepted
- **Date:** 2026-09-17

## Context

Ingest reads four kinds of source. A native bundle from this suite's collectors knows which
catalogue entry claimed each file, because the collector matched it on the endpoint with the
environment and the agents' own state files in front of it. A KAPE output tree, a
Velociraptor collection and a mounted image know nothing: they are a root full of files, and
the analyzer has to decide what each one is after the fact.

That leaves two questions. What to do with a file no catalogue entry claims, and how to
stop the matching from claiming files it should not.

## Decision

A file nothing claims is carried into the case with its non-match recorded, named in the
ingest report, and counted as a gap. It is not skipped and not silently filed under an
unknown agent. Such a file is either an agent nobody has catalogued yet or a gap in the
catalogue, and both of those are findings that a case should surface rather than absorb.

Every attribution records where it came from. A native bundle's entries are attributed to
the collector; a tree's are attributed to a path match made afterwards, and the case says
so per row and once per source as a gap. A native bundle is always read by the native
adapter even when the caller asks for something else, because the manifest is the only
record of what the endpoint knew.

Matching is deliberately conservative in the two places where it cannot be precise. A
pattern rooted at a relocation variable, and a pattern rooted at a working copy, can only be
matched at any location. Both are therefore matched only when what sits below the root is
distinctive on its own, and skipped otherwise.

## Consequences

An ingest of a mounted image produces a list of paths to look at, which is usually the most
useful thing a first pass can produce.

The conservative matching means some real evidence goes unattributed: a genuinely relocated
data tree, and a project file whose pattern reduces to a bare file extension. That is the
right direction to fail in, and the first version of this code proved it. Matching
relocated patterns anywhere turned a pattern like `$VAR/**/*.jsonl` into a claim on every
line-delimited transcript on the disk, and four agents were credited with each other's
conversations. A mis-attributed file is an error nobody sees. An unattributed one is a
question somebody answers.

The cost of recording every file, parsed or not, is a larger case and a report that always
has an uncomfortable number in it. That number is the point: it is the difference between
no events from an agent and nothing from that agent having been collected, which are
opposite conclusions.

## Alternatives considered

- Skip unmatched files. It would make a collection of an uncatalogued agent
  indistinguishable from a clean host, which is the failure this project is built to avoid.
- Attribute by file content rather than by path. Worth doing eventually as a second signal,
  and no substitute: the paths are what the catalogue knows and what the vendors document.
- Trust a tree's layout to identify the collecting tool and its conventions. Too fragile to
  rest attribution on, and the layout is already used for the one thing it does say
  reliably, which is the original path.
