# ADR 0018: One unified log format, and it is the event model on the wire

- **Status:** accepted
- **Date:** 2026-09-17

## Context

Three consumers need agent history in a form that is not a SQLite case database.

A fleet collection returns results from many hosts at once, and nobody wants a database per
host. A collection tool already running on the endpoint, Velociraptor in particular, can do
the normalization there and return only the parsed result, which avoids shipping anything
to the endpoint. And the viewer runs in a browser with no server, so it needs a file.

All three want the same thing: a stream of normalized records. The question was what shape,
and there were two ways to get it wrong. Defining a second model would give two definitions
of what an agent's log says, and the moment they disagreed about one agent there would be no
way to tell which was right. Defining nothing and letting each consumer invent a shape would
give three.

The viewer already had a fourth answer: it normalizes Codex and Copilot logs into a
Claude-Code-shaped event, which works for rendering and is wrong as a format, because one
vendor's record shape is not a neutral one and every new agent has to be bent into it.

## Decision

There is one format, and it is `agentforensics.model.event.Event` serialized: JSON Lines,
one event per record, defined by `src/agentforensics/unified/agentlog.v1.schema.json`.
Version 1.

The schema is a file inside the package, not a dict in a module, so a producer that is not
Python can validate against it by reading a path.

Every record stands alone and carries its own version `v`. There is no file header and no
required ordering. Two logs therefore concatenate into a valid third one, and a producer
that emits rows rather than files can produce the format directly.

`agent` and `raw` are required. An event that cannot be attributed to an agent gets counted
anyway and is worth less than no event; `raw` is what makes a mapping mistake cost
interpretation rather than evidence.

`event_id` travels but is derived, so a reader recomputes it and records a disagreement
instead of correcting it. `producer` says what normalized the record.

`afx normalize` produces the format through the same source adapters and the same parsers as
`afx ingest`, and a test asserts that a log and a case built from one source hold exactly
the same events.

## Consequences

One place to add an agent, and every consumer gains it: the case database, the unified log,
the exporters and the viewer.

The cost is that the format inherits the event model's decisions, including the ones a
consumer may not want. It carries `raw` on every record, which roughly doubles a log's size
against a format that dropped it. It has a closed list of event kinds, so a producer with a
genuinely new kind has to add it here rather than in its own output. And a record is verbose:
nulls are written rather than omitted, because a field that is absent and a field that is
present and empty are different claims about the evidence.

We would revisit this if a producer appeared that could not carry `raw`, for example one
reading a database too large to quote. The answer then is a documented per-record exception,
not a second format.

## Alternatives considered

- **A separate wire model, mapped to and from the event model.** Two definitions of the same
  thing, and the mapping is where they would drift apart unnoticed.
- **The viewer's Claude-shaped event as the shared format.** Already implemented, and
  already the reason every new agent is bent into one vendor's record shape.
- **CSV, one row per event.** Loses `raw`, loses nested tool input and output, and the tool
  input is one of the three things an analyst is always asked about.
- **A header line carrying the version once.** Cheaper per record and incompatible with both
  a row-emitting producer and concatenation, which are the two uses that motivated the
  format.
