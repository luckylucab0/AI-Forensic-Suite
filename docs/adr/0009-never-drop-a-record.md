# ADR 0009: No record is ever dropped, truncated or hidden

- **Status:** accepted
- **Date:** 2026-09-14

## Context

The inherited viewer silently discarded evidence in five places, all of them the kind of
defect that looks harmless in ordinary software:

- A line that failed to parse was stored truncated to 2000 characters, and the renderer
  returned nothing for its record type, so it never appeared at all.
- Any record type the renderer did not recognize returned nothing.
- An assistant record without a `message.id` fell through the turn-grouping logic into that
  same nothing.
- The Codex normalizer skipped every record that was not a `response_item`, including
  `compacted` records, which mark context compaction and are the usual explanation for an
  apparent gap in a transcript.
- The Copilot normalizer's `default` branch dropped unknown event types.

In a normal application these produce a slightly incomplete view. In a forensic tool they
produce a confident wrong answer, because an analyst who sees nothing concludes nothing was
there. A crash would have been better: a crash is visible.

## Decision

Nothing that exists in a log may be absent from the view or from the model.

- Unparsed lines are kept in full, never truncated, with their 1-based line number, and are
  rendered as their own visibly marked row.
- A well-formed line that is not a JSON object gets its own kind, since that is itself an
  anomaly.
- Unknown record types and unknown event types are preserved as `unknown-record` and
  rendered, with the original record available in full.
- Assistant records without an id get a turn of their own.
- A record that is deliberately not shown as a turn still exists, and where it is kept
  depends on what the reader is for. The viewer reads one transcript as a conversation, so
  it may fold such records into one visibly marked row naming their number and their
  subtypes, which is how it handles the Codex `event_msg` mirrors of `response_item`. The
  analyzer and the exported endpoint queries may not, because they are the evidence path:
  each of those records becomes an event of its own, at a kind the conversation views do not
  read from, carrying its line number and its content. A case holding a count where it
  should hold the record is the same wrong answer this decision is about, one level deeper,
  and the Codex parser held one until the differential against the endpoint query in
  `scripts/check_velociraptor_vql.py` named the line.
- The session header counts unparsed lines, so a transcript that did not read cleanly
  cannot look clean.
- In the analyzer, every event carries `raw`, the original record kept verbatim, so a
  mapping mistake in a parser costs interpretation and not evidence.

The only records deliberately not rendered are the synthetic `meta` event the normalizers
prepend, and a user turn carrying nothing but tool results, which the tool rows already
show.

This is a testable property, and new parsers need a test for it.

## Consequences

Buys: the view can be trusted as a statement about the file. An empty result means the file
was empty, not that the parser shrugged.

Costs: a noisier transcript when an agent release introduces record types we do not
understand yet, and more code in every parser and renderer branch. Noise is the correct
trade here: an analyst can ignore a row they do not care about, but cannot ignore a row
that was never drawn.

## Alternatives considered

- Log unknown records to the console: nobody reads a browser console during an
  investigation, and it does not survive into the case database.
- A debug mode that shows everything: makes the safe behavior opt-in, so the default stays
  wrong.
