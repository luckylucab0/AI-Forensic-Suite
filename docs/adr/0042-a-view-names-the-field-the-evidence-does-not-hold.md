# ADR 0042: A view names the field the evidence does not hold, rather than leaving it blank

- **Status:** accepted
- **Date:** 2026-09-21

## Context

The Evidence Desk redesign was drawn as a set of mockups before it was built against a real
case. Three of the columns in those mockups have no data behind them, and each one is the
kind of field a reader trusts without checking.

**A byte offset into the source file.** The mockup's evidence panel shows `0x0004A91C`
beside every row. Nothing in this suite records one. A locator is text on purpose
(`line:1486`, `log:0 record:12`, `table:threads key:9`), because those are three different
things and an integer column would lose which one it was; see the note on `_SESSION_SQL` in
`webui/api.py`. The finest place a line-delimited store can honestly give is the line.

**A volatility grade per artifact.** The mockup shows `high · 30 d` in the case view.
The catalogue does carry a `volatility` field, but it is prose written for a human — "Removed
on CLEAN EXIT", "only the FIVE newest copies are kept, so this rotates by count, not by age"
— and it is not in the case database at all. Compressing that into a grade would be this
tool inventing a number, and the number would be the part an analyst quotes.

**How long a tool call took.** The mockup's tool view has a duration column. No collector
in this suite records a duration, and no agent format read so far carries one. A call has a
timestamp; its result may have another, but the two are written by the producer at times it
chose, and subtracting them would be presenting a write-latency as a runtime.

The tempting move in all three cases is a blank cell or a dash. A blank column under a
header that says "Byte offset" does not read as "we do not know"; it reads as zero, or as a
field that happens to be empty for this row, and the header keeps promising the field exists.

## Decision

A view shows what the case holds. Where the design asked for a field the evidence does not
have, the view either leaves the column out entirely or prints what is missing in words.

Concretely, in the viewer:

1. **The evidence column prints `Byte offset — not recorded`**, beside the locator the store
   could give, with a tooltip saying no collector records one. It is left out where the
   record is the whole file, because an offset into all of it means nothing.
2. **There is no volatility column.** The per-artifact table shows the two counts the case
   actually holds: records nothing could read, and records read out of a format nobody has
   mapped.
3. **There is no duration column.** `/api/tools` says so in its own `note`, so a second
   client cannot reintroduce the column by assuming the field is merely absent from this one.

The same rule is why a tool call with no recorded result shows *no result recorded* rather
than a success, and why an event with no timestamp says so instead of being sorted early.

## Consequences

What this buys is that every field on screen is a field somebody can check against the
bundle. An analyst quoting the evidence panel into a report is quoting the case.

The cost is that the screen is less complete than the picture it was drawn from, and the
three absent fields are ones investigators genuinely want. A byte offset would let a reader
seek to the exact bytes in a carved file rather than counting lines. A volatility grade
would let the artifact list be sorted by what is about to disappear. A duration would make a
tool call that hung visible.

Revisit each one when the evidence supports it, and note that each is a change further down
the stack than the viewer:

- **Byte offset** needs the line readers in `parsers/base.py` to record the offset they are
  already walking past, and the locator vocabulary to carry `byte:` beside `line:`. That is
  a parser and format change, and it touches the provenance every event id is derived from.
- **Volatility** needs the catalogue's prose to gain a structured field beside it, and
  ingest to carry that field onto the artifact row. The prose stays: the grade would be a
  facet for sorting, never the answer.
- **Duration** needs a producer that records one. Until an agent format is found that writes
  it, there is nothing to carry, and the honest interim is the absence this ADR describes.

## Alternatives considered

- **A blank cell under the mockup's header.** The cheapest, and the reason for this ADR: an
  empty column under "Byte offset" is read as a value, not as an absence.
- **Deriving a duration from the call and result timestamps.** Available today, and wrong:
  it measures when the producer wrote two records, not how long anything ran.
- **Grading the catalogue's volatility prose with a heuristic.** A regular expression over
  sentences like "rotates by count, not by age" would produce a grade that is confident and
  sometimes backwards, in the column an analyst reads first.
