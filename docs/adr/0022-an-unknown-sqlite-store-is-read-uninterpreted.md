# ADR 0022: An unknown SQLite store is read uninterpreted

- **Status:** accepted
- **Date:** 2026-09-18

## Context

Twenty-eight catalogue artifacts are SQLite databases, twenty-one of them transcript
stores, across fifteen agents. Until this decision not one of them produced an event. A
collected `opencode.db` became a single `artifact.fs` record: the case stated that the file
existed and nothing at all about the conversations in it. An analyst reading that case would
conclude there was nothing to read, which is the failure ADR 0009 exists to prevent, in the
place it was easiest to overlook because nothing looked broken.

The obvious fix is a parser per store. That is the right end state and it is slow: each one
needs a schema read against its vendor or its source code, and five of the fifteen agents
are closed source. Waiting for all of them means the stores stay invisible in the meantime.

The tempting fix is a mapping that looks about right for a chat table. That is the same
defect as an invented catalogue path (ADR 0015): output that reads as an answer while being
wrong, and a wrong timeline is worse for an investigation than an unread one.

## Decision

One module reads every SQLite store in the catalogue, and it interprets nothing.

It returns the store's tables with their real row counts, then every row as its own event
with the whole row in `raw`. From a row it reads only what the row literally says: a column
named as a time is a time and names itself as the source, a column named as text is text.
Every event carries a `parse_problem` stating that this is an uninterpreted reading. That is
the same rule the generated Velociraptor artifact applies to a line-delimited log it has no
mapping for, so a fleet hunt and a local case agree about what uninterpreted means.

The reader never opens evidence in place. The database and its `-wal`, `-shm` and
`-journal` siblings are copied to a temporary directory and the copy is opened `mode=ro`.
The siblings travel because a store collected from a running agent can have its newest
messages only in the write-ahead log, and opening the database without it returns a
conversation that stops early.

Three stores are inventoried and their rows are not ingested: a symbol cache, a repository
index and a vector store. They are machine-generated derived data and one of them can hold
several hundred thousand chunks of a working copy. The tables and the counts are still
returned, with the reason on the event, because how much of a working copy an agent had
indexed is itself evidence.

The set of claimed artifact ids is committed in the module and compared against the
catalogue by a test, so adding a SQLite store to the catalogue fails CI until somebody
decides how it is read.

## Consequences

Every collected SQLite store now produces evidence, and a rule or a search over the case
reaches its content. An analyst can see that a store holds four hundred rows in a table
called `message` and go read them, which is the difference between an inconclusive answer
and an absent one.

The cost is volume and noise. A row per row means a large store contributes thousands of
`unparsed.record` events, all of them counted as records nobody read, and a case summary
will say so loudly. That count is honest, and it is also the pressure that gets the
per-agent parsers written. The per-table limit is 50,000 rows, reported in the output rather
than applied silently.

The second cost is that these events carry little structure: no actor, usually no
timestamp, no session in most stores. They will not group into conversations and will sit at
the undated end of a timeline. That is what an unread store honestly looks like.

We revisit a store the moment its schema is verified: a per-agent parser is placed ahead of
this one in `PARSERS` and takes the artifact over, with no change to the claimed set.

## Alternatives considered

- A parser per store first, nothing until then. Correct and slow; it leaves twenty-one
  transcript stores invisible for as long as it takes, and five vendors are closed source.
- A guessed chat mapping (a table named like messages, a column named like role). Produces a
  case that reads as answered and is wrong wherever the guess misses, which is the one
  defect this project treats as worse than no output.
- Opening the collected database in place. Takes a lock on evidence and makes a read-only
  WAL connection create a shared-memory file beside it, so hashing the bundle afterwards
  would show it changed by the act of reading.
- Skipping the index and cache stores entirely. Cheaper, but how much of a working copy an
  agent had indexed is evidence, and a skipped file reads as a file with nothing in it.
