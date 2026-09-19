# ADR 0027: A whole JSON document is split by its structure, not by its meaning

- **Status:** accepted
- **Date:** 2026-09-19

## Context

The catalogue holds 161 artifacts whose format is a whole JSON document and 149 of them had
no parser. Thirteen of those are transcripts and prompt histories: the conversation itself,
collected and reaching a case as one `artifact.fs` event that says a file existed. That is
the failure ADR 0009 exists to prevent, and ADR 0022 already answered it for SQLite stores
and a later change answered it for line-delimited logs.

Neither of those answers transfers. Both formats hand a reader its own records: a store has
rows, a line-delimited log has lines, and the floor under them is "return each one, read
nothing out of it but what it literally says". A whole JSON document has no records. It has
a value, and where the records are inside it is a question about what the document means.

That is the question this decision refuses to answer by guessing. A reader that went
looking for the array that is probably the conversation, by trying keys named `messages`,
`items` or `conversation`, would be right for most agents and quietly wrong for the rest,
and a case that shows four messages out of a file holding forty is worse than one that
shows the file whole and unread.

There is a structural answer that claims nothing about meaning. A document either is a list
of things or it is not, and a key whose value is a list of objects is a list of things
whatever those things are. Saying that much is checkable against the bytes.

## Decision

One module reads every JSON document in the catalogue, and it interprets nothing.

It splits by structure only:

- A document whose root is a list is one event per element, at `$[n]`.
- A document whose root is an object is one event for the document, and then one event per
  element of each **top-level** key whose value is a list of objects, at `$.key[n]`.
- Anything else is one event, at `$`.

It goes exactly one level deep and no further. A document that nests its records under
another object keeps them in the document event, whole and searchable as text, because
descending to find them means deciding which branch holds the records, which is the guess
this decision exists to avoid.

From a record it reads only what the record literally names, in the same field names and
the same order as the reader for line-delimited logs, so the two agree about an unmapped
record. Every event says on itself that this is an uninterpreted reading, in the words the
other two generic readers use, and the whole value is in `raw`.

Two limits are part of the decision.

A list longer than 10,000 elements stays one event with all of it in `raw`, and the event
says how many elements it holds and why it was not split. This is the rule ADR 0022 applies
to an index or a cache store, moved from a list of artifact ids to the data itself: an
event per element there buries a case's evidence under a machine-generated index.

Artifacts the catalogue marks `sensitivity: secret` are not claimed. Their content is not
copied by default, so usually there is nothing to read; where an analyst collected it with
`--include-secrets` on purpose, the file is in the bundle and its existence and hash are in
the case, and putting a token into the payload of a timeline event is not what that flag
was for. This is a narrowing of what is read, not of what is kept.

The set of claimed artifact ids is committed in the module and compared against the
catalogue by a test, so adding a JSON artifact to the catalogue fails CI until somebody
decides how it is read.

## Consequences

Every collected JSON document now produces evidence, and a rule or a search over a case
reaches its content. A conversation store nobody has a schema for shows its turns one by
one, with a JSON path an analyst can follow back into the file.

The cost is the same one ADR 0022 accepted, in a new place: volume, and events with little
structure. A configuration file contributes one event whose payload is mostly a document
nobody read, and it is counted as a record in a format nobody has mapped. That count is
honest and it is the pressure that gets the verified parsers written.

The second cost is the one-level rule. An agent that writes `{"data": {"messages": [...]}}`
gets one event holding the whole document rather than one per message, so its turns are in
the case but not separately timestamped, grouped or counted. That is visibly a partial
reading rather than a wrong one, and it is exactly the shape that justifies writing a
verified parser for that agent.

We revisit an artifact the moment its shape is read against a vendor source: a parser is
placed ahead of this one in `PARSERS` and takes it over, with no change to the claimed set.

## Alternatives considered

- **One event per document, never split.** Simplest and honest, and it makes every
  conversation in these stores a single blob with one provenance, which no timeline, rule
  or session view can use.
- **Descend recursively and split every list of objects found.** Produces events for a
  configuration's nested arrays as readily as for a conversation, with paths nobody can
  interpret, and multiplies the volume cost without adding a fact.
- **Find the records by key name (`messages`, `items`, `conversation`).** The guess this
  ADR exists to avoid: right for most agents, silently wrong for the rest, and it is the
  wrong ones an investigation turns on.
- **A verified parser per store first, nothing until then.** Correct and slow. Thirteen
  transcript and prompt-history artifacts stay invisible for as long as it takes, and one
  vendor's own documentation says not to rely on the structure at all.
