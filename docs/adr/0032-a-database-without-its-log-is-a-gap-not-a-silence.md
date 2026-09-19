# ADR 0032: A database without its write-ahead log is a gap, not a silence

- **Status:** accepted
- **Date:** 2026-09-19

## Context

Twenty-eight of the catalogue's artifacts are SQLite databases, and most agents run theirs
in write-ahead-log mode. In that mode the newest transactions are in a file named after the
database with `-wal` appended, and nowhere else.

Collect the database alone and it opens. Every table is there. Every row reads. The
conversation stops before its last messages, and SQLite reports no error of any kind. It is
the only failure in this pipeline that is indistinguishable from success, which makes it
the exact shape non-negotiable 6 exists to prevent: an analyst would quote a last message
that was not the last message.

The reader has always copied the `-wal` and `-shm` siblings out of the bundle before
opening a store, so a collection that carried them is read completely. What was missing is
any statement about the case where they were not carried. Sixty-two database paths across
twenty-three catalogue entries have no `-wal` pattern anywhere in the catalogue, so no
collection of them could ever have taken one.

The obvious check, "this database journals ahead and no log arrived", is useless on its
own. An application that closes cleanly folds the log into the database and deletes it,
leaving a header that still says write-ahead logging. On a dead-box collection nearly every
database is in that state, so that check would fire almost every time and train an analyst
to scroll past it.

## Decision

The sixty-two paths get their `-wal` and `-shm` siblings written into the catalogue, on the
entry that already claims the database, listed as unsourced where the entry is verified,
because the vendor's page states the database and says nothing about the files SQLite keeps
beside it. That is one hundred and twenty-four paths, and it is the ordinary way this
project changes what is collected: the catalogue is the single source of truth, so both
collectors, all five collection-rule exporters, the generated documentation and the
analyzer pick the change up from one place with no new code. A rollback journal is not
derived, because the entries that already catalogued their siblings by hand catalogue these
two and not that one.

The check stays, for the entries somebody adds next. The gap is reported where the
catalogue never asked for the log. `Catalogue`
answers which entries those are, from SQLite's own naming rule rather than from anything a
vendor has to state, and the ingest checks the header of files belonging to those entries
alone.

It is recorded as a collection gap rather than an event, because it is a statement about
what the collection carried and not about a record in a file. The reason it carries gives
both readings, since the evidence cannot distinguish them, and says what to collect to
settle it.

A test asserts that no catalogued database is left without its log. It is the only thing
standing between a new entry and a collection that reads a conversation short, so it holds
the set at empty rather than at a list somebody has to maintain.

## Consequences

An analyst reading a case now knows which stores were read completely and which might have
stopped short, which is the difference between a timeline and a timeline with a hole in it
nobody can see. The check costs one hundred-byte header read per file of the affected
entries.

The cost is that the gap still cannot say whether anything was actually lost. It says the
collection could not have carried the log; whether one existed on the endpoint is a
question only the endpoint could have answered, and by the time the case is built it is
gone. An examiner with access to the endpoint can settle it; one working from a bundle
cannot.

The catalogue carries a hundred and twenty-four more paths that have to be kept in step
with their databases by hand, which is the cost of not putting the rule in code. The test
above is what makes that safe: a database whose siblings are missing fails before anybody
collects with it. The alternative, deriving the paths while the catalogue loads, would have
been one rule instead of a hundred and twenty-four lines, at the price of a catalogue file
that no longer says what a collection takes.

## Alternatives considered

- **Flag every write-ahead-mode database with no log.** Fires on nearly every store in a
  dead-box collection, so it would be scrolled past exactly when it mattered.
- **Say nothing, as before.** The reading looks complete and may not be, which is the one
  outcome this project treats as worse than reading nothing.
- **An event per affected store rather than a gap.** There is no event kind for it that
  would not be a lie: it is not a record that failed to parse and not a record nobody has
  mapped, and filing it as either would corrupt the two counts a case is judged by.
- **Refuse to read a database whose log is absent.** Throws away a store that is usually
  complete, to avoid a case where it might not be.
- **Derive the siblings in the loader instead of writing them down.** One rule rather than a
  hundred and twenty-four lines, and every consumer would get it for free. Rejected because
  reading `catalog/zed.yaml` would then no longer tell you what a collection of Zed takes,
  and that file is where this project sends anybody asking that question.
- **Teach the two collectors the rule instead.** It would have to be taught to the five
  exporters as well, since they render the catalogue rather than call the collector, so it
  is more places to drift and not fewer, and it breaks the invariant that the catalogue is
  the single source of truth.
