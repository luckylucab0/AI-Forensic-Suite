# ADR 0034: A database's sidecar is named for what it is rather than opened as a store

- **Status:** accepted
- **Date:** 2026-09-20

## Context

ADR 0032 put the `-wal` and `-shm` siblings of every catalogued database into the
catalogue, on the entry that already claims the database, so a collection carries the file
holding a live store's newest writes. The reader has always copied those siblings out of
the bundle before opening a store, so that half works: a row committed to the log and not
yet to the database is in the case.

What nobody looked at is what the sidecar itself becomes. A collection carries it as a file
of its own, with its own manifest entry, and the ingest hands every collected file to the
parser that claims its artifact id. For twenty-four entries that parser is the one that
opens SQLite stores, because the database and its log are claimed by the same entry. It
tried to open the log, SQLite said the file is not a database, and the case got:

    this store the table list could not be read: file is not a database

Two defects in one sentence. It does not read as English, because the message was written
to follow the words "this store" and this one starts with a noun phrase. Worse, it claims
a store that could not be read, on a file whose records are in the case already: they were
read through the database beside it, which is the whole point of collecting the log.

That is non-negotiable 6 upside down. The rule says a record that could not be read must be
surfaced rather than hidden, and the reason is that silence makes an analyst conclude
nothing was there. A loss reported where there was none does the same damage from the other
side: an analyst counting unreadable stores in a case would have counted up to twenty-four
that were never unreadable, and gone looking for a corrupt database that does not exist.
Two further entries are a database's sidecars and nothing else, so no parser claimed them
at all and they arrived as an inventory row: a file was there, and nothing about what it
was.

## Decision

Every parser that opens a SQLite store asks first whether the file it was handed is one of
a database's sidecars, and if it is, emits one record saying what it is instead of trying
to open it. There are four answers and they are different findings:

- A `-wal` whose database is in the collection: the records in here are the newest writes
  the store took, and they are on that database's events already.
- A `-wal` whose database is not in the collection: those records cannot be read at all,
  because a log holds changed pages rather than rows. This one is a finding, and it says
  what to collect to settle it.
- A `-shm`: no records of its own, rebuilt from the log, and its presence says the store
  was open when it was collected, because a clean shutdown removes it.
- A `-journal`: the pages as they stood before the transaction that was in flight, so the
  store was mid write when it was collected.

The two entries that are only sidecars are claimed as well, by the generic reader, so they
get the same sentence rather than an inventory row.

The check is a shared function rather than a rule in the dispatcher, because which files
belong beside a database is SQLite's business and the ingest has no business knowing it. A
test asks the catalogue which entries claim a sidecar and asks each one's parser what it
makes of one, so a ninth store parser written without the branch fails before it ships.

## Consequences

A case now distinguishes three things it used to call one: a store that could not be read,
a log whose content is already in the case, and a log whose database is missing. The first
count is the one an examiner judges the collection by, and it is no longer inflated by two
dozen files that were never stores.

The sidecar records carry no rows, so they add one event per collected sidecar and nothing
to the timeline. That is deliberate: the file is in the bundle and the case has to say what
it is, or a reader working from the file list is left to guess.

The end of it is tested through the whole pipeline rather than in pieces. The synthetic
profile now holds a store in the state a live collection finds one in, with its newest
message in the log and nowhere else, and a test asks a case built from that profile for
that message. The pieces were all tested before and the thing that has to work was not: if
the mapping from an original path to a place in a bundle ever stopped putting a database
and its log side by side, every piece would still pass and every live-collected store would
quietly read one message short.

## Alternatives considered

- **Leave it, since the records are read anyway.** The reading is right and the case says
  it failed, which is worse than saying nothing: an analyst cannot tell this line from a
  real unreadable store.
- **Fix only the grammar.** The sentence would parse and still claim a loss that did not
  happen.
- **Skip a sidecar silently.** A file in the bundle that no event mentions reads as a file
  that held nothing, which is the failure this project is built around.
- **Intercept it in the ingest before any parser sees it.** Puts SQLite's naming rules in
  the dispatcher, which would then have to know them for every other format too.
- **Read the log directly, page by page.** It would let a case recover rows from a log
  whose database is missing, and it is a page-level reading of a format whose pages this
  suite does not otherwise parse. Worth doing when an investigation needs it; not worth
  guessing at now, and the record for that case says plainly what is missing.
- **Stop catalogueing the sidecars.** Undoes ADR 0032 and loses the newest messages of
  every store collected from a running agent.
