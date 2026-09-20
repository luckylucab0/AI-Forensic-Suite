# ADR 0035: A deleted prompt is evidence, and is read out of the pages nothing points at

- **Status:** accepted
- **Date:** 2026-09-20

## Context

One editor keeps the prompts a user wrote for its agent in an LMDB store rather than in
files. That was a gap in two places at once.

The catalogue had the directory only under its macOS spelling, inside an entry about
installed extensions. The editor builds the path from `prompts_dir()`, which is
`config_dir()/prompts` on macOS and `data_dir()/prompts` on Linux and Windows, so the one
spelling collected nothing on two platforms, and what it did collect was filed as evidence
that something was installed rather than as the instruction surface.

The store itself was read by nothing. Every other instruction artifact in this catalogue is
a file of prose, so the reader for them takes a path and returns its text; this one is a
page format with two named sub-databases, one holding a prompt's title and the time it was
last saved and the other holding the text. A case recorded that a directory existed and said
nothing about what the agent had been told to obey.

There is a third thing, and it is the reason this has its own decision. The format never
overwrites a page. Every write copies the page it changes and leaves the old one to be
reused later, so a store holds earlier versions of the prompts in it and the prompts
somebody deleted, until the space is taken again. A reader that walked the tree would report
the library as it is now, correctly, and an analyst reading that case would have no way to
know that a prompt telling the agent to skip the review step was in the library last week.

## Decision

The prompts directory becomes its own catalogue entry, `zed.prompt_library`, under the
category the text in it belongs to, with the per-platform paths the editor's own path crate
states and the store's layout recorded in the entry.

The page format is implemented in this package rather than taken from a dependency, for the
reason ADR 0031 gives for the browser engine's store: this suite has to be vendorable into
an air-gapped environment, and the format reads cleanly with `struct`. It was written
against stores liblmdb 0.9.35 wrote and every record was compared against what that library
returned for the same file, including a two-level tree, a hundred duplicates under one key
and a value in an overflow page. That comparison is kept as a test that skips where the
library is absent, so anybody who has it can re-run the one the reader was built on.

The pages the current tree does not reach are read, and what comes out is filed as an
instruction source like the rest, carrying `recovered` and the sentences that say what it
is: which half of a prompt it holds, that its page is one the store no longer points at, and
whether a record under the same key is still live. A recovered record whose key is not one
of this store's keys, which is what the store's own bookkeeping looks like, is kept as an
unparsed record rather than called a prompt.

Filing them as instruction sources rather than as unparsed records is the substance of this
decision. The question this suite exists to answer includes what the agent was told to obey,
and a prompt that was removed is part of that answer. Hiding it under a kind the instruction
surface does not show would be the failure of non-negotiable 6 in its subtler form: the
record is in the case, and nobody reading the case for instructions would ever see it.

What is not decided here is what a recovered record means. The file cannot say whether it is
a deletion or an earlier version of something still present, so the event says both readings
and says which one the key being live or absent points to. Two recovered halves of one
prompt are not paired, because the file does not record that they belong together.

## Consequences

An analyst can read what the agent was told to obey on the two platforms where this store
was collected by nothing, and can see the prompts that are no longer in the library. On the
synthetic profile that is a prompt telling the agent to push to the default branch without
review, which is in no other artifact of that profile.

A case gets more events per store than there are prompts, and on a library that has been
edited for a year most of them will be earlier versions of live prompts rather than
deletions. The reader caps how many recovered records reach a case and says when it has, and
every one of them is labelled, so the cost is length rather than confusion.

Two defects came out of building it and are fixed here.

An event is identified by its provenance and its kind, so two events from one file that
share a locator are one row in the case: the insert takes the first and drops the second
without a word. Locating a prompt by its id did exactly that, because the live prompt, an
earlier version of it and the two halves of a recovered one all carry the same id. The
recovered events carry their page in the locator now, and the ingest counts and names any
file whose parser hands out two events with one identity, which is a defect in this suite
rather than in the evidence and had no way of being noticed before.

The reader also recovers a store whose first meta page is torn. The page size is written in
that page and nowhere else, so the second meta page cannot be found without it; the reader
tries the page sizes a machine can have and checks each candidate against the page's own
statement of it. The C library refuses such a file outright, which for a file copied off a
running endpoint would mean losing every record in it.

## Alternatives considered

- **Read only the live tree.** One line shorter and it answers the question an analyst is
  least likely to be asking. The library as it stands is also in the live tree of any
  running copy of the editor; what a collection adds is the history the file kept.
- **File recovered prompts as unparsed records.** They would be in the case and invisible to
  the view that answers what the agent was told to obey, which is the only view anybody
  would look for them in.
- **Pair the two recovered halves of a prompt.** It would make a nicer event and it would be
  invention: nothing in a freed page says which other freed page it was written with.
- **Depend on the C library.** One import instead of a page reader, and a compiled
  dependency in a tool that has to be vendorable offline, for one artifact. ADR 0031 settled
  the same question the same way.
- **Leave the directory inside the extensions entry and add the two missing paths.** The
  paths would be collected and the text in them would still be filed as evidence that
  something was installed, so it would never reach the instruction surface.
