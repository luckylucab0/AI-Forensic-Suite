# ADR 0038: A store is read with the file beside it that says which project it is

- **Status:** accepted
- **Date:** 2026-09-20

## Context

Two of the products in this catalogue keep one key/value store per workspace, in a
directory whose name says nothing. A measurement settled what that name is not: it is not a
digest of the folder path, because fifty combinations of normalisation and digest algorithm
failed to reproduce one, and the same folder produces the same name in both products. So it
cannot be computed back into a path.

The editor writes the answer beside the store, in a small `workspace.json` holding the
folder's URI in plain text. The catalogue claims that file under the same entry as the
store, which sends it to the same parser, which opened it as a database. It failed, and the
case got one event saying the file is not a database, with the URI in no field of it: not in
the payload, not in the raw. The content was in the bundle and in no event, which is the
failure this project is built around.

The second half is worse because it is silent. `project_path` is a field of the event model
and fifteen parsers set it. The one that reads these two products' stores set it never, so
every row out of every per-workspace store of both products was unattributed. Nothing said
so. A view grouped by project showed them nowhere, and a rule that grouped by project could
not be written at all, which is how the question that started this came up: the rule wanted
to say that one folder was open in two different products, and there was no field to say it
with.

## Decision

The parser reads `workspace.json` as the document it is, with its text and its parsed form
on the event, and sets `project_path` from the URI in it.

It also resolves the neighbour. A store whose original path has a per-workspace directory
level in it reads the `workspace.json` beside it and puts the folder on `project_path` of
every event it produces, the inventory and each row alike. On the rows rather than only on
the store, because a rule sees one event at a time and groups by a field on that event, and
a folder recorded once on the store's own event answers nothing about the three thousand
rows next to it.

Four things the resolution does rather than assumes:

- A `file:` URI is percent-decoded, because on Windows the drive letter is encoded too and
  a reader that skipped it produces `/c%3A/Users/...`, a path no filesystem has.
- Any other scheme is carried whole and the event says the workspace was not local. A
  remote URI's path component is a path on another machine, and reporting it as a local one
  would send somebody to a directory that was never on this endpoint.
- A global store is never given a neighbour's folder. It belongs to no single workspace and
  a file beside it would be somebody else's.
- A column in a row that names a path wins over the store's folder, because a row about one
  project inside a store about another is the row's own answer.

Where no `workspace.json` was collected, the store says so in a parse problem rather than
leaving the field quietly empty. The difference is whether the next person goes and looks
for the file or concludes the parser does not fill that field.

The neighbour is read per store and nothing is remembered across the run. A parser holding
one workspace while reading another would attribute rows to the wrong project, and a wrong
project on an event is worse than no project at all.

## Consequences

Every row of both products' per-workspace stores is attributable to a folder, which makes
them answerable in the timeline and in the views, and makes a rule that groups by project
possible for them for the first time.

The cost is a new kind of coupling: a parser now reads a file other than the one it was
given. It is safe here because the bundle mirrors original paths, so the neighbour is where
the endpoint had it, and because the file it reads is one the same catalogue entry already
claims. It is still a precedent, and the test suite pins the four cases above so that the
next parser tempted to do it has an example with its limits written down.

The second cost is that an unresolved store now carries a parse problem where it used to
carry silence. That is deliberate and it will appear on collections that did not take the
whole directory. It is the honest reading: the store was collected and the file that
explains it was not.

What would make us revisit it: a vendor publishing how the directory name is derived, which
would make the neighbour unnecessary for the forward direction, though not for a store whose
neighbour is the only copy left.

## Alternatives considered

- **Leave it as it was.** One event per workspace file saying it is not a database, and
  `project_path` empty on every row of both products.
- **Read the name as a digest and compute the folder.** It is not a digest. Fifty
  combinations were tried against a known folder and none of them matched.
- **Resolve from the global store instead.** The global store does carry a list of opened
  folders, which is a real second source, but it is a list rather than a mapping: it says
  which folders were opened and not which of them this directory is. It stays what it is,
  a lead for a store whose neighbour was not collected.
- **Hold a mapping across the run and apply it afterwards.** Faster, and it makes a
  misattribution possible whenever two stores are read out of order or one neighbour is
  missing. A wrong project on an event is worse than an empty one.
- **Put the folder only on the store's own event.** Cheaper and it does not answer the
  question: a rule and a timeline both read the field on the event in front of them.
