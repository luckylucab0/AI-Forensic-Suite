# ADR 0037: A first-hand measurement may refute a path but never verifies one

- **Status:** accepted
- **Date:** 2026-09-20

## Context

Two of the products in this catalogue ship no source and document almost nothing about
where their conversations go. Their entries rest on community write-ups, on strings read
out of the packages they ship, and in a few places on nothing better than a plausible
shape. The catalogue has no way to find out it is wrong about them, because every source
it can reach is the same set of pages that were wrong in the first place.

So one of the two desktop products and its command line agent were installed on a clean
Windows host, used for one trivial conversation each, and then uninstalled, with a
directory listing taken before, between and after. The result is the first evidence in
this repository that came from a machine rather than from a page.

It is also evidence of a different kind, and the difference is the whole decision. A
measurement that finds a file proves that this version, on this operating system, with
this feature used, writes that file. A measurement that does not find a file proves
almost nothing on its own: the feature may be off, the version may be newer, the path may
belong to an enterprise deployment nobody configured here. Three of the paths that were
absent on the measured host are built by code in the vendor's own shipped package, read
in the previous round of work, so their absence says the host never triggered them.

The one case where an absence is worth more than a presence is a path that never had a
source: the measurement searched the whole profile recursively for its filename and did
not find it anywhere. There the absence is the strongest statement anyone has made about
that path, and it outweighs the community write-up the entry rested on.

## Decision

`source_kind: observed` enters the catalogue, with `source` spelled
`observed on <os> <version>` and nothing else, because a measurement is taken on somebody's
machine and the schema must not become a place where that machine gets described.

What a measurement may do:

- It may **add** an artifact nobody had catalogued. The entry is `observed` and
  `unverified`, exactly like a community write-up, because one host is not a product.
- It may **correct** a path's shape where the measurement found the real one, and the note
  says both spellings so an older version on an endpoint is still collected.
- It may **refute** a path, and this is the part that is worth the work. A refutation
  removes the path or marks the entry `legacy`, and only under two conditions together:
  the entry rested on `community` or `recollection`, and the measurement searched for the
  filename across the whole profile rather than at the one place it expected it.

What a measurement may never do:

- It may not make an entry `verified`. The schema already refuses this, and the reason is
  worth writing down: verified means somebody can re-read the statement at a URL, and a
  measurement is gone as soon as the host is wiped.
- It may not remove a path that the vendor's own documentation or its own shipped code
  states. Such a path stays, and the entry gains a note saying a fresh installation of the
  named version did not create it. That note is evidence too: it tells an analyst that an
  empty result at that path is the ordinary case rather than a wiped one.

An entry a measurement touched says so in its notes, with the version measured, because
a path that was right in one version is the commonest way this catalogue goes stale.

## Consequences

The catalogue can now be wrong in public and find out. Nine paths across the two closed
products were refuted by this one round, among them a credential file that three
independent write-ups name and that does not exist, and the entry that would have sent an
analyst to the wrong extension directory for pre-edit file content.

The cost is that `observed` entries are the only ones nobody else can check. A community
source is at least a URL that somebody can disagree with; a measurement is an assertion in
a file. The mitigation is the version string in every note: an entry that claims a path for
one named version is falsifiable by installing that version, which is more than the
entries it replaces offered.

The second cost is scope. One host, one operating system, one version, one conversation
each. Everything this round says about the two products is true of exactly that, and the
notes say so rather than generalizing. A second measurement on another operating system
will contradict some of it, and that is the intended behaviour rather than a problem.

We revisit this if a vendor publishes the layout, because a URL beats a machine.

## Alternatives considered

- **Keep measurements out of the catalogue and put them in a document.** The catalogue is
  the single source of truth, and a fact about a path that lives beside it is a fact the
  collectors do not act on.
- **Let a measurement verify an entry.** It reads well and it destroys the one guarantee
  `verified` carries. An analyst who finds nothing at a verified path has to be able to
  conclude something, and that only works while verified means re-readable.
- **Treat every absence as a refutation.** It would have deleted four entries built from
  the vendor's own shipped code, all of them correct, on the evidence of a host where
  nobody turned the feature on.
- **Record the measured host so the finding can be reproduced.** That is the one thing the
  OpSec rule forbids outright, and the version string carries the reproducible part of it.
