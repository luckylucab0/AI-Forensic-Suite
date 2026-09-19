# ADR 0030: A record nobody has mapped is still looked at by a rule that names a kind

- **Status:** accepted
- **Date:** 2026-09-19

## Context

A rule may say which kinds of event it is about, and most do. That restriction is what
keeps a rule about commands from reporting a prompt that mentions one, and it is what keeps
a pack of eighty rules from running eighty patterns over every event in a large case.

The generic readers put a second population under `unparsed.record`: a record that was read
fine out of a store, a log or a document nobody has a verified mapping for. Those records
carry the mark the case counts with, and the count exists precisely because the two
populations are opposite answers. One is a defect in the evidence. The other is intact
evidence with no reading yet.

The restriction was quietly wrong about the second population. A record out of an unmapped
store is filed under `unparsed.record` because nobody could establish what kind of event it
is, which is not the same as establishing that it is not a command. For several agents in
this catalogue the only copy of a conversation on the endpoint is in such a format: an
encrypted container, a store with no schema, a text log. A pack that skipped those records
said nothing at all about exactly the evidence those cases have left, and said nothing
about saying nothing.

## Decision

A rule's kind restriction does not exclude a record that carries the uninterpreted mark. A
record with no mark, which is a record nothing could read, stays excluded: matching a
pattern in the bytes that survived a decode failure would report a command out of a damaged
record.

Every finding that rests on such a record says so, in the summary an analyst reads first:
the kind of the record has not been established. A finding is then a lead with its
provenance and its limit attached, rather than a claim that the agent ran something.

A rule that wants a whole-record arm for exactly this case writes one, gated on the mark
through the ordinary condition grammar. `AFX-DANGEROUSCOMMANDS-002` carries the first, and
it is the pattern for the rest: the structured arms stay the right test where a parser
mapped the fields, and the text arm reaches the records where nothing did.

## Consequences

The conversations in unmapped and encrypted stores are now within reach of the packs, which
is what makes reading them worth doing: a decrypted trajectory that nothing scanned would
have been a viewer feature rather than a finding.

The cost is precision, and it is bounded rather than hidden. A rule that names a kind now
also sees records whose kind is unknown, so a pattern that would have been confined to
commands can match text that turns out to be a quotation, a proposal or a log line about a
command. The severity and the false positives section of each rule already carry that kind
of caveat; what this adds is a sentence on every affected finding saying which records it
rests on.

The second cost is volume. A case holding a large text log now runs every kind-restricted
rule over its lines. That is the same trade the readers themselves make, and the case
summary says which artifacts those records came out of, so a pack firing on one noisy log
is visible rather than mysterious.

We revisit this if a pack starts producing findings that are mostly from unmapped records,
which would mean the packs need a way to weight them rather than a way to hide them.

## Alternatives considered

- **Leave the restriction as it was.** Keeps every rule's scope exactly as its author
  described it, and makes the suite silent about the agents whose only record is unmapped.
- **Let every rule see everything.** Drops the restriction entirely, and with it the reason
  it exists: a rule about commands would report every prompt that mentions one.
- **Require each rule to opt in.** Thirty rules to edit for a property that is true of all
  of them, and the one somebody forgot would be the silent gap this project keeps finding.
