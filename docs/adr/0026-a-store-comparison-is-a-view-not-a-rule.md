# ADR 0026: Comparing an agent's stores is a view, not a rule

- **Status:** accepted
- **Date:** 2026-09-19

## Context

Several agents keep one conversation in more than one place. Zed has a thread store and a
sidebar index beside it. Codex has rollout files and a database that projects them into
rows. More than one agent writes a prompt history beside the session it belongs to. Two
parsers added in the same week made that concrete: the vendor's own migration history for
Zed's sidebar store shows threads reaching one store and not the other, in both
directions, and Codex's thread history holds a conversation whose rollout file may be gone.

A conversation that one store remembers and another does not is exactly the kind of thing
this suite exists to surface, and nothing in it could. A parser reads one file. A rule is
offered one event at a time, and an aggregate rule is offered the events it matched,
bucketed by a grouping key, firing on a count. There is no way in that model to say "this
group has an event from store A and none from store B", because an absence is not an event.

The rule model could be extended. The engine change is small: a second bucket per rule and
a set difference over the group keys, about twenty lines in the grouped path. The obstacle
is the rule file rather than the engine. A rule carries its own samples and `tests[].event`
is one partial event, so an absence rule could not state its own test without the test
format growing a set of events too. That is two format changes to the two files that
define what a rule is.

## Decision

The comparison is a projection over a case, beside the instruction surface and the artifact
list: `api.corroboration`, `/api/corroboration`, `afx sessions`, and a Conversations tab.
It reports, per agent, which of its stores name conversations at all and what each pair of
them agrees about, and then per conversation which stores name it and which stay silent.

Three properties are part of the decision rather than of the implementation.

1. **It is derived from the case, not from a table of which store pairs with which.** A
   store that names conversations is one that names conversations, whatever agent it
   belongs to. A pairing table would be a second place to be wrong about an agent nobody
   has looked at yet.
2. **Silence is reported as a lead and never as a finding.** A store may never have held a
   conversation, because it indexes only what was opened or because the two stores were
   written by different generations of one product. Every silent store says how many
   conversations of that agent it does name, so a store that knows one in forty is visibly
   not a peer of one that knows all of them.
3. **A pair with no conversation in common says so in its own words.** Two stores of one
   agent that share nothing are far likelier to use two id spaces than to have lost every
   conversation, and the pair line says which of the two it looks like. Left to read that
   out of a zero, an analyst would go looking for a deletion that never happened.

Findings stay the output of the rule packs. This view produces none.

## Consequences

The question is answered for every agent at once rather than for the one somebody wrote a
rule about, and it was answered without touching either format that defines a rule.

The cost is that the answer does not reach the places a finding reaches. It is not in the
findings table, not in a findings CSV, and not in the counts a report is built from, so an
analyst who never opens the view never sees it. That is the price of not making a claim
the evidence does not support: silence between two stores is ordinary often enough that a
finding per occurrence would be noise, and noise in a findings list costs more than a view
nobody opened.

Revisit this when there are numbers. The view makes the frequency measurable: if cases show
that silence between a particular pair of stores is rare and meaningful, an absence rule
becomes justifiable, and it can then be written with a false-positive rate somebody
measured rather than guessed. Extending `aggregate` with an absent condition, and
`tests[]` with a set of events, is the shape that change would take.

## Alternatives considered

- **An absence condition in the rule model.** The engine part is twenty lines; the rule
  format and the test format would both have to grow, and the rule would have been written
  before anybody knew how often it fires.
- **A gap record written at ingest.** The comparison would run once per bundle, so a case
  that later receives a second bundle would never redo it, and the answer would silently
  belong to whichever bundle arrived first.
- **Synthetic events, so the existing rules can fire on them.** Cheap, and it would put
  inferences in a table whose contract is that every row is a record that was on disk with
  its own provenance.
