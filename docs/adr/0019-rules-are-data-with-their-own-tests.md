# ADR 0019: A rule is data, carries its own tests, and findings live in the case

- **Status:** accepted
- **Date:** 2026-09-17
- **Supersedes:** the `AAFS-` rule id prefix and the `org_scope` pack in the original brief

## Context

The brief asked for a declarative YAML rule engine with inline tests, ten starter packs and
findings written to the case database. Four questions had to be settled before writing any
of it.

How much a rule may express. A detection language wide enough to be convenient becomes an
expression evaluator, and an expression evaluator inside a forensic tool is a way to run
code from a public repository over text an attacker controls.

What a rule has to prove before it ships. The failure mode of a detection pack is not a
rule that misses. It is a rule that fires on everything, after which an analyst stops
reading the pack, and every rule in it is then worthless.

Where a finding lives, and what happens when the same case is scanned twice, which it will
be: scanning again after fixing a rule is the normal workflow.

And what an empty result means.

## Decision

**A rule is data.** One YAML file per rule: a tree of `all`, `any` and `none` over leaves
that each name one field and one operator, validated against a JSON Schema. There is no
expression to evaluate and nothing callable in a rule file. A rule may address event
fields, paths under `payload`, `raw` and `provenance`, and three whole-record text views,
and nothing else. Everything is compiled when the rule is loaded, so a misspelled field or
a regex that does not compile is a rule that fails to load rather than a rule that quietly
matches nothing.

There is no general `not`. The useful shape is always "and none of these apply", and a bare
negation over a field that resolves to a list has two defensible meanings.

**A rule carries its own tests, and needs one of each direction.** The loader refuses a
rule with only positive samples, because a rule that fires on everything passes all of
those. Every sample in every shipped rule is its own pytest case, and `afx scan
--self-test` runs the same code with no case, so an operator handed a pack can check it.

**Findings go in the case database**, in `findings` plus a `finding_events` link table, and
a finding is keyed by its rule and the event ids it rests on. Re-scanning therefore changes
nothing. The link table rather than a column because an aggregate rule fires on a group.

**Every scan is recorded**, in `scan_runs`, naming each rule that ran whether or not it
fired.

Two names from the brief do not survive. Rule ids are `AFX-<PACK>-<nnn>`, because the
brief's four-letter acronym is the one ADR 0002 keeps out of this repository, and a rule id
is exactly the string that ends up quoted in somebody's report. And there is no `org_scope`
pack, per ADR 0010.

The case schema goes to version 2 with no migration. The version check already refuses an
older file with a sentence telling the reader to re-ingest, and that stance is right for a
forensic tool: re-ingest is idempotent and cheap, and a partly migrated case is worse than
two honest ones.

## Consequences

Buys: a pack an analyst can read, diff and argue about without opening the engine; a
guarantee that no rule file can execute anything; a scan that is safe to repeat; and an
empty findings list that is a statement rather than an absence.

Costs are real and worth naming. A rule that genuinely needs a comparison between two
fields of the same event cannot be written, because a leaf compares a field to a constant.
A rule that needs to correlate across sessions cannot be written either; `aggregate` groups
and counts, and that is the whole of its power. When one of those is needed, the answer is
a new operator with its own tests, not an escape hatch into code.

The whole-record text views are the other cost. They are what lets the secrets pack find a
credential in a field no parser mapped, and they mean those rules run a regex over every
record in a case. That is the expensive part of a scan, and it is the price of not missing
the cases that matter.

We would revisit the no-code decision if a pack needed something genuinely algorithmic,
entropy over a candidate string being the obvious example. The answer even then is an
operator in the engine with tests behind it, not code in a rule file.

## Alternatives considered

- **Sigma.** A real standard with tooling, and shaped for log records with flat fields. An
  agent event's payload is nested and its interesting values are inside tool arguments, so
  the mapping would have been the whole of the work and the result would not have been
  Sigma anybody else could run.
- **Rules as Python functions in a package.** More expressive, unreviewable by the people
  who should be reviewing detections, and executable code from a public repository.
- **Findings in a separate file rather than the case.** Simpler, and it breaks the link
  between a finding and its evidence, which is the only thing that makes a finding
  checkable.
- **Keeping the brief's id prefix.** Ruled out by ADR 0002 for the same reason the package
  name was.
