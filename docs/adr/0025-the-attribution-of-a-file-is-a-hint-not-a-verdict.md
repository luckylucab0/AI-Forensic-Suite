# ADR 0025: The attribution of a file is a hint, not a verdict

- **Status:** accepted
- **Date:** 2026-09-18

## Context

One file on disk can be claimed by several catalogue entries. That is intended: an entry
can name a directory and another can name a file inside it, and an analyst asking which
entries cover a file wants both. But a parser is chosen from one entry, so something has to
pick, and two parts of this suite were picking by two different rules.

The collector picks the claimant whose catalogue entry has the fewest path patterns. That
is a proxy for specificity rather than specificity itself: an entry holding one broad glob
over a whole directory has fewer patterns than an entry whose pattern names the file.

The analyzer's tree matcher picks by how many literal characters of the matching pattern
matched, which is the right concept, and broke a tie by artifact id.

Both were wrong, and the two were wrong in different places, measured on the synthetic
profile:

- Via a bundle, five files arrived attributed to the container that holds them. Those
  entries have no parser, the ingest stopped there, and 36 parsed events were absent from
  the case: one agent's entire chat transcript, filed under category `config`, and four
  task files of another agent, filed under install evidence. The same files read as a tree
  produced all 36. That is the primary way the tool is used, collect on the endpoint and
  analyse in the lab, and it was the reading that lost evidence.
- In the tree matcher, `~/.claude/CLAUDE.md` and `<project>/.claude/CLAUDE.md` both count
  sixteen literal characters, because a placeholder contributes none. The tie went to the
  project entry on alphabetical order, so the user's own instruction file was reported at
  project scope. Scope is what an analyst reads off the instruction surface to answer which
  rules applied where.

## Decision

Three parts, all in the present tense.

1. **An attributed entry that has a parser is used, always.** A source that attributed a
   file well is not second-guessed. A native bundle beats a tree reading because its
   manifest is the only record of what the endpoint knew, and overruling it on a guess made
   afterwards would throw that away.
2. **When the attributed entry has no parser, the other claimants are tried,** most
   specific first. The manifest already records every claimant, so this needs nothing new
   collected. The attributed entry stays as it is in the manifest and in the case's
   artifacts row, the events name the entry whose parser read them, and the case records an
   `attribution_disagreement` so the two can be compared later.
3. **Specificity is the matching pattern's literal length, then whether it is anchored at a
   known root, then the artifact id.** A pattern for a working copy or for a tree relocated
   by a variable compiles to a claim that can match at any depth anywhere on the disk, and
   that is less specific than a claim on one named directory whatever the character count
   says. The id stays as the last key so that ordering is stable, and is no longer the
   second, because deciding which catalogue entry a file belongs to by alphabet is deciding
   it by accident.

## Consequences

The bundle path and the tree path now agree on the synthetic profile except for one file
the collector deliberately does not follow, a symlink pointing out of the profile, which is
recorded as a gap. The instruction surface reports a user-level instruction file at user
scope.

The costs, named:

- **A file can now be read under an entry the manifest does not name.** That is a
  divergence between a case and the bundle it came from, which this project otherwise
  treats as a defect. It is made visible rather than avoided: the report lists every one and
  the case carries the record. If that list is ever long, the answer is to fix the catalogue
  entry whose claim is too broad, not to grow the fallback.
- **The collector still uses its own rule,** so a manifest can still name a container entry
  as the attribution and give a transcript the category `config`. The fallback keeps that
  from costing evidence, but it does not make the manifest right, and a manifest is what a
  second tool reads. One rule, specified once and implemented in both, is still outstanding.
- **The ranking change moves attribution for files nobody has looked at yet.** Both
  claimants are still recorded and the fallback still applies, so the exposure is a label
  rather than a loss, but a tie broken differently is a different answer.

We revisit this if the fallback starts carrying real traffic. A handful of files means a
few catalogue entries to tighten. A hundred means the specificity rule is wrong.

## Alternatives considered

**Always prefer the most specific claimant, ignoring the attribution.** Rejected: it
overrules the endpoint's own record with a decision made later, which is the reason a native
bundle is preferred over a tree reading in the first place. It would also have hidden the
collector's rule being wrong, instead of leaving a record that says so.

**Run every claimant's parser and keep all the events.** Rejected: the same records would
enter the case twice under two artifact ids, and a forensic tool that double-counts records
is worse than one that labels some of them imprecisely.

**Count literal characters only, and break the tie by declaration order in the catalogue.**
Rejected: it makes attribution depend on the order of a YAML file, which is invisible and
changes when somebody sorts it.
