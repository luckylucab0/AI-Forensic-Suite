# ADR 0011: Agent guidance and the original brief are not published

- **Status:** accepted
- **Date:** 2026-09-14
- **Supersedes:** the instruction in the original project brief to commit it verbatim

## Context

The brief asked for two documents to be committed: itself, verbatim, on the assessment that
it contained nothing confidential, and a `CLAUDE.md` with guidance for an agent working in
the repository.

Reading them as published artifacts changes that assessment. Both are written in the first
person by someone describing their own situation: that they are a DFIR analyst, that they
built a scan for their employer's domains, that a previous version was hosted on a personal
subdomain, which identifiers that scan used. None of it names the employer. Together it
describes the author closely enough to be worth not publishing, and a short identifier
prefix sitting next to the phrase "employer's domain" is itself a hint.

The project owner asked for both to stay out of the public repository.

## Decision

`CLAUDE.md`, `CLAUDE.local.md`, `.claude/` and `docs/BRIEF.md` are gitignored. The files
stay in the working tree, so an agent session in this checkout has the same context as
before, but that context does not become part of the public record.

Nothing a contributor needs may live only in those files. Specifically:

- The full command reference, the conventions and the catalogue honesty rules are in
  `CONTRIBUTING.md`.
- The architecture, the event model, the bundle rationale and the phase plan are in
  `docs/ARCHITECTURE.md`, `docs/BUNDLE_FORMAT.md` and `docs/COLLECTION.md`, written
  impersonally, with the rules documentation to follow in phase 4.
- Every decision, including the ones that supersede the brief, is an ADR here.

## Consequences

Buys: the published repository describes a tool, not a person. The reasoning survives in
documents written for readers rather than for one author.

Costs: a fresh clone has no agent guidance file, so an agent session in a new checkout
starts without it and the operator has to bring their own copy. Some transparency is lost:
a reader cannot see the original requirements as they were stated. The ADRs carry the
substance of them, which is the part that helps a contributor.

## Alternatives considered

- Publish a redacted brief: still a first-person document about the author's employment,
  and redaction marks draw attention to what was removed.
- Rewrite the brief impersonally and publish it as design goals: reasonable, but it would
  duplicate `docs/ARCHITECTURE.md` and the ADRs, which already say the same things for a
  reader who is not the author.
