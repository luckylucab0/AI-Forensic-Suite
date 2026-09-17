# ADR 0021: The licence is the Elastic License 2.0, not MIT

- **Status:** accepted
- **Date:** 2026-09-17

## Context

The repository shipped under MIT from its first commit. MIT permits anything, including
taking the work, closing it and selling it as a service, with no obligation beyond keeping
a copyright line. The author wanted two things MIT does not give: that nobody resells this
as a product or a hosted service, and that a fork credits the original.

The first instinct was a non-commercial licence, and it was the wrong instrument for this
particular tool. This is DFIR software. Its real users are incident response firms,
corporate security teams and managed providers, all of them commercial, none of them
selling the tool. A non-commercial clause forbids exactly the people the suite is for while
permitting a hobbyist to do anything. The distinction that matters here is not whether
money is involved in the use, it is whether the work itself is being resold.

## Decision

The licence is the **Elastic License 2.0**, unmodified, as published by its author. `LICENSE`
holds that file verbatim; the text was fetched from the publisher and from the SPDX licence
list and the two were compared word for word before it was committed.

`NOTICE` carries the copyright line and names the three clauses a fork has to act on. It
exists because the licence's own notice-preservation clause is the attribution mechanism:
keeping the notices is what credits the original, so the credit has to be in a file that
counts as a notice rather than in prose somewhere.

What this permits: use, including in paid professional work; reading, changing, forking and
redistributing. What it forbids: providing the software to third parties as a hosted or
managed service that gives them a substantial set of its features; removing or obscuring
the licensing and copyright notices; and shipping a modified copy without prominent notice
that it was modified.

The package metadata states the SPDX expression `Elastic-2.0` and carries no `License ::`
classifier, which PEP 639 forbids alongside an expression and for which no accurate value
exists anyway.

## Consequences

The tool stays usable for the work it was written for. An analyst at a consultancy can run
it on an engagement they are paid for, which a non-commercial licence would have prohibited
and which would have made the suite pointless.

It is no longer open source in the OSI sense, and the documentation says so rather than
letting the word stand. Expect that to cost inclusion in distributions and in some
corporate approval processes, which is a real price and was accepted knowingly.

The MIT grant on the versions published before this date is not withdrawn and cannot be.
Anyone who obtained the code under MIT keeps that permission for those versions; this
licence governs this version and later ones. `NOTICE` and the README both say so, because a
relicensing that quietly implied otherwise would be a claim about other people's rights.

Contributions are a loose end this ADR does not close: there is no contributor licence
agreement, so a contribution is offered under the repository's licence by the act of
offering it and nothing here asks a contributor to assign anything. If the project ever
needs to relicense again, every contributor would have to agree.

We would revisit this if the resale concern turned out to be theoretical while the
distribution cost turned out to be real, in which case Apache 2.0 with a trademark policy
is the honest fallback.

## Alternatives considered

- **MIT, unchanged.** Nothing to maintain, and no answer to either of the author's two
  concerns.
- **PolyForm Noncommercial 1.0.0.** Purpose-built for software and the literal reading of
  "non-commercial", and it locks out every professional user of a professional tool.
- **CC BY-NC 4.0.** Has the explicit attribution wording, is written for content rather than
  code, carries no patent grant, and Creative Commons itself advises against using it for
  software.
- **Business Source License 1.1.** Same posture with an automatic conversion to open source
  after a delay, at the cost of a parameter table nobody would maintain and a date that has
  to be right in every release.
