# ADR 0014: One path is one manifest entry, and the strictest claim on it wins

- **Status:** accepted
- **Date:** 2026-09-14

## Context

The catalogue routinely claims the same file twice. That is not sloppiness, it is how the
catalogue describes reality: a cross-cutting entry claims every `CLAUDE.md` on the host
while an agent-specific entry claims the one in the user directory, and an entry for an
agent's data directory claims a whole tree while a second entry inside it names the one
file holding API keys. Nine such overlaps exist in the current catalogue, and more arrive
with every agent added.

The first collector decided per match rather than per path, which produced two defects
that only a reading of the collection loop would reveal.

The first was protective and not theoretical. A JetBrains directory glob marked `normal`
matches `c.kdbx`, the password database, which its own entry marks `secret`. Whether the
credential bytes were copied into the bundle therefore depended on which artifact the loop
reached first, and the loop's order came from the catalogue file order. The same ordering
decided `~/.cline/data/secrets.json`.

The second was that the second claim was dropped in silence. The loop skipped a path
already present in the manifest, so a file that a cross-cutting entry and an
agent-specific entry both matched was recorded under one of them, with no trace that the
other had matched. An analyst filtering the manifest by the cross-cutting artifact id
would then see nothing and conclude the instruction file did not exist.

## Decision

Matching and collecting are two passes. The first resolves every artifact claim on every
path. The second walks the resolved paths in sorted order and decides once per path:

- The bytes are withheld if **any** artifact claiming the path is `sensitivity: secret`.
  Secret is a property of the file, not of whichever entry matched first.
- `artifact_id` names the most specific claim, which is the claiming artifact with the
  fewest path patterns, so a file is attributed to the entry that names it rather than to
  a directory glob that happened to include it.
- `artifact_ids` lists every distinct claim, sorted, and is written only when there is
  more than one. One artifact matching a path through two of its own patterns is one
  claim.

A path appears exactly once in `files`. Both collectors implement this and the conformance
suite tests it against the bundle rather than against either implementation.

## Consequences

Whether a credential file reaches the bundle is now decided by the file, so the answer is
the same on every host and every catalogue reordering. No claim is lost, which is ADR 0009
applied to the manifest rather than to a transcript.

The cost is that the collector holds the full match table for one user profile in memory
before copying anything, which for a fleet-sized profile is tens of thousands of entries
rather than a constant. Measured against a synthetic host it is far below the cost of
hashing the files themselves, and a per-user table bounds it. It would be worth revisiting
if a single profile ever made the table the dominant cost.

A second cost is that the most-specific rule is a heuristic. Two entries with one path
pattern each claiming the same file are separated by artifact id, which is arbitrary but
deterministic, and `artifact_ids` still records both.

## Alternatives considered

- **Decide per artifact, as before.** Rejected: the outcome for credential material
  depended on iteration order.
- **One manifest entry per claim.** Honest about the overlap, but it duplicates the hash
  and the copy of every shared file and makes `counts.collected` no longer the number of
  files collected.
- **Forbid overlapping claims in the schema.** Rejected: the overlap is a property of the
  agents, not of the catalogue. Forbidding it would force the catalogue to describe a
  cross-cutting artifact less completely than it exists.
