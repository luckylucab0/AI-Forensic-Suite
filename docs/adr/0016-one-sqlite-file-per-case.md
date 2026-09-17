# ADR 0016: one SQLite file per case, keyed by provenance

- **Status:** accepted
- **Date:** 2026-09-17

## Context

The analyzer has to put events somewhere that an analyst can copy, hash, hand to a
colleague and open again in two years, on a workstation that may be air-gapped and that
certainly has no database server on it. It also has to survive the thing that will happen
repeatedly: a parser is found to be wrong, it is fixed, and the same evidence is read
again.

## Decision

One SQLite file per case, created by the analyzer, with a schema version in it.

Every event id is a hash of its provenance and its kind, never a counter. Provenance is the
bundle identifier, the original path on the endpoint, the file hash and a locator inside the
file. So the same evidence always produces the same identifier, which makes re-ingest a
no-op instead of a duplication, and a finding recorded last week still points at the same
event after the case is rebuilt.

A tree with no manifest gets a bundle identifier derived from its root path for the same
reason. A generated one would have made re-ingesting a mounted image double the case.

The kind is in the hash because one record legitimately produces several events: a
transcript turn that calls a tool is both an assistant turn and a tool call, and they share
a locator while needing separate identities.

Identity columns point at a users table and a hosts table rather than holding names, so
pseudonymizing a case later is an update to two small tables rather than a rewrite of every
row. Nothing in the schema cascades on delete, and nothing in the code deletes an event:
the way to discard a case is to discard the file.

## Consequences

A case is a single file, which is what makes it evidence somebody can handle. Re-ingest is
safe, which is what makes fixing a parser a normal thing to do rather than a decision about
whether the case survives it.

The cost is that a schema change is not a migration. A case written by an older schema is
refused rather than upgraded, with a message saying to re-ingest into a new one, because a
partly migrated case would have counts nobody could trust and a count is what an analyst
reads first. That is acceptable while the bundles are the durable artifact and the case is
derived from them; it would not be acceptable if the case ever became the only copy.

Hashing provenance also means an event id changes when the file it came from changes, even
if the record inside it did not. That is the correct behaviour for evidence, and it does
mean two collections of the same endpoint produce two sets of events for the same
conversation. They are distinguishable by bundle, which is what an analyst comparing two
collections wants anyway.

## Alternatives considered

- A row id and a separate natural key. The natural key would have had to be indexed and
  checked on every insert anyway, and every finding would have pointed at a number that
  changed when a case was rebuilt.
- One file per bundle. A case regularly holds more than one collection: an endpoint
  collected twice, or an endpoint and the SSH host it worked on, and the questions asked
  span them.
- A document store or a server-backed database. Neither is in the standard library, and
  the deployment target is an examiner's workstation with no network.
