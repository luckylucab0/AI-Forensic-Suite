# ADR 0005: The evidence bundle mirrors original paths, and custody is a hash chain

- **Status:** accepted
- **Date:** 2026-09-14

## Context

The analyzer must read evidence from several sources: our own collector, a KAPE output
tree, a Velociraptor offline collection, a mounted disk image, and an exported user
profile. Written naively that is five ingest paths with five sets of assumptions.

Separately, a chain of custody is expected to be append-only, but it lives as a file in a
writable directory, so "append-only" cannot be enforced by the format.

## Decision

A bundle is a directory, optionally zipped: `manifest.json`, `chain_of_custody.jsonl`, and
a `files/` tree that mirrors each artifact's original absolute path, KAPE style
(`files/C/Users/alice/...`, `files/Users/alice/...`).

Because every supported source reduces to a root plus original paths, one adapter shape
handles all of them.

The path encoding from an original absolute path to a bundle-relative path is specified
with its inverse, covering Windows drive letters and UNC paths, characters that are legal
on the source but not on the analyst's filesystem, reserved Windows device names, non-UTF8
bytes on Linux, over-long components, and case collisions when a case-sensitive source is
written to a case-insensitive destination. The manifest always carries the true original
path, so the encoding is never the only record of where a file came from.

`chain_of_custody.jsonl` is a hash chain: each record carries the hash of the previous
record and of `manifest.json`.

## Consequences

Buys: uniform ingest, and a custody log where a removed or altered record breaks the chain
visibly.

Costs: the path encoding is the fiddly part of the format and needs its own tests, since
every rule in it exists because some real filesystem disagrees with another. The honest
claim about custody is tamper-evident, not tamper-proof, and the documentation says so
rather than implying more. Stronger guarantees would need a signature or an external
timestamp, which is a later decision, not a format change.

## Alternatives considered

- Flat storage with paths only in the manifest: loses the shared ingest shape and makes a
  bundle unreadable without our tooling.
- Preserving paths verbatim: impossible across platforms, since a Windows path cannot be
  written on a case-sensitive POSIX volume without loss, and vice versa.
