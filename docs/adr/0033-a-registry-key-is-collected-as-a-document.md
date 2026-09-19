# ADR 0033: A registry key is collected as a document

- **Status:** accepted
- **Date:** 2026-09-19

## Context

Six catalogue entries are Windows registry keys, and two of them are the managed policy
that says what an agent was allowed to do. On Windows that policy can exist in the registry
alone, with no file anywhere. Neither collector could read a key, no generated collection
rule covered one, and four separate places in this repository said otherwise until that was
corrected. So a case built from a Windows endpoint said nothing about the control that was
supposed to be in force, and a reader would take that as no policy rather than as nobody
having looked.

The bundle format had no way to carry a key. Everything in it is a file copied off the
disk, mirrored at its original path, hashed as bytes.

## Decision

A registry key is collected as a JSON document written by the collector, placed under
`files/registry/` and named after the key. Its manifest entry is an ordinary entry with
`source_kind: registry`, the key as `original_path`, and the document's hash, so it
verifies and ingests exactly like a file. The shape is specified in
docs/BUNDLE_FORMAT.md and both collectors write it.

Four of the six entries are read this way, not all six. The list is in
`scripts/build_collectors.py`, which marks them in the embedded catalogue, and the analyzer
holds the same four with a test binding the two. Left out are the platform's own execution
evidence and an installer's persistence keys: every general purpose registry tool reads
those better than this one would, and a second, worse answer beside an examiner's existing
one is not worth having.

Only on a live host. A hive file needs a parser this suite does not have, so with a root
set the entries record `registry_needs_a_live_host` rather than looking like absent keys.

A key that exists and is empty gets a document with no values; a key that does not exist
gets an entry with nothing behind it. For a policy key those are different answers and the
format keeps them apart.

## Consequences

The managed policy reaches a case, and the rules about permissions, endpoints and hooks see
it: one product stores its whole settings document as JSON in a single string value, and
the reader parses it, so a policy is searched the way a settings file is. The hive is a
field, which makes AFX-PERMISSIONBYPASS-009 possible: a policy under the user's own hive is
one a non-administrator could have written, and that distinction exists nowhere else.

The cost is an asymmetry between the two collectors, and it is documented rather than
hidden. The Python collector records the key's last-write time from one standard-library
call. PowerShell 5.1 cannot: reaching it needs RegQueryInfoKey through P/Invoke, which
means compiling code on a machine under investigation, and a collector that writes a
temporary assembly to an endpoint, which application control is entitled to block, is a
worse trade than a document with no timestamp. So that field is null from the PowerShell
collector, every event says the time is the key's rather than the value's, and an examiner
who needs key times takes the hive with a tool built to parse one.

What would make us revisit it: a way to read a key's last-write time from PowerShell 5.1
without compiling, or a hive parser small enough to live in this package, which would turn
this from a live-host capability into an image one.

## Alternatives considered

- **Leave the keys uncollected and say so.** The state this replaces. It answers the
  question a policy key exists to answer with silence.
- **Collect the hive files instead.** They are locked on a running system, they are large,
  and nothing here could read one, so it would move the gap rather than close it.
- **Read all six entries.** Duplicates work that established tools do better and puts a
  second answer next to an examiner's existing one.
- **Use P/Invoke for the last-write time.** Buys one field and costs the property that
  makes this collector deployable: a single file that compiles nothing on the endpoint.
