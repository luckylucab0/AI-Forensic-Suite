# ADR 0029: An encrypted store is read only with a key the examiner supplies

- **Status:** accepted
- **Date:** 2026-09-19

## Context

One agent in the catalogue keeps its conversations in an AES-GCM container around a
protocol buffer. Those files are its whole conversation record: the vendor's own
troubleshooting page tells a stuck user to delete the directory they live in, and archiving
a conversation replaces it with a zero-byte file, so what is on the disk when a collection
runs is often all there will ever be.

The key is not the user's and not a secret. It is compiled into the product, it is the same
on every installation, and several public repositories write it down. That makes the files
readable in principle and raises two questions this project had to answer rather than drift
into.

The first is whether to ship the key. A repository that carried it would be distributing a
vendor's key for the convenience of not typing it, and it would do so in a public place
under this project's name.

The second is the cipher. ADR 0012 keeps the runtime to two pure Python dependencies with
no transitive dependencies of their own, because an analyst workstation may be air-gapped
and every wheel has to be vendored. The library that has AES-GCM is neither pure Python nor
dependency-free.

## Decision

The key comes from the examiner at run time, through `--key <agent>=<key>` or
`AFX_KEY_<AGENT>` in the environment, and this repository ships none.

The cipher is an optional extra, `agentforensics[encrypted]`, imported lazily.

A file that cannot be opened is never silently skipped and never guessed at. Each of the
four states produces an event that says which one it is: no key was given, the cipher is
not installed, the key given is not a key, or the key did not open the container. The file
is recorded by size and hash in every case, so it is identifiable in the case and readable
from the bundle by anything else.

The container's framing is tried rather than assumed. Nothing published states where this
product puts the nonce and the tag, so the reader tries a small set of layouts and reports
the one that authenticated. That is not a guess: GCM's tag fails on a wrong framing, so an
authenticated reading is a verified one, and the event records the framing so somebody else
can repeat it.

The plaintext is walked as a protocol buffer with no schema. Fields come out as numbers
because names live in the schema, and every record says so.

## Consequences

The conversations of that agent are readable in a case for the first time, with the
provenance an analyst needs: a locator that is a path through the message, and a statement
of what the reading does and does not know.

The costs are real and deliberate. A default installation cannot open these files, so an
examiner who meets this agent has to install the extra and find the key, and this project
will not hand them the second one. The reading has no field names, so a report quoting it
quotes a string from field 3 of a message rather than "the prompt", which is honest and
less convenient. And a container layout the vendor changes will stop authenticating, which
shows up as a file this reader says it could not open rather than as silence.

We revisit this if the vendor publishes a schema, or if a container layout appears that the
tried set does not cover.

## Alternatives considered

- **Ship the key in the catalogue.** Convenient, and it makes this repository a
  distribution point for a vendor's key. Declined.
- **Make the cipher a hard dependency.** Breaks the air-gap reasoning of ADR 0012 for every
  case, including the ones that never meet this agent.
- **Leave the files unread.** That was the status quo, and it left the only record of a
  product's conversations as a file name in a case.
- **Implement AES-GCM in pure Python.** Avoids the wheel and puts hand-written cryptography
  in the trusted path of a forensic tool, where a subtle bug would be a wrong reading of
  evidence.
