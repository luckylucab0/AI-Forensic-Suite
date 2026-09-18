# ADR 0024: The analyzer's Python floor is 3.14

- **Status:** accepted
- **Date:** 2026-09-18

## Context

Zed keeps its agent threads in `threads.db` and compresses the thread content with zstd
inside a BLOB column. The consequence is the single worst kind for this project: `strings`
over the file finds nothing, a keyword search finds nothing, and the generic SQLite reader
can only report a hash and a length. An analyst looking at that concludes the agent was not
used, which is exactly the failure non-negotiable 6 exists to prevent.

Reading it needs zstd. The analyzer had a floor of Python 3.11, where zstd is not in the
standard library, so there were three ways out and all of them cost something.

ADR 0012 keeps the runtime dependencies to two, both pure Python with no transitive
dependencies of their own, because an analyst workstation may be air-gapped and every wheel
has to be vendored. `zstandard` is a compiled extension with platform wheels, which is a
different class of dependency from the two already there.

## Decision

The analyzer requires Python 3.14. `compression.zstd` is in the standard library there
(PEP 784), so a compressed transcript becomes readable with no dependency at all and ADR
0012's two-dependency rule stands.

The collectors are untouched and stay at Python 3.8 and PowerShell 5.1. They run on the
endpoint under whatever interpreter a corporate machine happens to have, which is the whole
reason they are single files with no imports beyond the standard library. The floor raised
here is the analyst's workstation, which is a machine somebody chose.

## Consequences

Zed's threads become readable, and so does anything else an agent compresses this way. That
is 6 catalogue artifacts for Zed alone, two of them transcript stores.

The cost is the floor itself. 3.14 is recent, and an analyst on a long-term-support
distribution will not have it from the package manager. The mitigations are real but they
are still work: `uv` installs an interpreter on request, and the tool is source-available
so a workstation image can carry one. An air-gapped workstation now has to vendor an
interpreter as well as two wheels.

The second cost is that this is the first version-gated feature in the project. Until now
any 3.11 interpreter would run the analyzer, and a bug report could be reproduced anywhere.

We would revisit this if a case arrived where the floor blocked an examination that
mattered more than reading Zed: the answer then is `zstandard` as an optional extra, with
the zstd reader reporting an uncompressed blob honestly when neither is available.

## Alternatives considered

- **`zstandard` as a runtime dependency.** Works on 3.11 and adds a compiled extension with
  platform wheels to a set of dependencies deliberately kept pure Python.
- **Leave Zed's threads uninterpreted.** Cheapest, and it leaves the generic reader reporting
  a hash and a length for the one agent whose content is least reachable by any other means.
- **Shell out to a `zstd` binary.** No dependency in the package, and a dependency on the
  examiner's machine that the tool cannot check for, plus a subprocess in the read path of
  evidence.
- **Vendor a pure-Python zstd decoder.** None exists that is maintained, and a decompressor
  nobody audits in the read path of evidence is worse than not reading the file.
