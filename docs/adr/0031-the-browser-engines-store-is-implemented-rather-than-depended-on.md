# ADR 0031: The browser engine's store is implemented here rather than depended on

- **Status:** accepted
- **Date:** 2026-09-19

## Context

Two of the catalogued desktop products are Electron applications, so their window state
lives where a browser puts it: IndexedDB, Local Storage and Session Storage, each a LevelDB
directory. For one of the two, the published writeup behind the catalogue entry puts the
prompts and the responses in that store and adds that it is removed when the user logs out.
Until this decision the suite collected those directories and read nothing in them, so a
case said four file names and an analyst reading it would conclude the product had not been
used. That is the failure non-negotiable 6 exists to prevent.

Reading the format needs three things: the table and log framing, Snappy for the blocks
that are compressed with it, and zstd for the blocks that are not. The last is in the
standard library since the floor this project already sits on (ADR 0024). The first two are
not, and every library that offers them is a compiled extension.

ADR 0012 keeps the runtime to two pure-Python dependencies so the tool can be vendored into
an air-gapped environment. A compiled extension is the opposite of that: it has to be built
per platform and per Python version, and an examiner's workstation is exactly where that
goes wrong.

## Decision

The table format, the log framing and Snappy block decompression are implemented in this
package, in `parsers/leveldb.py` and `parsers/snappy.py`. No dependency is added.

The reading stops at the records. A key and a value come out as bytes, every record carries
the uninterpreted mark, and the text offered beside a record is extracted from it rather
than decoded, which the record says of itself. The engine's own object serialisation is not
read, because nobody here has a source for it.

Block checksums are not verified. They are CRC32C, whose polynomial the standard library
does not carry, and a reader that refused a block over an unverified checksum would refuse
evidence that expands perfectly well. A block that fails to expand fails loudly instead,
and the records that came out before it stay in the case.

## Consequences

The two stores are read on any machine that runs the analyzer at all, with nothing to
build. The floor is the same one every other unmapped format stands on, so a reader for the
engine's serialisation can be put in front of it later without changing a single record
that is already in a case.

The cost is that this package now carries two format implementations that somebody has to
maintain, and they are tested against files built from the specification rather than
against files a real product wrote, because no real agent data may enter this repository.
A store that uses a block compression this reader does not know, or a table variant it does
not expect, fails loudly on that file rather than reading it.

What would make us revisit it: a pure-Python implementation of either format published as a
package worth depending on, or a store in this catalogue whose blocks this reader cannot
expand.

## Alternatives considered

- **Depend on a compiled LevelDB or Snappy binding.** Breaks air-gapped vendoring, which is
  the one property ADR 0012 was written to protect.
- **Read only the table files.** The write-ahead log is where a running application's newest
  writes are until a compaction, so this would return a store's whole history except the
  part of it that happened last.
- **Shell out to a carving tool.** A runtime dependency on something that is not in the
  bundle, on an examiner's machine, for a format that is a few hundred lines.
- **Leave the stores unread and say so in the case.** Honest, and the state this replaces.
  It answers "was this product used" with a file listing when the conversation is on the
  disk and readable.
