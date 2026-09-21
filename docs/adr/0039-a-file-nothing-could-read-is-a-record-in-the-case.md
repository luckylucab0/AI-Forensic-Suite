# ADR 0039: A file nothing could read is a record in the case

- **Status:** accepted
- **Date:** 2026-09-21

## Context

A suite-wide test hands every reader a file whose content is not the format that reader
expects, at a path the reader's own catalogue entry claims, and asserts that something
comes out. Two readers produced nothing, and both were declared in that test with their
reason rather than fixed on the spot, because what a reader emits is what a case contains.

Both are line readers for formats whose records are announced by a prefix.

`crosscutting.shell_fish_history` reads fish's history, where every entry begins with
`- cmd:`. Everything in front of the first one was skipped, documented as what a rotated or
partially copied file begins with. A file with no such line anywhere is all
before-the-first-record, so the reader walked to the end of it and yielded nothing.

`aider.input_history` reads prompt_toolkit's recall file, where an entry is a blank line, a
`# ` stamp and one `+` line per line of the prompt. Any other line closed the open entry
and was not itself reported. A file with no `+` line anywhere has no entry in it, and the
reader ended without one.

Both reasons said the same true thing: the file's own bytes are in the collection either
way. That is also true of every other reader in the suite, all of which still say
something. What an analyst had was an artifact row with zero events beside it, which is not
the same as an agent with no artifacts, but it is the same as a shell nobody typed into and
an aider nobody used. Deciding which of those it is, from a case, was not possible.

## Decision

Neither reader answers with silence. A run of lines that a reader can make no record out of
leaves it as one `unparsed.record` event: the lines in `raw` and in `payload.text`, the
first line of the run as the locator, and a sentence saying what the reader was looking for
and did not find.

Two sentences, because they are two findings. Where records follow, the lines in front of
the first one say that the record they belonged to began before the file does and the
command it ran is not in it: a rotation, a partial copy, or an edit. Where there is no
record anywhere in the file, the sentence says the file is at a path the catalogue records
as this format and holds nothing of it, and names how the format announces a record, so
somebody can tell a wrong catalogue path from a replaced file. The second sentence is
shared, in `parsers.base.NO_RECORD`, because it is the same answer in every format.

A run of blank lines produces nothing, and so does an empty file. Silence is the honest
answer there: the artifact row says the file was collected and zero is true.

The mechanics are one helper, `parsers.base.unreadable_lines`, so that a third reader gets
them by calling it. It groups a run into one event rather than one per line, and says a
decode note that every line of the run carries once instead of repeating it.

The declaration table in the suite-wide test is now empty and stays in the file. An entry
in it needs a sentence saying why an analyst is better served by silence, and a case test
showing what they do have instead, which is deliberately more work than fixing the reader.

## Consequences

An analyst can now tell a file that held nothing from a file whose content was not what the
catalogue says, and both from an agent that was never used. That is the distinction
non-negotiable 6 exists for, and it was the last place in the suite where it was missing.

The cost is events in cases that had none. A collected fish history that is not a fish
history now adds one event per file, and a prompt history with a damaged region adds one per
region. Both count as unparsed records, which is the count a case is judged by, so a
collection of profiles where these files are habitually something else would raise that
number. The count is per file and per damaged run, not per line, which is what keeps it from
becoming noise.

The fish reader now reports the leading fragment even when records follow it, which is
strictly more than the silence question asked for. It is the same defect in a smaller form:
a `when:` with no command above it is evidence that a command was there and is now gone, and
skipping it hid that.

What would make us revisit this: a real collection where one of these sentences fires on
files that are simply in a format the vendor changed. That is a reader to teach, not a
sentence to remove, but the volume would say so first.

## Alternatives considered

- **Leave both declared, as before.** The declaration made the silence visible to a reader
  of the test suite and to nobody reading a case.
- **A collection gap rather than an event.** A gap is a statement about what the collection
  carried. This is a statement about a file that was carried, so it belongs where the file's
  other records would have been: in the timeline an analyst filters.
- **One event per unreadable line.** A file of forty lines in the wrong format would be
  forty identical findings, and the decode note would be said forty times.
- **Fail the parse instead.** The artifact row would say `failed`, which is right, and the
  lines would be nowhere. The reason this suite keeps the content is that the content is
  what tells somebody which of the readings it is.
- **Report an empty file too.** There is nothing to report: an event about it would be a
  claim about bytes that are not there.
