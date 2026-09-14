# ADR 0004: Two single-file collectors, Python 3.8 and PowerShell 5.1

- **Status:** accepted
- **Date:** 2026-09-14

## Context

Collection happens on a machine under investigation. Realistically that means: no
dependencies may be installed, nothing may be downloaded, the interpreter is whatever the
corporate image ships, and the operator may only have a live-response channel that can put
one file and run one command. Several agents delete their own history on a 30 day default
schedule, so this has to be possible in minutes.

Python is not reliably present on Windows. PowerShell is not present on macOS or Linux in
any version worth targeting.

## Decision

Two implementations of one specification:

- `collector/collect.py`, POSIX, Python 3.8 or newer, standard library only
- `collector/collect.ps1`, Windows, PowerShell 5.1 or newer, no modules

Each is a single file with the catalogue embedded. Python 3.8 and PowerShell 5.1 are the
floors because that is what corporate fleets actually have.

Drift between two implementations is prevented by three things, not one:

1. A bundle conformance suite, written once in pytest, run against a bundle from either
   collector.
2. A differential test in CI that diffs the two manifests, modulo a documented list of
   fields that are allowed to differ.
3. The written format specification in `docs/BUNDLE_FORMAT.md`.

The list of fields allowed to differ is part of the specification, not an implementation
detail, because it is where the operating systems genuinely disagree: `birthtime` does not
exist on Linux, `atime` is meaningless on a volume mounted `noatime` or `relatime`, `ctime`
is inode change time on Unix and creation time on Windows, and uid/gid do not exist on
Windows.

## Consequences

Buys: a collector that runs anywhere, deployable through EDR live response or a USB stick,
with no supply chain at collection time.

Costs: every collector feature is implemented twice, and the two languages disagree in ways
that will bite silently unless tested. PowerShell 5.1 in particular defaults to UTF-16LE
output, a `ConvertTo-Json` depth of 2, and non-deterministic hashtable ordering. Python 3.8
excludes a decade of syntax. Both are accepted deliberately and pinned by CI jobs that run
the real interpreters.

## Alternatives considered

- One Python collector plus a bundled interpreter: no longer a single small file, and
  dropping an interpreter onto a machine under investigation is its own problem.
- A compiled binary: signing, architecture and trust problems on every platform, and much
  harder for an operator to read before running it, which matters when the tool touches
  evidence.
- Shell script for POSIX: deferred, noted as a later fallback for hosts without Python.
