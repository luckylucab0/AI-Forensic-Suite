# ADR 0001: Build a suite around the existing viewer rather than replacing it

- **Status:** accepted
- **Date:** 2026-09-14

## Context

The project started as one dependency-free HTML file that renders Claude Code, Codex CLI
and GitHub Copilot CLI transcripts read-only. It works, it is in use, and it needs no
install. What it cannot do is collect evidence, verify it, cover the other agents, run
detection rules, or produce a timeline.

The obvious move for a Python suite would be to replace it with a web UI served by the
analyzer. That would cost the property that makes it useful in the field: an analyst can
put that one file on a USB stick and open it on a machine where nothing may be installed
and nothing may be downloaded.

## Decision

The viewer stays as a component, at `viewer/index.html`, single-file and dependency-free,
with both of its documented run modes preserved: scraping a served directory listing, and
reading a folder through the browser's File System Access API. The suite adds a third
source that reads the analyzer's local API, without touching the renderer.

Its data layer already sits behind a two-method interface (`listDir`, `readText`) over
opaque path strings, which is the seam that makes this possible.

The Claude-shaped event model the viewer renders is preserved as a projection target: the
analyzer must be able to project any agent's session back into that shape, so the renderer
keeps working unchanged and Claude Code fidelity does not regress.

## Consequences

Buys: a zero-install capability that survives the suite growing, and a UI that is already
built and understood rather than rewritten.

Costs: two rendering paths to keep working, and a constraint on the analyzer's export
format. The viewer also stays a single inline-script file, which means no useful
Content-Security-Policy for its own scripts, so escaping discipline has to carry that
weight instead. That trade is revisited if the viewer ever stops being useful standalone.

## Alternatives considered

- Replace with a served web UI: loses the zero-install property, which is the point.
- Keep them as two separate projects: the event model would drift immediately.
