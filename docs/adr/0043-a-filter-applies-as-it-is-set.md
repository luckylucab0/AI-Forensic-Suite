# ADR 0043: A filter applies as it is set, and there is no pending state to commit

- **Status:** accepted
- **Date:** 2026-09-21

## Context

The time window in the Evidence Desk mockup is a panel with **Cancel** and **Apply** at the
bottom: the analyst picks a preset, types a bound, flips the switches, and nothing happens
until they commit. That is the usual shape for a form with several fields, and the window
does have several — two bounds, a timezone, and four switches.

It sits badly against ADR 0009. The rule there is that a filter may take rows off the
screen because somebody asked it to, and may never leave them looking absent; the line
saying how many rows are out of view is what makes that true. A panel with a pending state
has two answers to "what is hidden right now" — the window that is applied, and the window
that is typed — and the count under the chip row can only report one of them. Whichever it
reports is wrong half the time the panel is open.

The other half of the problem is the presets. Several of them are derived rather than typed:
*Before the deletion* resolves to the timestamp of the first thing a rule called
anti-forensic, *Collection* to the bundle's own start and finish, *Session span* to the open
conversation's first and last record. An analyst clicking one of those is asking a question
whose answer they cannot predict. Behind an Apply button they find out what they asked only
after committing to it.

## Decision

Every filter in the viewer applies the moment it is set, including the time window. The
panel has no Cancel and no Apply. It has **reset**, which clears the window, and **Done**,
which closes the panel and changes nothing.

The count travels with it. The window's own trigger prints how many rows it is hiding — its
own rows, not what every filter together is hiding — and the red line under the chip row
prints the total with a link that clears everything. Both are true at every moment the panel
is open, because there is only ever one window.

Where a view cannot honestly count what a window removed, it says nothing rather than
guessing: the timeline's window is applied by the case before the rows are paged, so the
viewer never sees what was left out and its trigger carries no number.

## Consequences

What this buys is that the hidden-row count is never stale, and that a derived preset shows
its answer instead of promising one. Clicking *Before the deletion* fills the bounds, redraws
the rows, and says how many it took out, all before the analyst has decided whether that was
the question they meant.

The cost is real and worth naming. Each change re-runs the view, so on a case where the
window is served rather than applied locally — the timeline, the tool list — flipping three
switches is three round trips where a form would have made one. On a large case that is
visible. It also means there is no way to build a window up privately and then look: the
screen moves under the analyst while they are still deciding.

Revisit this if the round trips become the complaint, and note that the fix is not a Cancel
and Apply pair. It is to debounce the fetch — keep applying as it is set, and coalesce the
requests — so the count stays honest and only the network settles down.

## Alternatives considered

- **Cancel and Apply, as drawn.** Two windows exist while the panel is open and the hidden
  count can only describe one of them, which is the thing ADR 0009 exists to prevent.
- **Apply live, but show a preview count for the pending window.** Two numbers on screen,
  one of which describes rows that are not being hidden yet. Worse than either.
- **Apply live for the local views, Cancel and Apply for the served ones.** One control that
  means two different things depending on which tab it is in, which is how an analyst ends
  up believing a filter is set when it is not.
